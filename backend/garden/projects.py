"""Private graph drafts, shared editing and email invitations."""
import asyncio
import hashlib
import os
import secrets
import sqlite3
import time
import zlib
from datetime import UTC, datetime
from email.message import EmailMessage
from typing import Annotated, Literal
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import Field, StringConstraints, ValidationError, model_validator

from garden.accounts import check_origin, current_user, normalize_email, public_url, rate_limit
from garden.integrations import prepare_smtp_send
from garden.models import Id, Model, Node, Source, Workflow


async def private_response(response: Response) -> None:
    response.headers["Cache-Control"] = "private, no-store"
    response.headers["Vary"] = "Cookie"


router = APIRouter(prefix="/api", dependencies=[Depends(private_response)])
ProjectName = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=100)]
Role = Literal["owner", "editor"]
MERGE_HISTORY = 32
PRESENCE_SECONDS = 35


class ProjectGraph(Workflow):
    """Drafts can have disconnected blocks or no sources while people edit them."""
    name: ProjectName
    nodes: list[Node] = Field(max_length=40)
    files: list[Source] = Field(max_length=400)

    @model_validator(mode="after")
    def valid_workflow(self):
        nodes = {node.id for node in self.nodes}
        if len(nodes) != len(self.nodes) or len({edge.id for edge in self.edges}) != len(self.edges):
            raise ValueError("Повторяющийся идентификатор в графе")
        if any(edge.source not in nodes or edge.target not in nodes for edge in self.edges):
            raise ValueError("Связь указывает на отсутствующий блок")
        return self


class ProjectSummary(Model):
    id: str
    name: str
    role: Role
    revision: int
    updated_at: str


class ProjectDetail(ProjectSummary):
    workflow: ProjectGraph


class NewProject(Model):
    name: ProjectName
    workflow: ProjectGraph | None = None


class SaveProject(Model):
    base_revision: int = Field(ge=1, le=2**63-1)
    workflow: ProjectGraph
    edit_base: ProjectGraph | None = None


class Invite(Model):
    email: str = Field(max_length=254)


class AcceptInvite(Model):
    token: str = Field(min_length=40, max_length=100, pattern=r"^[a-zA-Z0-9_-]+$")


def init_projects(db: sqlite3.Connection):
    db.executescript("""
        CREATE TABLE IF NOT EXISTS projects (
            id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, name TEXT NOT NULL, revision INTEGER NOT NULL,
            updated_at TEXT NOT NULL, body TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS projects_owner ON projects(owner_id);
        CREATE TABLE IF NOT EXISTS project_versions (
            project_id TEXT NOT NULL, revision INTEGER NOT NULL, body BLOB NOT NULL,
            PRIMARY KEY(project_id,revision));
        CREATE TABLE IF NOT EXISTS project_members (
            id TEXT PRIMARY KEY, project_id TEXT NOT NULL, email TEXT NOT NULL, account_id TEXT,
            token_hash TEXT UNIQUE, expires_at INTEGER, UNIQUE(project_id,email));
        CREATE INDEX IF NOT EXISTS members_by_account ON project_members(account_id,project_id);
        CREATE TABLE IF NOT EXISTS project_presence (
            project_id TEXT NOT NULL, account_id TEXT NOT NULL, expires_at INTEGER NOT NULL,
            PRIMARY KEY(project_id,account_id));
        CREATE INDEX IF NOT EXISTS presence_expiry ON project_presence(expires_at);
        DELETE FROM project_presence WHERE expires_at <= unixepoch();
    """)


def project_query(include_graph: bool) -> str:
    fields = "p.id,p.name,p.revision,p.updated_at,CASE WHEN p.owner_id=:user THEN 'owner' ELSE 'editor' END"
    return "SELECT " + fields + (",p.body" if include_graph else "") + """
        FROM projects p WHERE (p.owner_id=:user OR EXISTS (
            SELECT 1 FROM project_members m WHERE m.project_id=p.id AND m.account_id=:user))"""


def summary(row) -> ProjectSummary:
    return ProjectSummary(id=row[0], name=row[1], revision=row[2], updated_at=row[3], role=row[4])


def accessible_row(request: Request, project_id: str, include_graph: bool = True):
    user = current_user(request)
    row = request.app.state.store.db.execute(project_query(include_graph) + " AND p.id=:id",
                                             {"user": user.id, "id": project_id}).fetchone()
    if not row:
        raise HTTPException(404, "Проект не найден или доступ отозван")
    return row


def require_project(request: Request, project_id: str) -> ProjectDetail:
    row = accessible_row(request, project_id)
    return ProjectDetail(**summary(row).model_dump(), workflow=ProjectGraph.model_validate_json(row[5]))


def require_owner(request: Request, project_id: str) -> ProjectSummary:
    project = summary(accessible_row(request, project_id, False))
    if project.role != "owner":
        raise HTTPException(403, "Управлять доступом может только владелец")
    return project


def schedule(request: Request, project: ProjectDetail):
    callback = getattr(request.app.state, "reschedule_project", None)
    if callback:
        callback(project.id, project.workflow)


@router.get("/projects")
async def list_projects(request: Request) -> list[ProjectSummary]:
    user = current_user(request)
    rows = request.app.state.store.db.execute(project_query(False) + " ORDER BY p.updated_at DESC,p.id",
                                              {"user": user.id})
    return [summary(row) for row in rows]


@router.post("/projects", status_code=201)
async def create_project(request: Request, body: NewProject) -> ProjectDetail:
    check_origin(request)
    user = current_user(request)
    graph = (body.workflow.model_copy(update={"name": body.name}) if body.workflow else
             ProjectGraph(name=body.name, nodes=[Node(id="start", kind="manual", x=0, y=0)], edges=[], files=[]))
    project = ProjectDetail(id=uuid4().hex, name=graph.name, role="owner", revision=1,
                            updated_at=datetime.now(UTC).isoformat(), workflow=graph)
    db = request.app.state.store.db
    with db:
        db.execute("INSERT INTO projects(id,owner_id,name,revision,updated_at,body) VALUES(?,?,?,?,?,?)",
                   (project.id, user.id, graph.name, 1, project.updated_at, graph.model_dump_json()))
    schedule(request, project)
    return project


@router.get("/projects/{project_id}", response_model=ProjectDetail)
async def get_project(request: Request, response: Response, project_id: Id):
    # Authorize even conditional requests; a cached revision never confers access.
    row = accessible_row(request, project_id, False)
    tag = f'"{project_id}-{row[2]}"'
    headers = {"ETag": tag, "Cache-Control": "private, no-cache", "Vary": "Cookie"}
    if request.headers.get("if-none-match") == tag:
        return Response(status_code=304, headers=headers)
    project = require_project(request, project_id)
    response.headers.update({**headers, "ETag": f'"{project_id}-{project.revision}"'})
    return project


_MISSING = object()


def merge_value(base, mine, theirs, path):
    if mine == base:
        return theirs
    if theirs == base or mine == theirs:
        return mine
    raise HTTPException(409, f"Параллельно изменено: {path}. Откройте актуальную версию для сравнения.")


def merge_items(base, mine, theirs, key, label):
    old, local, current = ({item[key]: item for item in sequence} for sequence in (base, mine, theirs))
    merged = []
    for ident in dict.fromkeys((*current, *local)):
        a, b, c = (items.get(ident, _MISSING) for items in (old, local, current))
        path = f"{label}/{ident}"
        if all(isinstance(item, dict) for item in (a, b, c)):
            # Models were normalized before saving. Lists inside a block are one atomic setting.
            item = {field: merge_value(a[field], b[field], c[field], path + "/" + field) for field in a}
        else:
            item = merge_value(a, b, c, path)
        if item is not _MISSING:
            merged.append(item)
    return merged


def merge_graph(base: ProjectGraph, mine: ProjectGraph, theirs: ProjectGraph) -> ProjectGraph:
    old, local, current = (item.model_dump() for item in (base, mine, theirs))
    merged = {"name": merge_value(old["name"], local["name"], current["name"], "название")}
    for field, key in (("nodes", "id"), ("edges", "id"), ("files", "path")):
        merged[field] = merge_items(old[field], local[field], current[field], key, field)
    try:
        return ProjectGraph.model_validate(merged)
    except ValidationError:
        raise HTTPException(409, "Совместные правки несовместимы. Сравните граф с актуальной версией.") from None


@router.put("/projects/{project_id}")
async def update_project(request: Request, project_id: Id, body: SaveProject) -> ProjectDetail:
    check_origin(request)
    db = request.app.state.store.db
    with db:
        db.execute("BEGIN IMMEDIATE")
        project = require_project(request, project_id)
        graph = body.workflow
        if body.edit_base is not None:
            # Typing can continue while the previous PUT is in flight. Its submitted
            # graph, not the server's merged response, is the base of these new edits.
            graph = merge_graph(body.edit_base, graph, project.workflow)
        elif body.base_revision != project.revision:
            row = db.execute("SELECT body FROM project_versions WHERE project_id=? AND revision=?",
                             (project_id, body.base_revision)).fetchone()
            if not row:
                raise HTTPException(409, "Исходная версия устарела. Откройте актуальную версию для сравнения.")
            graph = merge_graph(ProjectGraph.model_validate_json(zlib.decompress(row[0])), graph, project.workflow)
        if graph == project.workflow:
            return project
        db.execute("INSERT INTO project_versions VALUES(?,?,?)",
                   (project_id, project.revision, zlib.compress(project.workflow.model_dump_json().encode(), 1)))
        project = project.model_copy(update={"workflow": graph, "name": graph.name, "revision": project.revision + 1,
                                             "updated_at": datetime.now(UTC).isoformat()})
        db.execute("UPDATE projects SET name=?,revision=?,updated_at=?,body=? WHERE id=?",
                   (graph.name, project.revision, project.updated_at, graph.model_dump_json(), project_id))
        db.execute("DELETE FROM project_versions WHERE project_id=? AND revision<?",
                   (project_id, project.revision - MERGE_HISTORY))
    schedule(request, project)
    return project


@router.get("/projects/{project_id}/members")
async def list_members(request: Request, project_id: Id):
    accessible_row(request, project_id, False)
    db = request.app.state.store.db
    owner = db.execute("""SELECT a.id,a.email,a.name FROM accounts a
                          JOIN projects p ON p.owner_id=a.id WHERE p.id=?""", (project_id,)).fetchone()
    members = [{"id": owner[0], "email": owner[1], "name": owner[2], "role": "owner", "status": "active"}]
    rows = db.execute("""SELECT m.id,m.email,a.name,m.account_id FROM project_members m
                         LEFT JOIN accounts a ON m.account_id=a.id WHERE m.project_id=? ORDER BY m.email""", (project_id,))
    members.extend({"id": ident, "email": email, "name": name or "", "role": "editor",
                    "status": "active" if account else "pending"} for ident, email, name, account in rows)
    return members


@router.post("/projects/{project_id}/presence")
async def project_presence(request: Request, project_id: Id):
    check_origin(request)
    user = current_user(request)
    db = request.app.state.store.db
    now = int(time.time())
    with db:
        db.execute("BEGIN IMMEDIATE")
        accessible_row(request, project_id, False)
        db.execute("DELETE FROM project_presence WHERE expires_at<=?", (now,))
        db.execute("""INSERT INTO project_presence VALUES(?,?,?) ON CONFLICT(project_id,account_id)
                      DO UPDATE SET expires_at=excluded.expires_at""", (project_id, user.id, now + PRESENCE_SECONDS))
        rows = db.execute("""SELECT a.id,a.name FROM project_presence p JOIN accounts a ON a.id=p.account_id
                             WHERE p.project_id=? AND p.account_id!=? ORDER BY a.name,a.id""",
                          (project_id, user.id)).fetchall()
    return {"peers": [{"id": account, "name": name} for account, name in rows]}


def send_invitation(email: str, name: str, token: str) -> str:
    host = os.getenv("GARDEN_SMTP_HOST")
    if not host:
        return "link"
    try:
        origin = public_url()
        if not origin.startswith("https://"):
            return "failed"
        message = EmailMessage()
        message["To"] = email
        message["Subject"] = "Garden — приглашение в проект"
        message.set_content(f"Вас пригласили редактировать проект «{name}». Войдите с адресом {email} "
                            f"и примите приглашение в течение семи дней.\n\n{origin}/#invite={token}")
        send = prepare_smtp_send(message)
        send()
        return "sent"
    except (KeyError, OSError, ValueError, OverflowError):
        return "failed"


@router.post("/projects/{project_id}/members", status_code=201)
async def invite_member(request: Request, project_id: Id, body: Invite):
    check_origin(request)
    try:
        email = normalize_email(body.email)
    except ValueError as err:
        raise HTTPException(422, "Укажите корректную почту") from err
    token = secrets.token_urlsafe(32)
    digest = hashlib.sha256(token.encode()).hexdigest()
    db = request.app.state.store.db
    if os.getenv("GARDEN_SMTP_HOST"):
        require_owner(request, project_id)
        rate_limit(request, "send-invitations", 30)
    with db:
        db.execute("BEGIN IMMEDIATE")
        project = require_owner(request, project_id)
        if current_user(request).email == email:
            raise HTTPException(409, "Вы уже владелец проекта")
        row = db.execute("SELECT id,account_id FROM project_members WHERE project_id=? AND email=?",
                         (project_id, email)).fetchone()
        if row and row[1]:
            raise HTTPException(409, "Участник уже имеет доступ")
        member_id = row[0] if row else uuid4().hex
        db.execute("""INSERT INTO project_members(id,project_id,email,token_hash,expires_at) VALUES(?,?,?,?,?)
                      ON CONFLICT(project_id,email) DO UPDATE SET token_hash=excluded.token_hash,
                      expires_at=excluded.expires_at""", (member_id, project_id, email, digest, int(time.time())+7*86400))
    delivery = await asyncio.to_thread(send_invitation, email, project.name, token)
    return {"id": member_id, "email": email, "token": token, "delivery": delivery}


@router.post("/project-invitations/accept")
async def accept_invite(request: Request, body: AcceptInvite) -> ProjectDetail:
    check_origin(request)
    user = current_user(request)
    db = request.app.state.store.db
    with db:
        db.execute("BEGIN IMMEDIATE")
        row = db.execute("""SELECT id,project_id,email,expires_at FROM project_members
                            WHERE token_hash=? AND account_id IS NULL""",
                         (hashlib.sha256(body.token.encode()).hexdigest(),)).fetchone()
        if not row or row[3] <= time.time():
            raise HTTPException(404, "Приглашение недействительно или истекло")
        if row[2] != user.email:
            raise HTTPException(403, "Войдите с адресом, на который отправлено приглашение")
        db.execute("UPDATE project_members SET account_id=?,token_hash=NULL,expires_at=NULL WHERE id=?", (user.id, row[0]))
        project = require_project(request, row[1])
    return project


@router.delete("/projects/{project_id}/members/{member_id}", status_code=204)
async def revoke_member(request: Request, project_id: Id, member_id: Id):
    check_origin(request)
    db = request.app.state.store.db
    with db:
        db.execute("BEGIN IMMEDIATE")
        require_owner(request, project_id)
        member = db.execute("DELETE FROM project_members WHERE project_id=? AND id=? RETURNING account_id",
                            (project_id, member_id)).fetchone()
        if not member:
            raise HTTPException(404, "Участник или приглашение не найдены")
        db.execute("DELETE FROM project_presence WHERE project_id=? AND account_id=?", (project_id, member[0]))
    return Response(status_code=204)
