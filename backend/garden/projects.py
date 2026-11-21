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
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import Field, StringConstraints, ValidationError, model_validator

from garden import board_presence
from garden.accounts import check_origin, current_user, normalize_email, public_url, rate_limit, session_user
from garden.integrations import prepare_smtp_send
from garden.invitations import InviteToken, find_invitation
from garden.models import Id, Model, Node, Source, Workflow


async def private_response(response: Response) -> None:
    response.headers["Cache-Control"] = "private, no-store"
    response.headers["Vary"] = "Cookie"


router = APIRouter(prefix="/api", dependencies=[Depends(private_response)])
ProjectName = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=100)]
MemberRole = Literal["editor", "viewer", "reporter"]
Role = Literal["owner", "editor", "viewer", "reporter"]
Permission = Literal["view_reports", "view_graph", "edit", "run"]
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
    can_run: bool
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
    client_id: board_presence.ClientId | None = None
    lease_id: board_presence.ClientId | None = None


class Invite(Model):
    email: str = Field(max_length=254)
    role: MemberRole | None = None
    can_run: bool | None = Field(default=None, strict=True)
    reissue_id: Id | None = None


class MemberAccess(Model):
    role: MemberRole
    can_run: bool = Field(strict=True)

    @model_validator(mode="after")
    def valid_access(self):
        if self.role == "reporter" and self.can_run:
            raise ValueError("Для запуска проверок нужен доступ к графу")
        return self


class AcceptInvite(Model):
    token: InviteToken


class InvitePreview(Model):
    status: Literal["pending", "wrong_account", "sign_in", "accepted"]
    project_name: str | None = None
    email_hint: str | None = None
    project_id: str | None = None


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
    with db:
        db.execute("BEGIN IMMEDIATE")
        columns = {row[1] for row in db.execute("PRAGMA table_info(project_members)")}
        if "role" not in columns:
            db.execute("""ALTER TABLE project_members ADD COLUMN role TEXT NOT NULL DEFAULT 'editor'
                          CHECK(role IN ('editor','viewer','reporter'))""")
        if "can_run" not in columns:
            db.execute("""ALTER TABLE project_members ADD COLUMN can_run INTEGER NOT NULL DEFAULT 1
                          CHECK(can_run IN (0,1) AND (role!='reporter' OR can_run=0))""")


def project_query(include_graph: bool) -> str:
    fields = """p.id,p.name,p.revision,p.updated_at,CASE WHEN p.owner_id=:user THEN 'owner' ELSE m.role END,
                CASE WHEN p.owner_id=:user THEN 1 ELSE m.can_run END"""
    return "SELECT " + fields + (",p.body" if include_graph else "") + """
        FROM projects p LEFT JOIN project_members m ON m.project_id=p.id AND m.account_id=:user
        WHERE (p.owner_id=:user OR m.id IS NOT NULL)"""


def summary(row) -> ProjectSummary:
    return ProjectSummary(id=row[0], name=row[1], revision=row[2], updated_at=row[3], role=row[4], can_run=row[5])


def accessible_row(request: Request, project_id: str, include_graph: bool, permission: Permission = "view_graph"):
    user = current_user(request)
    row = request.app.state.store.db.execute(project_query(include_graph) + " AND p.id=:id",
                                             {"user": user.id, "id": project_id}).fetchone()
    if not row:
        raise HTTPException(404, "Проект не найден или доступ отозван")
    if permission == "view_graph" and row[4] == "reporter":
        raise HTTPException(403, "Вам доступны только отчёты проекта")
    if permission == "edit" and row[4] not in ("owner", "editor"):
        raise HTTPException(403, "У вас нет права редактировать этот проект")
    if permission == "run" and (not row[5] or row[4] == "reporter"):
        raise HTTPException(403, "У вас нет права запускать проверки проекта")
    return row


def require_access(request: Request, project_id: str, permission: Permission = "view_reports") -> ProjectSummary:
    return summary(accessible_row(request, project_id, False, permission))


def require_project(request: Request, project_id: str,
                    permission: Literal["edit", "run", "view_graph"] = "view_graph") -> ProjectDetail:
    row = accessible_row(request, project_id, True, permission)
    return ProjectDetail(**summary(row).model_dump(), workflow=ProjectGraph.model_validate_json(row[6]))


def require_owner(request: Request, project_id: str) -> ProjectSummary:
    project = require_access(request, project_id)
    if project.role != "owner":
        raise HTTPException(403, "Управлять доступом может только владелец")
    return project


def schedule(request: Request, project: ProjectDetail):
    callback = getattr(request.app.state, "reschedule_project", None)
    if callback:
        callback(project.id, project.workflow)


def team_connections() -> set[str]:
    return {item.strip() for item in os.environ.get("GARDEN_TEAM_CONNECTIONS", "ollama").split(",") if item.strip()}


def ensure_team_targets(workflow: Workflow):
    allowed = team_connections()
    if any(target.connection not in allowed for node in workflow.nodes if node.kind == "explain"
           for target in node.selected_models()):
        raise HTTPException(422, "Выберите AI-подключение, доступное для совместных проектов")


def can_schedule(workflow: Workflow, *, shared: bool = True) -> bool:
    if not any(node.kind == "schedule" and node.enabled for node in workflow.nodes):
        return False
    try:
        valid = Workflow.model_validate(workflow.model_dump())
        if shared:
            ensure_team_targets(valid)
    except (ValidationError, HTTPException):
        return False
    return True


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
    project = ProjectDetail(id=uuid4().hex, name=graph.name, role="owner", can_run=True, revision=1,
                            updated_at=datetime.now(UTC).isoformat(), workflow=graph)
    db = request.app.state.store.db
    with db:
        db.execute("INSERT INTO projects(id,owner_id,name,revision,updated_at,body) VALUES(?,?,?,?,?,?)",
                   (project.id, user.id, graph.name, 1, project.updated_at, graph.model_dump_json()))
    schedule(request, project)
    return project


@router.get("/projects/{project_id}/access")
async def get_access(request: Request, project_id: Id) -> ProjectSummary:
    return require_access(request, project_id)


@router.get("/projects/{project_id}", response_model=ProjectDetail)
async def get_project(request: Request, response: Response, project_id: Id):
    # Authorize even conditional requests; a cached revision never confers access.
    row = accessible_row(request, project_id, False)
    tag = f'"{project_id}-{row[2]}-{row[4]}-{int(row[5])}"'
    headers = {"ETag": tag, "Cache-Control": "private, no-cache", "Vary": "Cookie"}
    if request.headers.get("if-none-match") == tag:
        return Response(status_code=304, headers=headers)
    project = require_project(request, project_id)
    response.headers.update(headers)
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
        project = require_project(request, project_id, "edit")
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
        if not project.can_run:
            before, after = ({n.id: n.cron for n in draft.nodes if n.kind == "schedule" and n.enabled}
                             for draft in (project.workflow, graph))
            if before != after or (after and can_schedule(graph) and not can_schedule(project.workflow)):
                raise HTTPException(403, "Для изменения действующего расписания нужно право запуска проверок")
        edited_lease = board_presence.check_write(request, project_id, body.client_id, project.workflow, graph, body.lease_id)
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
    board_presence.after_write(request, project_id, graph, edited_lease)
    schedule(request, project)
    return project


@router.get("/projects/{project_id}/members")
async def list_members(request: Request, project_id: Id):
    project = require_access(request, project_id)
    if project.role not in ("owner", "editor"):
        raise HTTPException(403, "У вас нет права просматривать список доступов")
    db = request.app.state.store.db
    owner = db.execute("""SELECT a.id,a.email,a.name FROM accounts a
                          JOIN projects p ON p.owner_id=a.id WHERE p.id=?""", (project_id,)).fetchone()
    members = [{"id": owner[0], "email": owner[1], "name": owner[2], "role": "owner", "can_run": True, "status": "active"}]
    rows = db.execute("""SELECT m.id,m.email,a.name,m.account_id,m.expires_at,substr(m.token_hash,1,24),m.role,m.can_run
                         FROM project_members m
                         LEFT JOIN accounts a ON m.account_id=a.id WHERE m.project_id=? ORDER BY m.email""", (project_id,))
    now = time.time()
    for ident, email, name, account, expires_at, version, role, can_run in rows:
        status = "active"
        if not account:
            status = "pending" if expires_at and expires_at > now else "expired"
        member = {"id": ident, "email": email, "name": name or "", "role": role, "can_run": bool(can_run), "status": status}
        if project.role == "owner" and status == "pending":
            member["invite_version"] = version
        members.append(member)
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


@router.get("/projects/{project_id}/presence/stream", response_class=StreamingResponse)
async def presence_stream(request: Request, project_id: Id, client_id: board_presence.ClientId):
    check_origin(request, include_read=True)

    def authorize():
        accessible_row(request, project_id, False)

    authorize()
    return board_presence.open_stream(request, project_id, client_id, current_user(request), authorize)


@router.post("/projects/{project_id}/presence/cursor", status_code=204)
async def update_cursor(request: Request, project_id: Id, body: board_presence.CursorUpdate) -> Response:
    check_origin(request)
    accessible_row(request, project_id, False)
    board_presence.move_cursor(request, project_id, body)
    return Response(status_code=204)


@router.post("/projects/{project_id}/presence/lock", status_code=204,
             responses={200: {"description": "Идентификатор текущей блокировки"}})
async def set_node_lock(request: Request, project_id: Id, body: board_presence.EditLock) -> Response:
    check_origin(request)
    require_access(request, project_id, "edit")
    if body.node_id is not None:
        exists = request.app.state.store.db.execute("""
            SELECT 1 FROM projects p, json_each(p.body,'$.nodes') node
            WHERE p.id=? AND json_extract(node.value,'$.id')=? LIMIT 1""", (project_id, body.node_id)).fetchone()
        if not exists:
            raise HTTPException(404, "Блок уже удалён из проекта")
    lease_id = board_presence.edit_node(request, project_id, body)
    if body.return_lease:
        return JSONResponse({"lease_id": lease_id}, headers={"Cache-Control": "private, no-store"})
    return Response(status_code=204)


@router.post("/projects/{project_id}/presence/lock/activity", status_code=204)
async def renew_node_lock(request: Request, project_id: Id, body: board_presence.EditActivity) -> Response:
    check_origin(request)
    accessible_row(request, project_id, False, "edit")
    board_presence.edit_activity(request, project_id, body)
    return Response(status_code=204)


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
        message.set_content(f"Вас пригласили в проект «{name}». Войдите с адресом {email} "
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
        row = db.execute("SELECT id,account_id,role,can_run FROM project_members WHERE project_id=? AND email=?",
                         (project_id, email)).fetchone()
        if body.reissue_id is not None and (not row or row[0] != body.reissue_id):
            raise HTTPException(404, "Это приглашение уже удалено. Обновите список участников")
        if row and row[1]:
            raise HTTPException(409, "Участник уже имеет доступ")
        if row:
            member_id, role, can_run = row[0], row[2], bool(row[3])
            if body.reissue_id is None and (
                (body.role is not None and body.role != role)
                or (body.can_run is not None and body.can_run != can_run)
            ):
                raise HTTPException(409, "Для этой почты уже есть приглашение с другими правами. Выберите «Изменить права» в списке участников.")
        else:
            member_id, role = uuid4().hex, body.role or "editor"
            can_run = role == "editor" if body.can_run is None else body.can_run
            if role == "reporter" and can_run:
                raise HTTPException(422, "Для запуска проверок нужен доступ к графу")
        db.execute("""INSERT INTO project_members(id,project_id,email,token_hash,expires_at,role,can_run) VALUES(?,?,?,?,?,?,?)
                      ON CONFLICT(project_id,email) DO UPDATE SET token_hash=excluded.token_hash,
                      expires_at=excluded.expires_at""",
                   (member_id, project_id, email, digest, int(time.time())+7*86400, role, can_run))
    delivery = await asyncio.to_thread(send_invitation, email, project.name, token)
    return {"id": member_id, "email": email, "token": token, "delivery": delivery, "invite_version": digest[:24],
            "role": role, "can_run": can_run}


@router.post("/project-invitations/preview", response_model_exclude_none=True)
async def preview_invite(request: Request, body: AcceptInvite) -> InvitePreview:
    check_origin(request)
    invite = find_invitation(request.app.state.store.db, body.token)
    user = session_user(request)
    if invite.account_id:
        if user and invite.account_id == user.id:
            return InvitePreview(status="accepted", project_name=invite.project_name, project_id=invite.project_id)
        return InvitePreview(status="wrong_account" if user else "sign_in")
    mailbox, domain = invite.email.rsplit("@", 1)
    hint = f"{mailbox[:1] if len(mailbox) > 1 else ''}•••@{domain}"
    return InvitePreview(status="wrong_account" if user and user.email != invite.email else "pending",
                         project_name=invite.project_name, email_hint=hint)


@router.post("/project-invitations/accept")
async def accept_invite(request: Request, body: AcceptInvite) -> ProjectDetail | ProjectSummary:
    check_origin(request)
    user = current_user(request)
    db = request.app.state.store.db
    with db:
        db.execute("BEGIN IMMEDIATE")
        invite = find_invitation(db, body.token)
        if invite.account_id and invite.account_id != user.id:
            raise HTTPException(404, "Приглашение недоступно для этого аккаунта")
        if invite.email != user.email:
            raise HTTPException(403, "Войдите с адресом, на который отправлено приглашение")
        if invite.account_id is None:
            db.execute("UPDATE project_members SET account_id=?,expires_at=NULL WHERE id=?", (user.id, invite.member_id))
        access = require_access(request, invite.project_id)
        return access if access.role == "reporter" else require_project(request, invite.project_id)


@router.patch("/projects/{project_id}/members/{member_id}", status_code=204)
async def change_member_access(request: Request, project_id: Id, member_id: Id, body: MemberAccess) -> Response:
    check_origin(request)
    db = request.app.state.store.db
    with db:
        db.execute("BEGIN IMMEDIATE")
        require_owner(request, project_id)
        row = db.execute("SELECT account_id,role,can_run FROM project_members WHERE project_id=? AND id=?",
                         (project_id, member_id)).fetchone()
        if not row:
            raise HTTPException(404, "Участник или приглашение не найдены")
        account, old_role, old_run = row
        if old_role == body.role and bool(old_run) == body.can_run:
            return Response(status_code=204)
        db.execute("UPDATE project_members SET role=?,can_run=? WHERE project_id=? AND id=?",
                   (body.role, body.can_run, project_id, member_id))
        if account and body.role == "reporter":
            db.execute("DELETE FROM project_presence WHERE project_id=? AND account_id=?", (project_id, account))
    if account and (body.role == "reporter" or (old_role == "editor" and body.role != "editor")):
        board_presence.remove_account(request, project_id, account)
    return Response(status_code=204)


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
    if member[0]:
        board_presence.remove_account(request, project_id, member[0])
    return Response(status_code=204)
