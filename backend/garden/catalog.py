"""Shared template snapshots. Project files and membership stay with the source project."""
import sqlite3
from uuid import uuid4

from fastapi import APIRouter, HTTPException, Request
from pydantic import Field

from garden.accounts import check_origin, current_user
from garden.models import Blueprint, Id, Model
from garden.projects import NewProject, ProjectGraph, ProjectName, create_project, require_project
from garden.scenarios import Plan, blueprint


router = APIRouter(prefix="/api/catalog")


class Publish(Model):
    project_id: Id
    name: ProjectName
    description: str = Field(min_length=1, max_length=1500)


def init_catalog(db: sqlite3.Connection):
    db.execute("""CREATE TABLE IF NOT EXISTS community_templates (
        id TEXT PRIMARY KEY, author_id TEXT NOT NULL REFERENCES accounts(id),
        name TEXT NOT NULL, description TEXT NOT NULL, graph TEXT NOT NULL, node_count INTEGER NOT NULL)""")


def official():
    definitions = [
        ("repair", "Repair Desk", ["secrets", "sast", "sca"], True,
         "Проверяет секреты, Kotlin-код и зависимости. При находках добавляет объяснение и отправляет отчёт во входящие."),
        ("secrets", "Поиск секретов", ["secrets"], False, "Ищет встроенные ключи и пароли в исходниках."),
        ("gradle", "Аудит зависимостей Gradle", ["sca"], False, "Проверяет версии библиотек и известные уязвимости."),
    ]
    for key, name, checks, explain, description in definitions:
        graph = blueprint(Plan(name=name, checks=checks, schedule=None, condition="any",
                               explain=explain, notify=explain, destination="inbox"))
        yield key, description, graph


def card(key, name, description, author, count, curated=False):
    return dict(id=key, name=name, description=description, author=author, node_count=count, curated=curated)


@router.get("")
async def list_templates(request: Request):
    current_user(request)
    rows = request.app.state.store.db.execute("""
        SELECT t.id,t.name,t.description,a.name,t.node_count FROM community_templates t
        JOIN accounts a ON a.id=t.author_id ORDER BY t.rowid DESC""")
    return [*(card(key, graph.name, desc, "Garden", len(graph.nodes), True) for key, desc, graph in official()),
            *(card(*row) for row in rows)]


@router.post("", status_code=201)
async def publish(request: Request, body: Publish):
    check_origin(request)
    author = current_user(request)
    project = require_project(request, body.project_id)
    if project.role != "owner":
        raise HTTPException(403, "Опубликовать шаблон может владелец проекта")
    description = body.description.strip()
    if not description:
        raise HTTPException(422, "Добавьте описание шаблона")
    try:
        graph = Blueprint(name=body.name, nodes=project.workflow.nodes, edges=project.workflow.edges)
    except ValueError:
        raise HTTPException(422, "Перед публикацией соедините блоки в рабочий граф") from None
    key = uuid4().hex
    db = request.app.state.store.db
    with db:
        db.execute("INSERT INTO community_templates VALUES (?,?,?,?,?,?)",
                   (key, author.id, graph.name, description, graph.model_dump_json(), len(graph.nodes)))
    return card(key, graph.name, description, author.name, len(graph.nodes))


@router.post("/{key}/projects", status_code=201)
async def use_template(key: Id, request: Request):
    check_origin(request)
    current_user(request)
    graph = next((graph for ident, _, graph in official() if ident == key), None)
    if graph is None:
        row = request.app.state.store.db.execute("SELECT graph FROM community_templates WHERE id=?", (key,)).fetchone()
        if not row:
            raise HTTPException(404, "Шаблон не найден")
        graph = Blueprint.model_validate_json(row[0])
    for node in graph.nodes:
        if node.kind == "schedule":
            node.enabled = False
    draft = ProjectGraph(**graph.model_dump(), files=[])
    project = await create_project(request, NewProject(name=graph.name, workflow=draft))
    return {"id": project.id}
