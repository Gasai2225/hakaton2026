import asyncio
import json
import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit
from uuid import uuid4

import httpx
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse, Response, StreamingResponse
from pydantic import Field, SecretStr, ValidationError

from garden.actions_history import ActionsHistory
from garden import accounts, account_oauth, projects, catalog, notifications
from garden.github_source import GitHubSource, import_github
from garden.integrations import Gateway
from garden.models import (Blueprint, BrowserReport, BrowserReportNotice, Finding, Id, Model, PublicConnection,
                           Receipt, Report, Run, RunSummary, Source, Target, WebhookDelivery, Workflow)
from garden.runner import Engine, reason
from garden.scenarios import generate, repair_demo, repair_template, sources
from garden.storage import Store
from garden.submission import readable_report, submission


class Start(Model):
    workflow: Workflow
    trigger: str


class ProjectStart(Model):
    trigger: Id
    revision: int = Field(ge=1)


def schedules(app: FastAPI, workflow, project_id: str | None = None) -> None:
    scheduler = app.state.scheduler
    prefix = f"{project_id}/" if project_id else ""
    for job in scheduler.get_jobs():
        if (job.id.startswith(prefix) if project_id else "/" not in job.id):
            scheduler.remove_job(job.id)
    if not projects.can_schedule(workflow, shared=project_id is not None):
        return

    async def scheduled(key: str) -> None:
        if project_id:
            row = app.state.store.db.execute("SELECT body FROM projects WHERE id=?", (project_id,)).fetchone()
            if not row:
                return
            try:
                current = Workflow.model_validate_json(row[0])
                projects.ensure_team_targets(current)
            except (ValidationError, HTTPException):
                return
        else:
            current = app.state.store.workflow()
        if any(n.id == key and n.kind == "schedule" and n.enabled for n in current.nodes):
            app.state.engine.start(current, key, project_id=project_id)

    for node in workflow.nodes:
        if node.kind == "schedule" and node.enabled:
            scheduler.add_job(scheduled, CronTrigger.from_crontab(node.cron, timezone="Europe/Moscow"),
                              args=[node.id], id=prefix + node.id, coalesce=True)


@asynccontextmanager
async def lifespan(app: FastAPI):
    path = Path(os.environ.get("GARDEN_DB", Path(__file__).parents[1] / "data/garden.sqlite"))
    async with httpx.AsyncClient(timeout=60) as client:
        gateway = Gateway.configured(client)
        store = Store(path, lambda: repair_demo(gateway, allow_sample=True))
        app.state.store = store
        accounts.init_accounts(store.db)
        projects.init_projects(store.db)
        catalog.init_catalog(store.db)
        notifications.init_notifications(store.db)
        app.state.actions_history = ActionsHistory(path.parent / "reports")
        app.state.engine = Engine(store, gateway)
        app.state.scheduler = AsyncIOScheduler(timezone="Europe/Moscow")
        app.state.reschedule_project = lambda pid, workflow: schedules(app, workflow, pid)
        schedules(app, store.workflow())
        for pid, body in store.db.execute("""SELECT id,body FROM projects WHERE EXISTS (
                SELECT 1 FROM json_each(body,'$.nodes')
                WHERE json_extract(value,'$.kind')='schedule' AND json_extract(value,'$.enabled')=1)"""):
            schedules(app, projects.ProjectGraph.model_validate_json(body), pid)
        app.state.scheduler.start()
        try:
            yield
        finally:
            app.state.scheduler.shutdown(wait=False)
            await asyncio.gather(*app.state.engine.tasks, return_exceptions=True)
            store.db.close()


app = FastAPI(title="Garden Workflow", version="0.1.0", lifespan=lifespan)
app.include_router(accounts.router)
app.include_router(account_oauth.router)
app.include_router(projects.router)
app.include_router(catalog.router)
app.include_router(notifications.router)


@app.middleware("http")
async def private_api_responses(request: Request, call_next):
    response = await call_next(request)
    if request.url.path.startswith("/api/"):
        response.headers.setdefault("Cache-Control", "private, no-store")
        if "Cookie" not in response.headers.get("Vary", "").split(", "):
            response.headers.add_vary_header("Cookie")
    return response


def is_local_studio(request: Request) -> bool:
    local = {"127.0.0.1", "localhost", "::1"}
    public_origin = os.environ.get("GARDEN_PUBLIC_ORIGIN")
    return bool((not public_origin or urlsplit(public_origin).hostname in local) and
                request.client and request.client.host in local and request.url.hostname in local)


async def local_studio(request: Request) -> None:
    if not is_local_studio(request):
        raise HTTPException(403, "Локальная студия доступна только на этом компьютере")
    if request.method != "GET":
        accounts.check_origin(request)


async def studio_user(request: Request) -> None:
    if not is_local_studio(request):
        accounts.current_user(request)
    if request.method != "GET":
        accounts.check_origin(request)


@app.exception_handler(RequestValidationError)
async def invalid_request(request: Request, error: RequestValidationError):
    # Pydantic errors may include the entire uploaded source as their input.
    details = []
    missing_sources = False
    for item in error.errors()[:3]:
        field = item["loc"][-1] if item["loc"] else None
        empty = item["type"] in {"too_short", "missing"}
        if empty and field == "nodes":
            details.append("В сценарии нет блоков. Добавьте блок запуска.")
        elif item["type"] == "missing_sources" or (empty and field == "files"):
            if not details:
                missing_sources = True
            details.append("В проекте нет исходных файлов для проверки.")
        else:
            details.append(item["msg"].removeprefix("Value error, "))
    content = {"detail": " · ".join(details)}
    if missing_sources:
        content["code"] = "missing_sources"
    return JSONResponse(status_code=422, content=content)


@app.get("/api/workflow", dependencies=[Depends(local_studio)])
async def get_workflow() -> Workflow:
    return app.state.store.workflow()


@app.get("/api/demo", dependencies=[Depends(studio_user)])
async def get_demo() -> Workflow:
    return repair_demo(app.state.engine.gateway, allow_sample=True)


@app.put("/api/workflow", dependencies=[Depends(local_studio)])
async def save_workflow(workflow: Workflow) -> Workflow:
    app.state.store.save(workflow)
    schedules(app, workflow)
    return workflow


@app.get("/api/connections", dependencies=[Depends(studio_user)])
async def connections() -> list[PublicConnection]:
    return [p.public() for p in app.state.engine.gateway.profiles.values()]


@app.get("/api/projects/{project_id}/connections")
async def project_connections(project_id: Id, request: Request) -> list[PublicConnection]:
    projects.require_access(request, project_id, "view_graph")
    return [p.public().model_copy(update={"local_key_entry": False}) for p in app.state.engine.gateway.profiles.values()
            if p.id in projects.team_connections()]


@app.get("/api/projects/{project_id}/runs")
async def project_runs(project_id: Id, request: Request) -> list[RunSummary]:
    projects.require_access(request, project_id, "view_reports")
    return app.state.store.recent(project_id)


@app.post("/api/projects/{project_id}/runs", status_code=202)
async def start_project_run(project_id: Id, body: ProjectStart, request: Request) -> Run:
    accounts.check_origin(request)
    project = projects.require_project(request, project_id, "run")
    if body.revision != project.revision:
        raise HTTPException(409, "Граф изменился перед запуском. Дождитесь синхронизации и повторите.")
    try:
        workflow = Workflow.model_validate(project.workflow.model_dump())
    except ValidationError as exc:
        raise RequestValidationError(exc.errors(include_input=False)) from None
    projects.ensure_team_targets(workflow)
    if not any(n.id == body.trigger and n.kind == "manual" for n in workflow.nodes):
        raise HTTPException(422, "Для запуска по кнопке укажите ручной триггер")
    return app.state.engine.start(workflow, body.trigger, project_id=project_id)


class OpenAIKey(Model):
    key: SecretStr = Field(min_length=1, max_length=4096)


@app.post("/api/connections/openai/key")
async def connect_openai(body: OpenAIKey, request: Request) -> PublicConnection:
    origin = urlsplit(request.headers.get("origin", ""))
    local = {"localhost", "127.0.0.1", "::1"}
    if (not is_local_studio(request) or origin.hostname not in local
            or origin.netloc != request.headers.get("host") or origin.scheme not in {"http", "https"}):
        raise HTTPException(403, "Откройте редактор на локальном компьютере")
    gateway = app.state.engine.gateway
    profile = gateway.profiles.get("openai")
    if profile is None or not profile.public().local_key_entry:
        raise HTTPException(409, "Для этого подключения ключ задаётся в окружении сервера")
    key = body.key.get_secret_value().strip()
    if not key or not key.isascii() or any(c.isspace() for c in key) or not key.isprintable():
        raise HTTPException(422, "Проверьте формат ключа")
    try:
        response = await gateway.client.get("https://api.openai.com/v1/models", headers={"Authorization": "Bearer " + key})
        response.raise_for_status()
    except httpx.HTTPError as error:
        raise HTTPException(502, reason(error)) from None
    from keyring.backends.Windows import WinVaultKeyring
    WinVaultKeyring().set_password("Garden Security Workflow", "OpenAI", key)
    return profile.public()


class Template(Model):
    id: str
    graph: Blueprint
    description: str = ""


class TemplateDraft(Blueprint):
    description: str = Field(default="", max_length=1500)

    def published(self, key: str) -> Template:
        return Template(id=key, graph=self, description=self.description)


class Description(Model):
    text: str = Field(min_length=3, max_length=1500)
    target: Target


@app.get("/api/templates", dependencies=[Depends(local_studio)])
async def templates() -> list[Template]:
    rows = app.state.store.db.execute("SELECT id,body FROM templates ORDER BY rowid DESC")
    return [Template(id="repair", graph=repair_template(app.state.engine.gateway),
                     description="Проверка секретов, Kotlin-кода и зависимостей с отчётом по находкам."),
            *(TemplateDraft.model_validate_json(raw).published(key) for key, raw in rows)]


@app.post("/api/templates", status_code=201, dependencies=[Depends(local_studio)])
async def publish_template(graph: TemplateDraft) -> Template:
    key = uuid4().hex
    store = app.state.store
    with store.db:
        store.db.execute("INSERT INTO templates VALUES (?,?)", (key, graph.model_dump_json()))
    return graph.published(key)


@app.post("/api/templates/generate", dependencies=[Depends(studio_user)])
async def generate_template(body: Description, request: Request) -> Blueprint:
    if not is_local_studio(request) and body.target.connection not in projects.team_connections():
        raise HTTPException(403, "Это подключение недоступно в совместных проектах")
    try:
        return await generate(app.state.engine.gateway, body.text, body.target)
    except (ValueError, httpx.HTTPError, LookupError, TypeError) as error:
        raise HTTPException(422, reason(error)) from None


@app.get("/api/demo/repair", dependencies=[Depends(studio_user)])
async def repair() -> Workflow:
    try:
        return repair_demo(app.state.engine.gateway)
    except FileNotFoundError as error:
        raise HTTPException(404, str(error)) from None


@app.get("/api/practice/{project}", dependencies=[Depends(studio_user)])
def practice_sources(project: Literal["book-index", "label-studio", "reading-room", "parcel-ledger"]) -> list[Source]:
    root = Path(__file__).resolve().parents[2] / "samples/practice" / project
    if not root.is_dir():
        raise HTTPException(404, "Учебный проект отсутствует в этой установке")
    return sources(root)


@app.post("/api/sources/github", dependencies=[Depends(studio_user)])
async def github_sources(body: GitHubSource) -> list[Source]:
    try:
        return await import_github(app.state.engine.gateway.client, body)
    except FileNotFoundError as error:
        raise HTTPException(404, str(error)) from None
    except httpx.HTTPError as error:
        raise HTTPException(502, reason(error)) from None
    except ValueError as error:
        raise HTTPException(422, str(error)) from None


@app.post("/api/inbox", status_code=201)
async def receive(body: Receipt, request: Request):
    key = request.headers.get("Idempotency-Key", "")
    db = app.state.store.db
    project_run = db.execute("SELECT 1 FROM project_runs WHERE run_id=?", (body.run_id,)).fetchone()
    if project_run or not is_local_studio(request):
        # Shared projects accept only deliveries already recorded by their engine.
        node_id = key.removeprefix(body.run_id + "/")
        recorded = db.execute(
            "SELECT body FROM outgoing_webhooks WHERE run_id=? AND node_id=?", (body.run_id, node_id)).fetchone()
        if not recorded or recorded[0] != await request.body():
            raise HTTPException(403, "Неизвестная доставка")
    accounts.check_origin(request)
    run = app.state.store.run(body.run_id)
    if run is None:
        raise HTTPException(404, "Прогон не найден")
    if not any(f"{run.id}/{step.node_id}" == key and step.kind == "webhook" for step in run.steps):
        raise HTTPException(422, "Получатель ожидает идентификатор шага доставки")
    store = app.state.store
    with store.db:
        inserted = store.db.execute("INSERT OR IGNORE INTO receipts VALUES (?,?)",
                                    (key, body.model_dump_json(exclude_unset=True)))
        if not inserted.rowcount:
            previous, = store.db.execute("SELECT body FROM receipts WHERE key=?", (key,)).fetchone()
            if Receipt.model_validate_json(previous) != body:
                raise HTTPException(409, "Этот шаг уже доставил другой отчёт")
    return {"received": True}


@app.get("/api/runs/{key}/receipts", response_model=list[Receipt])
async def receipts(key: Id, request: Request) -> JSONResponse:
    await get_run(key, request)
    rows = app.state.store.db.execute("SELECT body FROM receipts WHERE substr(key,1,?)=?", (len(key)+1, key+"/"))
    payloads = []
    for (record,) in rows:
        receipt = Receipt.model_validate_json(record)
        # Preserve the response defaults that predate scan status, including reviews.
        payloads.append(receipt.model_dump(mode="json", exclude={"analysis_status"} - receipt.model_fields_set))
    return JSONResponse(payloads)


@app.post("/api/runs", status_code=202, dependencies=[Depends(local_studio)])
async def start_run(body: Start) -> Run:
    if not any(n.id == body.trigger and n.kind == "manual" for n in body.workflow.nodes):
        raise HTTPException(422, "Для запуска по кнопке укажите ручной триггер")
    return app.state.engine.start(body.workflow, body.trigger)


@app.get("/api/runs", dependencies=[Depends(local_studio)])
async def recent_runs() -> list[RunSummary]:
    return app.state.store.recent()


@app.get("/api/ci/history", dependencies=[Depends(local_studio)])
def ci_history() -> dict:
    return app.state.actions_history.history()


@app.get("/api/ci/history/{run_id}/reports", dependencies=[Depends(local_studio)])
def ci_reports(run_id: int, attempt: int = 1) -> dict:
    if run_id < 1 or attempt < 1:
        raise HTTPException(422, "Номер запуска и попытки должны быть положительными")
    return app.state.actions_history.reports(run_id, attempt)


async def authorized_run(key: str, request: Request, permission: Literal["view_graph", "view_reports"]) -> Run:
    owner = app.state.store.db.execute("SELECT project_id FROM project_runs WHERE run_id=?", (key,)).fetchone()
    if owner:
        projects.require_access(request, owner[0], permission)
    else:
        await local_studio(request)
    run = app.state.store.run(key)
    if run is None:
        raise HTTPException(404, "Прогон не найден")
    return run


@app.get("/api/runs/{key}")
async def get_run(key: str, request: Request) -> Run:
    return await authorized_run(key, request, "view_graph")


class ReportReview(Model):
    label: str
    report: Report


class RunReport(Model):
    findings: list[Finding]
    complete: bool
    reviews: list[ReportReview]


async def finished_report_run(key: str, request: Request) -> Run:
    run = await authorized_run(key, request, "view_reports")
    if run.status in {"pending", "running"}:
        raise HTTPException(409, "Дождитесь завершения прогона")
    return run


@app.get("/api/runs/{key}/report")
async def run_report(key: str, request: Request) -> RunReport:
    run = await finished_report_run(key, request)
    reviews = []
    for step in run.steps:
        if step.reviews:
            reviews.extend(ReportReview(label=f"{review.label} {review.model}".strip(), report=review.report)
                           for review in step.reviews if review.report is not None)
        elif step.report is not None:
            reviews.append(ReportReview(label="Модель", report=step.report))
    return RunReport(findings=run.findings, complete=run.analysis_complete, reviews=reviews)


@app.get("/api/runs/{key}/steps/{node_id}/delivery", response_model=WebhookDelivery,
         response_model_exclude={"browser_report"})
async def webhook_delivery(key: Id, node_id: Id, request: Request):
    run = await get_run(key, request)
    step = next((s for s in run.steps if s.node_id == node_id and s.kind == "webhook"), None)
    if step is None:
        raise HTTPException(404, "У этого прогона нет такого webhook-шага")
    if step.status == "skipped":
        return WebhookDelivery(state="not_sent")
    db = app.state.store.db
    if step.webhook_attempted is not None:
        row = db.execute("""SELECT o.body,b.created_at FROM outgoing_webhooks o
                            LEFT JOIN browser_reports b USING (run_id,node_id)
                            WHERE o.run_id=? AND o.node_id=?""", (key, node_id)).fetchone()
        if row or step.webhook_attempted:
            state = "delivered" if step.status == "succeeded" else "attempted"
            body = {"state": state, "payload": json.loads(row[0]) if row else None}
            if row and row[1]:
                body["browser_report"] = True
            return JSONResponse(body)
    if step.status in {"pending", "running"}:
        return WebhookDelivery(state="pending")
    if step.webhook_attempted is not None:
        return WebhookDelivery(state="not_sent")
    # Older external deliveries have no dispatch trace. An inbox receipt is independent evidence.
    row = db.execute("SELECT body FROM receipts WHERE key=?", (f"{key}/{node_id}",)).fetchone()
    if row:
        return JSONResponse({"state": "delivered", "payload": json.loads(row[0])})
    return WebhookDelivery(state="delivered" if step.status == "succeeded" else "unknown")


async def browser_report_owner(request: Request, local: bool) -> str | None:
    if local:
        await local_studio(request)
        return None
    return accounts.current_user(request).id


@app.get("/api/browser-reports/next")
async def next_browser_report(request: Request, local: bool = False) -> BrowserReportNotice | None:
    owner_id = await browser_report_owner(request, local)
    return app.state.store.next_browser_report(owner_id)


@app.post("/api/browser-reports/{key}/{node_id}/dismiss", status_code=204)
async def dismiss_browser_report(key: Id, node_id: Id, request: Request, local: bool = False):
    accounts.check_origin(request)
    owner_id = await browser_report_owner(request, local)
    if not app.state.store.dismiss_browser_report(key, node_id, owner_id):
        raise HTTPException(404, "Уведомление не найдено")


@app.get("/api/runs/{key}/steps/{node_id}/report")
async def browser_report(key: Id, node_id: Id, request: Request) -> BrowserReport:
    await authorized_run(key, request, "view_reports")
    report = app.state.store.browser_report(key, node_id)
    if report is None:
        raise HTTPException(404, "Отчёт не найден")
    return report


@app.get("/api/runs/{key}/steps/{node_id}/report.json", response_class=JSONResponse)
async def browser_report_json(key: Id, node_id: Id, request: Request) -> Response:
    report = await browser_report(key, node_id, request)
    data = {"created_at": report.created_at, **report.payload.model_dump(mode="json")}
    return Response(json.dumps(data, ensure_ascii=False, indent=2) + "\n", media_type="application/json")


@app.get("/api/runs/{key}/events", response_class=StreamingResponse)
async def events(key: str, request: Request):
    await get_run(key, request)
    engine = app.state.engine

    async def stream():
        wake = asyncio.Event()
        subscribers = engine.listeners.setdefault(key, set())
        subscribers.add(wake)
        try:
            while not await request.is_disconnected():
                wake.clear()
                try:
                    run = await get_run(key, request)
                except HTTPException:
                    break
                yield f"data: {run.model_dump_json()}\n\n"
                if run.status != "running":
                    break
                try:
                    await asyncio.wait_for(wake.wait(), timeout=12)
                except TimeoutError:
                    yield ": keep-alive\n\n"
        finally:
            subscribers.discard(wake)
            if not subscribers:
                engine.listeners.pop(key, None)

    return StreamingResponse(stream(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.get("/api/runs/{key}/submission", response_class=JSONResponse,
         responses={200: {"content": {"text/html": {"schema": {"type": "string"}}}}})
async def export_submission(key: str, request: Request, format: Literal["json", "html"] = "json"):
    run = await finished_report_run(key, request)
    try:
        data = submission(run.findings)
    except ValueError as error:
        raise HTTPException(409, str(error)) from error
    headers = {"Content-Disposition": f'attachment; filename="findings-{run.id}.{format}"'}
    if format == "html":
        html = readable_report(data["findings"], complete=run.analysis_complete, workflow_status=run.status)
        return HTMLResponse(html, headers=headers)
    return JSONResponse(data, headers=headers)
