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
from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from pydantic import Field, SecretStr

from garden.github_source import GitHubSource, import_github
from garden.integrations import Gateway
from garden.models import Blueprint, Id, Model, PublicConnection, Receipt, Run, RunSummary, Source, Target, WebhookDelivery, Workflow
from garden.runner import Engine, reason
from garden.scenarios import generate, repair_demo, repair_template, sources
from garden.storage import Store
from garden.submission import readable_report, submission


class Start(Model):
    workflow: Workflow
    trigger: str


def schedules(app: FastAPI, workflow: Workflow) -> None:
    scheduler = app.state.scheduler
    scheduler.remove_all_jobs()

    async def scheduled(key: str) -> None:
        current = app.state.store.workflow()
        if any(n.id == key and n.kind == "schedule" and n.enabled for n in current.nodes):
            app.state.engine.start(current, key)

    for node in workflow.nodes:
        if node.kind == "schedule" and node.enabled:
            scheduler.add_job(scheduled, CronTrigger.from_crontab(node.cron, timezone="Europe/Moscow"),
                              args=[node.id], id=node.id, coalesce=True)


@asynccontextmanager
async def lifespan(app: FastAPI):
    path = Path(os.environ.get("GARDEN_DB", Path(__file__).parents[1] / "data/garden.sqlite"))
    async with httpx.AsyncClient(timeout=60) as client:
        gateway = Gateway.configured(client)
        store = Store(path, lambda: repair_demo(gateway, allow_sample=True))
        app.state.store = store
        app.state.engine = Engine(store, gateway)
        app.state.scheduler = AsyncIOScheduler(timezone="Europe/Moscow")
        schedules(app, store.workflow())
        app.state.scheduler.start()
        try:
            yield
        finally:
            app.state.scheduler.shutdown(wait=False)
            await asyncio.gather(*app.state.engine.tasks, return_exceptions=True)
            store.db.close()


app = FastAPI(title="Garden Workflow", version="0.1.0", lifespan=lifespan)


@app.exception_handler(RequestValidationError)
async def invalid_request(request: Request, error: RequestValidationError):
    # Pydantic errors may include the entire uploaded source as their input.
    details = [item["msg"].removeprefix("Value error, ") for item in error.errors()]
    return JSONResponse(status_code=422, content={"detail": " · ".join(details[:3])})


@app.get("/api/workflow")
async def get_workflow() -> Workflow:
    return app.state.store.workflow()


@app.get("/api/demo")
async def get_demo() -> Workflow:
    return repair_demo(app.state.engine.gateway, allow_sample=True)


@app.put("/api/workflow")
async def save_workflow(workflow: Workflow) -> Workflow:
    app.state.store.save(workflow)
    schedules(app, workflow)
    return workflow


@app.get("/api/connections")
async def connections() -> list[PublicConnection]:
    return [p.public() for p in app.state.engine.gateway.profiles.values()]


class OpenAIKey(Model):
    key: SecretStr = Field(min_length=1, max_length=4096)


@app.post("/api/connections/openai/key")
async def connect_openai(body: OpenAIKey, request: Request) -> PublicConnection:
    origin = urlsplit(request.headers.get("origin", ""))
    local = {"localhost", "127.0.0.1", "::1"}
    if (not request.client or request.client.host not in local or origin.hostname not in local
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


@app.get("/api/templates")
async def templates() -> list[Template]:
    rows = app.state.store.db.execute("SELECT id,body FROM templates ORDER BY rowid DESC")
    return [Template(id="repair", graph=repair_template(app.state.engine.gateway),
                     description="Проверка секретов, Kotlin-кода и зависимостей с отчётом по находкам."),
            *(TemplateDraft.model_validate_json(raw).published(key) for key, raw in rows)]


@app.post("/api/templates", status_code=201)
async def publish_template(graph: TemplateDraft) -> Template:
    key = uuid4().hex
    store = app.state.store
    with store.db:
        store.db.execute("INSERT INTO templates VALUES (?,?)", (key, graph.model_dump_json()))
    return graph.published(key)


@app.post("/api/templates/generate")
async def generate_template(body: Description) -> Blueprint:
    try:
        return await generate(app.state.engine.gateway, body.text, body.target)
    except (ValueError, httpx.HTTPError, LookupError, TypeError) as error:
        raise HTTPException(422, reason(error)) from None


@app.get("/api/demo/repair")
async def repair() -> Workflow:
    try:
        return repair_demo(app.state.engine.gateway)
    except FileNotFoundError as error:
        raise HTTPException(404, str(error)) from None


@app.get("/api/practice/{project}")
def practice_sources(project: Literal["book-index", "label-studio", "reading-room", "parcel-ledger"]) -> list[Source]:
    root = Path(__file__).resolve().parents[2] / "samples/practice" / project
    if not root.is_dir():
        raise HTTPException(404, "Учебный проект отсутствует в этой установке")
    return sources(root)


@app.post("/api/sources/github")
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
    run = await get_run(body.run_id)
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
async def receipts(key: Id) -> JSONResponse:
    rows = app.state.store.db.execute("SELECT body FROM receipts WHERE substr(key,1,?)=?", (len(key)+1, key+"/"))
    payloads = []
    for (record,) in rows:
        receipt = Receipt.model_validate_json(record)
        # Preserve the response defaults that predate scan status, including reviews.
        payloads.append(receipt.model_dump(mode="json", exclude={"analysis_status"} - receipt.model_fields_set))
    return JSONResponse(payloads)


@app.post("/api/runs", status_code=202)
async def start_run(body: Start) -> Run:
    if not any(n.id == body.trigger and n.kind == "manual" for n in body.workflow.nodes):
        raise HTTPException(422, "Для запуска по кнопке укажите ручной триггер")
    return app.state.engine.start(body.workflow, body.trigger)


@app.get("/api/runs")
async def recent_runs() -> list[RunSummary]:
    return app.state.store.recent()


@app.get("/api/runs/{key}")
async def get_run(key: str) -> Run:
    run = app.state.store.run(key)
    if run is None:
        raise HTTPException(404, "Прогон не найден")
    return run


@app.get("/api/runs/{key}/steps/{node_id}/delivery", response_model=WebhookDelivery)
async def webhook_delivery(key: Id, node_id: Id):
    run = await get_run(key)
    step = next((s for s in run.steps if s.node_id == node_id and s.kind == "webhook"), None)
    if step is None:
        raise HTTPException(404, "У этого прогона нет такого webhook-шага")
    if step.status == "skipped":
        return WebhookDelivery(state="not_sent")
    db = app.state.store.db
    if step.webhook_attempted is not None:
        row = db.execute("SELECT body FROM outgoing_webhooks WHERE run_id=? AND node_id=?", (key, node_id)).fetchone()
        if row or step.webhook_attempted:
            state = "delivered" if step.status == "succeeded" else "attempted"
            return JSONResponse({"state": state, "payload": json.loads(row[0]) if row else None})
    if step.status in {"pending", "running"}:
        return WebhookDelivery(state="pending")
    if step.webhook_attempted is not None:
        return WebhookDelivery(state="not_sent")
    # Older external deliveries have no dispatch trace. An inbox receipt is independent evidence.
    row = db.execute("SELECT body FROM receipts WHERE key=?", (f"{key}/{node_id}",)).fetchone()
    if row:
        return JSONResponse({"state": "delivered", "payload": json.loads(row[0])})
    return WebhookDelivery(state="delivered" if step.status == "succeeded" else "unknown")


@app.get("/api/runs/{key}/events", response_class=StreamingResponse)
async def events(key: str, request: Request):
    await get_run(key)
    engine = app.state.engine

    async def stream():
        wake = asyncio.Event()
        subscribers = engine.listeners.setdefault(key, set())
        subscribers.add(wake)
        try:
            while not await request.is_disconnected():
                wake.clear()
                run = await get_run(key)
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
async def export_submission(key: str, format: Literal["json", "html"] = "json"):
    run = await get_run(key)
    if run.status == "running":
        raise HTTPException(409, "Дождитесь завершения прогона")
    try:
        data = submission(run.findings)
    except ValueError as error:
        raise HTTPException(409, str(error)) from error
    headers = {"Content-Disposition": f'attachment; filename="findings-{run.id}.{format}"'}
    if format == "html":
        html = readable_report(data["findings"], complete=run.analysis_complete, workflow_status=run.status)
        return HTMLResponse(html, headers=headers)
    return JSONResponse(data, headers=headers)
