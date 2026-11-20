import asyncio
from datetime import UTC, datetime
from uuid import uuid4

import httpx
import regex
from pydantic import ValidationError

from garden.integrations import Gateway, deliver
from garden.models import Branch, Finding, Node, Review, Run, Step, TRIGGERS, Workflow
from garden.scanners import analyze
from garden.storage import Store


def branch(node: Node, findings: list[Finding]) -> Branch:
    if node.predicate == "count_gte":
        matched = len(findings) >= int(node.value)
    elif node.predicate == "severity_eq":
        matched = any(f.severity == node.value for f in findings)
    else:
        matched = any(regex.search(node.value, f.rule, timeout=0.03) for f in findings)
    return "yes" if matched else "no"


def reason(error: Exception) -> str:
    if isinstance(error, httpx.HTTPStatusError):
        return f"Сервис вернул HTTP {error.response.status_code}"
    if isinstance(error, (httpx.TimeoutException, TimeoutError)):
        return "Истекло время ожидания"
    if isinstance(error, httpx.RequestError):
        return "Не удалось связаться с сервисом"
    if isinstance(error, ValidationError):
        return "Ответ не соответствует схеме"
    if type(error) is ValueError:
        return str(error)[:300]
    return "Ошибка обработки данных"


class Engine:
    def __init__(self, store: Store, gateway: Gateway):
        self.store = store
        self.gateway = gateway
        self.tasks: set[asyncio.Task] = set()
        self.listeners: dict[str, set[asyncio.Event]] = {}

    def start(self, workflow: Workflow, trigger: str) -> Run:
        run = Run(id=uuid4().hex, name=workflow.name, started=datetime.now(UTC).isoformat(), trigger=trigger,
                  steps=[Step(node_id=n.id, kind=n.kind) for n in workflow.nodes])
        self.store.insert(run, workflow)
        task = asyncio.create_task(self.execute(workflow, run))
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)
        return run

    def publish(self, run: Run) -> None:
        self.store.update(run)
        for event in self.listeners.get(run.id, ()):
            event.set()

    async def explain(self, node: Node, step: Step, run: Run, findings: list[Finding]) -> None:
        for target in node.selected_models():
            profile = self.gateway.profiles.get(target.connection)
            model = target.model or (profile.model if profile else "")
            if any(r.connection == target.connection and r.model == model for r in step.reviews):
                continue
            step.reviews.append(Review(connection=target.connection, model=model, label=profile.label if profile
                                       else target.connection, status="running" if findings else "skipped"))
        self.publish(run)
        if not findings:
            step.message = "Входных находок нет"
            return

        async def review(item: Review) -> None:
            try:
                item.report = await self.gateway.explain(item.connection, item.model, findings)
                item.status = "succeeded"
            except Exception as error:
                item.status = "failed"
                item.message = reason(error)
            self.publish(run)

        await asyncio.gather(*(review(item) for item in step.reviews))
        reports = [item.report for item in step.reviews if item.report is not None]
        step.report = next(iter(reports), None)  # Older clients display a single report.
        step.message = f"Ответили модели: {len(reports)} из {len(step.reviews)}"
        if not reports:
            step.message += ". Доступны рекомендации правил"

    async def execute(self, workflow: Workflow, run: Run) -> None:
        steps = {step.node_id: step for step in run.steps}
        nodes = {node.id: node for node in workflow.nodes}
        findings: dict[str, Finding] = {}
        report_sources: dict[str, set[str]] = {}
        failed_paths: set[str] = set()
        for key in workflow.order():
            node, step = nodes[key], steps[key]
            incoming = [edge for edge in workflow.edges if edge.target == key]
            active = [e.source for e in incoming if steps[e.source].status in {"succeeded", "warning"}
                      and (e.branch is None or e.branch == steps[e.source].branch)]
            blocked = any(e.source in failed_paths for e in incoming)
            if blocked or (node.kind in TRIGGERS and key != run.trigger) or (node.kind not in TRIGGERS and not active):
                step.status = "skipped"
                step.message = "Ошибка входного шага" if blocked else "Ветка не выбрана"
                if blocked:
                    failed_paths.add(key)
                self.publish(run)
                continue
            step.status = "running"
            step.input_ids = list(dict.fromkeys(fid for src in active for fid in steps[src].output_ids))
            report_sources[key] = {r for src in active for r in report_sources[src]}
            self.publish(run)
            incoming_findings = [findings[fid] for fid in step.input_ids]
            step.output_ids = step.input_ids.copy()
            try:
                outcome = "succeeded"
                if node.kind in {"secrets", "sca", "sast"}:
                    analysis = await asyncio.to_thread(analyze, node.kind, workflow.files, node.pattern)
                    hits, count = analysis.findings, analysis.checked
                    findings.update((f.id, f) for f in hits)
                    step.output_ids = list(dict.fromkeys(step.input_ids + [f.id for f in hits]))
                    run.findings = list(findings.values())
                    step.message = f"Файлов проверено: {count}. Найдено: {len(hits)}"
                    if node.kind == "sca":
                        step.message += f". Объявлений Maven проверено {analysis.checked_packages} из {len(analysis.packages)}"
                        if analysis.lockfile.files:
                            step.lockfile = analysis.lockfile
                            step.message += f". Дополнительно по lockfile {step.lockfile.checked} из {len(step.lockfile.packages)}"
                    issues = analysis.issues + analysis.lockfile.issues
                    if issues:
                        step.message += f". Неполная проверка ({len(issues)}): " + " · ".join(issues[:3])
                        outcome = "warning" if count else "failed"
                        if not count:
                            failed_paths.add(key)
                    elif count == 0:
                        step.message = "Подходящих файлов по маске нет"
                        outcome = "warning"
                elif node.kind == "condition":
                    step.branch = branch(node, incoming_findings)
                    step.message = "Условие выполнено" if step.branch == "yes" else "Условие не выполнено"
                elif node.kind == "explain":
                    await self.explain(node, step, run, incoming_findings)
                    report_sources[key].add(key)
                    if any(r.status == "failed" for r in step.reviews):
                        outcome = "warning"
                elif node.kind == "webhook":
                    reviews = [r for k in sorted(report_sources[key]) for r in steps[k].reviews]
                    code = await deliver(self.gateway.client, run.id, key, incoming_findings,
                                         [r.report for r in reviews if r.report], reviews, node.destination)
                    step.message = f"Отчёт доставлен · HTTP {code}"
                else:
                    step.message = f"Исходных файлов: {len(workflow.files)}"
                step.status = outcome
            except Exception as error:
                step.status = "warning" if node.kind == "explain" else "failed"
                step.message = reason(error)
                if node.kind == "explain":
                    step.message += ". Доступны рекомендации правил"
                else:
                    failed_paths.add(key)
            self.publish(run)
        statuses = {s.status for s in run.steps}
        run.status = "failed" if "failed" in statuses else "warning" if "warning" in statuses else "succeeded"
        self.publish(run)
