"""Run static checks or a saved Garden workflow on a checked-out project."""
import argparse
import asyncio
import json
import subprocess
import sys
from contextlib import closing
from dataclasses import asdict
from pathlib import Path

import httpx
from pydantic import ValidationError

from garden.ci_revision import verify_sources
from garden.integrations import Gateway
from garden.models import ANALYZERS, Blueprint, Finding, GitEvent, GitEventName, Node, Status, Workflow
from garden.runner import Engine
from garden.scanners import analyze
from garden.scenarios import sources
from garden.storage import Store
from garden.submission import readable_report, submission


def write_report(output: Path, findings: list[Finding], *, html_output: Path | None = None,
                 complete: bool = True, workflow_status: Status | None = None) -> None:
    if html_output is not None and html_output.resolve() == output.resolve():
        raise ValueError("Укажите разные файлы для JSON и HTML")
    data = submission(findings)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    if html_output is not None:
        html_output.parent.mkdir(parents=True, exist_ok=True)
        html_output.write_text(readable_report(data["findings"], complete=complete, workflow_status=workflow_status),
                               encoding="utf-8")


def check(root: Path, output: Path, sca_inventory: Path | None = None, extended_sca: bool | None = None,
          online_cve: bool = False, *, html_output: Path | None = None) -> int:
    files = sources(root)
    findings = []
    issues = []
    lock_critical = 0
    checked = 0
    for kind in ANALYZERS:
        analysis = analyze(kind, files, "*", extended_sca, online_cve)
        checked += analysis.checked
        findings.extend(analysis.findings)
        issues.extend(analysis.issues)
        if kind == "sca":
            print(f"Maven declarations checked: {analysis.checked_packages}/{len(analysis.packages)}")
            if online_cve:
                osv_checked = sum(p.osv_status == "checked" for p in analysis.packages)
                print(f"Direct declarations checked with OSV: {osv_checked}/{len(analysis.packages)}")
            lock = analysis.lockfile
            if lock.files:
                advisories = [a for p in lock.packages for a in p.advisories]
                lock_critical = sum(a.severity == "critical" for a in advisories)
                print(f"Additional locked versions checked: {lock.checked}/{len(lock.packages)}, "
                      f"advisories: {len(advisories)}, critical: {lock_critical}")
                issues.extend(lock.issues)
            if sca_inventory is not None:
                sca_inventory.parent.mkdir(parents=True, exist_ok=True)
                inventory = {"checked": analysis.checked_packages, "total": len(analysis.packages),
                             "packages": [asdict(p) for p in analysis.packages], "issues": analysis.issues,
                             "lockfile": lock.model_dump()}
                sca_inventory.write_text(json.dumps(inventory, ensure_ascii=False, indent=2), encoding="utf-8")
    if not checked and not issues:
        issues.append("Ни один анализатор не проверил файлы проекта")
    write_report(output, findings, html_output=html_output, complete=not issues)
    critical = sum(f.severity == "critical" for f in findings)
    print(f"Files: {len(files)}, findings: {len(findings)}, critical: {critical}")
    if issues:
        print("\n".join(dict.fromkeys(issues)), file=sys.stderr)
        return 2
    return int(critical > 0 or lock_critical > 0)


def checkout_event(root: Path, name: GitEventName, expected_sha: str | None) -> GitEvent:
    result = subprocess.run(["git", "-C", str(root), "rev-parse", "--verify", "HEAD^{commit}"],
                            text=True, capture_output=True)
    if result.returncode:
        raise ValueError("Для Git-события укажите проект внутри Git-репозитория с коммитом")
    sha = result.stdout.strip()
    if expected_sha is not None and expected_sha.lower() != sha:
        raise ValueError("--sha не совпадает с коммитом проекта")
    return GitEvent(name=name, sha=sha)


def selected_nodes(graph: Blueprint, selected: list[str]) -> list[Node]:
    reachable = set(selected)
    for key in graph.order():
        if key in reachable:
            reachable.update(edge.target for edge in graph.edges if edge.source == key)
    return [node for node in graph.nodes if node.id in reachable]


async def run_workflow(path: Path, root: Path, output: Path, trigger: str | None, offline: bool,
                       *, read_parent_catalog: bool = True, git_event: GitEvent | None = None,
                       require_analyzer: bool = False, html_output: Path | None = None) -> int:
    document = json.loads(path.read_bytes())
    if not isinstance(document, dict):
        raise ValueError("Файл сценария должен содержать объект Workflow")
    document.pop("files", None)
    graph = Blueprint.model_validate(document)
    start: GitEvent | str
    if git_event is not None:
        if trigger is not None:
            raise ValueError("Для Git-события точки входа выбираются по подписке")
        selected = graph.git_triggers(git_event.name)
        if not selected:
            print(f"Пропуск: в графе нет подписки на {git_event.name}. Новый отчёт не создан.")
            return 0
        print(f"Git {git_event.name} {git_event.sha}: {', '.join(selected)}")
        start = git_event
    else:
        manual = [node.id for node in graph.nodes if node.kind == "manual"]
        if trigger is None and len(manual) == 1:
            trigger = manual[0]
        if trigger is None or trigger not in manual:
            raise ValueError("Укажите --trigger с ID ручного триггера. Доступны: " + (", ".join(manual) or "нет"))
        selected = [trigger]
        start = trigger
    nodes = selected_nodes(graph, selected)
    has_analyzer = any(node.kind in ANALYZERS for node in nodes)
    if (require_analyzer or git_event is not None) and not has_analyzer:
        origin = "Git-ноду" if git_event else "ручной триггер"
        raise ValueError(f"Соедините {origin} с анализатором: выбранная ветка не проверяет проект")
    if offline:
        for node in nodes:
            if node.kind in {"explain", "webhook"} or node.online_cve:
                raise ValueError(f"В режиме --offline нельзя выполнить сетевой узел {node.id} ({node.kind})")
    files = sources(root, read_parent_catalog=read_parent_catalog)
    if git_event:
        verify_sources(root, git_event.sha, files, read_parent_catalog=read_parent_catalog)
    workflow = Workflow(**document, files=files)

    store = Store(Path(":memory:"), lambda: workflow)
    with closing(store.db):
        async with httpx.AsyncClient(timeout=60) as client:
            gateway = Gateway(client, []) if offline else Gateway.configured(client)
            engine = Engine(store, gateway)
            run = engine.start(workflow, start)
            await asyncio.gather(*engine.tasks)
    write_report(output, run.findings, html_output=html_output, complete=run.analysis_complete, workflow_status=run.status)
    critical = sum(f.severity == "critical" for f in run.findings)
    lock_critical = sum(a.severity == "critical" for step in run.steps if step.lockfile
                        for package in step.lockfile.packages for a in package.advisories)
    print(f"Status: {run.status}, findings: {len(run.findings)}, critical: {critical}")
    if lock_critical:
        print(f"Additional critical advisories in lockfiles: {lock_critical}")
    if run.status != "succeeded":
        for step in run.steps:
            if step.status in {"warning", "failed"}:
                print(f"{step.node_id}: {step.message}", file=sys.stderr)
        return 2
    if not run.ran_analyzer:
        print("На выбранной ветке не выполнялся анализ проекта", file=sys.stderr if has_analyzer else sys.stdout)
        return 2 if has_analyzer else 0
    return int(critical > 0 or lock_critical > 0)


def main() -> int:
    args = argparse.ArgumentParser(description=__doc__)
    args.add_argument("--project", type=Path, required=True)
    args.add_argument("--output", type=Path, required=True)
    args.add_argument("--html-output", type=Path, help="Also write a readable HTML report from the same findings")
    args.add_argument("--workflow", type=Path, help="Run a saved workflow with files from --project")
    start = args.add_mutually_exclusive_group()
    start.add_argument("--trigger", help="Manual trigger node ID when a workflow has several")
    start.add_argument("--git-event", choices=["push", "pull_request"], help="Run the matching Git event nodes")
    args.add_argument("--sha", help="Expected project checkout SHA for --git-event")
    args.add_argument("--offline", action="store_true", help="Disallow external service calls in reachable steps")
    args.add_argument("--sca-inventory", type=Path)
    args.add_argument("--extended-sca", action=argparse.BooleanOptionalAction, default=None,
                      help="Use the extended offline Maven catalog and inspect gradle.lockfile")
    args.add_argument("--online-cve", action="store_true",
                      help="Also send Maven coordinates and versions to OSV for current advisories (enables extended SCA)")
    options = args.parse_args()
    if not options.workflow and (options.trigger is not None or options.git_event or options.offline):
        args.error("--trigger, --git-event and --offline require --workflow")
    if options.sha is not None and not options.git_event:
        args.error("--sha requires --git-event")
    if options.workflow and (options.sca_inventory or options.extended_sca is not None or options.online_cve):
        args.error("With --workflow, configure SCA on the saved nodes")
    if options.online_cve and options.extended_sca is False:
        args.error("--online-cve requires extended SCA")
    try:
        if options.workflow:
            event = checkout_event(options.project, options.git_event, options.sha) if options.git_event else None
            return asyncio.run(run_workflow(options.workflow, options.project, options.output,
                                            options.trigger, options.offline, git_event=event,
                                            html_output=options.html_output))
        return check(options.project, options.output, options.sca_inventory, options.extended_sca, options.online_cve,
                     html_output=options.html_output)
    except ValidationError as error:
        for issue in error.errors(include_input=False):
            print(f"{'.'.join(map(str, issue['loc']))}: {issue['msg']}", file=sys.stderr)
        return 2
    except (OSError, ValueError) as error:
        print(str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
