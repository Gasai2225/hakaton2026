"""Competition JSON and readable output are projections of the same scanner findings."""
import re
from html import escape

from garden.models import Finding, Status


def row(finding: Finding) -> dict:
    result = {"category": finding.category, "path": finding.path, "severity": finding.severity.upper(),
              "description": finding.title, "remediation": finding.fix}
    if finding.category == "SCA":
        dependency = finding.dependency
        if dependency is not None:
            result.update(dependency.model_dump())
        else:
            # Older local runs stored coordinates only in the detector's generated title.
            match = re.match(r"^([\w.-]+):([\w.-]+) ([0-9.]+) входит в диапазон ", finding.title)
            if not match:
                raise ValueError("Для выгрузки старого отчёта повторите проверку зависимостей")
            result.update(zip(("group", "artifact", "version"), match.groups()))
        result["advisoryId"] = finding.advisory
    else:
        result["class"] = finding.classification or (
            "route-authorization" if finding.rule == "SPRING-OPEN-DEFAULT" else finding.rule)
        result["line"] = finding.line
    return result


def submission(findings: list[Finding]) -> dict:
    return {"findings": [row(f) for f in findings]}


def readable_report(rows: list[dict], *, complete: bool, workflow_status: Status | None = None) -> str:
    def cells(values, tag):
        return "<tr>" + "".join(f"<{tag}>{escape(str(value))}</{tag}>" for value in values) + "</tr>"

    body = []
    if workflow_status == "failed":
        body.append("<p>Сценарий завершился с ошибкой. Подробности доступны в журнале запуска.</p>")
    elif workflow_status == "warning" and complete:
        body.append("<p>Сценарий завершился с предупреждением. Подробности доступны в журнале запуска.</p>")
    if not complete:
        body.append("<p>Проверка неполная.</p>")
    if not rows:
        body.append("<p>Находок нет.</p>" if complete else "<p>В проверенной части находок нет.</p>")
    else:
        head = cells(["Категория", "Класс или зависимость", "Описание", "Место", "Критичность", "Исправление"], "th")
        body.extend(["<table><thead>", head, "</thead><tbody>"])
        for item in rows:
            location = item["path"]
            if item["category"] == "SCA":
                name = f'{item["group"]}:{item["artifact"]}:{item["version"]} · {item["advisoryId"]}'
            else:
                name = item["class"]
                location += f':{item["line"]}'
            body.append(cells([item["category"], name, item["description"], location,
                               item["severity"], item["remediation"]], "td"))
        body.append("</tbody></table>")
    return ('<!doctype html><html lang="ru"><meta charset="utf-8"><title>Отчёт Garden</title>'
            '<body><h1>Результаты проверки Garden</h1>' + "\n".join(body) + "</body></html>\n")
