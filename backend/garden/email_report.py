from collections import Counter
from datetime import datetime
from email.message import EmailMessage
from email.utils import format_datetime
from html import escape
from zoneinfo import ZoneInfo

from garden.models import Finding, Receipt


SEVERITY = {"critical": "Критическая", "high": "Высокая", "medium": "Средняя", "low": "Низкая"}
SEVERITY_ORDER = {severity: index for index, severity in enumerate(SEVERITY)}
ANALYSIS = {
    "complete": "Проверка завершена",
    "partial": "Проверка неполная",
    "not_run": "Анализ исходников не запускался",
}
PREVIEW_SIZE = 8


def finding_location(finding: Finding) -> str:
    return f"{finding.path}:{finding.line}:{finding.column}"


def finding_cards(findings: list[Finding]) -> str:
    parts = []
    for number, finding in enumerate(findings, 1):
        details = [finding.category, finding.classification or finding.rule]
        if finding.dependency:
            dependency = finding.dependency
            details.append(f"{dependency.group}:{dependency.artifact}:{dependency.version}")
        if finding.advisory:
            details.append(finding.advisory)
        severity = SEVERITY[finding.severity] + (" · оценка анализатора" if finding.severity_estimated else "")
        parts.append(
            '<div style="border-top:1px solid #dce6df;padding:12px 0">'
            f'<h3 style="margin:0 0 6px;font-size:16px">{number}. {escape(finding.title)}</h3>'
            f'<p style="margin:4px 0;color:#40584c">{escape(severity)} · {escape(" · ".join(details))}</p>'
            f'<p style="margin:4px 0;overflow-wrap:anywhere"><code>{escape(finding_location(finding))}</code></p>'
            f'<p style="margin:8px 0 0;white-space:pre-wrap"><strong>Исправление</strong> {escape(finding.fix)}</p>'
            '</div>'
        )
    return "\n".join(parts)


def model_advice(receipt: Receipt, findings: list[Finding]) -> str:
    if not receipt.reports:
        return ""
    numbers = {finding.id: str(index) for index, finding in enumerate(findings, 1)}
    reviews = [review for review in receipt.reviews if review.report is not None]
    parts = ['<h2 style="margin:24px 0 8px;font-size:18px">Рекомендации моделей</h2>']
    for index, report in enumerate(receipt.reports):
        name = f"Модель {index + 1}"
        if index < len(reviews) and reviews[index].report == report:
            name = " · ".join(filter(None, (reviews[index].label, reviews[index].model))) or name
        parts.append(f'<h3 style="margin:12px 0 6px;font-size:16px">{escape(name)}</h3>')
        for group in report.groups:
            references = ", ".join(numbers[key] for key in group.finding_ids if key in numbers)
            parts.append('<div style="border-left:2px solid #a9c4b5;margin:8px 0;padding:0 10px">')
            if references:
                parts.append(f'<p style="margin:4px 0">Находки № {references}</p>')
            parts.append(f'<p style="margin:4px 0;white-space:pre-wrap"><strong>Риск</strong> {escape(group.risk)}</p>')
            parts.append(f'<p style="margin:4px 0;white-space:pre-wrap"><strong>Исправление</strong> {escape(group.fix)}</p>')
            parts.append('</div>')
    return "\n".join(parts)


def report_html(run_name: str, summary: list[str], findings: list[Finding], *, footer: str = "", advice: str = "") -> str:
    overview = "\n".join(f'<p style="margin:6px 0">{escape(line)}</p>' for line in summary)
    cards = ('<h2 style="margin:24px 0 8px;font-size:18px">Находки</h2>' + finding_cards(findings)) if findings else ""
    note = f'<p style="margin:16px 0 0;color:#40584c">{escape(footer)}</p>' if footer else ""
    return (
        '<!doctype html><html lang="ru"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1"><title>Отчёт Garden</title></head>'
        '<body style="margin:0;background:#eef3ef;color:#20352b;font:15px/1.55 Arial,sans-serif">'
        '<div style="max-width:680px;margin:0 auto;padding:14px">'
        '<div style="border:1px solid #dce6df;border-top:5px solid #22654b;background:#fff;padding:20px;overflow-wrap:anywhere">'
        '<h1 style="margin:0 0 8px;font-size:22px">Отчёт проверки Garden</h1>'
        f'<p style="margin:0 0 14px;font-size:16px"><strong>{escape(run_name)}</strong></p>'
        f'{overview}{cards}{advice}{note}</div></div></body></html>\n'
    )


def build_report_email(receipt: Receipt, recipient: str, run_name: str) -> EmailMessage:
    created = datetime.now(ZoneInfo("Europe/Moscow"))
    findings = sorted(receipt.findings, key=lambda finding: SEVERITY_ORDER[finding.severity])
    counts = Counter(finding.severity for finding in findings)
    breakdown = " · ".join(f"{label} {counts[level]}" for level, label in SEVERITY.items())
    summary = [
        f"Отчёт создан {created:%d.%m.%Y в %H:%M} МСК",
        ANALYSIS.get(receipt.analysis_status, "Статус проверки неизвестен"),
        f"Находок всего {len(findings)}",
    ]
    if findings:
        summary.append(breakdown)
    preview = findings[:PREVIEW_SIZE]
    remaining = len(findings) - len(preview)
    attachments = "Полный отчёт во вложении garden-report.html. Структурированные данные — в garden-report.json."
    if remaining:
        attachments = f"В письме показано {len(preview)} из {len(findings)} находок. " + attachments

    plain = ["Отчёт проверки Garden", run_name, "", *summary]
    for number, finding in enumerate(preview, 1):
        plain.extend(["", f"{number}. {finding.title} · {SEVERITY[finding.severity]}",
                      finding_location(finding), f"Исправление — {finding.fix}"])
    plain.extend(["", attachments])

    message = EmailMessage()
    message["To"] = recipient
    message["Subject"] = "Garden — отчёт проверки"
    message["Date"] = format_datetime(created)
    message.set_content("\n".join(plain))
    message.add_alternative(report_html(run_name, summary, preview, footer=attachments), subtype="html")
    message.add_attachment(report_html(run_name, summary, findings, advice=model_advice(receipt, findings)),
                           subtype="html", filename="garden-report.html")
    message.add_attachment(receipt.model_dump_json(indent=2).encode(), maintype="application", subtype="json",
                           filename="garden-report.json")
    return message
