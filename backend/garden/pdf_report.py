from collections import Counter
from datetime import datetime
from html import escape
from io import BytesIO
from pathlib import Path
from zoneinfo import ZoneInfo

from reportlab.lib.colors import HexColor, white
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import BaseDocTemplate, Frame, HRFlowable, PageTemplate, Paragraph, Spacer, Table, TableStyle

from garden.email_report import ANALYSIS, SEVERITY, SEVERITY_ORDER, finding_location
from garden.models import BrowserReport


FONT = "DejaVuSans"
BOLD = "DejaVuSans-Bold"
FONTS = Path(__file__).with_name("fonts")
pdfmetrics.registerFont(TTFont(FONT, str(FONTS / f"{FONT}.ttf")))
pdfmetrics.registerFont(TTFont(BOLD, str(FONTS / f"{BOLD}.ttf")))
pdfmetrics.registerFontFamily(FONT, normal=FONT, bold=BOLD)

INK = HexColor("#20352B")
MUTED = HexColor("#52695D")
GREEN = HexColor("#22654B")
RULE = HexColor("#DAE5DD")
SURFACE = HexColor("#F2F6F3")
SEVERITY_TONES = {
    "critical": HexColor("#8E3040"),
    "high": HexColor("#993E22"),
    "medium": HexColor("#775914"),
    "low": HexColor("#315F74"),
}
MARGIN = 42
PAGE_WIDTH, PAGE_HEIGHT = A4
WIDTH = PAGE_WIDTH - MARGIN * 2
STYLE = ParagraphStyle("Report text", fontName=FONT, fontSize=10, leading=14, textColor=INK, spaceAfter=6)
TITLE = ParagraphStyle("Report title", STYLE, fontName=BOLD, fontSize=25, leading=32, spaceAfter=6)
PROJECT = ParagraphStyle("Project name", STYLE, fontName=BOLD, fontSize=14, leading=20, spaceAfter=7)
SECTION = ParagraphStyle("Report section", STYLE, fontName=BOLD, fontSize=15, leading=20, spaceBefore=18,
                         spaceAfter=8, keepWithNext=True)
ITEM = ParagraphStyle("Report item", STYLE, fontName=BOLD, fontSize=11, leading=15, spaceAfter=3, keepWithNext=True)
META = ParagraphStyle("Report metadata", STYLE, fontSize=8.5, leading=12, textColor=MUTED, spaceAfter=3)
LOCATION = ParagraphStyle("Finding location", META, keepWithNext=True)


def text(value: str) -> str:
    return "<br/>".join(escape(line) for line in value.splitlines())


def draw_page(canvas, doc):
    canvas.setFillColor(GREEN)
    canvas.roundRect(MARGIN, PAGE_HEIGHT - 52, WIDTH, 25, 5, fill=1, stroke=0)
    canvas.setFillColor(white)
    canvas.setFont(BOLD, 10)
    canvas.drawString(MARGIN + 12, PAGE_HEIGHT - 44, "Garden")
    canvas.setStrokeColor(RULE)
    canvas.line(MARGIN, 43, PAGE_WIDTH - MARGIN, 43)
    canvas.setFillColor(MUTED)
    canvas.setFont(FONT, 8)
    canvas.drawString(MARGIN, 29, "Отчёт о проверке")
    canvas.drawRightString(PAGE_WIDTH - MARGIN, 29, f"Страница {doc.page}")


def metric_cards(counts: Counter, total: int) -> Table:
    metrics = [
        ("Всего", total, GREEN),
        ("Критические", counts["critical"], SEVERITY_TONES["critical"]),
        ("Высокие", counts["high"], SEVERITY_TONES["high"]),
        ("Средние", counts["medium"], SEVERITY_TONES["medium"]),
        ("Низкие", counts["low"], SEVERITY_TONES["low"]),
    ]
    count_style = ParagraphStyle("Metric value", STYLE, fontName=BOLD, fontSize=18, leading=24)
    labels = [Paragraph(label, META) for label, _, _ in metrics]
    values = [Paragraph(f'<font color="{tone.hexval()}">{value}</font>', count_style) for _, value, tone in metrics]
    table = Table([labels, values], colWidths=[WIDTH / len(metrics)] * len(metrics))
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), SURFACE),
        ("BOX", (0, 0), (-1, -1), 0.5, RULE),
        ("LINEAFTER", (0, 0), (-2, -1), 0.5, RULE),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, 0), 8),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 0),
        ("TOPPADDING", (0, 1), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 1), (-1, -1), 7),
    ]))
    return table


def render_report_pdf(report: BrowserReport) -> bytes:
    receipt = report.payload
    findings = sorted(receipt.findings, key=lambda finding: SEVERITY_ORDER[finding.severity])
    numbers = {finding.id: index for index, finding in enumerate(findings, 1)}
    status = ANALYSIS.get(receipt.analysis_status, "Статус проверки неизвестен")
    date = datetime.fromisoformat(report.created_at).astimezone(ZoneInfo("Europe/Moscow")).strftime("%d.%m.%Y, %H:%M МСК")
    story = [Paragraph("Отчёт о проверке", TITLE), Paragraph(text(report.name), PROJECT),
             Paragraph(f"{date} · {status}", META)]
    for review in receipt.reviews:
        if review.status == "failed":
            name = " · ".join(filter(None, (review.label or review.connection, review.model)))
            reason = f" — {text(review.message)}" if review.message else ""
            story.append(Paragraph(f"<b>Ошибка модели {text(name)}</b>{reason}", STYLE))
    story.extend([Spacer(1, 9), metric_cards(Counter(finding.severity for finding in findings), len(findings)),
                  Paragraph("Находки", SECTION)])

    if not findings:
        story.append(Paragraph("Находок нет." if receipt.analysis_status == "complete" else
                               "Зарегистрированных находок нет.", STYLE))
    for index, finding in enumerate(findings, 1):
        if index > 1:
            divider = HRFlowable(width="100%", color=RULE, thickness=0.5, spaceBefore=2, spaceAfter=6)
            divider.keepWithNext = True
            story.append(divider)
        severity = SEVERITY[finding.severity]
        if finding.severity_estimated:
            severity += " (оценка анализатора)"
        kind = finding.classification or finding.rule
        if finding.dependency:
            dependency = finding.dependency
            kind = f"{dependency.group}:{dependency.artifact}:{dependency.version}"
        meta = " · ".join(value for value in (severity, finding.category, kind, finding.advisory) if value)
        fix = Paragraph(f"<b>Исправление</b><br/>{text(finding.fix)}", STYLE)
        # Keep short fixes with the finding and let longer text flow across pages.
        location_style = LOCATION if fix.wrap(WIDTH, PAGE_HEIGHT)[1] <= 3 * STYLE.leading else META
        story.extend([
            Paragraph(f"{index}. {text(finding.title)}", ITEM),
            Paragraph(text(meta), LOCATION),
            Paragraph(text(finding_location(finding)), location_style),
            fix,
        ])

    if receipt.reports:
        story.append(Paragraph("Рекомендации моделей", SECTION))
        reviews = [review for review in receipt.reviews if review.report is not None]
        for index, model_report in enumerate(receipt.reports):
            name = f"Модель {index + 1}"
            if index < len(reviews) and reviews[index].report == model_report:
                name = " · ".join(filter(None, (reviews[index].label, reviews[index].model))) or name
            story.append(Paragraph(text(name), ITEM))
            for group in model_report.groups:
                references = ", ".join(str(numbers[key]) for key in group.finding_ids if key in numbers)
                if references:
                    story.append(Paragraph(f"Находки № {references}", LOCATION))
                story.extend([
                    Paragraph(f"<b>Риск</b><br/>{text(group.risk)}", STYLE),
                    Paragraph(f"<b>Исправление</b><br/>{text(group.fix)}", STYLE),
                ])

    buffer = BytesIO()
    document = BaseDocTemplate(buffer, pagesize=A4, title=f"Отчёт Garden - {report.name}", author="Garden")
    frame = Frame(MARGIN, 56, WIDTH, PAGE_HEIGHT - 128, leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0)
    document.addPageTemplates(PageTemplate("Report", frames=[frame], onPage=draw_page))
    document.build(story)
    return buffer.getvalue()
