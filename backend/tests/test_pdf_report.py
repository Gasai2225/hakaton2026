import unittest
from unittest.mock import patch

from reportlab.platypus import BaseDocTemplate, Paragraph

from garden.models import Advice, BrowserReport, Receipt, Report, Review
from garden.pdf_report import render_report_pdf


class PdfReportTests(unittest.TestCase):
    def test_failed_reviews_with_and_without_successful_recommendations(self):
        failed = Review(connection="local", model="mini", label="А & Б", status="failed",
                        message="Сервис вернул <error> & HTTP 503")
        other = Review(connection="backup", label="", status="failed", message="Истекло время ожидания")
        advice = Report(groups=[Advice(finding_ids=["one"], risk="Риск найден", fix="Исправьте правило")])
        success = Review(connection="remote", model="large", label="Рабочая модель", status="succeeded", report=advice)

        for additional in (other, success):
            with self.subTest(status=additional.status):
                payload = Receipt(run_id="run", findings=[], reviews=[failed, additional],
                                  reports=[advice] if additional.report else [], analysis_status="complete")
                report = BrowserReport(run_id="run", node_id="hook", name="Проект",
                                       created_at="2026-01-01T12:00:00+00:00", payload=payload)
                paragraphs = []

                def after_flowable(document, item):
                    if isinstance(item, Paragraph):
                        paragraphs.append(item.getPlainText())

                with patch.object(BaseDocTemplate, "afterFlowable", after_flowable):
                    self.assertTrue(render_report_pdf(report).startswith(b"%PDF-"))
                self.assertIn("Ошибка модели А & Б · mini — Сервис вернул <error> & HTTP 503", paragraphs)
                if additional.status == "failed":
                    self.assertIn("Ошибка модели backup — Истекло время ожидания", paragraphs)
                else:
                    self.assertIn("Рабочая модель · large", paragraphs)
                    self.assertIn("Исправьте правило", " ".join(paragraphs))
