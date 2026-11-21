import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from html import unescape
from pathlib import Path
from unittest.mock import patch

from garden.ci import main


class ReadableReportTests(unittest.TestCase):
    def setUp(self):
        folder = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.root = folder / "project"
        self.root.mkdir()
        self.html = folder / "report.html"
        self.json = folder / "report.json"

    def check_reports(self, status, *, saved=False):
        argv = ["garden.ci", "--project", str(self.root), "--output", str(self.json), "--html-output", str(self.html)]
        if saved:
            graph = Path(__file__).resolve().parents[2] / "samples/ci-workflow.json"
            argv.extend(["--workflow", str(graph), "--offline"])
        with patch("sys.argv", argv), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            self.assertEqual(main(), status)
        return json.loads(self.json.read_text(encoding="utf-8"))["findings"], self.html.read_text(encoding="utf-8")

    def test_clean_critical_and_partial_reports(self):
        code = self.root / "Demo.kt"
        code.write_text("class Demo", encoding="utf-8")
        build = self.root / "build.gradle.kts"
        build.write_text('dependencies { implementation("org.apache.commons:commons-text:1.10.0") }', encoding="utf-8")
        secret = self.root / "app&cfg.properties"
        secret.write_text("service.api-key=${SERVICE_KEY}", encoding="utf-8")
        rows, html = self.check_reports(0, saved=True)
        self.assertEqual(rows, [])
        self.assertIn("Находок нет.", html)
        build.write_text('dependencies { implementation("org.apache.commons:commons-text:1.9") }', encoding="utf-8")
        secret.write_text("service.api-key=sample-report-marker", encoding="utf-8")
        for saved in (True, False):
            with self.subTest(saved=saved):
                rows, html = self.check_reports(1, saved=saved)
                self.assertCountEqual([row["category"] for row in rows], ["SECRET", "SCA"])
                self.assertEqual(html.count("<tr>"), len(rows) + 1)
                self.assertIn("app&amp;cfg.properties:1", html)
                self.assertNotIn("sample-report-marker", html + str(rows))
                for row in rows:
                    for value in row.values():
                        self.assertIn(str(value), unescape(html))
        build.write_text("dependencies {}", encoding="utf-8")
        code.write_text("fun (", encoding="utf-8")
        secret.write_text("service.api-key=${SERVICE_KEY}", encoding="utf-8")
        rows, html = self.check_reports(2, saved=True)
        self.assertEqual(rows, [])
        self.assertIn("Проверка неполная", html)
        self.assertIn("В проверенной части находок нет", html)
