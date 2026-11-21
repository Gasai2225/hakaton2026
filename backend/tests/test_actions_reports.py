import json
import tempfile
import unittest
from io import BytesIO
from pathlib import Path
from unittest.mock import patch
from zipfile import ZIP_DEFLATED, ZipFile

from garden import actions_reports as reports


def artifact(files):
    buffer = BytesIO()
    with ZipFile(buffer, "w", compression=ZIP_DEFLATED) as archive:
        for name, content in files.items():
            archive.writestr(name, content)
    return buffer.getvalue()


class ActionsReportTests(unittest.TestCase):
    def test_directory_and_archive_return_official_report_fields(self):
        common = {"path": "Demo.kt", "severity": "HIGH", "description": "Описание", "remediation": "Исправление"}
        code = {**common, "category": "SAST", "class": "route-authorization", "line": 12}
        dependency = {**common, "category": "SCA", "group": "org.jsoup", "artifact": "jsoup",
                      "version": "1.14.1", "advisoryId": "CVE-2021-37714"}
        files = {"002-clean.json": '{"findings":[]}', "001-label-studio.html": "<h1>HTML</h1>",
                 "001-label-studio.json": json.dumps({"findings": [{**code, "unrelated": 42}, dependency]})}
        expected = [{"name": "label-studio", "findings": [code, dependency]}, {"name": "clean", "findings": []}]
        self.assertEqual(reports.read_archive(artifact(files)), expected)
        folder = Path(self.enterContext(tempfile.TemporaryDirectory()))
        for name, content in files.items():
            (folder / name).write_text(content, encoding="utf-8")
        self.assertEqual(reports.read_directory(folder), expected)

    def test_empty_and_unreadable_are_distinct(self):
        self.assertEqual(reports.read_archive(artifact({})), [])
        for document in ("{}", "null", "{", '{"findings":[{}]}', '{"findings":true}'):
            with self.subTest(document=document), self.assertRaises(ValueError):
                reports.read_archive(artifact({"001-project.json": document}))
        with self.assertRaises(ValueError):
            reports.read_archive(b"invalid archive")
        folder = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.assertEqual(reports.read_directory(folder), [])
        self.assertEqual(reports.read_directory(folder / "new-run"), [])
        (folder / "001-project.json").write_bytes(b"broken")
        with self.assertRaises(ValueError):
            reports.read_directory(folder)

    def test_only_generated_report_names_are_accepted(self):
        for name in ("nested/001-name.json", "../001-name.json", r"nested\001-name.json", "manifest.json"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                reports.read_archive(artifact({name: '{"findings":[]}'}))

    def test_report_archive_and_directory_bounds(self):
        payload = '{"findings":[]}'
        data = artifact({"001-demo.json": payload, "001-demo.html": "x" * 100})
        for limit in ("MAX_REPORT_BYTES", "MAX_ARCHIVE_BYTES", "MAX_EXPANDED_BYTES", "MAX_ENTRIES"):
            with self.subTest(limit=limit), patch.object(reports, limit, 1), self.assertRaises(ValueError):
                reports.read_archive(data)
        folder = Path(self.enterContext(tempfile.TemporaryDirectory()))
        (folder / "001-demo.json").write_text(payload, encoding="utf-8")
        with patch.object(reports, "MAX_REPORT_BYTES", 1), self.assertRaises(ValueError):
            reports.read_directory(folder)
