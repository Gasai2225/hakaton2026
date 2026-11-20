"""File and line references for the team's synthetic Spring projects."""
import json
import os
import unittest
from pathlib import Path
from unittest.mock import patch

from garden.scanners import analyze
from garden.scenarios import sources


PRACTICE = Path(__file__).resolve().parents[2] / "samples/practice"


class PracticeProjects(unittest.TestCase):
    @patch.dict(os.environ, {"GARDEN_EXTENDED_SCA": "0"})
    def test_parcel_ledger_oracle(self):
        oracle = json.loads((Path(__file__).parent / "fixtures/parcel-ledger.json").read_bytes())
        files = sources(PRACTICE / "parcel-ledger")
        text = {f.path: f.text.splitlines() for f in files}
        for case in oracle["findings"] + oracle["controls"]:
            self.assertTrue(text[case["path"]][case["line"] - 1].strip(), case)
        for kind, category in (("secrets", "SECRET"), ("sast", "SAST"), ("sca", "SCA")):
            with self.subTest(category=category):
                result = analyze(kind, files, "*")
                expected = [(c["path"], c["line"], c.get("class"), c.get("package"), c.get("version"), c.get("advisoryId"))
                            for c in oracle["findings"] if c["category"] == category]
                actual = []
                for f in result.findings:
                    dep = f.dependency
                    self.assertEqual(f.category, category)
                    actual.append((f.path, f.line, f.classification, f"{dep.group}:{dep.artifact}" if dep else None,
                                   dep.version if dep else None, f.advisory))
                self.assertCountEqual(actual, expected)
                self.assertEqual(result.issues, [])
                self.assertEqual(len({f.id for f in result.findings}), len(actual))
                for case in oracle["controls"]:
                    if case["category"] != category:
                        continue
                    location = case["path"], case["line"]
                    self.assertFalse(any(row[:2] == location for row in actual), case)
                    if case.get("status") == "checked":
                        self.assertIn((*location, case["package"], case["version"], "checked"),
                                      [(p.path, p.line, p.package, p.version, p.status) for p in result.packages])
                    elif case.get("status") == "undeclared":
                        self.assertNotIn(case["package"], [p.package for p in result.packages])

    @patch.dict(os.environ, {"GARDEN_EXTENDED_SCA": "0"})
    def test_editor_sources_against_known_cases(self):
        expected = {
            "book-index": [
                ("SECRET", "src/main/resources/application.yml", 2, "api-key"),
                ("SAST", "src/main/kotlin/practice/books/BookIndex.kt", 20, "sql-injection"),
                ("SCA", "build.gradle.kts", 18, "org.apache.commons:commons-text:1.9/CVE-2022-42889"),
            ],
            "label-studio": [
                ("SECRET", "src/main/kotlin/practice/labels/LabelStudio.kt", 12, "secret-fallback"),
                ("SAST", "src/main/kotlin/practice/labels/LabelStudio.kt", 19, "credentialed-cors"),
                ("SCA", "build.gradle.kts", 14, "org.jsoup:jsoup:1.14.1/CVE-2021-37714"),
            ],
            "reading-room": [],
        }
        for project, wanted in expected.items():
            with self.subTest(project=project):
                files = sources(PRACTICE / project)
                rows = []
                issues = []
                for kind in ("secrets", "sast", "sca"):
                    result = analyze(kind, files, "*")
                    issues.extend(result.issues)
                    for hit in result.findings:
                        label = hit.classification
                        if hit.dependency:
                            dep = hit.dependency
                            label = f"{dep.group}:{dep.artifact}:{dep.version}/{hit.advisory}"
                        rows.append((hit.category, hit.path, hit.line, label))
                    if project == "reading-room" and kind == "sca":
                        self.assertIn(("org.apache.commons:commons-text", "1.10.0", "checked"),
                                      [(p.package, p.version, p.status) for p in result.packages])
                self.assertCountEqual(rows, wanted)
                self.assertEqual(issues, [])
