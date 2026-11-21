import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from tests.compare_submission import main


class CompareSubmission(unittest.TestCase):
    row = {"category": "SECRET", "class": "token", "path": "Alt.kt", "line": 7, "severity": "HIGH",
           "description": "private-fixture-marker"}
    label = {"id": "A", "category": "SECRET", "class": "token", "path": "Main.kt", "line": 1, "endLine": 2,
             "alternateLocations": [{"path": "Alt.kt", "line": 6, "endLine": 7}], "severity": "HIGH"}
    sca = {"category": "SCA", "path": "build.gradle.kts", "group": "g", "artifact": "a", "version": "1"}

    def run_cli(self, rows, expected, controls=()):
        with tempfile.TemporaryDirectory() as temp:
            report, labels = (Path(temp) / name for name in ("report.json", "reference.json"))
            report.write_text(json.dumps({"findings": rows}), encoding="utf-8")
            labels.write_text(json.dumps({"findings": expected, "controls": controls}), encoding="utf-8")
            output = io.StringIO()
            with redirect_stdout(output), redirect_stderr(output):
                status = main([str(report), str(labels)])
        self.assertNotIn("private-fixture-marker", output.getvalue())
        return status, output.getvalue()

    def test_alternate_location_advisory_alias_and_optional_severity(self):
        label = {**self.sca, "advisoryIds": ["one", "two"]}
        rows = [self.row, {**self.sca, "advisoryId": "two"}]
        self.assertEqual(self.run_cli(rows, [self.label, label])[0], 0)
        for wrong in [{"advisoryId": "other"}, {"version": "2"}, {"path": "other.gradle.kts"}]:
            with self.subTest(wrong=wrong):
                self.assertEqual(self.run_cli([rows[0], {**rows[1], **wrong}], [self.label, label])[0], 1)

    def test_extra_duplicate_missing_ambiguous_control_and_severity(self):
        for rows, labels, controls, message in [
            ([{**self.row, "class": "other"}], [self.label], [], "Unexpected report"),
            ([self.row, self.row], [self.label], [], "matched 2 times"),
            ([], [self.label], [], "matched 0 times"),
            ([self.row], [self.label, {**self.label, "id": "B"}], [], "Ambiguous"),
            ([self.row], [self.label], [self.label], "negative control"),
            ([{**self.row, "severity": "LOW"}], [self.label], [], "Severity mismatch"),
        ]:
            with self.subTest(message=message):
                status, diagnostic = self.run_cli(rows, labels, controls)
                self.assertEqual(status, 1)
                self.assertIn(message, diagnostic)

    def test_malformed_inputs_cannot_be_accepted_as_an_empty_report(self):
        self.assertEqual(self.run_cli({}, [])[0], 2)
        self.assertEqual(self.run_cli([], [self.label, self.label])[0], 2)
        self.assertEqual(self.run_cli([{**self.sca, "advisoryId": "two"}], [{**self.sca, "advisoryIds": "twotwo"}])[0], 2)

    def test_windows_separator_and_interval_limits(self):
        label = {**self.label, "path": "src/App.kt", "line": 7, "endLine": 8}
        row = {**self.row, "path": r"src\App.kt"}
        self.assertEqual(self.run_cli([{**row, "endLine": 21}], [label])[0], 0)
        for invalid in (6, 22, 7.0, "8", True, None):
            with self.subTest(end=invalid):
                self.assertEqual(self.run_cli([{**row, "endLine": invalid}], [label])[0], 2)
