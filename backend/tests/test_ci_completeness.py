import asyncio
import io
import json
import os
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from garden.ci import main
from garden.ci_projects import run_projects
from garden.models import GitEvent


class CICompleteness(unittest.TestCase):
    def setUp(self):
        self.repo = Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
        self.project = self.repo / "samples/practice/example"
        self.project.mkdir(parents=True)
        self.reports = self.repo / "reports"
        self.errors = io.StringIO()
        self.enterContext(redirect_stdout(io.StringIO()))
        self.enterContext(redirect_stderr(self.errors))

    def check(self, label):
        output = self.reports / (label + ".json")
        argv = ["garden.ci", "--project", str(self.project), "--output", str(output),
                "--html-output", str(output.with_suffix(".html"))]
        with patch("sys.argv", argv):
            return main(), output

    def commit(self):
        subprocess.run(["git", "init", "-q", str(self.repo)], check=True)
        subprocess.run(["git", "-C", str(self.repo), "add", "-A"], check=True)
        subprocess.run(["git", "-C", str(self.repo), "-c", "user.name=Test", "-c", "user.email=ci@example.invalid",
                        "-c", "commit.gpgsign=false", "commit", "-qm", "Synthetic sources"], check=True)
        return subprocess.check_output(["git", "-C", str(self.repo), "rev-parse", "HEAD"], text=True).strip()

    def assert_report(self, path, *, complete):
        self.assertEqual(json.loads(path.read_bytes()), {"findings": []})
        html = path.with_suffix(".html").read_text(encoding="utf-8")
        self.assertEqual("Проверка неполная" in html, not complete)
        self.assertEqual("<p>Находок нет.</p>" in html, complete)

    def test_static_scan_requires_at_least_one_checked_input(self):
        (self.project / "libs.versions.toml").write_text('[versions]\n', encoding="utf-8")
        status, output = self.check("metadata")
        self.assertEqual(status, 2)
        self.assert_report(output, complete=False)
        (self.project / "application.properties").write_text("server.port=8080", encoding="utf-8")
        status, output = self.check("verified")
        self.assertEqual(status, 0)
        self.assert_report(output, complete=True)

    def test_directory_read_error_cannot_hide_behind_a_clean_sibling(self):
        private = self.project / "nested"
        private.mkdir()
        (private / "Nested.kt").write_text("class Nested", encoding="utf-8")
        (self.project / "Clean.kt").write_text("class Clean", encoding="utf-8")
        scandir = os.scandir

        def read_dir(path):
            if Path(path) == private:
                raise PermissionError(13, "test source directory unavailable", str(private))
            return scandir(path)

        with patch("os.scandir", read_dir):
            status, output = self.check("unavailable")
        self.assertEqual(status, 2)
        self.assertFalse(output.exists())
        self.assertIn("nested", self.errors.getvalue())
        status, output = self.check("available")
        self.assertEqual(status, 0)
        self.assert_report(output, complete=True)

    def test_ci_requires_an_executed_analyzer_on_the_selected_event_branch(self):
        (self.project / "Demo.kt").write_text("class Demo", encoding="utf-8")
        head = self.commit()
        graph = {"name": "Conditional CI", "nodes": [
            {"id": "git", "kind": "git_event", "git_events": ["push"], "x": 0, "y": 0},
            {"id": "manual", "kind": "manual", "x": 0, "y": 1},
            {"id": "gate", "kind": "condition", "predicate": "count_gte", "value": "1", "x": 1, "y": 0},
            {"id": "check", "kind": "secrets", "x": 2, "y": 0}],
            "edges": [{"id": "g", "source": "git", "target": "gate"},
                      {"id": "m", "source": "manual", "target": "gate"},
                      {"id": "c", "source": "gate", "target": "check", "branch": "yes"}]}
        definition = self.repo / "samples/ci-workflow.json"
        for branch, expected in [("yes", 2), ("no", 0)]:
            graph["edges"][-1]["branch"] = branch
            definition.write_text(json.dumps(graph), encoding="utf-8")
            for start in ("push", "manual"):
                with self.subTest(branch=branch, start=start):
                    event = GitEvent(name="push", sha=head) if start == "push" else None
                    folder = self.reports / branch / start
                    status = asyncio.run(run_projects(self.repo, ["example"], folder, git_event=event))
                    self.assertEqual(status, expected)
                    self.assert_report(folder / "001-example.json", complete=expected == 0)
        event = GitEvent(name="pull_request", sha="b"*40)
        folder = self.reports / "unsubscribed"
        self.assertEqual(asyncio.run(run_projects(self.repo, ["example"], folder, git_event=event)), 0)
        self.assertFalse(folder.exists())

    def test_sha_covers_project_inputs_and_only_its_referenced_parent_catalog(self):
        definition = self.repo / "samples/ci-workflow.json"
        definition.write_text(json.dumps({"name": "CI", "nodes": [
            {"id": "git", "kind": "git_event", "x": 0, "y": 0},
            {"id": "s", "kind": "secrets", "x": 1, "y": 0}],
            "edges": [{"id": "scan", "source": "git", "target": "s"}]}), encoding="utf-8")
        setting = 'dependencyResolutionManagement { versionCatalogs { create("libs") { from(files("../gradle/libs.versions.toml")) } } }'
        (self.project / "settings.gradle.kts").write_text(setting, encoding="utf-8")
        local = self.project / "Demo.kt"
        local.write_bytes(b"class Original\n")
        (self.project / ".gitignore").write_text("scratch.kt\n", encoding="utf-8")
        catalog = self.project.parent / "gradle/libs.versions.toml"
        catalog.parent.mkdir()
        catalog.write_bytes(b'[versions]\nexample="1"\n')
        other = self.repo / "Outside.kt"
        other.write_text("class Other", encoding="utf-8")
        sha = self.commit()
        other.write_text("class ChangedOutside", encoding="utf-8")

        def verify(label, expected):
            output = self.reports / (label + ".json")
            argv = ["garden.ci", "--workflow", str(definition), "--project", str(self.project), "--git-event", "push",
                    "--sha", sha, "--offline", "--output", str(output)]
            with patch("sys.argv", argv):
                self.assertEqual(main(), expected, label)
            self.assertEqual(output.exists(), expected == 0)

        verify("unrelated", 0)
        local.write_bytes(b"class Other\n")
        verify("modified", 2)
        local.unlink()
        verify("missing", 2)
        local.write_bytes(b"class Original\r\n")
        verify("line-endings", 0)
        scratch = self.project / "scratch.kt"
        scratch.write_bytes(b"class Scratch")
        verify("untracked-ignored", 2)
        scratch.unlink()
        catalog.write_bytes(b'[versions]\nexample="2"\n')
        verify("modified-catalog", 2)
        catalog.unlink()
        verify("deleted-catalog", 2)

    def test_source_error_in_one_project_keeps_other_verified_reports(self):
        (self.project / "Demo.kt").write_text("class Demo", encoding="utf-8")
        other = self.project.with_name("invalid")
        other.mkdir()
        bad = other / "Broken.kt"
        bad.write_bytes(b"\xff")
        graph = {"name": "CI", "nodes": [{"id": "m", "kind": "manual", "x": 0, "y": 0},
                                        {"id": "s", "kind": "secrets", "x": 1, "y": 0}],
                 "edges": [{"id": "e", "source": "m", "target": "s"}]}
        (self.repo / "samples/ci-workflow.json").write_text(json.dumps(graph), encoding="utf-8")
        names = ["invalid", "example"]
        self.assertEqual(asyncio.run(run_projects(self.repo, names, self.reports)), 2)
        self.assertIn("Broken.kt", self.errors.getvalue())
        self.assertFalse((self.reports / "001-invalid.json").exists())
        self.assert_report(self.reports / "002-example.json", complete=True)
        bad.write_text("class Recovered", encoding="utf-8")
        self.assertEqual(asyncio.run(run_projects(self.repo, names, self.reports)), 0)
        self.assert_report(self.reports / "001-invalid.json", complete=True)

    def test_parser_warning_keeps_confirmed_rows_and_marks_the_report_partial(self):
        broken = self.project / "Sample.kt"
        broken.write_text("fun (", encoding="utf-8")
        (self.project / "application.properties").write_text("sample.token=fixture-only", encoding="utf-8")
        for label, expected in (("partial", 2), ("valid", 0)):
            with self.subTest(label=label):
                status, output = self.check(label)
                self.assertEqual(status, expected)
                rows = json.loads(output.read_bytes())["findings"]
                self.assertEqual([(r["category"], r["path"]) for r in rows], [("SECRET", "application.properties")])
                html = output.with_suffix(".html").read_text(encoding="utf-8")
                self.assertEqual("Проверка неполная" in html, expected == 2)
                self.assertIn("application.properties:1", html)
                self.assertNotIn("fixture-only", html)
            broken.write_text("class Sample", encoding="utf-8")
