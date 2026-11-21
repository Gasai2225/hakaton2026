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

from garden.ci_projects import ZERO_SHA, main, projects, run_projects
from garden.models import GitEvent
from garden.runner import Engine
from garden.scenarios import sources


class PracticeChanges(unittest.TestCase):
    def setUp(self):
        temp = Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
        self.repo = temp / "repo"
        self.repo.mkdir()
        self.temp = temp
        self.git("init", "-q", "-b", "main")

    def git(self, *args):
        return subprocess.check_output(["git", "-c", "user.name=CI", "-c", "user.email=ci@example.invalid",
                                        "-c", "commit.gpgsign=false", "-c", "core.autocrlf=false", *args],
                                       cwd=self.repo).decode().strip()

    def write(self, path, text="fun main() = Unit\n"):
        path = self.repo / path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def commit(self):
        self.git("add", "-A")
        self.git("commit", "-qm", "fixture")
        return self.git("rev-parse", "HEAD")

    def push(self, before, after, **extra):
        data = {"before": before, "after": after, "repository": {"default_branch": "main"},
                "ref": "refs/heads/new-feature", **extra}
        return projects(self.repo, "push", data, after)

    def test_push_covers_multiple_commits_moves_deletions_and_new_projects(self):
        practice = "samples/practice/"
        moved = self.write(practice + "from/Move.kt")
        self.write(practice + "from/Keep.kt")
        removed = self.write(practice + "deleted/Only.kt")
        self.write(practice + "untouched/Keep.kt")
        before = self.commit()
        self.git("update-ref", "refs/remotes/origin/main", before)
        self.write(practice + "space; echo BAD/Keep.kt")
        moved.rename(self.repo / practice / "space; echo BAD/Move.kt")
        removed.unlink()
        first = self.commit()
        self.write(practice + "new/Added.kt")
        self.write(practice + "notes/readme.md", "docs")
        self.write(practice + "README.md", "docs")
        self.write("elsewhere/NotAllowed.kt")
        head = self.commit()
        expected = ["from", "new", "space; echo BAD"]
        self.assertEqual(self.push(before, head), expected)
        self.assertEqual(self.push(ZERO_SHA, head), expected)
        self.assertEqual(self.push(head, head), [])
        self.assertEqual(self.push("f"*40, head), sorted([*expected, "untouched"]))
        self.assertEqual(self.push(head, ZERO_SHA, deleted=True), [])
        with self.assertRaisesRegex(ValueError, "checked-out"):
            self.push(before, first)

    def test_pr_uses_merge_base_and_checks_the_actual_head(self):
        self.write("samples/practice/base/Base.kt")
        self.commit()
        self.git("checkout", "-qb", "feature")
        self.write("samples/practice/pr/Changed.kt")
        head = self.commit()
        self.git("checkout", "-q", "main")
        self.write("samples/practice/base/Base.kt", "// base branch change\n")
        base = self.commit()
        event = {"pull_request": {"base": {"sha": base}, "head": {"sha": head}}}
        with self.assertRaisesRegex(ValueError, "checked-out"):
            projects(self.repo, "pull_request", event, head)
        self.git("checkout", "-q", head)
        self.assertEqual(projects(self.repo, "pull_request", event, head), ["pr"])
        self.assertEqual(self.push(ZERO_SHA, head), ["base", "pr"])
        self.git("update-ref", "refs/remotes/origin/main", base)
        self.assertEqual(self.push(ZERO_SHA, head), ["pr"])
        self.assertEqual(self.push(ZERO_SHA, head, ref="refs/heads/main"), ["base", "pr"])
        with self.assertRaisesRegex(ValueError, "existing project"):
            projects(self.repo, "workflow_dispatch", {"inputs": {"project": "../../outside"}}, head)
        self.assertEqual(projects(self.repo, "workflow_dispatch", {"inputs": {"project": "base"}}, head), ["base"])

    def test_symlinks_submodules_and_build_outputs_are_not_project_inputs(self):
        self.write("external/Only.kt")
        self.write("samples/practice/generated/build/Generated.kt")
        before = self.commit()
        blob = self.git("rev-parse", before + ":external/Only.kt")
        self.git("update-index", "--add", "--cacheinfo", "120000", blob, "samples/practice/link/Only.kt")
        self.git("update-index", "--add", "--cacheinfo", "160000", before, "samples/practice/submodule")
        self.git("commit", "-qm", "links")
        head = self.git("rev-parse", "HEAD")
        self.assertEqual(self.push(before, head), [])
        self.assertEqual(self.push(ZERO_SHA, head, ref="refs/heads/main"), [])

    def test_retained_project_with_no_remaining_sources_fails_the_check(self):
        sample = Path(__file__).resolve().parents[2] / "samples/ci-workflow.json"
        self.write("samples/ci-workflow.json", sample.read_text(encoding="utf-8"))
        old = self.write("samples/practice/emptied/Only.kt")
        gone = self.write("samples/practice/gone/Only.kt")
        before = self.commit()
        old.rename(old.with_name("README.md"))
        gone.unlink()
        self.write("samples/practice/new-docs/README.md", "documentation")
        head = self.commit()
        self.assertEqual(self.push(before, head), ["emptied"])
        error = io.StringIO()
        with redirect_stdout(io.StringIO()), redirect_stderr(error):
            self.assertEqual(asyncio.run(run_projects(self.repo, ["emptied"], self.temp)), 2)
        self.assertIn("нет поддерживаемых исходников", error.getvalue())

    def test_subscribed_unconnected_git_node_is_incomplete_and_unsubscribed_event_skips(self):
        workflow = {"name": "CI", "nodes": [{"id": "push", "kind": "git_event", "git_events": ["push"],
                                             "x": 0, "y": 0},
                                            {"id": "manual", "kind": "manual", "x": 0, "y": 1},
                                            {"id": "scanner", "kind": "secrets", "x": 1, "y": 1}],
                    "edges": [{"id": "hand", "source": "manual", "target": "scanner"}]}
        self.write("samples/ci-workflow.json", json.dumps(workflow))
        self.write("samples/practice/demo/Code.kt")
        head = self.commit()
        error, log = io.StringIO(), io.StringIO()
        with redirect_stdout(log), redirect_stderr(error):
            for event, expected in [("push", 2), ("pull_request", 0)]:
                code = asyncio.run(run_projects(self.repo, ["demo"], self.temp, git_event=GitEvent(name=event, sha=head)))
                self.assertEqual(code, expected)
        self.assertIn("Соедините Git-ноду с анализатором", error.getvalue())
        self.assertIn("нет подписки", log.getvalue())
        self.assertEqual(list(self.temp.glob("*.json")), [])

    def test_push_pr_and_dispatch_run_their_own_graph_branches(self):
        workflow = {"name": "CI", "nodes": [
            {"id": "push", "kind": "git_event", "git_events": ["push"], "x": 0, "y": 0},
            {"id": "another-push", "kind": "git_event", "git_events": ["push"], "x": 0, "y": 4},
            {"id": "pr", "kind": "git_event", "git_events": ["pull_request"], "x": 0, "y": 1},
            {"id": "manual", "kind": "manual", "x": 0, "y": 2},
            {"id": "second-manual", "kind": "manual", "x": 0, "y": 3},
            {"id": "sca", "kind": "sca", "extended_sca": False, "x": 1, "y": 0},
            {"id": "secrets", "kind": "secrets", "x": 1, "y": 1}],
            "edges": [{"id": "p", "source": "push", "target": "sca"},
                      {"id": "p-again", "source": "another-push", "target": "sca"},
                      {"id": "r", "source": "pr", "target": "secrets"},
                      {"id": "m", "source": "manual", "target": "sca"}]}
        self.write("samples/ci-workflow.json", json.dumps(workflow))
        before = self.commit()
        for name, version in [("a critical", "1.9"), ("z clean", "1.10.0")]:
            self.write(f"samples/practice/{name}/build.gradle.kts",
                       'dependencies { implementation("org.apache.commons:commons-text:' + version + '") }')
        head = self.commit()
        event = self.temp / "event.json"
        for name, payload, expected_code, files in [
            ("push", {"before": before, "after": head}, 1, ["001-a_critical.json", "002-z_clean.json"]),
            ("pull_request", {"pull_request": {"base": {"sha": before}, "head": {"sha": head}}}, 0,
             ["001-a_critical.json", "002-z_clean.json"]),
            ("workflow_dispatch", {"inputs": {"project": "a critical", "trigger": "manual"}}, 1,
             ["001-a_critical.json"]),
        ]:
            with self.subTest(event=name):
                output = self.temp / (name + "-output")
                event.write_text(json.dumps(payload), encoding="utf-8")
                env = {"GITHUB_WORKSPACE": str(self.repo), "RUNNER_TEMP": str(self.temp), "GITHUB_OUTPUT": str(output),
                       "GITHUB_EVENT_NAME": name, "GITHUB_EVENT_PATH": str(event), "CHECKED_SHA": head}
                with patch.dict(os.environ, env), redirect_stdout(io.StringIO()), \
                     patch("garden.ci.sources", wraps=sources) as read, \
                     patch.object(Engine, "start", autospec=True, side_effect=Engine.start) as launch:
                    self.assertEqual(main(), expected_code)
                self.assertEqual(read.call_count, len(files))
                self.assertTrue(all(call.kwargs == {"read_parent_catalog": False} for call in read.call_args_list))
                expected = "manual" if name == "workflow_dispatch" else GitEvent(name=name, sha=head)
                self.assertEqual([call.args[-1] for call in launch.call_args_list], [expected] * len(files))
                key, path = output.read_text().strip().split("=", 1)
                self.assertEqual(key, "report_dir")
                self.assertEqual(Path(path).parent, self.temp)
                reports = sorted(Path(path).glob("*.json"))
                self.assertEqual([p.name for p in reports], files)
                self.assertEqual(sorted(p.name for p in Path(path).glob("*.html")),
                                 [p.with_suffix(".html").name for p in reports])
                severities = [[r["severity"] for r in json.loads(p.read_bytes())["findings"]] for p in reports]
                self.assertEqual(severities[0], ["CRITICAL"] if expected_code else [])
                if len(files) > 1:
                    self.assertEqual(severities[1], [])
