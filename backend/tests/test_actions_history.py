import json
import tempfile
import unittest
from io import BytesIO
from pathlib import Path
from unittest.mock import patch
from zipfile import ZipFile

from garden.actions_history import ActionsHistory


def workflow_run(event, run_id, **fields):
    return {"path": ".github/workflows/garden.yml", "id": run_id, "run_number": run_id, "run_attempt": 1,
            "event": event, "head_sha": "a" * 40, "head_branch": "lesson",
            "created_at": "2026-08-12T12:00:00Z", "run_started_at": "2026-08-12T12:00:00Z",
            "updated_at": "2026-08-12T12:04:00Z", "status": "completed", "conclusion": "success", **fields}


class ActionsHistoryTests(unittest.TestCase):
    def setUp(self):
        self.dir = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.enterContext(patch.dict("os.environ", {"GARDEN_GITHUB_REPOSITORY": "example/garden"}))
        self.history = ActionsHistory(self.dir)

    def test_distinct_push_and_pr_on_same_commit_survive_restart_offline(self):
        runs = [workflow_run("pull_request", 12), workflow_run("push", 11), workflow_run("workflow_dispatch", 10)]
        with patch.object(self.history, "_get", return_value=json.dumps({"workflow_runs": runs}).encode()) as fetch:
            first = self.history.history()
            self.assertEqual([(r["id"], r["event"]) for r in first["runs"]], [(12, "pull_request"), (11, "push")])
            self.assertEqual(self.history.history(), first)
            fetch.assert_called_once()
        restarted = ActionsHistory(self.dir)
        with patch.object(restarted, "_get", side_effect=ValueError("offline")):
            offline = restarted.history()
        self.assertEqual(offline["runs"], first["runs"])
        self.assertTrue(offline["error"])

    def test_new_run_loads_its_project_archive_without_a_local_download(self):
        archive = BytesIO()
        with ZipFile(archive, "w") as out:
            out.writestr("001-example.json", '{"findings":[]}')
        run = workflow_run("push", 3)
        older = {"id": 6, "name": "saved-workflow-findings", "created_at": "2026-08-12T11:05:00Z",
                 "expired": False, "size_in_bytes": len(archive.getvalue())}
        current = {**older, "id": 7, "created_at": "2026-08-12T12:03:59Z"}
        def fetch(path, *args):
            if path.startswith("workflows/"):
                return json.dumps({"workflow_runs": [run]}).encode()
            if path.startswith("runs/3/artifacts"):
                return json.dumps({"artifacts": [older, current]}).encode()
            self.assertEqual(path, "artifacts/7/zip")
            return archive.getvalue()
        with patch.object(self.history, "_get", side_effect=fetch):
            result = self.history.reports(3, 1)
        self.assertIsNone(result["error"])
        self.assertEqual(result["reports"], [{"name": "example", "findings": []}])
        with patch.object(self.history, "_get", side_effect=AssertionError("unexpected network call")):
            self.assertEqual(self.history.reports(3, 1)["reports"], result["reports"])
            self.assertTrue(self.history.reports(3, 2)["error"])
            self.assertTrue(self.history.reports(999, 1)["error"])

    def test_expired_artifact_is_explicit_and_never_downloaded(self):
        objects = [{"workflow_runs": [workflow_run("push", 3)]},
                   {"artifacts": [{"name": "saved-workflow-findings", "id": 7, "expired": True,
                                   "size_in_bytes": 20, "created_at": "2026-08-12T12:01:00Z"}]}]
        with patch.object(self.history, "_get", side_effect=[json.dumps(obj).encode() for obj in objects]):
            result = self.history.reports(3, 1)
        self.assertTrue(result["error"])
        self.assertEqual(result["reports"], [])
