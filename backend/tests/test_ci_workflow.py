import io
import json
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

import httpx

from garden.ci import main


SAMPLES = Path(__file__).resolve().parents[2] / "samples"
GRAPH = SAMPLES / "ci-workflow.json"


class SavedWorkflowCI(unittest.TestCase):
    def setUp(self):
        temp = self.enterContext(tempfile.TemporaryDirectory())
        self.graph = Path(temp) / "workflow.json"
        self.output = Path(temp) / "report.json"

    def invoke(self, project, workflow=GRAPH, *extra, offline=True):
        argv = ["garden.ci", "--workflow", str(workflow), "--project", str(SAMPLES / "practice" / project),
                "--output", str(self.output), *extra]
        if offline:
            argv.append("--offline")
        error = io.StringIO()
        with patch("sys.argv", argv), redirect_stdout(io.StringIO()), redirect_stderr(error):
            status = main()
        return status, error.getvalue()

    def test_same_graph_writes_report_for_clean_and_critical_projects(self):
        self.assertEqual(self.invoke("reading-room"), (0, ""))
        self.assertEqual(json.loads(self.output.read_bytes()), {"findings": []})
        self.assertEqual(self.invoke("book-index"), (1, ""))
        rows = json.loads(self.output.read_bytes())["findings"]
        self.assertCountEqual([r["category"] for r in rows], ["SECRET", "SAST", "SCA"])
        self.assertEqual([r["advisoryId"] for r in rows if r["severity"] == "CRITICAL"], ["CVE-2022-42889"])

    def test_selects_only_the_requested_manual_branch(self):
        graph = json.loads(GRAPH.read_bytes())
        graph["nodes"].append({"id": "second", "kind": "manual", "x": 0, "y": 300})
        self.graph.write_text(json.dumps(graph), encoding="utf-8")
        status, error = self.invoke("book-index", self.graph)
        self.assertEqual(status, 2)
        self.assertIn("--trigger", error)
        self.assertEqual(self.invoke("book-index", self.graph, "--trigger", "second"), (0, ""))
        self.assertEqual(json.loads(self.output.read_bytes()), {"findings": []})
        self.assertEqual(self.invoke("book-index", self.graph, "--trigger", "start"), (1, ""))
        self.assertEqual(self.invoke("book-index", self.graph, "--trigger", "sca")[0], 2)

    def test_offline_rejects_external_nodes_before_running(self):
        for kind in ("explain", "webhook", "sca"):
            with self.subTest(kind=kind):
                graph = json.loads(GRAPH.read_bytes())
                graph["nodes"][-1] = {"id": "sca", "kind": kind, "x": 750, "y": 0}
                self.graph.write_text(json.dumps(graph), encoding="utf-8")
                status, error = self.invoke("book-index", self.graph)
                self.assertEqual(status, 2)
                self.assertIn("--offline", error)
                self.assertFalse(self.output.exists())

    def test_configured_workflow_can_use_delivery(self):
        graph = json.loads(GRAPH.read_bytes())
        graph["nodes"].append({"id": "send", "kind": "webhook", "destination": "inbox", "x": 1000, "y": 0})
        graph["edges"].append({"id": "deliver", "source": "sca", "target": "send"})
        self.graph.write_text(json.dumps(graph), encoding="utf-8")
        response = httpx.Response(204, request=httpx.Request("POST", "http://local/api/inbox"))
        with patch.object(httpx.AsyncClient, "send", return_value=response) as delivery:
            self.assertEqual(self.invoke("book-index", self.graph, offline=False), (1, ""))
        delivery.assert_awaited_once()

    def test_offline_git_path_can_share_a_graph_with_manual_integrations(self):
        graph = json.loads(GRAPH.read_bytes())
        graph["nodes"].extend([
            {"id": "send", "kind": "webhook", "x": 1, "y": 1},
            {"id": "ai", "kind": "explain", "x": 2, "y": 1},
            {"id": "online", "kind": "sca", "extended_sca": True, "x": 3, "y": 1},
        ])
        graph["edges"].extend([
            {"id": "hand-send", "source": "start", "target": "send"},
            {"id": "send-ai", "source": "send", "target": "ai"},
            {"id": "ai-online", "source": "ai", "target": "online"},
        ])
        self.graph.write_text(json.dumps(graph), encoding="utf-8")
        sha = subprocess.check_output(["git", "-C", str(SAMPLES), "rev-parse", "HEAD"], text=True).strip()
        with patch.object(httpx.AsyncClient, "send", side_effect=AssertionError("unexpected network call")) as network:
            self.assertEqual(self.invoke("book-index", self.graph, "--git-event", "push", "--sha", sha), (1, ""))
            self.assertEqual(len(json.loads(self.output.read_bytes())["findings"]), 3)
            self.assertEqual(self.invoke("book-index", self.graph, "--git-event", "push", "--sha", "0"*40)[0], 2)
            graph["nodes"].append({"id": "if", "kind": "condition", "x": 1, "y": 2})
            graph["edges"].extend([{"id": "after", "source": "sca", "target": "if"},
                                   {"id": "negative", "source": "if", "target": "send", "branch": "no"}])
            self.graph.write_text(json.dumps(graph), encoding="utf-8")
            result, error = self.invoke("book-index", self.graph, "--git-event", "push")
            self.assertEqual(result, 2)
            self.assertIn("--offline", error)
            network.assert_not_awaited()

    def test_legacy_manual_graph_is_not_an_implicit_git_subscription(self):
        graph = json.loads(GRAPH.read_bytes())
        graph["nodes"] = [n for n in graph["nodes"] if n["kind"] != "git_event"]
        graph["edges"] = [e for e in graph["edges"] if e["source"] != "repository"]
        graph["files"] = [{"path": "snapshot.kt", "text": "fun oldSnapshot() = Unit"}]
        self.graph.write_text(json.dumps(graph), encoding="utf-8")
        with patch("garden.ci.sources", side_effect=AssertionError("unsubscribed workflow read files")):
            self.assertEqual(self.invoke("book-index", self.graph, "--git-event", "push"), (0, ""))
        self.assertFalse(self.output.exists())
        self.assertEqual(self.invoke("book-index", self.graph), (1, ""))
        self.assertEqual(len(json.loads(self.output.read_bytes())["findings"]), 3)
