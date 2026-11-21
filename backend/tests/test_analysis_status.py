import asyncio
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

import httpx

from garden.api import app, lifespan
from garden.ci import run_workflow
from garden.integrations import Gateway
from garden.models import Edge, Node, Run, Source, Workflow


def chain(*kinds, broken=False):
    nodes = [Node(id="start", kind="manual", x=0, y=0)]
    nodes.extend(Node(id=kind, kind=kind, x=0, y=0, connection="missing-fixture-profile") for kind in kinds)
    return Workflow(name="Classroom", nodes=nodes, edges=[
        Edge(id=f"e{i}", source=a.id, target=b.id) for i, (a, b) in enumerate(zip(nodes, nodes[1:]))
    ], files=[Source(path="Classroom.kt", text="fun (" if broken else "class Classroom"),
              Source(path="application.properties", text="classroom.api-key=classroom-test-marker")])


class AnalysisStatus(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.enterContext(patch.dict(os.environ, {"GARDEN_DB": str(self.root / "runs.sqlite"),
                                                  "GARDEN_WEBHOOK_URL": "http://fixture.invalid/receive"}))
        self.api = await self.enterAsyncContext(httpx.AsyncClient(base_url="http://localhost",
                                                                   transport=httpx.ASGITransport(app=app)))

    async def execute(self, graph):
        response = await self.api.post("/api/runs", json={"workflow": graph.model_dump(), "trigger": "start"})
        self.assertEqual(response.status_code, 202, response.text)
        await asyncio.gather(*app.state.engine.tasks)
        return "/api/runs/" + response.json()["id"]

    async def test_api_reports_coverage_separately_from_workflow_status(self):
        cases = [
            (chain("secrets", "webhook"), 500, "failed", "complete", 1),
            (chain("secrets", "explain"), 204, "warning", "complete", 1),
            (chain("secrets", "webhook", broken=True), 204, "warning", "partial", 1),
            (chain("webhook", "secrets"), 500, "failed", "not_run", 0),
            (chain("secrets", "webhook", "sast"), 500, "failed", "partial", 1),
        ]
        async with lifespan(app):
            for graph, http_code, status, coverage, count in cases:
                with self.subTest(graph=[n.kind for n in graph.nodes], status=status, coverage=coverage):
                    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda _: httpx.Response(http_code))) as sink:
                        with patch.object(app.state.engine.gateway, "client", sink):
                            url = await self.execute(graph)
                    run = (await self.api.get(url)).raise_for_status().json()
                    self.assertEqual((run["status"], run["analysis_status"]), (status, coverage))
                    rows = (await self.api.get(url + "/submission")).raise_for_status().json()["findings"]
                    self.assertEqual([r["path"] for r in rows], ["application.properties"] * count)
                    html = (await self.api.get(url + "/submission", params={"format": "html"})).raise_for_status().text
                    self.assertEqual("Проверка неполная" in html, coverage != "complete")
                    self.assertEqual("Сценарий завершился с ошибкой" in html, status == "failed")
                    self.assertNotIn("classroom-test-marker", html)

    async def test_ci_exit_code_keeps_integration_and_scan_failures(self):
        project = self.root / "project"
        project.mkdir()
        for downstream, broken, http_code in (("webhook", False, 500), ("explain", False, 204), ("webhook", True, 204)):
            with self.subTest(downstream=downstream, broken=broken):
                graph = chain("secrets", downstream, broken=broken)
                for file in graph.files:
                    (project / file.path).write_text(file.text, encoding="utf-8")
                definition = self.root / "graph.json"
                definition.write_text(graph.model_dump_json(exclude={"files"}), encoding="utf-8")
                output, html = self.root / "report.json", self.root / "report.html"
                async with httpx.AsyncClient(transport=httpx.MockTransport(lambda _: httpx.Response(http_code))) as sink:
                    with patch.object(Gateway, "configured", return_value=Gateway(sink, [])), \
                            redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                        status = await run_workflow(definition, project, output, "start", False, html_output=html)
                self.assertEqual(status, 2)
                self.assertEqual([r["path"] for r in json.loads(output.read_bytes())["findings"]], ["application.properties"])
                self.assertEqual("Проверка неполная" in html.read_text(encoding="utf-8"), broken)

    async def test_only_the_chosen_condition_branch_contributes_to_coverage(self):
        graph = chain("secrets", "condition")
        graph.nodes.append(Node(id="unselected", kind="sast", x=0, y=0, pattern="missing.*"))
        graph.edges.append(Edge(id="no", source="condition", target="unselected", branch="no"))
        async with lifespan(app):
            url = await self.execute(graph)
            run = (await self.api.get(url)).raise_for_status().json()
            self.assertEqual(run["steps"][-1]["status"], "skipped")
            self.assertEqual((run["status"], run["analysis_status"]), ("succeeded", "complete"))

    async def test_coverage_condition_evaluates_only_its_active_inputs(self):
        graph = chain("secrets", broken=True)
        graph.nodes.append(Node(id="clean", kind="secrets", pattern="*.properties", x=0, y=0))
        graph.edges.append(Edge(id="start-clean", source="start", target="clean"))
        for target, coverage, inputs in [
            ("complete", "complete", ["clean"]),
            ("partial", "partial", ["secrets"]),
            ("unchecked", "not_run", ["start"]),
            ("merged", "partial", ["clean", "secrets"]),
            ("wrong", "complete", ["clean", "secrets"]),
        ]:
            graph.nodes.append(Node(id=target, kind="condition", predicate="analysis_status_eq",
                                    value=coverage, x=0, y=0))
            graph.edges.extend(Edge(id=f"{source}-{target}", source=source, target=target) for source in inputs)
        async with lifespan(app):
            url = await self.execute(graph)
            run = (await self.api.get(url)).raise_for_status().json()
        self.assertEqual(run["analysis_status"], "partial")
        self.assertEqual({step["node_id"]: step["branch"] for step in run["steps"] if step["kind"] == "condition"},
                         {"complete": "yes", "partial": "yes", "unchecked": "yes", "merged": "yes", "wrong": "no"})

    async def test_each_receiver_gets_the_coverage_of_its_own_inputs(self):
        graph = chain("secrets", "condition", broken=True)
        graph.files[-1].text = "classroom.api-key=${API_KEY}"
        graph.nodes.extend([Node(id="clean", kind="secrets", pattern="*.properties", x=0, y=0),
                            Node(id="explain", kind="explain", x=0, y=0)])
        graph.edges.extend([Edge(id="manual-clean", source="start", target="clean"),
                            Edge(id="no-hits", source="condition", target="explain", branch="no")])
        for target, inputs in [("direct", ["start"]), ("complete", ["clean"]), ("partial", ["explain"]),
                               ("merged", ["explain", "clean"])]:
            graph.nodes.append(Node(id=target, kind="webhook", x=0, y=0))
            graph.edges.extend(Edge(id=f"{src}-{target}", source=src, target=target) for src in inputs)
        received = {}
        def receive(request):
            _, node_id = request.headers["Idempotency-Key"].split("/")
            received[node_id] = json.loads(request.content)
            return httpx.Response(204)
        async with lifespan(app), httpx.AsyncClient(transport=httpx.MockTransport(receive)) as sink:
            with patch.object(app.state.engine.gateway, "client", sink):
                url = await self.execute(graph)
            run = (await self.api.get(url)).raise_for_status().json()
            self.assertEqual(run["analysis_status"], "partial")
            self.assertEqual({k: v["analysis_status"] for k, v in received.items()},
                             {"direct": "not_run", "complete": "complete", "partial": "partial", "merged": "partial"})
            for key, body in received.items():
                stored = (await self.api.get(f"{url}/steps/{key}/delivery")).raise_for_status().json()
                self.assertEqual(stored, {"state": "delivered", "payload": body})
                self.assertEqual(body["findings"], [])
            explain = next(s for s in run["steps"] if s["node_id"] == "explain")
            self.assertIn("В проверенной части", explain["message"])

    async def test_recovery_preserves_coverage_at_the_point_of_interruption(self):
        graph = chain("secrets", "sast", "webhook")
        snapshots = {}
        async with lifespan(app), httpx.AsyncClient(transport=httpx.MockTransport(lambda _: httpx.Response(204))) as sink:
            store = app.state.store
            update = store.update
            def capture(run):
                update(run)
                for step in run.steps:
                    if step.status == "running" and step.kind in {"sast", "webhook"}:
                        snapshots[step.kind] = run.model_dump_json()
            with patch.object(store, "update", side_effect=capture), patch.object(app.state.engine.gateway, "client", sink):
                await self.execute(graph)
            self.assertEqual(set(snapshots), {"sast", "webhook"})
            for key, body in snapshots.items():
                interrupted = Run.model_validate_json(body)
                interrupted.id = key
                store.insert(interrupted, graph)
        async with lifespan(app):
            for key, coverage in (("sast", "partial"), ("webhook", "complete")):
                with self.subTest(interrupted_at=key):
                    url = "/api/runs/" + key
                    run = (await self.api.get(url)).raise_for_status().json()
                    self.assertEqual((run["status"], run["analysis_status"]), ("failed", coverage))
                    html = (await self.api.get(url + "/submission", params={"format": "html"})).raise_for_status().text
                    self.assertEqual("Проверка неполная" in html, coverage != "complete")
                    self.assertIn("application.properties:1", html)

    def test_legacy_export_preserves_original_completeness(self):
        raw = dict(id="old", name="old", started="then", trigger="start",
                   steps=[dict(node_id="secrets", kind="secrets", status="succeeded")])
        for status, complete in (("succeeded", True), ("warning", False), ("failed", False)):
            with self.subTest(status=status):
                run = Run.model_validate({**raw, "status": status})
                self.assertEqual(run.analysis_complete, complete)
