import asyncio
import json
import os
import tempfile
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from threading import Thread
from unittest.mock import patch

import httpx

from garden.api import app, lifespan
from garden.models import Edge, Finding, Node, Report, Workflow, demo
from garden.scanners import Analysis
from garden.scenarios import Plan, blueprint


class WebhookDeliveryTests(unittest.IsolatedAsyncioTestCase):
    async def test_parallel_scanners_deliver_their_own_finding_metadata(self):
        self.enterContext(patch.dict(os.environ, {"GARDEN_DB": ":memory:", "GARDEN_WEBHOOK_URL": "http://test/receive"}))
        await self.enterAsyncContext(lifespan(app))
        received = []
        def receive(request):
            received.append(json.loads(request.content))
            return httpx.Response(204)

        base = Finding(id="shared", category="SCA", rule="fixture-advisory", severity="medium", path="build.gradle.kts",
                       line=1, column=1, title="Local entry", fix="Upgrade")
        enriched = base.model_copy(update={"severity": "critical", "title": "Enriched entry"})
        def analyze_fixture(kind, files, pattern, extended, online):
            return Analysis(findings=[enriched if extended else base], checked=1)
        self.enterContext(patch("garden.runner.analyze", side_effect=analyze_fixture))
        client = await self.enterAsyncContext(httpx.AsyncClient(transport=httpx.MockTransport(receive)))
        self.enterContext(patch.object(app.state.engine.gateway, "client", client))
        nodes = [Node(id="start", kind="manual", x=0, y=0)]
        edges = []
        for name, extended in (("local", False), ("enriched", True)):
            nodes.extend([Node(id=name, kind="sca", extended_sca=extended, x=0, y=0),
                          Node(id=f"{name}-gate", kind="condition", predicate="severity_eq", value="critical", x=0, y=0),
                          Node(id=f"{name}-send", kind="webhook", x=0, y=0)])
            for src, dst in (("start", name), (name, f"{name}-gate"), (name, f"{name}-send")):
                edges.append(Edge(id=f"{src}-to-{dst}", source=src, target=dst))
        workflow = Workflow(name="Two feeds", nodes=nodes, edges=edges, files=demo().files)
        run = app.state.engine.start(workflow, "start")
        await asyncio.gather(*app.state.engine.tasks)
        self.assertEqual(run.status, "succeeded")
        self.assertEqual({s.node_id: s.branch for s in run.steps if s.kind == "condition"},
                         {"local-gate": "no", "enriched-gate": "yes"})
        self.assertCountEqual([body["findings"] for body in received],
                              [[base.model_dump()], [enriched.model_dump()]])

    async def test_outgoing_body_is_available_during_dispatch_and_after_restart(self):
        temp = self.enterContext(tempfile.TemporaryDirectory())
        self.enterContext(patch.dict(os.environ, {"GARDEN_DB": str(Path(temp) / "runs.sqlite"),
                                                   "GARDEN_WEBHOOK_URL": "http://test/receive"}))
        entered, release = asyncio.Event(), asyncio.Event()
        requests = []
        async def receiver(request):
            requests.append(request.content)
            entered.set()
            await release.wait()
            return httpx.Response(204)

        api = await self.enterAsyncContext(httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test"))
        async with lifespan(app), httpx.AsyncClient(transport=httpx.MockTransport(receiver)) as sink:
            graph = demo()
            graph.nodes.append(Node(id="send", kind="webhook", x=0, y=0))
            graph.edges.append(Edge(id="scan-send", source="scan", target="send"))
            with patch.object(app.state.engine.gateway, "client", sink):
                result = (await api.post("/api/runs", json={"trigger": "start", "workflow": graph.model_dump()})).raise_for_status()
                key = result.json()["id"]
                path = f"/api/runs/{key}/steps/send/delivery"
                try:
                    await asyncio.wait_for(entered.wait(), 5)
                    payload = json.loads(requests[0])
                    self.assertEqual((await api.get(path)).json(), {"state": "attempted", "payload": payload})
                    body, = app.state.store.db.execute("SELECT body FROM outgoing_webhooks WHERE run_id=? AND node_id='send'",
                                                       (key,)).fetchone()
                    self.assertEqual(body, requests[0])
                finally:
                    release.set()
                    await asyncio.gather(*app.state.engine.tasks)
        async with lifespan(app):
            self.assertEqual((await api.get(path)).json(), {"state": "delivered", "payload": payload})

    async def test_manual_workflow_sends_only_on_yes_and_reports_http_errors(self):
        requests = []

        class Receiver(BaseHTTPRequestHandler):
            def do_POST(self):
                requests.append(self.rfile.read(int(self.headers["Content-Length"])))
                self.send_response_only(response_code)
                self.end_headers()

        server = self.enterContext(HTTPServer(("127.0.0.1", 0), Receiver))
        thread = Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05})
        thread.start()
        self.addCleanup(thread.join)
        self.addCleanup(server.shutdown)
        self.enterContext(patch.dict(os.environ, {
            "GARDEN_DB": ":memory:",
            "GARDEN_WEBHOOK_URL": f"http://127.0.0.1:{server.server_port}/report",
            "no_proxy": "127.0.0.1",
        }))
        await self.enterAsyncContext(lifespan(app))
        api = await self.enterAsyncContext(httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                                             base_url="http://test"))
        graph = blueprint(Plan(name="Webhook", checks=["secrets"], schedule=None, condition="any",
                               explain=True, notify=True))
        next(node for node in graph.nodes if node.kind == "webhook").destination = "configured"
        def advice(connection, model, findings):
            return Report(groups=[{"finding_ids": [f.id for f in findings], "risk": "Учебный ключ доступен.",
                                   "fix": "Отозвать учебный ключ."}])
        self.enterContext(patch.object(app.state.engine.gateway, "explain", side_effect=advice))

        for project, response_code, branch, delivery_status in [
            ("book-index", 204, "yes", "succeeded"),
            ("reading-room", 204, "no", "skipped"),
            ("book-index", 500, "yes", "failed"),
        ]:
            with self.subTest(project=project, response_code=response_code):
                requests.clear()
                files = (await api.get(f"/api/practice/{project}")).raise_for_status().json()
                if branch == "yes":
                    self.assertTrue(any("training-only-book-key" in file["text"] for file in files))
                started = await api.post("/api/runs", json={"trigger": "start", "workflow": {
                    **graph.model_dump(), "files": files}})
                self.assertEqual(started.status_code, 202, started.text)
                run_id = started.json()["id"]
                await asyncio.gather(*app.state.engine.tasks)
                run = (await api.get(f"/api/runs/{run_id}")).raise_for_status().json()
                steps = {step["kind"]: step for step in run["steps"]}
                self.assertEqual(steps["condition"]["branch"], branch)
                self.assertEqual(steps["webhook"]["status"], delivery_status)
                self.assertEqual(run["status"], "failed" if response_code == 500 else "succeeded")
                delivery = (await api.get(f"/api/runs/{run_id}/steps/notify/delivery")).raise_for_status().json()
                if branch == "no":
                    self.assertEqual(requests, [])
                    self.assertEqual(delivery, {"state": "not_sent", "payload": None})
                    continue
                self.assertEqual(len(requests), 1)
                self.assertNotIn(b"training-only-book-key", requests[0])
                payload = json.loads(requests[0])
                self.assertEqual(payload["run_id"], run_id)
                self.assertEqual(payload["findings"], run["findings"])
                self.assertEqual([hit["category"] for hit in payload["findings"]], ["SECRET"])
                self.assertEqual(payload["reports"], [steps["explain"]["report"]])
                self.assertEqual(payload["reviews"], steps["explain"]["reviews"])
                self.assertEqual(delivery, {"state": "delivered" if response_code == 204 else "attempted",
                                            "payload": payload})
                self.assertIn(f"HTTP {response_code}", steps["webhook"]["message"])
