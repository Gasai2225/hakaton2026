import json
import os
import unittest
from unittest.mock import patch

import httpx

from garden.api import app, lifespan
from garden.models import Edge, Node, Run, Step, demo


class ReceiptCompatibility(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.enterContext(patch.dict(os.environ, {"GARDEN_DB": ":memory:"}))
        await self.enterAsyncContext(lifespan(app))
        self.client = await self.enterAsyncContext(
            httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://localhost")
        )
        graph = demo()
        graph.nodes.append(Node(id="send", kind="webhook", x=0, y=0))
        graph.edges.append(Edge(id="notify", source="scan", target="send"))
        run = Run(id="example", name=graph.name, trigger="start", started="2026-11-21T00:00:00Z", status="succeeded",
                  steps=[Step(node_id=node.id, kind=node.kind, status="succeeded") for node in graph.nodes])
        app.state.store.insert(run, graph)
        self.legacy = {"run_id": run.id, "findings": [], "reports": []}
        self.headers = {"Idempotency-Key": f"{run.id}/send"}

    async def post(self, payload):
        return await self.client.post("/api/inbox", json=payload, headers=self.headers)

    async def test_legacy_receipt_can_be_replayed_without_changing_its_body(self):
        original = json.dumps(self.legacy, indent=2)
        db = app.state.store.db
        with db:
            db.execute("INSERT INTO receipts VALUES (?, ?)", ("example/send", original))
        for replay in (self.legacy, {**self.legacy, "reviews": []}):
            self.assertEqual((await self.post(replay)).status_code, 201)
        for changed in ({"reports": [{"groups": []}]}, {"analysis_status": "complete"}):
            self.assertEqual((await self.post({**self.legacy, **changed})).status_code, 409)
        stored, = db.execute("SELECT body FROM receipts WHERE key=?", ("example/send",)).fetchone()
        self.assertEqual(stored, original)
        history = await self.client.get("/api/runs/example/receipts")
        self.assertEqual(history.json(), [{**self.legacy, "reviews": []}])
        delivery = await self.client.get("/api/runs/example/steps/send/delivery")
        self.assertEqual(delivery.json(), {"state": "delivered", "payload": self.legacy})

    async def test_status_is_preserved_and_participates_in_idempotency(self):
        payload = {**self.legacy, "reviews": [], "analysis_status": "partial"}
        for _ in range(2):
            self.assertEqual((await self.post(payload)).status_code, 201)
        self.assertEqual((await self.post({**payload, "analysis_status": "complete"})).status_code, 409)
        self.assertEqual((await self.post(self.legacy)).status_code, 409)
        self.assertEqual((await self.client.get("/api/runs/example/receipts")).json(), [payload])

    async def test_first_submission_by_an_older_sender_keeps_coverage_unknown(self):
        self.assertEqual((await self.post(self.legacy)).status_code, 201)
        history = await self.client.get("/api/runs/example/receipts")
        self.assertEqual(history.json(), [{**self.legacy, "reviews": []}])
