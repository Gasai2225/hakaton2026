import asyncio
import json
import os
import unittest
from unittest.mock import patch

import httpx
from pydantic import ValidationError

from garden.api import app, lifespan
from garden.models import Edge, GitEvent, Node, Workflow, demo


class GitTriggerTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.enterContext(patch.dict(os.environ, {"GARDEN_DB": ":memory:", "GARDEN_WEBHOOK_URL": "http://test/hook"}))
        await self.enterAsyncContext(lifespan(app))
        self.api = await self.enterAsyncContext(httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                                                  base_url="http://localhost"))
        self.engine = app.state.engine

    async def test_overlapping_subscriptions_share_one_run_and_one_delivery(self):
        graph = demo()
        graph.nodes.extend([Node(id="both", kind="git_event", x=0, y=0),
                            Node(id="push", kind="git_event", git_events=["push"], x=0, y=0),
                            Node(id="pr", kind="git_event", git_events=["pull_request"], x=0, y=0),
                            Node(id="hook", kind="webhook", x=0, y=0)])
        for trigger in ("both", "push", "pr"):
            graph.edges.append(Edge(id=trigger + "-scan", source=trigger, target="scan"))
        for trigger in ("push", "pr"):
            target = trigger + "-only"
            graph.nodes.append(Node(id=target, kind="secrets", x=0, y=0))
            graph.edges.append(Edge(id=trigger + "-branch", source=trigger, target=target))
            graph.edges.append(Edge(id=target + "-hook", source=target, target="hook"))
        graph.edges.append(Edge(id="send", source="scan", target="hook"))
        graph = Workflow.model_validate(graph.model_dump())
        deliveries = []
        def receive(request):
            deliveries.append(json.loads(request.content)["run_id"])
            return httpx.Response(204)

        async with httpx.AsyncClient(transport=httpx.MockTransport(receive)) as sink:
            with patch.object(self.engine.gateway, "client", sink):
                for event_name, selected, skipped in [("push", "push", "pr"), ("pull_request", "pr", "push")]:
                    with self.subTest(event=event_name):
                        event = GitEvent(name=event_name, sha="b" * 40)
                        run = self.engine.start(graph, event)
                        await asyncio.gather(*self.engine.tasks)
                        result = (await self.api.get("/api/runs/" + run.id)).json()
                        self.assertEqual((result["status"], result["git_event"]), ("succeeded", event.model_dump()))
                        steps = {s["node_id"]: s for s in result["steps"]}
                        for key in ("both", selected):
                            self.assertEqual(steps[key]["status"], "succeeded")
                            self.assertIn(event_name, steps[key]["message"])
                            self.assertIn(event.sha, steps[key]["message"])
                        self.assertEqual((steps["start"]["status"], steps[skipped]["status"]), ("skipped", "skipped"))
                        self.assertEqual((steps[selected + "-only"]["status"], steps[skipped + "-only"]["status"]),
                                         ("succeeded", "skipped"))
                        self.assertEqual(len(result["findings"]), 1)
                        self.assertEqual(deliveries.count(run.id), 1)
                        history = (await self.api.get("/api/runs")).json()
                        self.assertEqual(next(row["git_event"] for row in history if row["id"] == run.id), event.model_dump())
        self.assertEqual(len((await self.api.get("/api/runs")).json()), 2)
        button = await self.api.post("/api/runs", json={"trigger": "both", "workflow": graph.model_dump()})
        self.assertEqual(button.status_code, 422)

    async def test_unmatched_event_legacy_run_and_validation(self):
        graph = demo()
        with self.assertRaisesRegex(ValueError, "нет подписки"):
            self.engine.start(graph, GitEvent(name="push", sha="a" * 40))
        self.assertEqual((await self.api.get("/api/runs")).json(), [])
        with self.assertRaises(ValidationError):
            GitEvent(name="push", sha="short")
        for events in ([], ["push", "push"], ["fork"]):
            with self.subTest(events=events), self.assertRaises(ValidationError):
                Node(id="git", kind="git_event", x=0, y=0, git_events=events)
        run = self.engine.start(graph, "start")
        await asyncio.gather(*self.engine.tasks)
        old = run.model_dump(exclude={"git_event"})
        with self.engine.store.db:
            self.engine.store.db.execute("UPDATE runs SET body=? WHERE id=?", (json.dumps(old), run.id))
        self.assertIsNone((await self.api.get("/api/runs/" + run.id)).json()["git_event"])
        self.assertIsNone((await self.api.get("/api/runs")).json()[0]["git_event"])
