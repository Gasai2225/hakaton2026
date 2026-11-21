import asyncio
import json
import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import httpx

from garden.api import app, lifespan
from garden.models import Edge, Node, demo


class WorkspaceIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        directory = Path(self.enterContext(TemporaryDirectory()))
        self.enterContext(patch.dict(os.environ, {"GARDEN_DB": str(directory / "garden.sqlite"),
                                                 "GARDEN_SMTP_HOST": "", "GARDEN_PUBLIC_ORIGIN": "",
                                                 "GARDEN_WEBHOOK_URL": "http://test.invalid/hook"}))
        await self.enterAsyncContext(lifespan(app))
        self.owner, self.editor, self.other = [
            await self.enterAsyncContext(httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="https://garden.test"))
            for _ in range(3)]
        for name, client in (("owner", self.owner), ("editor", self.editor), ("other", self.other)):
            result = await client.post("/api/auth/register", json={"name": name, "email": name+"@example.org",
                                                                   "password": "workspace-tests-only"})
            self.assertEqual(result.status_code, 201, result.text)

    async def shared(self, graph):
        resp = await self.owner.post("/api/projects", json={"name": graph.name, "workflow": graph.model_dump()})
        self.assertEqual(resp.status_code, 201, resp.text)
        project = resp.json()
        path = "/api/projects/" + project["id"]
        invite = (await self.owner.post(path + "/members", json={"email": "editor@example.org"})).json()
        accepted = await self.editor.post("/api/project-invitations/accept", json={"token": invite["token"]})
        self.assertEqual(accepted.status_code, 200, accepted.text)
        return project, path, invite["id"]

    async def test_public_installation_keeps_the_local_workspace_private_behind_a_proxy(self):
        with patch.dict(os.environ, {"GARDEN_PUBLIC_ORIGIN": "https://garden.test"}):
            for route in ("workflow", "runs", "templates", "ci/history"):
                response = await self.owner.get("/api/" + route, headers={"host": "localhost"})
                self.assertEqual(response.status_code, 403, route)
            projects = await self.owner.get("/api/projects")
            self.assertEqual(projects.status_code, 200)
            self.assertIn("no-store", projects.headers["cache-control"])
            self.assertIn("Cookie", projects.headers["vary"])
            graph = demo()
            project, path, _ = await self.shared(graph)
            denied = await self.editor.put(path, headers={"origin": "https://other.test"},
                json={"base_revision": project["revision"], "workflow": graph.model_dump()})
            self.assertEqual(denied.status_code, 403)

    async def test_catalog_preserves_private_files_and_template_copies_are_independent(self):
        official = (await self.other.get("/api/catalog")).json()
        self.assertEqual(len(official), 3)
        self.assertTrue(all(card["curated"] and card["description"] for card in official))
        graph = demo()
        graph.nodes.append(Node(id="timer", kind="schedule", enabled=True, cron="0 0 1 1 *", x=1, y=2))
        graph.edges.append(Edge(id="timer-scan", source="timer", target="scan"))
        project, path, _ = await self.shared(graph)
        payload = {"project_id": project["id"], "name": "Проверка сообщества", "description": "Поиск секретов"}
        self.assertEqual((await self.other.post("/api/catalog", json=payload)).status_code, 404)
        self.assertEqual((await self.editor.post("/api/catalog", json=payload)).status_code, 403)
        result = await self.owner.post("/api/catalog", json=payload)
        self.assertEqual(result.status_code, 201, result.text)
        card = result.json()
        listing = (await self.other.get("/api/catalog")).json()
        self.assertEqual([item for item in listing if not item["curated"]], [card])
        self.assertEqual((card["name"], card["author"], card["description"]), (payload["name"], "owner", payload["description"]))
        copied = await self.other.post("/api/catalog/"+card["id"]+"/projects")
        self.assertEqual(copied.status_code, 201, copied.text)
        copy_path = "/api/projects/"+copied.json()["id"]
        draft = (await self.other.get(copy_path)).json()
        self.assertEqual(draft["role"], "owner")
        self.assertEqual(draft["workflow"]["files"], [])
        self.assertFalse(next(n for n in draft["workflow"]["nodes"] if n["kind"] == "schedule")["enabled"])
        self.assertIsNone(app.state.scheduler.get_job(draft["id"]+"/timer"))
        self.assertEqual((await self.owner.get(copy_path)).status_code, 404)
        source = (await self.owner.get(path)).json()
        self.assertTrue(source["workflow"]["files"])
        self.assertTrue(next(n for n in source["workflow"]["nodes"] if n["kind"] == "schedule")["enabled"])
        self.assertIsNotNone(app.state.scheduler.get_job(source["id"]+"/timer"))

    async def test_project_runs_export_and_open_event_stream_stop_after_revoke(self):
        arrived, release = asyncio.Event(), asyncio.Event()
        async def hold_delivery(request):
            arrived.set()
            await release.wait()
            return httpx.Response(200)
        gateway = await self.enterAsyncContext(httpx.AsyncClient(transport=httpx.MockTransport(hold_delivery)))
        self.enterContext(patch.object(app.state.engine.gateway, "client", gateway))
        graph = demo()
        graph.nodes.append(Node(id="hook", kind="webhook", x=400, y=0))
        graph.edges.append(Edge(id="scan-hook", source="scan", target="hook"))
        project, path, member_id = await self.shared(graph)
        try:
            run_body = {"revision": project["revision"], "trigger": "start"}
            self.assertEqual((await self.other.post(path+"/runs", json=run_body)).status_code, 404)
            start = await self.editor.post(path+"/runs", json=run_body)
            self.assertEqual(start.status_code, 202, start.text)
            key = start.json()["id"]
            run_path = "/api/runs/"+key
            await asyncio.wait_for(arrived.wait(), 3)
            stream = asyncio.create_task(self.editor.get(run_path+"/events"))
            for _ in range(100):
                if app.state.engine.listeners.get(key):
                    break
                await asyncio.sleep(.01)
            self.assertTrue(app.state.engine.listeners.get(key))
            self.assertEqual((await self.editor.get(run_path)).status_code, 200)
            self.assertEqual((await self.editor.get(path+"/runs")).json()[0]["id"], key)
            self.assertEqual((await self.owner.delete(path+"/members/"+member_id)).status_code, 204)
        finally:
            release.set()
            await asyncio.gather(*app.state.engine.tasks)

        result = await asyncio.wait_for(stream, 2)
        self.assertEqual(result.status_code, 200)
        events = [json.loads(line[6:]) for line in result.text.splitlines() if line.startswith("data: ")]
        self.assertTrue(events)
        self.assertTrue(all(event["status"] == "running" for event in events))
        for client in (self.other, self.editor):
            for endpoint in ("", "/events", "/submission", "/submission?format=html", "/steps/hook/delivery", "/receipts"):
                with self.subTest(endpoint=endpoint):
                    self.assertEqual((await client.get(run_path+endpoint)).status_code, 404)
            self.assertEqual((await client.get(path+"/runs")).status_code, 404)
        for endpoint in ("", "/submission", "/submission?format=html", "/steps/hook/delivery", "/receipts"):
            self.assertEqual((await self.owner.get(run_path+endpoint)).status_code, 200)
        self.assertEqual((await self.owner.get(run_path)).json()["status"], "succeeded")
