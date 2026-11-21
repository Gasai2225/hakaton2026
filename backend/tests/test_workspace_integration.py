import asyncio
import json
import os
import unittest
from datetime import UTC, datetime
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

import httpx
from cryptography.fernet import Fernet

from garden.api import app, lifespan
from garden.models import Edge, Node, demo


NOTIFICATIONS = "/api/auth/notifications"


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

    async def deliver(self, path, revision, client):
        result = await client.post(path + "/runs", json={"revision": revision, "trigger": "start"})
        self.assertEqual(result.status_code, 202, result.text)
        run_id = result.json()["id"]
        await asyncio.gather(*app.state.engine.tasks)
        return (await client.get(f"/api/runs/{run_id}/steps/hook/delivery")).raise_for_status().json()

    async def test_garden_sender_delivers_to_address_chosen_by_owner_without_a_code(self):
        graph = demo()
        graph.nodes.append(Node(id="hook", kind="webhook", destination="email", x=400, y=0))
        graph.edges.append(Edge(id="scan-hook", source="scan", target="hook"))
        project, path, _ = await self.shared(graph)
        self.enterContext(patch.dict(os.environ, {"GARDEN_SMTP_HOST": "smtp.example.org", "GARDEN_SMTP_USER": "",
                                                  "GARDEN_SMTP_FROM": "garden@example.org", "GARDEN_SMTP_MODE": "starttls",
                                                  "GARDEN_EMAIL_TO": "global@example.org"}))
        smtp = self.enterContext(patch("garden.integrations.smtplib.SMTP"))
        mail = smtp.return_value.send_message
        self.assertEqual((await self.deliver(path, project["revision"], self.editor))["state"], "not_sent")
        mail.assert_not_called()

        saved = await self.owner.put(NOTIFICATIONS + "/email", json={
            "mode": "garden", "recipient": "chosen@example.org",
        })
        self.assertEqual(saved.raise_for_status().json()["email_recipient"], "chosen@example.org")
        self.assertIsNone((await self.editor.get(NOTIFICATIONS)).json()["email_recipient"])
        mail.assert_not_called()

        delivered = await self.deliver(path, project["revision"], self.editor)
        self.assertEqual(delivered["state"], "delivered")
        report, = mail.call_args.args
        self.assertEqual(report["To"], "chosen@example.org")
        self.assertEqual(report["From"], "garden@example.org")
        attachments = {part.get_filename(): part for part in report.iter_attachments()}
        self.assertIn(graph.name, report.get_body(("plain",)).get_content())
        self.assertEqual(attachments["garden-report.html"].get_content_type(), "text/html")
        attachment = attachments["garden-report.json"]
        self.assertEqual(json.loads(attachment.get_payload(decode=True)), delivered["payload"])
        disconnected = await self.owner.delete(NOTIFICATIONS + "/email")
        self.assertIsNone(disconnected.raise_for_status().json()["email_recipient"])

    async def test_personal_smtp_password_is_encrypted_and_used_only_for_the_owner(self):
        graph = demo()
        graph.nodes.append(Node(id="hook", kind="webhook", destination="email", x=400, y=0))
        graph.edges.append(Edge(id="scan-hook", source="scan", target="hook"))
        project, path, _ = await self.shared(graph)
        key = Fernet.generate_key()
        self.enterContext(patch.dict(os.environ, {"GARDEN_SMTP_CREDENTIAL_KEY": key.decode()}))
        smtp = self.enterContext(patch("garden.integrations.PublicSMTP"))
        personal = {"mode": "personal", "recipient": "report@example.org", "sender": "sender@example.org",
                    "host": "smtp.example.org", "security": "starttls", "password": "example-app-password"}
        saved = await self.owner.put(NOTIFICATIONS + "/email", json=personal)
        self.assertEqual(saved.raise_for_status().json()["email_mode"], "personal")
        self.assertNotIn("example-app-password", saved.text)
        encrypted, = app.state.store.db.execute("SELECT encrypted_password FROM account_email_notifications").fetchone()
        self.assertNotIn(b"example-app-password", encrypted)
        self.assertEqual(Fernet(key).decrypt(encrypted), b"example-app-password")

        personal.pop("password")
        personal["recipient"] = "updated@example.org"
        self.assertEqual((await self.owner.put(NOTIFICATIONS + "/email", json=personal)).status_code, 200)
        self.assertEqual((await self.editor.put(NOTIFICATIONS + "/email", json=personal)).status_code, 422)
        delivery = await self.deliver(path, project["revision"], self.editor)
        self.assertEqual(delivery["state"], "delivered")
        smtp.assert_called_once_with("smtp.example.org", 587, timeout=8)
        connection = smtp.return_value
        self.assertEqual([call[0] for call in connection.method_calls], ["starttls", "login", "send_message"])
        connection.login.assert_called_once_with("sender@example.org", "example-app-password")
        report, = connection.send_message.call_args.args
        self.assertEqual((report["From"], report["To"]), ("sender@example.org", "updated@example.org"))

    async def test_browser_notice_opens_a_timestamped_report_with_project_access(self):
        graph = demo()
        graph.nodes.append(Node(id="hook", kind="webhook", destination="browser", x=400, y=0))
        graph.edges.append(Edge(id="scan-hook", source="scan", target="hook"))
        project, path, _ = await self.shared(graph)
        delivery = await self.deliver(path, project["revision"], self.editor)
        self.assertEqual(delivery["state"], "delivered")
        self.assertTrue(delivery["browser_report"])
        feed = "/api/browser-reports/next"
        notice = (await self.owner.get(feed)).raise_for_status().json()
        self.assertEqual(notice["project_id"], project["id"])
        self.assertEqual(notice["run_id"], delivery["payload"]["run_id"])
        self.assertIsNone((await self.editor.get(feed)).raise_for_status().json())
        self.assertIsNone((await self.other.get(feed)).raise_for_status().json())

        run_url = f"/api/runs/{notice['run_id']}"
        report_url = run_url + "/steps/hook/report"
        report = (await self.editor.get(report_url)).raise_for_status().json()
        self.assertEqual(report["payload"], delivery["payload"])
        started = (await self.owner.get(run_url)).raise_for_status().json()["started"]
        self.assertLessEqual(datetime.fromisoformat(started), datetime.fromisoformat(report["created_at"]))
        self.assertLessEqual(datetime.fromisoformat(report["created_at"]), datetime.now(UTC))
        self.assertEqual((await self.other.get(report_url)).status_code, 404)
        raw_url = report_url + ".json"
        raw = (await self.editor.get(raw_url)).raise_for_status()
        self.assertEqual(raw.headers["content-type"], "application/json")
        self.assertTrue(raw.text.startswith('{\n  "created_at": '))
        self.assertEqual(raw.json(), {"created_at": report["created_at"], **delivery["payload"]})
        self.assertEqual((await self.other.get(raw_url)).status_code, 404)
        dismiss = f"/api/browser-reports/{notice['run_id']}/hook/dismiss"
        self.assertEqual((await self.editor.post(dismiss)).status_code, 404)
        self.assertEqual((await self.owner.post(dismiss)).status_code, 204)
        self.assertIsNone((await self.owner.get(feed)).raise_for_status().json())
        self.assertEqual((await self.owner.get(report_url)).raise_for_status().json(), report)
        self.assertEqual((await self.owner.get(raw_url)).raise_for_status().json(), raw.json())

    async def test_telegram_link_is_private_one_time_and_uses_shared_bot(self):
        secret = "fixture-tg-webhook-secret-value-123456"
        self.enterContext(patch.dict(os.environ, {"GARDEN_TELEGRAM_BOT_TOKEN": "123:fixture",
                                                  "GARDEN_TELEGRAM_BOT_USERNAME": "garden_fixture_bot",
                                                  "GARDEN_TELEGRAM_WEBHOOK_SECRET": secret,
                                                  "GARDEN_TELEGRAM_CHAT_ID": "42"}))
        graph = demo()
        graph.nodes.append(Node(id="hook", kind="webhook", destination="telegram", x=400, y=0))
        graph.edges.append(Edge(id="scan-hook", source="scan", target="hook"))
        project, path, _ = await self.shared(graph)
        post = self.enterContext(patch("garden.integrations.post_telegram"))
        self.assertEqual((await self.deliver(path, project["revision"], self.editor))["state"], "not_sent")
        post.assert_not_called()

        link = (await self.owner.post(NOTIFICATIONS + "/telegram/link")).raise_for_status().json()["url"]
        url = urlsplit(link)
        self.assertEqual((url.hostname, url.path), ("t.me", "/garden_fixture_bot"))
        code, = parse_qs(url.query)["start"]
        callback = "/api/notifications/telegram/callback"
        update = {"message": {"chat": {"id": 1234567, "type": "private"}, "text": "/start " + code}}
        self.assertEqual((await self.other.post(callback, json=update)).status_code, 403)
        headers = {"X-Telegram-Bot-Api-Secret-Token": secret}
        self.assertEqual((await self.other.post(callback, headers=headers, json=update)).status_code, 204)
        update["message"]["chat"]["id"] = 7654321
        self.assertEqual((await self.other.post(callback, headers=headers, json=update)).status_code, 204)
        self.assertTrue((await self.owner.get(NOTIFICATIONS)).json()["telegram_linked"])
        self.assertFalse((await self.editor.get(NOTIFICATIONS)).json()["telegram_linked"])

        self.assertEqual((await self.deliver(path, project["revision"], self.editor))["state"], "delivered")
        token, body = post.call_args.args
        self.assertEqual(token, "123:fixture")
        self.assertEqual(json.loads(body)["chat_id"], 1234567)

    async def test_legacy_project_delivery_uses_browser_for_manual_and_scheduled_runs(self):
        graph = demo()
        graph.nodes.extend([Node(id="timer", kind="schedule", enabled=True, cron="0 0 1 1 *", x=0, y=100),
                            Node(id="hook", kind="webhook", x=400, y=0)])
        graph.edges.extend([Edge(id="timer-scan", source="timer", target="scan"),
                            Edge(id="scan-hook", source="scan", target="hook")])
        project, path, _ = await self.shared(graph)
        address = "https://owner.example.org/unused"
        owner = (await self.owner.get("/api/auth/me")).raise_for_status().json()
        db = app.state.store.db
        with db:
            db.execute("ALTER TABLE account_notifications ADD COLUMN webhook_url TEXT")
            db.execute("INSERT INTO account_notifications(account_id,webhook_url) VALUES (?,?)", (owner["id"], address))
        self.assertNotIn("webhook_configured", (await self.owner.get(NOTIFICATIONS)).raise_for_status().json())
        removed = await self.owner.put(NOTIFICATIONS + "/webhook", json={"url": address})
        self.assertIn(removed.status_code, (404, 405))
        external = self.enterContext(patch("garden.runner.prepare_notification", side_effect=AssertionError))

        delivery = await self.deliver(path, project["revision"], self.editor)
        self.assertTrue(delivery["browser_report"])
        first = delivery["payload"]["run_id"]
        dismissed = await self.owner.post(f"/api/browser-reports/{first}/hook/dismiss")
        self.assertEqual(dismissed.status_code, 204)
        job = app.state.scheduler.get_job(project["id"] + "/timer")
        await job.func(*job.args)
        await asyncio.gather(*app.state.engine.tasks)
        notice = (await self.owner.get("/api/browser-reports/next")).raise_for_status().json()
        self.assertEqual(notice["project_id"], project["id"])
        self.assertNotEqual(notice["run_id"], first)
        external.assert_not_called()

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
        graph.nodes.append(Node(id="hook", kind="webhook", destination="inbox", x=400, y=0))
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
