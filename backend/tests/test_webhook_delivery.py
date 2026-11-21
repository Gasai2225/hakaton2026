import asyncio
import json
import os
import smtplib
import socket
import tempfile
import unittest
from email import policy
from email.parser import BytesParser
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from threading import Thread
from unittest.mock import patch

import httpx

from garden.api import app, lifespan
from garden.email_report import build_report_email
from garden.integrations import public_smtp_socket
from garden.models import Edge, Finding, Node, Receipt, Report, Workflow, demo
from garden.scanners import Analysis
from garden.scenarios import Plan, blueprint


class ReportEmailTests(unittest.TestCase):
    def test_email_prioritizes_important_findings_and_full_attachment_keeps_the_rest(self):
        base = Finding(id="low", category="SECRET", rule="SECRET-LITERAL", severity="low", path="src/<файл>.kt",
                       line=4, column=8, title="Обычная находка", fix="Перенесите значение в настройки.")
        findings = [base.model_copy(update={"id": f"low-{index}", "title": f"Обычная находка {index}"})
                    for index in range(1, 10)]
        findings.append(base.model_copy(update={"id": "critical", "severity": "critical", "title": "Критичная <находка>"}))
        report = Report(groups=[{"finding_ids": ["critical"], "risk": "Есть <риск>.", "fix": "Вынесите настройку."}])
        receipt = Receipt(run_id="test", findings=findings, reports=[report], analysis_status="partial")
        message = build_report_email(receipt, "alerts@example.org", "Проверка <projects>")
        parsed = BytesParser(policy=policy.default).parsebytes(message.as_bytes(policy=policy.SMTP))

        plain = parsed.get_body(("plain",)).get_content()
        html = parsed.get_body(("html",)).get_content()
        self.assertIn("Проверка неполная", plain)
        self.assertIn("МСК", plain)
        self.assertIn("1. Критичная <находка>", plain)
        self.assertIn("В письме показано 8 из 10 находок", html)
        self.assertIn("Проверка &lt;projects&gt;", html)
        self.assertIn("src/&lt;файл&gt;.kt:4:8", html)
        self.assertNotIn("Обычная находка 9", html)
        self.assertNotIn("<находка>", html)

        attachments = {part.get_filename(): part for part in parsed.iter_attachments()}
        full = attachments["garden-report.html"].get_content()
        self.assertIn("Обычная находка 9", full)
        self.assertIn("Находки № 1", full)
        self.assertIn("Есть &lt;риск&gt;.", full)
        raw = attachments["garden-report.json"].get_payload(decode=True)
        self.assertIn(b'\n  "run_id"', raw)
        self.assertEqual(json.loads(raw), receipt.model_dump())


class PersonalSMTPTransportTests(unittest.TestCase):
    def test_personal_smtp_rejects_local_resolution_before_connecting(self):
        local = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 587))]
        with (patch("garden.integrations.socket.getaddrinfo", return_value=local),
              patch("garden.integrations.socket.create_connection") as connect):
            with self.assertRaisesRegex(ValueError, "общедоступный IP"):
                public_smtp_socket("smtp.example.org", 587, 8)
        connect.assert_not_called()


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

    async def test_formatted_outgoing_body_is_available_during_dispatch_and_after_restart(self):
        temp = self.enterContext(tempfile.TemporaryDirectory())
        self.enterContext(patch.dict(os.environ, {"GARDEN_DB": str(Path(temp) / "runs.sqlite"),
                                                   "GARDEN_WEBHOOK_URL": "http://test/receive"}))
        entered, release = asyncio.Event(), asyncio.Event()
        requests = []
        async def receiver(request):
            requests.append(request)
            entered.set()
            await release.wait()
            return httpx.Response(204)

        api = await self.enterAsyncContext(httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://localhost"))
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
                    request = requests[0]
                    self.assertEqual(request.headers["Content-Type"], "application/json")
                    self.assertEqual(request.headers["Idempotency-Key"], f"{key}/send")
                    self.assertIn(b'\n  "run_id": ', request.content)
                    payload = json.loads(request.content)
                    self.assertEqual((await api.get(path)).json(), {"state": "attempted", "payload": payload})
                    body, = app.state.store.db.execute("SELECT body FROM outgoing_webhooks WHERE run_id=? AND node_id='send'",
                                                       (key,)).fetchone()
                    self.assertEqual(body, request.content)
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
                                                             base_url="http://localhost"))
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


class NotificationDeliveryTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.enterContext(patch.dict(os.environ, {"GARDEN_DB": ":memory:"}))
        await self.enterAsyncContext(lifespan(app))
        self.api = await self.enterAsyncContext(httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://localhost"))

    async def run_delivery(self, destination):
        graph = Workflow(name="Notification", files=[], nodes=[
            Node(id="start", kind="manual", x=0, y=0),
            Node(id="notify", kind="webhook", x=0, y=0, destination=destination),
        ], edges=[Edge(id="notify-edge", source="start", target="notify")])
        result = await self.api.post("/api/runs", json={"trigger": "start", "workflow": graph.model_dump()})
        self.assertEqual(result.status_code, 202, result.text)
        run_id = result.json()["id"]
        await asyncio.gather(*app.state.engine.tasks)
        run = (await self.api.get(f"/api/runs/{run_id}")).raise_for_status().json()
        delivery = (await self.api.get(f"/api/runs/{run_id}/steps/notify/delivery")).raise_for_status().json()
        return run, delivery

    async def test_local_browser_report_is_available_without_any_source_files(self):
        run, delivery = await self.run_delivery("browser")
        self.assertEqual(delivery["state"], "delivered")
        feed = await self.api.get("/api/browser-reports/next?local=1")
        notice = feed.raise_for_status().json()
        self.assertIsNone(notice["project_id"])
        self.assertEqual(notice["run_id"], run["id"])
        report = (await self.api.get(f"/api/runs/{run['id']}/steps/notify/report")).raise_for_status().json()
        self.assertEqual(report["payload"]["analysis_status"], "not_run")
        self.assertTrue(report["created_at"])

    async def test_legacy_https_node_creates_browser_report_without_sending_to_an_address(self):
        self.enterContext(patch.dict(os.environ, {"GARDEN_WEBHOOK_URL": "https://example.org/unused"}))
        external = self.enterContext(patch("garden.runner.prepare_notification", side_effect=AssertionError))
        run, delivery = await self.run_delivery("https")
        self.assertTrue(delivery["browser_report"])
        notice = (await self.api.get("/api/browser-reports/next?local=1")).raise_for_status().json()
        self.assertEqual(notice["run_id"], run["id"])
        external.assert_not_called()

    async def test_telegram_requires_confirmation_and_keeps_token_out_of_history(self):
        self.enterContext(patch.dict(os.environ, {"GARDEN_TELEGRAM_BOT_TOKEN": "123:test-token",
                                                  "GARDEN_TELEGRAM_CHAT_ID": "-100123"}))
        for status, ok, state in ((200, True, "delivered"), (200, False, "attempted"), (403, False, "attempted")):
            with self.subTest(status=status, ok=ok), patch("garden.integrations.HTTPSConnection") as https:
                connection = https.return_value
                response = connection.getresponse.return_value.__enter__.return_value
                response.status = status
                response.read.return_value = json.dumps({"ok": ok, "description": "123:test-token"}).encode()
                run, delivery = await self.run_delivery("telegram")
                https.assert_called_once_with("api.telegram.org", timeout=10)
                method, path, body, headers = connection.request.call_args.args
                self.assertEqual((method, path), ("POST", "/bot123:test-token/sendMessage"))
                self.assertEqual(headers["Content-Type"], "application/json")
                data = json.loads(body)
                self.assertEqual(data["chat_id"], -100123)
                self.assertIn(run["id"], data["text"])
                self.assertIn("Находок: 0", data["text"])
                self.assertEqual(delivery["state"], state)
                self.assertEqual(run["status"], "succeeded" if ok else "failed")
                self.assertEqual(delivery["payload"]["run_id"], run["id"])
                self.assertNotIn("123:test-token", json.dumps([run, delivery]))

    async def test_email_sends_readable_report_and_reports_recipient_refusal(self):
        self.enterContext(patch.dict(os.environ, {"GARDEN_SMTP_HOST": "smtp.example.org",
                                                  "GARDEN_SMTP_FROM": "garden@example.org", "GARDEN_SMTP_PORT": "587",
                                                  "GARDEN_SMTP_MODE": "starttls", "GARDEN_EMAIL_TO": "alerts@example.org",
                                                  "GARDEN_SMTP_USER": "user", "GARDEN_SMTP_PASSWORD": "test-password"}))
        for refused in (False, True):
            with self.subTest(refused=refused), patch("garden.integrations.smtplib.SMTP") as smtp:
                connection = smtp.return_value
                if refused:
                    connection.send_message.side_effect = smtplib.SMTPRecipientsRefused({
                        "alerts@example.org": (550, b"test-password"),
                    })
                run, delivery = await self.run_delivery("email")
                smtp.assert_called_once_with("smtp.example.org", 587, timeout=8)
                self.assertEqual([call[0] for call in connection.method_calls], ["starttls", "login", "send_message"])
                connection.login.assert_called_once_with("user", "test-password")
                message, = connection.send_message.call_args.args
                self.assertEqual(message["From"], "garden@example.org")
                self.assertEqual(message["To"], "alerts@example.org")
                attachments = {part.get_filename(): part for part in message.iter_attachments()}
                self.assertIn("Анализ исходников не запускался", message.get_body(("html",)).get_content())
                self.assertIn("Notification", attachments["garden-report.html"].get_content())
                attachment = attachments["garden-report.json"]
                self.assertEqual(attachment.get_content_type(), "application/json")
                self.assertEqual(json.loads(attachment.get_payload(decode=True)), delivery["payload"])
                self.assertEqual(delivery["state"], "attempted" if refused else "delivered")
                self.assertEqual(run["status"], "failed" if refused else "succeeded")
                self.assertNotIn("test-password", json.dumps([run, delivery]))

    async def test_missing_channel_settings_fail_before_dispatch(self):
        for destination, setting in (("telegram", "GARDEN_TELEGRAM_BOT_TOKEN"), ("email", "GARDEN_EMAIL_TO"),
                                     ("configured", "GARDEN_WEBHOOK_URL")):
            with self.subTest(destination=destination), patch.dict(os.environ, {setting: ""}):
                run, delivery = await self.run_delivery(destination)
                self.assertEqual(run["status"], "failed")
                self.assertIn(setting, run["steps"][-1]["message"])
                self.assertEqual(delivery, {"state": "not_sent", "payload": None})
