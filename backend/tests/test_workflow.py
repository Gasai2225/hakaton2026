import asyncio
import json
import os
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

import httpx
from pydantic import ValidationError

from garden.api import app, lifespan
from garden.integrations import Connection, Gateway, validate_report
from garden.models import Edge, Node, Report, Source, Target, Workflow, demo
from garden.osv_client import OsvResult
from garden.scanners import analyze, scan


class ScannerTests(unittest.TestCase):
    def test_secret_and_clean_controls(self):
        text = '''package training
// val token = "ignore"
/* val password = "ignored" */
val привет = "val apiKey = ignored"
val accessToken: String = "synthetic-value"
val password = System.getenv("PASSWORD")
'''
        hits, count = scan("secrets", [Source(path="Code.kt", text=text)], "*")
        self.assertEqual((count, len(hits), hits[0].line, hits[0].column), (1, 1, 5, 5))
        self.assertNotIn("synthetic-value", hits[0].model_dump_json())

    def test_config(self):
        text = '# password=ignored\nspring.datasource.password=demo\napi-key: \x24{API_KEY}\n'
        hits, _ = scan("secrets", [Source(path="application.properties", text=text)], "*")
        self.assertEqual([(f.rule, f.line) for f in hits], [("SECRET-LITERAL", 2)])

    def test_sast(self):
        text = '''import org.springframework.security.config.annotation.web.builders.HttpSecurity
fun configure(http: HttpSecurity) {
    http.authorizeHttpRequests { it.anyRequest().permitAll() }
}
'''
        source = Source(path="Security.kt", text=text)
        hits, _ = scan("sast", [source], "*")
        self.assertEqual([(f.rule, f.line) for f in hits], [("SPRING-OPEN-DEFAULT", 3)])
        for clean in [text.replace("permitAll", "authenticated"), text.replace("anyRequest()", 'requestMatchers("/public")')]:
            self.assertEqual(scan("sast", [Source(path=source.path, text=clean)], "*")[0], [])

    @patch.dict(os.environ, {"GARDEN_EXTENDED_SCA": "1"})
    def test_sca_range(self):
        for value, expected in [("0.9", 0), ("1.0", 1), ("1.1.10", 1), ("1.2.0", 0), ("1.10", 0)]:
            file = Source(path="build.gradle.kts", text='dependencies { implementation("training.demo:example-lib:' + value + '") }')
            with self.subTest(value=value):
                hits, _ = scan("sca", [file], "*")
                self.assertEqual(len(hits), expected)

    def test_graph_validator(self):
        graph = demo()
        graph.edges.append(Edge(id="cycle", source="scan", target="scan"))
        with self.assertRaises(ValidationError):
            Workflow.model_validate(graph.model_dump())

    @patch.dict(os.environ, {"GARDEN_EXTENDED_SCA": "1"})
    def test_gradle_variables_and_unknown_version(self):
        code = 'dependencies { implementation("training.demo:example-lib:$demoVersion") }'
        gradle = Source(path="build.gradle.kts", text=code)
        props = Source(path="gradle.properties", text="demoVersion=1.1")
        self.assertEqual(scan("sca", [gradle, props], "*")[0][0].advisory, "DEMO-001")
        gradle.text = 'val demoVersion = "1.2"\n' + code
        self.assertEqual(scan("sca", [gradle, props], "*")[0], [])
        gradle.text = code.replace("$demoVersion", "1.+")
        with self.assertRaisesRegex(ValueError, "версию"):
            scan("sca", [gradle], "*")

    def test_kotlin_security_dsl(self):
        source = Source(path="Access.kt", text="import org.springframework.security.config.annotation.web.builders.HttpSecurity\n"
                        'fun configure() { authorize(anyRequest, permitAll) }')
        self.assertEqual(scan("sast", [source], "*")[0], [])
        source.text = ("import org.springframework.security.config.annotation.web.builders.HttpSecurity\n"
                       "import org.springframework.security.config.annotation.web.invoke\n"
                       "fun configure(http: HttpSecurity) = http { authorizeHttpRequests { authorize(anyRequest, permitAll) } }")
        self.assertEqual(scan("sast", [source], "*")[0][0].line, 3)
        source.text = source.text.replace("anyRequest", '"/public"')
        self.assertEqual(scan("sast", [source], "*")[0], [])


class ApiTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        env = patch.dict(os.environ, {"GARDEN_DB": str(Path(temp.name) / "test.sqlite")})
        env.start()
        self.addCleanup(env.stop)
        await self.enterAsyncContext(lifespan(app))
        self.api = await self.enterAsyncContext(httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                                                  base_url="http://local"))

    async def execute(self, graph):
        response = await self.api.post("/api/runs", json={"workflow": graph.model_dump(), "trigger": "start"})
        self.assertEqual(response.status_code, 202, response.text)
        await asyncio.gather(*app.state.engine.tasks)
        return (await self.api.get("/api/runs/" + response.json()["id"])).json()

    async def test_sca_profiles_on_independent_branches(self):
        graph = Workflow(name="Gradle", files=[Source(path="build.gradle.kts", text=(
            'dependencies { implementation("org.springframework.boot:spring-boot-starter-web:2.6.5") }'
        ))], nodes=[Node(id="start", kind="manual", x=0, y=0),
                    Node(id="contest", kind="sca", x=1, y=0, extended_sca=False),
                    Node(id="extended", kind="sca", x=1, y=1)],
            edges=[Edge(id="a", source="start", target="contest"), Edge(id="b", source="start", target="extended")])
        coord = ("org.springframework.boot:spring-boot-starter-web", "2.6.5")
        with patch("garden.osv_client.check_maven", return_value={coord: OsvResult()}) as lookup:
            result = await self.execute(graph)
        lookup.assert_called_once_with([coord])
        steps = {step["node_id"]: step for step in result["steps"]}
        self.assertEqual([row["status"] for row in steps["contest"]["packages"]], ["outside-catalog"])
        self.assertEqual([row["status"] for row in steps["extended"]["packages"]], ["checked"])
        self.assertIsNone(steps["contest"]["packages"][0]["osv_status"])
        self.assertEqual(steps["extended"]["packages"][0]["osv_status"], "checked")
        self.assertEqual(steps["contest"]["output_ids"], [])
        self.assertEqual(len(steps["extended"]["output_ids"]), 1)
        self.assertEqual([hit["advisory"] for hit in result["findings"]], ["CVE-2022-22965"])

    async def test_live_run_and_fix(self):
        graph = demo()
        result = await self.execute(graph)
        self.assertEqual(result["status"], "succeeded")
        self.assertEqual([(f["line"], f["column"]) for f in result["findings"]], [(4, 9)])
        stream = await self.api.get("/api/runs/" + result["id"] + "/events")
        self.assertIn('"SECRET-LITERAL"', stream.text)
        self.assertNotIn("garden-demo-value", stream.text)
        graph.files[0].text = graph.files[0].text.replace('"garden-demo-value"', 'System.getenv("KEY")')
        self.assertEqual((await self.execute(graph))["findings"], [])
        self.assertEqual(len((await self.api.get("/api/runs")).json()), 2)

    async def test_run_uses_draft_until_explicit_save(self):
        graph = demo()
        graph.nodes[1].pattern = "*.xml"
        saved = await self.api.put("/api/workflow", json=graph.model_dump())
        self.assertEqual(saved.status_code, 200)
        self.assertEqual((await self.execute(graph))["findings"], [])

        graph.nodes[1].pattern = "*.kt"
        for _ in range(2):
            result = await self.execute(graph)
            self.assertEqual([f["path"] for f in result["findings"]], [graph.files[0].path])
            self.assertEqual((await self.api.get("/api/workflow")).json(), saved.json())

        response = await self.api.put("/api/workflow", json=graph.model_dump())
        self.assertEqual(response.status_code, 200)
        self.assertEqual((await self.api.get("/api/workflow")).json(), graph.model_dump())

    async def test_partial_run_exports_confirmed_findings(self):
        graph = demo()
        graph.files.append(Source(path="Broken.kt", text="fun ("))
        result = await self.execute(graph)
        step = result["steps"][-1]
        self.assertEqual((result["status"], step["status"]), ("warning", "warning"))
        self.assertIn("Broken.kt", step["message"])
        export = await self.api.get("/api/runs/" + result["id"] + "/submission")
        self.assertEqual([r["path"] for r in export.json()["findings"]], [graph.files[0].path])
        html = await self.api.get("/api/runs/" + result["id"] + "/submission", params={"format": "html"})
        self.assertEqual(html.status_code, 200)
        self.assertIn("Проверка неполная", html.text)
        self.assertIn(graph.files[0].path, html.text)
        self.assertNotIn("garden-demo-value", html.text)

    async def test_branch_fallback_and_delivery(self):
        graph = demo()
        for key in ["condition", "explain", "webhook", "sast"]:
            graph.nodes.append(Node(id=key, kind=key, x=0, y=0, extended_sca=False if key == "sca" else None))
        next(n for n in graph.nodes if n.kind == "explain").connection = "missing-profile"
        for src, dst, port in [("scan", "condition", None), ("condition", "explain", "yes"),
                               ("condition", "sast", "no"), ("explain", "webhook", None)]:
            graph.edges.append(Edge(id=src+dst, source=src, target=dst, branch=port))
        requests = []

        def receiver(request):
            requests.append(request)
            return httpx.Response(204)

        app.state.engine.gateway.client = await self.enterAsyncContext(httpx.AsyncClient(transport=httpx.MockTransport(receiver)))
        with patch.dict(os.environ, {"GARDEN_WEBHOOK_URL": "http://local/report"}):
            result = await self.execute(graph)
        self.assertEqual([s["status"] for s in result["steps"]], ["succeeded"] * 3 + ["warning", "succeeded", "skipped"])
        self.assertEqual(result["status"], "warning")
        self.assertEqual(len(requests), 1)
        self.assertNotIn(b"garden-demo-value", requests[0].content)
        self.assertIn(b"SECRET-LITERAL", requests[0].content)

    async def test_conditions_select_one_branch_and_reject_invalid_graphs(self):
        graph = demo()
        condition = Node(id="gate", kind="condition", x=0, y=0)
        graph.nodes.append(condition)
        graph.edges.append(Edge(id="to-gate", source="scan", target="gate"))
        for port in ("yes", "no"):
            graph.nodes.append(Node(id=port, kind="secrets", x=0, y=0))
            graph.edges.append(Edge(id=f"to-{port}", source="gate", target=port, branch=port))

        for predicate, yes_value, no_value in [("count_gte", "1", "2"), ("severity_eq", "medium", "critical"),
                                              ("rule_regex", r"^SECRET-.*$", r"^SCA-")]:
            for value, active, skipped in [(yes_value, "yes", "no"), (no_value, "no", "yes")]:
                with self.subTest(predicate=predicate, value=value):
                    condition.predicate, condition.value = predicate, value
                    result = await self.execute(graph)
                    steps = {step["node_id"]: step for step in result["steps"]}
                    self.assertEqual(result["status"], "succeeded")
                    self.assertEqual(steps["gate"]["branch"], active)
                    self.assertEqual(steps[active]["status"], "succeeded")
                    self.assertEqual((steps[skipped]["status"], steps[skipped]["message"]),
                                     ("skipped", "Ветка не выбрана"))

        condition.value = "["
        response = await self.api.put("/api/workflow", json=graph.model_dump())
        self.assertEqual(response.status_code, 422)
        self.assertIn("регулярное выражение", response.json()["detail"])
        condition.value = "SECRET"
        graph.edges.append(Edge(id="back", source="yes", target="scan"))
        response = await self.api.put("/api/workflow", json=graph.model_dump())
        self.assertEqual(response.status_code, 422)
        self.assertIn("цикл", response.json()["detail"])

    async def test_review_errors_keep_rule_advice_and_findings(self):
        graph = demo()
        graph.nodes.append(Node(id="ai", kind="explain", x=0, y=0))
        graph.edges.append(Edge(id="scan-ai", source="scan", target="ai"))
        expected = scan("secrets", graph.files, "*")[0][0].model_dump()

        for error in ("unknown-id", "unknown-path", "unknown-advisory", "timeout"):
            with self.subTest(error=error):
                def respond(request):
                    if error == "timeout":
                        raise httpx.ReadTimeout("test", request=request)
                    group = {"finding_ids": ["other" if error == "unknown-id" else "F1"],
                             "risk": "Значение доступно читателям проекта.", "fix": "Отзовите ключ."}
                    if error == "unknown-path":
                        group["fix"] += " См. invented.kt"
                    if error == "unknown-advisory":
                        group["fix"] += " См. CVE-2099-1234"
                    return httpx.Response(200, json={"message": {"content": json.dumps({"groups": [group]})}})

                async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as model:
                    with patch.object(app.state.engine.gateway, "client", model):
                        result = await self.execute(graph)
                step = result["steps"][-1]
                review, = step["reviews"]
                self.assertEqual((result["status"], step["status"], review["status"]), ("warning", "warning", "failed"))
                self.assertIsNone(step["report"])
                self.assertIn("рекомендации правил", step["message"])
                self.assertEqual(result["findings"], [expected])
                if error == "timeout":
                    self.assertEqual(review["message"], "Истекло время ожидания")

    async def test_llm_contract(self):
        hit = scan("secrets", demo().files, "*")[0][0]
        good = json.dumps({"groups": [{"finding_ids": [hit.id], "risk": "Ключ доступен читателям репозитория.", "fix": "Вынесите ключ в окружение"}]})
        for protocol in ["chat", "ollama", "anthropic", "gigachat"]:
            def response(request):
                if request.url.path == "/oauth":
                    return httpx.Response(200, json={"access_token": "demo", "expires_at": 9_000_000_000_000})
                self.assertNotIn(b"garden-demo-value", request.content)
                short = good.replace(hit.id, "F1")
                payloads = {"chat": {"choices": [{"message": {"content": short}}]}, "ollama": {"message": {"content": short}},
                            "anthropic": {"content": [{"type": "text", "text": short}]}}
                return httpx.Response(200, json=payloads.get(protocol, payloads["chat"]))

            client = await self.enterAsyncContext(httpx.AsyncClient(transport=httpx.MockTransport(response)))
            profile = Connection(id="p", label="test", model="training", protocol=protocol, url="http://local",
                                 oauth_url="http://local/oauth")
            report = await Gateway(client, [profile]).explain("p", "", [hit])
            self.assertEqual(report.groups[0].finding_ids, [hit.id])
        for invalid in [good.replace(hit.id, "other"), good.replace("fix", "wrong"),
                        good.replace('"risk": "', '"risk": "CVE-2099-9999 '),
                        good.replace('"risk": "', '"risk": "GHSA-abcd-2222-3333 '),
                        good.replace('"risk": "', '"risk": "На строках 82–91 ')]:
            with self.assertRaises(ValueError):
                validate_report(invalid, [hit])
        other = hit.model_copy(update={"id": "second", "path": "other.kt"})
        together = json.loads(good)
        together["groups"][0]["finding_ids"].append(other.id)
        raw = json.dumps(together)
        self.assertEqual(len(validate_report(raw, [hit, other]).groups), 1)
        for change in ({"classification": "secret-fallback"}, {"category": "SCA", "advisory": "CVE-2022-42889"}):
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, "разными причинами"):
                validate_report(raw, [hit, other.model_copy(update=change)])
        sca = hit.model_copy(update={"category": "SCA", "advisory": "CVE-2022-42889"})
        repeated = json.loads(good)
        advice = repeated["groups"][0]
        advice["risk"] = advice["fix"] + ". CVE-2022-42889"
        with self.assertRaisesRegex(ValueError, "повторила инструкцию"):
            validate_report(json.dumps(repeated), [sca])

    def test_sca_report_grounds_upgrade_in_scanner_facts(self):
        build = Source(path="build.gradle.kts", text='dependencies { implementation("org.apache.commons:commons-text:1.9") }')
        hit = scan("sca", [build], "*")[0][0]
        self.assertEqual(hit.fixed_version, "1.10.0")
        group = {"finding_ids": [hit.id], "risk": "Установленная версия затронута бюллетенем.", "fix": hit.fix}
        self.assertEqual(validate_report(json.dumps({"groups": [group]}), [hit]).groups[0].fix, hit.fix)
        for fix in ("Обновите до версии 99.2.", "Перейдите на версию 99.2.", "Обновите до 1.9.", "Проверьте org.example:other.",
                    "Перейдите на org.apache.commons:commons-text:99.2."):
            with self.subTest(fix=fix), self.assertRaises(ValueError):
                validate_report(json.dumps({"groups": [dict(group, fix=fix)]}), [hit])

    async def test_ungrounded_advice_gets_one_correction(self):
        hit = scan("secrets", demo().files, "*")[0][0]
        for correct in (True, False):
            with self.subTest(correct=correct):
                prompts = []
                def reply(request):
                    prompts.append(json.loads(request.content)["messages"])
                    fix = hit.fix if correct and len(prompts) == 2 else "Удалите значение из invented.kt"
                    group = {"finding_ids": ["F1"], "risk": "Ключ доступен читателям проекта.", "fix": fix}
                    return httpx.Response(200, json={"message": {"content": json.dumps({"groups": [group]})}})
                client = await self.enterAsyncContext(httpx.AsyncClient(transport=httpx.MockTransport(reply)))
                profile = Connection(id="p", label="test", model="fixture", protocol="ollama", url="http://local")
                attempt = Gateway(client, [profile]).explain("p", "", [hit])
                if correct:
                    self.assertEqual((await attempt).groups[0].finding_ids, [hit.id])
                else:
                    with self.assertRaisesRegex(ValueError, "позицию"):
                        await attempt
                self.assertEqual(len(prompts), 2)
                self.assertEqual(prompts[0][-1], prompts[1][-1])
                self.assertNotIn("invented.kt", str(prompts[1]))

    async def test_model_context_is_scoped_to_one_analyzer(self):
        hits = scan("secrets", demo().files, "*")[0] + scan("sca", [Source(path="build.gradle.kts",
                    text='dependencies { implementation("org.apache.commons:commons-text:1.9") }')], "*")[0]
        contexts = []
        def reply(request):
            prompt = json.loads(request.content)["messages"][-1]["content"]
            contexts.append([f["category"] for topic in json.loads(prompt) for f in topic])
            self.assertNotIn("garden-demo-value", prompt)
            self.assertNotIn("build.gradle.kts", prompt)
            advice = {"groups": [{"finding_ids": ["F1"], "risk": "Подтверждена проблема безопасности.",
                                  "fix": "Выполните рекомендацию соответствующего правила."}]}
            return httpx.Response(200, json={"message": {"content": json.dumps(advice)}})
        client = await self.enterAsyncContext(httpx.AsyncClient(transport=httpx.MockTransport(reply)))
        profile = Connection(id="p", label="test", model="fixture", protocol="ollama", url="http://local")
        report = await Gateway(client, [profile]).explain("p", "", hits)
        self.assertEqual(contexts, [["SECRET"], ["SCA"]])
        self.assertEqual([g.finding_ids for g in report.groups], [[f.id] for f in hits])

    async def test_detection_is_independent_of_model(self):
        graph = demo()
        graph.files.extend([
            Source(path="build.gradle.kts", text='dependencies { implementation("org.apache.commons:commons-text:1.9") }'),
            Source(path="Security.kt", text="import org.springframework.security.config.annotation.web.builders.HttpSecurity\n"
                   "fun configure(http: HttpSecurity) = http.authorizeHttpRequests { it.anyRequest().permitAll() }"),
        ])
        for key, previous in [("sca", "scan"), ("sast", "sca")]:
            graph.nodes.append(Node(id=key, kind=key, x=0, y=0))
            graph.edges.append(Edge(id=previous + key, source=previous, target=key))
        requests = []

        def fabricated_report(request):
            requests.append(request)
            raw = json.dumps({"groups": [{"finding_ids": ["EXTRA"], "severity": "critical",
                                          "risk": "CVE-2099-9999", "fix": "test"}]})
            return httpx.Response(200, json={"message": {"content": raw}})

        app.state.engine.gateway.client = await self.enterAsyncContext(httpx.AsyncClient(transport=httpx.MockTransport(fabricated_report)))
        baseline = await self.execute(graph)
        self.assertEqual(requests, [])
        self.assertEqual({f["rule"] for f in baseline["findings"]}, {"SECRET-LITERAL", "GRADLE-ADVISORY", "SPRING-OPEN-DEFAULT"})
        graph.nodes.append(Node(id="ai", kind="explain", x=0, y=0, model="training"))
        graph.edges.append(Edge(id="sast-ai", source="sast", target="ai"))
        with_ai = await self.execute(graph)
        self.assertEqual(len(requests), 1)
        self.assertNotIn(b"garden-demo-value", requests[0].content)
        self.assertEqual(with_ai["findings"], baseline["findings"])
        self.assertEqual(with_ai["steps"][-1]["status"], "warning")
        self.assertIsNone(with_ai["steps"][-1]["report"])

    async def test_schedule_and_real_http_receiver(self):
        graph = demo()
        graph.nodes[0] = Node(id="start", kind="schedule", x=0, y=0, enabled=True)
        graph.nodes.append(Node(id="notify", kind="webhook", x=500, y=0))
        graph.edges.append(Edge(id="deliver", source="scan", target="notify"))
        received = asyncio.get_running_loop().create_future()

        async def receive(reader, writer):
            headers = await reader.readuntil(b"\r\n\r\n")
            length = next(int(h.split(b":", 1)[1]) for h in headers.splitlines() if h.lower().startswith(b"content-length:"))
            body = await reader.readexactly(length)
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            await writer.drain()
            writer.close()
            await writer.wait_closed()
            received.set_result(json.loads(body))

        server = await self.enterAsyncContext(await asyncio.start_server(receive, "127.0.0.1", 0))
        port = server.sockets[0].getsockname()[1]
        with patch.dict(os.environ, {"GARDEN_WEBHOOK_URL": f"http://127.0.0.1:{port}/report"}):
            response = await self.api.put("/api/workflow", json=graph.model_dump())
            self.assertEqual(response.status_code, 200)
            app.state.scheduler.modify_job("start", next_run_time=datetime.now(UTC))
            payload = await asyncio.wait_for(received, timeout=5)
            await asyncio.gather(*app.state.engine.tasks)
        result = (await self.api.get("/api/runs/" + payload["run_id"])).json()
        self.assertEqual(result["trigger"], "start")
        self.assertEqual(result["status"], "succeeded")
        self.assertEqual(payload["findings"][0]["line"], 4)
        self.assertNotIn("garden-demo-value", json.dumps(payload))

    async def test_webhook_payload_uses_only_its_active_ai_sources_and_sent_finding_version(self):
        graph = demo()
        for key, kind in [("beta", "explain"), ("alpha", "explain"), ("independent", "explain"),
                          ("gate", "condition"), ("inactive", "explain"), ("single", "webhook"),
                          ("joined", "webhook"), ("later", "secrets")]:
            graph.nodes.append(Node(id=key, kind=kind, model=key, x=0, y=0))
        for src, dst, port in [("scan", "alpha", None), ("scan", "gate", None), ("gate", "beta", "yes"),
                               ("gate", "inactive", "no"), ("scan", "independent", None), ("alpha", "single", None),
                               ("single", "joined", None), ("alpha", "joined", None), ("beta", "joined", None),
                               ("inactive", "joined", None), ("joined", "later", None)]:
            graph.edges.append(Edge(id=f"{src}-{dst}", source=src, target=dst, branch=port))
        captured = {}
        def receiver(request):
            captured[request.headers["Idempotency-Key"].split("/")[1]] = json.loads(request.content)
            return httpx.Response(204)

        def advice(connection, model, findings):
            return Report(groups=[{"finding_ids": [f.id for f in findings], "risk": "Учебная рекомендация модели.",
                                   "fix": model}])

        original = analyze("secrets", graph.files, "*")
        enriched = analyze("secrets", graph.files, "*")
        enriched.findings[0].fix = "Уточнённая рекомендация следующего анализатора"
        gateway = app.state.engine.gateway
        async with httpx.AsyncClient(transport=httpx.MockTransport(receiver)) as sink:
            with (patch.dict(os.environ, {"GARDEN_WEBHOOK_URL": "http://local/receive"}),
                  patch.object(gateway, "client", sink), patch.object(gateway, "explain", side_effect=advice),
                  patch("garden.runner.analyze", side_effect=[original, enriched])):
                result = await self.execute(graph)
        self.assertEqual(result["status"], "succeeded")
        self.assertNotEqual(result["findings"], captured["joined"]["findings"])
        for key, models in [("single", ["alpha"]), ("joined", ["alpha", "beta"])]:
            response = await self.api.get(f"/api/runs/{result['id']}/steps/{key}/delivery")
            self.assertEqual(response.json(), {"state": "delivered", "payload": captured[key]})
            self.assertEqual([r["model"] for r in captured[key]["reviews"]], models)

    async def test_delivery_without_url_and_legacy_receipts(self):
        graph = demo()
        for key in ("first", "second"):
            graph.nodes.append(Node(id=key, kind="webhook", x=0, y=0))
            graph.edges.append(Edge(id=f"scan-{key}", source="scan", target=key))
        with patch.dict(os.environ, {"GARDEN_WEBHOOK_URL": ""}):
            result = await self.execute(graph)
        prefix = f"/api/runs/{result['id']}/steps"
        self.assertEqual((await self.api.get(prefix + "/first/delivery")).json(), {"state": "not_sent", "payload": None})
        self.assertEqual((await self.api.get(prefix + "/scan/delivery")).status_code, 404)

        for step in result["steps"]:
            step.pop("webhook_attempted", None)
            if step["kind"] == "webhook":
                step["status"] = "succeeded"
        result["status"] = "succeeded"
        payload = {"run_id": result["id"], "findings": result["findings"], "reports": [], "reviews": []}
        db = app.state.store.db
        with db:
            db.execute("UPDATE runs SET status=?, body=? WHERE id=?", ("succeeded", json.dumps(result), result["id"]))
            db.execute("INSERT INTO receipts(key, body) VALUES (?, ?)", (result["id"] + "/first", json.dumps(payload)))
        self.assertEqual((await self.api.get(prefix + "/first/delivery")).json(), {"state": "delivered", "payload": payload})
        self.assertEqual((await self.api.get(prefix + "/second/delivery")).json(), {"state": "delivered", "payload": None})
        result["steps"][-1]["status"] = "failed"
        with db:
            db.execute("UPDATE runs SET status='failed', body=? WHERE id=?", (json.dumps({**result, "status": "failed"}), result["id"]))
        self.assertEqual((await self.api.get(prefix + "/second/delivery")).json(), {"state": "unknown", "payload": None})

    async def test_parallel_reviews_and_partial_failure(self):
        graph = demo()
        graph.nodes.append(Node(id="ai", kind="explain", x=1, y=1,
                                targets=[Target(connection="ollama", model=m) for m in ["first", "second", "offline"]]))
        graph.edges.append(Edge(id="scan-ai", source="scan", target="ai"))
        graph.nodes.append(Node(id="send", kind="webhook", x=2, y=2))
        graph.edges.append(Edge(id="ai-send", source="ai", target="send"))
        entered, all_started, deliveries = [], asyncio.Event(), []

        async def endpoint(req):
            body = json.loads(req.content)
            if req.url.path == "/receive":
                deliveries.append(body)
                return httpx.Response(201)
            name = body["model"]
            entered.append(name)
            if len(entered) == 3:
                all_started.set()
            await asyncio.wait_for(all_started.wait(), 2)
            if name == "offline":
                return httpx.Response(503)
            answer = {"groups": [{"finding_ids": ["F1"], "risk": "Ключ доступен читателям репозитория.",
                                  "fix": "Загрузите ключ из окружения."}]}
            return httpx.Response(200, json={"message": {"content": json.dumps(answer)}})

        app.state.engine.gateway.client = await self.enterAsyncContext(httpx.AsyncClient(transport=httpx.MockTransport(endpoint)))
        with patch.dict(os.environ, {"GARDEN_WEBHOOK_URL": "http://local/receive"}):
            result = await self.execute(graph)
        reviews = result["steps"][-2]["reviews"]
        self.assertEqual([(r["model"], r["status"]) for r in reviews],
                         [("first", "succeeded"), ("second", "succeeded"), ("offline", "failed")])
        self.assertEqual(len(result["findings"]), 1)
        self.assertEqual((result["status"], len(deliveries[0]["reports"])), ("warning", 2))
        self.assertEqual(deliveries[0]["reviews"], reviews)
        evidence = await self.api.get(f"/api/runs/{result['id']}/steps/send/delivery")
        self.assertEqual(evidence.json(), {"state": "delivered", "payload": deliveries[0]})
        graph.files[0].text = "class Clean"
        with patch.dict(os.environ, {"GARDEN_WEBHOOK_URL": "http://local/receive"}):
            clean = await self.execute(graph)
        self.assertEqual(len(entered), 3)
        self.assertTrue(all(r["status"] == "skipped" for r in clean["steps"][-2]["reviews"]))

    async def test_demo_templates_and_clean_branch(self):
        graph = (await self.api.get("/api/demo")).json()
        self.assertEqual({n["kind"] for n in graph["nodes"]}, {"manual","schedule","secrets","sast","sca","condition","explain","webhook"})
        template = {k: graph[k] for k in ("name", "nodes", "edges")}
        saved = await self.api.post("/api/templates", json=template)
        self.assertEqual(saved.status_code, 201)
        self.assertIn(saved.json(), (await self.api.get("/api/templates")).json())
        self.assertNotIn("files", saved.json()["graph"])
        self.assertEqual((await self.api.post("/api/templates", json=graph)).status_code, 422)
        workflow = Workflow(**{**graph, "files": [{"path":"Clean.kt","text":"class Clean"}]})
        result = await self.execute(workflow)
        self.assertEqual(result["findings"], [])
        self.assertEqual(next(s["branch"] for s in result["steps"] if s["kind"] == "condition"), "no")
        self.assertEqual(next(s["status"] for s in result["steps"] if s["kind"] == "explain"), "skipped")

    async def test_template_description_and_independent_copy(self):
        graph = demo().model_dump(exclude={"files"})
        graph["name"] = "Проверка перед релизом"
        with app.state.store.db:
            app.state.store.db.execute("INSERT INTO templates VALUES (?,?)", ("legacy", json.dumps(graph)))
        description = "Проверяет исходники перед публикацией."
        response = await self.api.post("/api/templates", json={**graph, "description": description})
        self.assertEqual(response.status_code, 201)
        published = response.json()
        self.assertEqual(published["description"], description)
        copy = Workflow(**published["graph"], files=demo().files)
        next(node for node in copy.nodes if node.kind == "secrets").pattern = "*.yml"
        self.assertEqual((await self.api.put("/api/workflow", json=copy.model_dump())).status_code, 200)
        library = {item["id"]: item for item in (await self.api.get("/api/templates")).json()}
        self.assertEqual(library[published["id"]], published)
        self.assertEqual(library["legacy"]["description"], "")
        self.assertEqual(library["legacy"]["graph"], graph)

    async def test_generated_schedule_and_failed_draft(self):
        prompt = {"text": "Каждый день в 14:00 проверь секреты и отправь отчёт через webhook",
                  "target": {"connection": "ollama", "model": "local"}}
        plan = {"name": "Проверка секретов", "checks": ["secrets"], "schedule": "14:00",
                "condition": "always", "explain": False, "notify": True, "destination": "configured"}
        original = (await self.api.get("/api/workflow")).json()
        with patch.object(app.state.engine.gateway, "complete", return_value=json.dumps(plan)):
            response = await self.api.post("/api/templates/generate", json=prompt)
        self.assertEqual(response.status_code, 200)
        draft = Workflow(**response.json(), files=demo().files)
        by_kind = {node.kind: node for node in draft.nodes}
        self.assertEqual(set(by_kind), {"manual", "schedule", "secrets", "webhook"})
        self.assertEqual((by_kind["schedule"].cron, by_kind["schedule"].enabled), ("0 14 * * *", False))
        self.assertEqual(by_kind["webhook"].destination, "configured")
        self.assertEqual({(edge.source, edge.target) for edge in draft.edges},
                         {("start", "secrets"), ("schedule", "secrets"), ("secrets", "notify")})
        with patch.object(app.state.engine.gateway, "complete", return_value="invalid"):
            self.assertEqual((await self.api.post("/api/templates/generate", json=prompt)).status_code, 422)
        self.assertEqual((await self.api.get("/api/workflow")).json(), original)

    async def test_credentials_stay_local(self):
        url = "http://127.0.0.1:5188/api/connections/openai/key"
        for origin in ("https://external.invalid", "http://localhost:8888", "null"):
            result = await self.api.post(url, headers={"Origin": origin}, json={"key": "private-test-value"})
            self.assertEqual(result.status_code, 403)
            self.assertNotIn("private-test-value", result.text)
        listed = (await self.api.get("/api/connections")).json()
        self.assertTrue(any(p["id"] == "openai" for p in listed))
        self.assertFalse(any("key" in p or "url" in p for p in listed))

    @unittest.skipUnless(os.environ.get("GARDEN_TEST_OLLAMA") == "1", "Требуется локальная модель Ollama")
    async def test_local_model(self):
        graph = demo()
        graph.nodes.append(Node(id="ai", kind="explain", x=600, y=0, model="qwen2.5:1.5b"))
        graph.edges.append(Edge(id="scan-ai", source="scan", target="ai"))
        result = await self.execute(graph)
        step = result["steps"][-1]
        self.assertEqual(step["status"], "succeeded", step["message"])
        group = step["report"]["groups"][0]
        self.assertEqual(group["finding_ids"], [result["findings"][0]["id"]])
        print("Ollama:", group["risk"], group["fix"])
