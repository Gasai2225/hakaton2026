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
from garden.models import Edge, Node, Source, Target, Workflow, demo
from garden.scanners import scan


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
        self.assertEqual(scan("sast", [source], "*")[0][0].line, 2)
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

    async def test_partial_run_exports_confirmed_findings(self):
        graph = demo()
        graph.files.append(Source(path="Broken.kt", text="fun ("))
        result = await self.execute(graph)
        step = result["steps"][-1]
        self.assertEqual((result["status"], step["status"]), ("warning", "warning"))
        self.assertIn("Broken.kt", step["message"])
        export = await self.api.get("/api/runs/" + result["id"] + "/submission")
        self.assertEqual([r["path"] for r in export.json()["findings"]], [graph.files[0].path])

    async def test_branch_fallback_and_delivery(self):
        graph = demo()
        for key in ["condition", "explain", "webhook", "sast"]:
            graph.nodes.append(Node(id=key, kind=key, x=0, y=0))
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
                   "fun configure() { authorize(anyRequest, permitAll) }"),
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
