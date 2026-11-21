import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from garden.models import Node, Source
from garden.runner import branch
from garden.scanners import analyze
from garden.submission import row


class SeverityPolicy(unittest.TestCase):
    def test_compound_password_keeps_password_severity(self):
        src = Source(path="Database.kt", text='val adminPassword = "fix" + "ture"')
        analysis = analyze("secrets", [src], "*")
        self.assertEqual(analysis.issues, [])
        self.assertEqual([(h.classification, h.severity) for h in analysis.findings], [("recoverable-token", "high")])

    def test_builtin_token_depends_on_observed_use(self):
        for path, method, extra, expected in [
            ("/monitor/health", "GET()", "", "low"),
            ("/status", "POST(HttpRequest.BodyPublishers.noBody())", "", "high"),
            ("/accounts", "GET()", "", "high"),
            ("/status", "GET()", "    publish(access)\n", "high"),
            ("/status?full=true", "GET()", "", "high"),
        ]:
            with self.subTest(path=path, method=method, extra=extra):
                src = ('import java.net.URI\nimport java.net.http.HttpRequest\n'
                       'fun make(): HttpRequest {\n    val access = System.getenv("HEALTH_TOKEN") ?: "fixture"\n'
                       + extra + f'    return HttpRequest.newBuilder(URI("https://service.test{path}"))\n'
                       '        .header("Authorization", "Bearer $access")\n'
                       f'        .{method}.build()\n}}')
                analysis = analyze("secrets", [Source(path="Probe.kt", text=src)], "*")
                self.assertEqual(analysis.issues, [])
                self.assertEqual([(h.classification, h.severity) for h in analysis.findings], [("secret-fallback", expected)])
                self.assertNotIn("fixture", str(row(analysis.findings[0])))

    def test_all_catalog_levels_reach_the_condition_and_export(self):
        levels = ("low", "medium", "high", "critical")
        catalog = [{"package": "example:lib", "advisory": level.upper(), "introduced": "1", "fixed": "2",
                    "severity": level} for level in levels]
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "catalog.json"
            path.write_text(json.dumps(catalog), encoding="utf-8")
            with patch.dict("os.environ", {"GARDEN_CATALOG": str(path), "GARDEN_EXTENDED_SCA": "0"}):
                analysis = analyze("sca", [Source(path="build.gradle.kts", text='dependencies { implementation("example:lib:1") }')], "*")
        self.assertEqual(analysis.issues, [])
        self.assertCountEqual([hit.severity for hit in analysis.findings], levels)
        for hit in analysis.findings:
            self.assertEqual(row(hit)["severity"], hit.advisory)
            for level in levels:
                gate = Node(id="gate", kind="condition", x=0, y=0, predicate="severity_eq", value=level)
                self.assertEqual(branch(gate, [hit]), "yes" if hit.severity == level else "no")

    def test_fallback_with_unconfirmed_scope_keeps_high_severity(self):
        code = ('import java.net.http.HttpRequest as Request\nimport java.net.URI as Address\n'
                'fun make(): Request {\n val token = System.getenv("HEALTH_TOKEN") ?: "fixture"\n'
                ' val local = 1\n return Request.newBuilder(Address.create("https://sample.test/readyz"))\n'
                '   .header("Authorization", "Bearer ${token}").build()\n}')
        for variant, expected in [
            (code, "low"),
            (code.replace("HEALTH_TOKEN", "ADMIN_HEALTH_TOKEN"), "high"),
            (code.replace("HEALTH_TOKEN", "GENERAL_TOKEN"), "high"),
            (code.replace("java.net.http.HttpRequest", "example.HttpRequest"), "high"),
            (code.replace("val local = 1", 'val local = "${publish(token)}"'), "high"),
            ('fun test() { val token = System.getenv("HEALTH_TOKEN") ?: "fixture"; return }', "high"),
        ]:
            with self.subTest(variant=variant):
                analysis = analyze("secrets", [Source(path="Other.kt", text=variant)], "*")
                self.assertEqual(analysis.issues, [])
                self.assertEqual([h.severity for h in analysis.findings], [expected])
