"""Checks against the participant checkout, plus independent rule boundary cases."""
import asyncio
import json
import os
import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import httpx

from garden.api import app, lifespan
from garden.maven import Interval
from garden.models import Edge, Node, Source, Workflow
from garden.scanners import analyze, scan
from garden.scenarios import sources
from tests.compare_submission import compare


TRAINING = Path(__file__).resolve().parents[2] / "samples/training"


def training_workflow(root: Path) -> Workflow:
    files = sources(root)
    kinds = ["manual", "secrets", "sast", "sca"]
    nodes = [Node(id=k, kind=k, x=i*260, y=50, extended_sca=False if k == "sca" else None) for i, k in enumerate(kinds)]
    return Workflow(name="Repair Desk", files=files, nodes=nodes,
                    edges=[Edge(id=a+b, source=a, target=b) for a, b in zip(kinds, kinds[1:])])


@unittest.skipUnless((TRAINING / "training-project").exists(), "Требуется открытый набор Repair Desk")
class ParticipantDataset(unittest.IsolatedAsyncioTestCase):
    @patch.dict(os.environ, {"GARDEN_EXTENDED_SCA": "1"})
    def test_all_direct_maven_dependencies_are_checked(self):
        result = analyze("sca", sources(TRAINING / "training-project"), "*")
        self.assertEqual(result.issues, [])
        packages = {p.package: (p.version, p.source) for p in result.packages}
        self.assertEqual((result.checked_packages, len(result.packages), len(packages)), (14, 14, 14))
        lock = result.lockfile
        self.assertEqual(lock.issues, [])
        self.assertEqual((lock.checked, len(lock.packages)), (53, 53))
        self.assertEqual(len({p.package for p in lock.packages} & packages.keys()), 0)
        self.assertTrue(all(p.scope == "transitive" and not p.advisories for p in lock.packages))
        for package, version, source in [
            ("org.springframework.boot:spring-boot-starter-jdbc", "4.0.9", "gradle.lockfile"),
            ("org.springframework.boot:spring-boot-starter-security", "4.0.9", "gradle.lockfile"),
            ("org.springframework.security:spring-security-test", "7.0.8", "spring-boot-dependencies:4.0.9"),
            ("org.junit.platform:junit-platform-launcher", "6.0.3", "spring-boot-dependencies:4.0.9"),
        ]:
            with self.subTest(package=package):
                self.assertEqual(packages[package], (version, source))

    def test_renamed_and_relocated_project(self):
        original = sources(TRAINING / "training-project")
        paths = {f.path: (f"src/main/kotlin/variant/Component{i}.kt" if f.path.endswith(".kt") else f.path)
                 for i, f in enumerate(original)}
        renamed = []
        for f in reversed(original):
            text = f.text.replace("lab.repairdesk", "demo.alternate")
            text = re.sub(r"\b(frameTag|ticketCode|ticketId|archiveFormatVersion|manifestVersion)\b", r"renamed_\1", text)
            renamed.append(Source(path=paths[f.path], text="\n\n" + text))
        for kind in ("secrets", "sast", "sca"):
            with self.subTest(kind=kind):
                baseline = scan(kind, original, "*")[0]
                changed = scan(kind, renamed, "*")[0]
                expected = [(paths[f.path], f.line+2, f.rule, f.classification, f.advisory) for f in baseline]
                self.assertEqual(len(expected), 5)
                self.assertCountEqual(expected, [(f.path, f.line, f.rule, f.classification, f.advisory) for f in changed])

    async def test_public_export_and_controls(self):
        graph = training_workflow(TRAINING / "training-project")
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {"GARDEN_DB": str(Path(temp) / "tmp.sqlite")}):
            async with lifespan(app), httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://local") as api:
                response = await api.post("/api/runs", json={"workflow": graph.model_dump(), "trigger": "manual"})
                self.assertEqual(response.status_code, 202)
                await asyncio.gather(*app.state.engine.tasks)
                url = "/api/runs/" + response.json()["id"]
                result = (await api.get(url)).json()
                self.assertEqual(result["status"], "succeeded")
                sca = next(s for s in result["steps"] if s["kind"] == "sca")
                self.assertIsNone(sca["lockfile"])
                export = await api.get(url + "/submission")
                self.assertEqual(export.status_code, 200)
                self.assertIn("attachment", export.headers["content-disposition"])
                html = await api.get(url + "/submission", params={"format": "html"})
                self.assertEqual(html.status_code, 200)
                self.assertIn("text/html", html.headers["content-type"])
                self.assertTrue(html.headers["content-disposition"].endswith('.html"'))
                self.assertNotIn("Проверка неполная", html.text)
        rows = export.json()["findings"]
        self.assertEqual(html.text.count("<tr>"), len(rows) + 1)
        gold = json.loads((TRAINING / "ground-truth/training-findings.json").read_bytes())
        self.assertEqual(compare(export.json(), gold), [])
        self.assertEqual(len(rows), len(result["findings"]))
        for row, finding in zip(rows, result["findings"], strict=True):
            self.assertEqual(finding["severity"].upper(), row["severity"])


class RuleBoundaries(unittest.TestCase):
    def test_update_accounts_for_other_advisories_on_the_package(self):
        entries = [{"package": "example:lib", "advisory": code, "introduced": lo, "fixed": hi, "severity": "high"}
                   for code, lo, hi in [("A", "1.0", "1.2"), ("B", "1.2", "1.3")]]
        build = Source(path="build.gradle.kts", text='dependencies { implementation("example:lib:1.1") }')
        with tempfile.TemporaryDirectory() as temp:
            catalog = Path(temp) / "catalog.json"
            catalog.write_text(json.dumps(entries), encoding="utf-8")
            with patch.dict(os.environ, {"GARDEN_CATALOG": str(catalog)}):
                result = analyze("sca", [build], "*")
        self.assertEqual([(hit.advisory, hit.fixed_version) for hit in result.findings], [("A", "1.3")])
        self.assertIn("1.3", result.findings[0].fix)

    @patch.dict(os.environ, {"GARDEN_EXTENDED_SCA": "0"})
    def test_competition_catalog_and_numeric_scope(self):
        files = [Source(path="build.gradle.kts", text='''dependencies {
    implementation("org.apache.commons:commons-text:1.9.0")
    implementation("com.mysql:mysql-connector-j:8.1.0")
    implementation("org.jsoup:jsoup:1.14.1-RC1")
}'''), Source(path="gradle.lockfile", text="org.yaml:snakeyaml:1.33=runtimeClasspath")]
        result = analyze("sca", files, "*")
        self.assertEqual([(h.dependency.version, h.advisory) for h in result.findings], [("1.9.0", "CVE-2022-42889")])
        self.assertEqual([p.status for p in result.packages], ["checked", "outside-catalog", "unresolved"])
        self.assertEqual(result.lockfile.files, [])

    @patch.dict(os.environ, {"GARDEN_EXTENDED_SCA": "1"})
    def test_lock_reports_follow_module_and_resolved_version(self):
        build = 'dependencies { implementation("org.yaml:snakeyaml:2.5") }'
        files = [Source(path="app/build.gradle.kts", text=build),
                 Source(path="app/gradle.lockfile", text="org.yaml:snakeyaml:2.5=runtimeClasspath"),
                 Source(path="lib/build.gradle.kts", text="dependencies {}"),
                 Source(path="lib/gradle.lockfile", text="# Gradle\nempty=test\norg.yaml:snakeyaml:1.33=runtime\n"
                             "org.yaml:snakeyaml:2.5=test\norg.yaml:snakeyaml:1.33=compile,runtime")]
        for pattern in ("*", "lib/build.gradle.kts", "lib/gradle.lockfile"):
            with self.subTest(pattern=pattern):
                result = analyze("sca", files, pattern)
                self.assertEqual(result.issues + result.lockfile.issues, [])
                self.assertEqual(result.findings, [])
                rows = result.lockfile.packages
                self.assertEqual([(p.path, p.line, p.version, p.configurations, [a.id for a in p.advisories])
                                  for p in rows], [("lib/gradle.lockfile", 3, "1.33", ["compile", "runtime"], ["CVE-2022-1471"]),
                                                   ("lib/gradle.lockfile", 4, "2.5", ["test"], [])])

    @patch.dict(os.environ, {"GARDEN_EXTENDED_SCA": "1"})
    def test_orphan_and_unknown_locked_package_show_incomplete_coverage(self):
        files = [Source(path="gradle.lockfile", text="org.yaml:snakeyaml:1.33=runtime\nunknown:lib:1=runtime\nbad-row")]
        result = analyze("sca", files, "*")
        self.assertEqual(result.lockfile.checked, 1)
        self.assertTrue(all(p.scope == "unclassified" for p in result.lockfile.packages))
        self.assertEqual(result.lockfile.packages[1].status, "outside-catalog")
        self.assertTrue(any("строка 3" in i for i in result.lockfile.issues))

    @patch.dict(os.environ, {"GARDEN_EXTENDED_SCA": "1"})
    def test_ranges_and_lockfile(self):
        interval = Interval(lower="1.1", upper="2.0", lowerInclusive=False, upperInclusive=True)
        self.assertEqual([interval.contains(v) for v in ("1.1.0", "1.9", "2", "2.0.1")], [False, True, True, False])
        self.assertTrue(Interval(lower=None, upper="1.0", lowerInclusive=False, upperInclusive=False).contains("0.0.1"))
        files = [Source(path="sub/build.gradle.kts", text='dependencies { add("api", "training.demo:example-lib:1.2") }'),
                 Source(path="sub/gradle.lockfile", text="training.demo:example-lib:1.1=compileClasspath\nother:transitive:1=compileClasspath")]
        hits, _ = scan("sca", files, "*")
        self.assertEqual([(h.dependency.version, h.path) for h in hits], [("1.1", "sub/build.gradle.kts")])

    def test_environment_value_and_unused_fallback(self):
        file = Source(path="Settings.kt", text='''
fun setup() {
    val access = System.getenv("AUTH") ?: "unused"
    setBearerAuth(System.getenv("REAL_TOKEN"))
}
''')
        self.assertEqual(scan("secrets", [file], "*")[0], [])

    def test_scoped_cors(self):
        file = Source(path="Web.kt", text='''
import org.springframework.web.cors.CorsConfiguration
fun configs() {
    val public = CorsConfiguration().apply { allowedOriginPatterns = listOf("*") }
    val privateConfig = CorsConfiguration().apply { allowCredentials = true }
}
''')
        self.assertEqual(scan("sast", [file], "*")[0], [])

    def test_owner_scoped_query(self):
        repo = Source(path="Records.kt", text='''
@Repository class Records(val db: JdbcTemplate) {
    fun read(id: Long) = db.queryForMap("SELECT owner_id FROM records WHERE id = ? AND owner_id = ?", id, currentOwner())
}
''')
        api = Source(path="Api.kt", text='''
@RestController class Api(val records: Records) {
    @GetMapping fun get(@PathVariable key: Long) = records.read(key)
}
''')
        self.assertEqual(scan("sast", [repo, api], "*")[0], [])
