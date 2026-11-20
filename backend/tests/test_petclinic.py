"""Self-contained regression cases for Kotlin, Spring, Gradle and configuration files."""
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

from garden.models import Source
from garden.scanners import analyze
from garden.scenarios import sources


COMPOSE = "docker-compose.yml"
BUILD = "build.gradle.kts"
QUERY = "src/main/kotlin/org/springframework/samples/petclinic/owner/QueryCheck.kt"


def cases():
    def compose(env):
        return "services:\n  db:\n    image: mysql:8\n    environment:\n" + env + "\n"

    for name, env, expected in [
        ("list credential", "      - MYSQL_PASSWORD=fixture-only", [(5, "password")]),
        ("map reference", "      MYSQL_PASSWORD: $DB_PASSWORD", []),
        ("required message", '      MYSQL_PASSWORD: "${DB_PASSWORD:?set a password}"', []),
        ("empty default", '      MYSQL_PASSWORD: "${DB_PASSWORD:-}"', []),
        ("literal default", '      - MYSQL_PASSWORD=${DB_PASSWORD:-fixture-only}', [(5, "secret-fallback")]),
        ("mount and flag", '      MYSQL_ROOT_PASSWORD_FILE: /run/secrets/db\n      MYSQL_ALLOW_EMPTY_PASSWORD: "yes"', []),
    ]:
        yield name, "secrets", COMPOSE, compose(env), expected
    for name, env, expected in [
        ("empty root", "      - MYSQL_ROOT_PASSWORD=\n      - MYSQL_ALLOW_EMPTY_PASSWORD=yes", [(6, "empty-database-root-password")]),
        ("mounted root", "      - MYSQL_ROOT_PASSWORD_FILE=/run/secrets/db\n      - MYSQL_ALLOW_EMPTY_PASSWORD=yes", []),
    ]:
        yield name, "sast", COMPOSE, compose(env), expected
    for name, expr, expected in [
        ("JPQL interpolation", '"SELECT o FROM Owner o WHERE o.lastName = \'$name\'"', [(8, "sql-injection")]),
        ("JPQL binding", '"SELECT o FROM Owner o WHERE o.lastName = :name"', []),
    ]:
        src = ('package org.springframework.samples.petclinic.owner\n'
               'import jakarta.persistence.EntityManager\nimport org.springframework.web.bind.annotation.*\n'
               '@RestController class QueryCheck(val em: EntityManager) {\n'
               ' @GetMapping("/query-check") fun check(@RequestParam name: String): Int {\n'
               '  val statement = ' + expr + '\n  val manager = em\n'
               '  val query = manager.createQuery(statement, Owner::class.java)\n'
               + ('  query.setParameter("name", name)\n' if not expected else '')
               + '  return query.resultList.size\n }\n}')
        yield name, "sast", QUERY, src, expected
    for name, scope, outer, inner, expected in [
        ("development", "developmentOnly", "1.1", None, [(3, "DEMO-001")]),
        ("fixed development", "developmentOnly", "1.2", None, []),
        ("test and development", "testAndDevelopmentOnly", "1.1", None, [(3, "DEMO-001")]),
        ("fixed local override", "implementation", "1.1", "1.2", []),
        ("affected local override", "implementation", "1.2", "1.1", [(4, "DEMO-001")]),
    ]:
        src = f'val checkVersion = "{outer}"\ndependencies {{\n'
        if inner:
            src += f' val checkVersion = "{inner}"\n'
        src += f' {scope}("training.demo:example-lib:$checkVersion")\n}}'
        yield name, "sca", BUILD, src, expected


def locations(result, path):
    return sorted((h.line, h.classification or h.advisory or h.rule) for h in result.findings if h.path == path)


@patch.dict("os.environ", {"GARDEN_EXTENDED_SCA": "1"})
class TransferRules(unittest.TestCase):
    def test_osv_release_boundaries(self):
        for package, affected, fixed, expected in [
            ("com.h2database:h2", "2.1.214", "2.2.220", {"CVE-2022-45868"}),
            ("com.mysql:mysql-connector-j", "8.1.0", "8.2.0", {"CVE-2023-22102"}),
            ("org.springframework.boot:spring-boot-starter-actuator", "4.0.0-M1", "4.0.4",
             {"CVE-2026-22731", "CVE-2026-22733"}),
        ]:
            for number, advisories in [(affected, expected), (fixed, set())]:
                with self.subTest(package=package, version=number):
                    code = f'dependencies {{ implementation("{package}:{number}") }}'
                    result = analyze("sca", [Source(path=BUILD, text=code)], "*")
                    self.assertEqual(result.issues, [])
                    self.assertEqual(result.checked_packages, 1)
                    self.assertEqual({hit.advisory for hit in result.findings}, advisories)

    def test_bom_requires_applied_plugins_and_respects_overrides(self):
        boot = 'id("org.springframework.boot") version "4.1.2"'
        management = 'id("io.spring.dependency-management") version "1.1.7"'
        def run(plugins, override="", declared="", locks=None):
            code = f'plugins {{\n{plugins}\n}}\n{override}\ndependencies {{ runtimeOnly("com.h2database:h2{declared}") }}'
            files = [Source(path=BUILD, text=code)]
            if locks:
                files.append(Source(path="gradle.lockfile", text=locks))
            return analyze("sca", files, "*")
        both = boot + "\n" + management
        for plugins in (boot, both.replace("4.1.2", "99.0"), both + " apply false", boot + " apply false\n" + management):
            result = run(plugins)
            self.assertTrue(result.issues)
            self.assertEqual(result.packages[0].status, "unresolved")
        for override in ('extra["h2.version"] = "2.1.214"', 'project.extra.set("h2.version", "2.1.214")'):
            self.assertEqual([h.advisory for h in run(both, override).findings], ["CVE-2022-45868"])
            self.assertEqual(run(both, override, ":2.2.220").findings, [])
        result = run(both, declared=":2.1.214", locks="com.h2database:h2:2.2.220=runtimeClasspath")
        self.assertEqual((result.packages[0].source, result.findings), ("gradle.lockfile", []))
        self.assertEqual(run(both, 'extra["h2.version"] = runtimeVersion()').checked_packages, 0)

    def test_shared_environment_is_reported_once(self):
        src = ('x-env: &defaults\n  DB_PASSWORD: fixture-only\nservices:\n'
               '  app: {image: app, environment: *defaults}\n  worker: {image: worker, environment: *defaults}\n')
        result = analyze("secrets", [Source(path=COMPOSE, text=src)], "*")
        self.assertEqual(locations(result, COMPOSE), [(2, "password")])

    def test_jpa_receiver_types(self):
        sj = next(case[3] for case in cases() if case[0] == "JPQL interpolation")
        for model_import, method, expected in [
            ("javax.persistence.EntityManager as Session", "createNativeQuery", [(8, "sql-injection")]),
            ("demo.reporting.Session", "createQuery", []),
        ]:
            with self.subTest(model_import=model_import):
                code = sj.replace("jakarta.persistence.EntityManager", model_import).replace("em: EntityManager", "em: Session")
                code = code.replace("manager.createQuery", "manager." + method)
                if method == "createNativeQuery":
                    code = code.replace("SELECT o FROM Owner o WHERE o.lastName", "SELECT * FROM owners WHERE last_name")
                result = analyze("sast", [Source(path=QUERY, text=code)], "*")
                self.assertEqual(result.issues, [])
                self.assertEqual(locations(result, QUERY), expected)

    def test_version_overrides_stay_in_their_block(self):
        code = '''val release = "1.1"
dependencies {
 val release = "1.2"
 developmentOnly("training.demo:example-lib:$release")
}
dependencies {
 implementation("training.demo:example-lib:$release")
}
'''
        result = analyze("sca", [Source(path=BUILD, text=code)], "*")
        self.assertEqual(result.issues, [])
        self.assertEqual(locations(result, BUILD), [(7, "DEMO-001")])

    def test_labelled_pairs(self):
        for name, kind, path, text, expected in cases():
            with self.subTest(case=name):
                result = analyze(kind, [Source(path=path, text=text)], "*")
                self.assertEqual(result.issues, [])
                self.assertEqual(locations(result, path), expected)
                for hit in result.findings:
                    self.assertNotIn("fixture-only", hit.model_dump_json())

    def test_resource_bundle_encodings(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            for name, encoding in [("messages_de.properties", "latin1"), ("messages.properties", "utf-8-sig")]:
                (root / name).write_bytes("title=Grüße\n".encode(encoding))
            self.assertEqual([f.text for f in sources(root)], ["title=Grüße\n"] * 2)
            (root / "Invalid.kt").write_bytes(b"\xff")
            with self.assertRaisesRegex(ValueError, "Invalid.kt"):
                sources(root)


    def test_resolution_in_synthetic_spring_project(self):
        build = Source(path=BUILD, text='''plugins {
    id("org.springframework.boot") version "4.1.2"
    id("io.spring.dependency-management") version "1.1.7"
    kotlin("jvm") version "2.4.21"
}
dependencies {
    implementation("org.jetbrains.kotlin:kotlin-reflect")
    runtimeOnly("com.mysql:mysql-connector-j")
}
''')
        result = analyze("sca", [build], "*")
        self.assertEqual(result.issues, [])
        self.assertEqual([(p.version, p.source) for p in result.packages],
                         [("2.4.21", "org.jetbrains.kotlin.jvm"), ("9.7.0", "spring-boot-dependencies:4.1.2")])
        self.assertEqual(result.findings, [])
        build.text += '\nextra["mysql.version"] = "8.1.0"\n'
        changed = analyze("sca", [build], "*")
        self.assertEqual(locations(changed, BUILD), [(8, "CVE-2023-22102")])
