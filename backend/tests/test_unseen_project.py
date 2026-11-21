"""Acceptance fixture for an observatory reservation service. No Gradle execution is needed."""
import json
import os
import unittest
from unittest.mock import patch

from garden.models import Source
from garden.scanners import analyze
from garden.submission import submission


SRC = "src/main/kotlin/sky/calendar/"
API, STORE, SECURITY, REMOTE = (SRC + name + ".kt" for name in ("NightApi", "NightStore", "Gate", "DomeClient"))
CONFIG = "src/main/resources/application.yml"
BUILD = "build.gradle.kts"

PROJECT = {
    "settings.gradle.kts": 'rootProject.name = "night-calendar"\n',
    BUILD: '''plugins {
    kotlin("jvm") version "2.2.21"
    kotlin("plugin.spring") version "2.2.21"
    id("org.springframework.boot") version "3.5.7"
}
repositories { mavenCentral() }
dependencies {
    implementation(platform("org.springframework.boot:spring-boot-dependencies:3.5.7"))
    implementation("org.springframework.boot:spring-boot-starter-web")
    implementation("org.springframework.boot:spring-boot-starter-security")
    implementation("org.springframework.boot:spring-boot-starter-jdbc")
    implementation("org.jetbrains.kotlin:kotlin-reflect")
    implementation(libs.mapper)
    implementation(libs.parser)
    runtimeOnly("com.h2database:h2")
}
''',
    "gradle/libs.versions.toml": '''[versions]
mapper = "3.5.5"
parser = "1.14.2"
[libraries]
mapper = { module = "org.mybatis:mybatis", version.ref = "mapper" }
parser = { module = "org.jsoup:jsoup", version.ref = "parser" }
''',
    CONFIG: '''spring:
  datasource:
    url: jdbc:h2:mem:dome
    password: ${NIGHT_DB_PASSWORD}
station:
  weather:
    api-key: fixture-cloud-reader
  telemetry:
    authorization: Bearer fixture-telemetry
  archive:
    password: ${NIGHT_ARCHIVE_PASSWORD:fixture-spare}
  relay:
    api-key: ${NIGHT_RELAY_KEY}
''',
    "src/main/resources/schema.sql": '''CREATE TABLE nights (
    seq BIGINT PRIMARY KEY, account_id VARCHAR(80) NOT NULL, target VARCHAR(80) NOT NULL
);
''',
    SRC + "App.kt": '''package sky.calendar
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication
@SpringBootApplication
class App
fun main(args: Array<String>) { runApplication<App>(*args) }
''',
    STORE: '''package sky.calendar
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.stereotype.Repository

@Repository
class NightStore(private val sql: JdbcTemplate) {
    fun reservation(seq: Long) =
        sql.queryForMap("SELECT account_id, target FROM nights WHERE seq = ?", seq)
    fun mine(seq: Long, account: String) =
        sql.queryForMap("SELECT target FROM nights WHERE seq = ? AND account_id = ?", seq, account)
    fun roster() = sql.queryForList("SELECT account_id, target FROM nights")
}
''',
    API: '''package sky.calendar
import java.security.Principal
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.web.bind.annotation.*

@RestController
class NightApi(private val calendar: NightStore, private val sql: JdbcTemplate) {
    // A reservation belongs to one account. Crew rosters are internal.
    @GetMapping("/night/reservation/{seq}")
    fun reservation(@PathVariable seq: Long) = calendar.reservation(seq)

    @GetMapping("/night/mine/{seq}")
    fun mine(@PathVariable seq: Long, principal: Principal) = calendar.mine(seq, principal.name)
    @GetMapping("/night/crew/roster")
    fun roster() = calendar.roster()

    @CrossOrigin(originPatterns = ["*"], allowCredentials = "true")
    @GetMapping("/night/search")
    fun matches(@RequestParam target: String) =
        sql.queryForList("SELECT target FROM nights WHERE target = '$target'", String::class.java)
    @CrossOrigin(origins = ["https://planning.example"], allowCredentials = "true")
    @GetMapping("/night/exact")
    fun exact(@RequestParam target: String) =
        sql.queryForList("SELECT target FROM nights WHERE target = ?", String::class.java, target)
}
''',
    SECURITY: '''package sky.calendar
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity

@Configuration
class Gate {
    @Bean fun chain(http: HttpSecurity) = http.authorizeHttpRequests { access ->
        access.requestMatchers("/favicon.ico").permitAll()
        access.requestMatchers("/night/crew/roster").permitAll()
        access.requestMatchers("/night/crew/**").hasAuthority("DOME_STAFF")
        access.anyRequest().authenticated()
    }.build()
}
''',
    REMOTE: '''package sky.calendar
import javax.net.ssl.HttpsURLConnection
import org.springframework.http.HttpHeaders

class DomeClient {
    fun configureLegacy(link: HttpsURLConnection) {
        link.setHostnameVerifier { _, _ -> true }
    }
    fun configureCurrent(link: HttpsURLConnection) {
        link.hostnameVerifier = HttpsURLConnection.getDefaultHostnameVerifier()
    }
    fun serviceHeaders() = HttpHeaders().apply {
        setBasicAuth("dome-console", "fixture-console-pass")
    }
    fun userHeaders(sessionToken: String) = HttpHeaders().apply {
        setBearerAuth(sessionToken)
    }
    fun oldArchiveHeaders() = HttpHeaders().apply {
        val prefix = "fixture-night-"
        val suffix = "terminal"
        setBearerAuth(prefix + suffix)
    }
}
''',
}

# Each anchor identifies a hand-labelled source line, independently of scanner output.
# Either end of the direct controller-to-store flow may be reported for ownership.
CODE_ORACLE = {
    "SECRET": [
        ("api-key", [(CONFIG, "api-key: fixture-cloud-reader")]),
        ("configuration-token", [(CONFIG, "authorization: Bearer fixture-telemetry")]),
        ("secret-fallback", [(CONFIG, "password: ${NIGHT_ARCHIVE_PASSWORD:fixture-spare}")]),
        ("password", [(REMOTE, 'setBasicAuth("dome-console", "fixture-console-pass")')]),
        ("recoverable-token", [(REMOTE, line) for line in (
            'val prefix = "fixture-night-"', 'val suffix = "terminal"', 'setBearerAuth(prefix + suffix)')]),
    ],
    "SAST": [
        ("sql-injection", [(API, '''sql.queryForList("SELECT target FROM nights WHERE target = '$target'", String::class.java)''')]),
        ("credentialed-cors", [(API, '@CrossOrigin(originPatterns = ["*"], allowCredentials = "true")')]),
        ("route-authorization", [(SECURITY, 'access.requestMatchers("/night/crew/roster").permitAll()')]),
        ("object-authorization", [
            (API, 'fun reservation(@PathVariable seq: Long) = calendar.reservation(seq)'),
            (STORE, 'sql.queryForMap("SELECT account_id, target FROM nights WHERE seq = ?", seq)'),
        ]),
        ("tls-verification", [(REMOTE, "link.setHostnameVerifier { _, _ -> true }")]),
    ],
}


def anchor(path, source_line):
    matches = [line for line, content in enumerate(PROJECT[path].splitlines(), 1) if content.strip() == source_line]
    if len(matches) != 1:
        raise ValueError(f"Ambiguous fixture anchor in {path}: {source_line}")
    return path, matches[0]


class ObservatoryAcceptance(unittest.TestCase):
    @patch.dict(os.environ, {"GARDEN_EXTENDED_SCA": "0"})
    def test_competition_submission(self):
        sources = [Source(path=path, text=content) for path, content in PROJECT.items()]
        runs = {kind: analyze(kind, sources, "*") for kind in ("secrets", "sast", "sca")}
        for kind, result in runs.items():
            self.assertEqual(result.issues, [], kind)
        rows = submission([hit for result in runs.values() for hit in result.findings])["findings"]
        for category, cases in CODE_ORACLE.items():
            with self.subTest(category=category):
                actual = [r for r in rows if r["category"] == category]
                matched = []
                for code, locations in cases:
                    allowed = {anchor(*loc) for loc in locations}
                    count = sum(r["class"] == code and (r["path"], r["line"]) in allowed for r in actual)
                    matched.extend([code] * count)
                self.assertCountEqual(matched, [code for code, _ in cases])
                self.assertEqual(len(actual), len(cases), [(r["class"], r["path"], r["line"]) for r in actual])
        # The contest feed gives MyBatis < 3.5.6 one advisory. jsoup 1.14.2 is its own fixed boundary.
        with self.subTest(category="SCA"):
            advisories = [r for r in rows if r["category"] == "SCA"]
            self.assertEqual([(r["path"], r["group"], r["artifact"], r["version"]) for r in advisories],
                             [(BUILD, "org.mybatis", "mybatis", "3.5.5")])
            self.assertIn(advisories[0]["advisoryId"], {"CVE-2020-26945", "GHSA-qq48-m4jx-xqh8"})
            self.assertTrue(any(p.package == "org.jsoup:jsoup" and p.version == "1.14.2" and p.status == "checked"
                                for p in runs["sca"].packages))
        self.assertNotIn("fixture-", json.dumps(rows))
