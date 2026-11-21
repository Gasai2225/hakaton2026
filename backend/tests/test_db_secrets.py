import unittest

from garden.models import Source
from garden.scanners import analyze
from garden.submission import row


class DatabaseSecrets(unittest.TestCase):
    def check(self, path, code, expected):
        result = analyze("secrets", [Source(path=path, text=code)], "*")
        self.assertEqual(result.issues, [])
        self.assertEqual([(f.line, f.classification, f.severity) for f in result.findings],
                         [(line, cls, "high") for line, cls in expected])
        for finding in result.findings:
            self.assertNotIn("fixture", finding.model_dump_json())
            self.assertNotIn("fixture", str(row(finding)))

    def test_spring_database_urls(self):
        for name, url, expected in [
            ("spring.datasource.url", "jdbc:postgresql://db/app?user=report&password=fixture", "password"),
            ("spring.datasource.hikari.jdbc-url", "jdbc:mysql://report:fixture@db/app", "password"),
            ("spring.datasource.url", "jdbc:postgresql://${DB_HOST}/app?password=fixture", "password"),
            ("spring.datasource.url", "jdbc:postgresql://db/app?password=${DB_PASSWORD:fixture}", "secret-fallback"),
            ("spring.r2dbc.url", "r2dbc:pool:postgresql://report:fixture%40a@db/app", "password"),
            ("spring.r2dbc.url", "r2dbc:postgresql://report@db/app", None),
            ("spring.r2dbc.url", "r2dbc:postgresql://report:${DB_PASSWORD}@db/app", None),
            ("spring.r2dbc.url", "r2dbc:postgresql://db/app?password=fixture", None),
            ("spring.r2dbc.url", "jdbc:postgresql://db/app?password=fixture", None),
            ("spring.datasource.url", "jdbc:postgresql://db/app?password=&user=fixture", None),
            ("spring.datasource.url", "jdbc:postgresql://db/app?password=%5BREDACTED%5D", None),
            ("spring.datasource.url", "jdbc:postgresql://db/app?note=password%3Dfixture", None),
            ("spring.datasource.url", "https://report:fixture@docs.example/path", None),
            ("docs.url", "jdbc:postgresql://db/app?password=fixture", None),
            ("spring.datasource.password", "[REDACTED]", None),
            ("spring.datasource.url", "jdbc:sqlserver://db;databaseName=app;PASSWORD={fixture;a}}b};encrypt=true", "password"),
            ("spring.datasource.url", "jdbc:sqlserver://db;applicationName={demo;password=fixture};encrypt=true", None),
        ]:
            with self.subTest(name=name, url=url):
                self.check("application.properties", f"{name}={url}", [(1, expected)] if expected else [])

    def test_nested_yaml_credential_and_unrelated_documentation(self):
        s = '''documentation:
  url: jdbc:postgresql://db/demo?password=fixture-doc
spring:
  datasource:
    hikari:
      jdbc-url: jdbc:postgresql://db/demo?password=fixture
  r2dbc:
    url: r2dbc:postgresql://sample:${DB_PASSWORD:fixture}@db/demo
'''
        self.check("application.yml", s, [(6, "password"), (8, "secret-fallback")])

    def test_driver_and_pool_calls(self):
        for statement, cls in [
            ('DM.getConnection(url, "app", "fixture")', "password"),
            ('DM.getConnection("jdbc:postgresql://db/app?password=fixture")', "password"),
            ('DM.getConnection(url, "app", System.getenv("DB_PASSWORD"))', None),
            ('DM.getConnection("r2dbc:postgresql://app:fixture@db/catalog")', None),
            ('h.setPassword("fixture")', "password"),
            ('h.password = "fixture"', "password"),
            ('h.setJdbcUrl("jdbc:mysql://app:fixture@db/catalog")', "password"),
            ('h.jdbcUrl = "jdbc:postgresql://db/app?password=fixture"', "password"),
            ('h.username = "fixture"', None),
            ('other.setPassword("fixture")', None),
            ('other.getConnection(url, "app", "fixture")', None),
            ('emit("jdbc:postgresql://db/app?password=fixture")', None),
        ]:
            with self.subTest(statement=statement):
                code = ('import java.sql.DriverManager as DM\nimport com.zaxxer.hikari.HikariConfig as Pool\n'
                        'fun configure(h: Pool, other: Labels, url: String) {\n ' + statement + '\n}')
                self.check("Config.kt", code, [(4, cls)] if cls else [])

    def test_r2dbc_pool_dsl_and_shadowed_factory(self):
        src = '''import io.r2dbc.spi.ConnectionFactories as CF
import com.zaxxer.hikari.HikariConfig
fun make() {
    CF.get("r2dbc:postgresql://collector:fixture@db/archive")
    HikariConfig().apply { password = "fixture" }
}
fun labels(CF: Labels) = CF.get("r2dbc:postgresql://collector:fixture@db/archive")
'''
        self.check("Database.kt", src, [(4, "password"), (5, "password")])

    def test_implicit_pool_members_may_be_shadowed(self):
        src = '''import com.zaxxer.hikari.HikariConfig
fun configure() {
    var password = readValue()
    HikariConfig().apply { password = "fixture" }
}
'''
        self.check("Database.kt", src, [])

    def test_spring_value_database_url_fallback(self):
        src = r'''import org.springframework.beans.factory.annotation.Value
class Db(@Value("\${spring.datasource.url:jdbc:postgresql://db/app?password=fixture}") val url: String)
'''
        self.check("Database.kt", src, [(2, "secret-fallback")])

    def test_local_credentials_are_reported_once_and_dynamic_sources_stay_clean(self):
        for decl in ('val credential = "fixture"', 'val dbPassword = "fixture"'):
            name = decl.split()[1]
            src = ('import java.sql.DriverManager\nfun make(url: String) {\n ' + decl + '\n'
                   f' DriverManager.getConnection(url, "app", {name})\n'
                   f' DriverManager.getConnection(url, "audit", {name})\n}}')
            with self.subTest(decl=decl):
                self.check("Db.kt", src, [(3, "password")])
        for branch in [
            'for (piece in inputs) { h.setPassword(piece) }',
            'inputs.forEach { piece -> h.setPassword(piece) }',
            'run { val piece = inputs.first(); h.setPassword(piece) }',
        ]:
            src = ('import com.zaxxer.hikari.HikariConfig\nfun make(h: HikariConfig, inputs: List<String>) {\n'
                   ' val piece = "fixture"\n ' + branch + '\n}')
            with self.subTest(branch=branch):
                self.check("Db.kt", src, [])
