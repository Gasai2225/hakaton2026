"""Independent Kotlin/Spring/Gradle examples. Only the static scanners see the sources."""
import unittest
from unittest.mock import patch

from garden.models import Source
from garden.scanners import analyze, scan
from garden.submission import row


def findings(kind, path, text, *support):
    hits, _ = scan(kind, [Source(path=path, text=text), *support], "*")
    return [row(hit) for hit in hits]


class KotlinVariants(unittest.TestCase):
    def test_formatted_sql_tracks_only_inserted_text(self):
        for expression, jdbc_args, expected in [
            ('"SELECT title FROM books ORDER BY %s".format(term.trim())', "query", True),
            ('String.format("SELECT %S", term)', "query", True),
            ('java.lang.String.format(Locale.ROOT, fmt, term)', "query", True),
            ('fmt.format(Locale.ROOT, term)', "query", True),
            ('fmt.format(Locale.getDefault(), term)', "query", True),
            ('"SELECT " + "%s".format(term)', "query", True),
            (r'"SELECT %2\$s".format("title", term)', "query", True),
            (r'"SELECT %2\$s, %<s".format(term, "title")', "query", False),
            (r'"SELECT %2\$s, %s".format(term, "title")', "query", True),
            ('"SELECT %s WHERE title = ?".format("title", term)', "query, term", False),
            ('"SELECT \'%%s\'%n".format(term)', "query", False),
            ('"SELECT %.0s".format(term)', "query", False),
            ('"SELECT %h".format(term)', "query", False),
            ('"SELECT %d, %s".format(term, term)', "query", False),
            ('"SELECT %03d, %-8.3S".format(2, term)', "query", True),
            (r'"SELECT %9\$s".format(term)', "query", False),
            ('"label=%s".format(term)', "query", False),
        ]:
            with self.subTest(expression=expression):
                code = ('import org.springframework.jdbc.core.JdbcTemplate\nimport java.util.Locale\n'
                        'fun list(db: JdbcTemplate, @RequestParam term: String) {\n'
                        ' val fmt = "SELECT title FROM books ORDER BY %s"\n'
                        f' val query = {expression}\n db.queryForList({jdbc_args})\n}}')
                rows = findings("sast", "Catalog.kt", code)
                self.assertEqual([(r["class"], r["line"]) for r in rows], [("sql-injection", 6)] if expected else [])

    def test_custom_format_and_jdbc_binding_are_clean(self):
        for declaration, expression in [
            ('import sample.format\n', '"SELECT %s".format(term)'),
            ('private fun String.format(term: String) = "SELECT 1"\n', '"SELECT %s".format(term)'),
            ('import demo.String as TextFactory\n', 'TextFactory.format("SELECT %s", term)'),
            ('', 'renderer.format("SELECT %s", term)'),
            ('', 'java.lang.String.format("SELECT %s", "title")'),
        ]:
            with self.subTest(declaration=declaration, expression=expression):
                code = ('import org.springframework.jdbc.core.JdbcTemplate\n' + declaration +
                        'fun list(db: JdbcTemplate, @RequestParam term: String) {\n'
                        f' db.queryForList({expression}, term)\n}}')
                self.assertEqual(findings("sast", "Catalog.kt", code), [])

    def test_formatted_jpql_through_a_helper(self):
        src = '''import jakarta.persistence.EntityManager
import java.util.Locale as Language
import kotlin.text.format as render
private fun statement(text: String) = "SELECT b FROM Book b ORDER BY %s".render(text)
fun read(em: EntityManager, @RequestParam term: String, loc: Language) {
    em.createQuery(statement(term))
    em.createQuery("SELECT b FROM Book b ORDER BY %s".render(loc, term))
    em.createQuery("SELECT b FROM Book b WHERE b.title = :title".render(loc, term)).setParameter("title", term)
}'''
        rows = findings("sast", "Books.kt", src)
        self.assertEqual([(r["class"], r["line"]) for r in rows], [("sql-injection", 6), ("sql-injection", 7)])

    def test_format_in_multiline_kotlin_queries(self):
        src = '''import org.springframework.jdbc.core.simple.JdbcClient
fun read(client: JdbcClient, @RequestParam term: String) {
    val pattern = """
        |SELECT title FROM books
        |ORDER BY %2${'$'}s
    """.trimMargin()
    client.sql(pattern.format("title", term))
    client.sql(pattern.format(term, "title"))
    client.sql("""SELECT %s""".trimIndent().format(term))
}'''
        self.assertEqual([r["line"] for r in findings("sast", "Books.kt", src)], [7, 9])

    def test_sql_built_with_kotlin_append(self):
        for builder, statements, arguments, expected in [
            ("buildString", 'append("SELECT title FROM books WHERE title = "); append(term)', "query", True),
            ("buildString", 'appendLine("SELECT title FROM books WHERE title = ?")', "query, term", False),
            ("kotlin.text.buildString(64)", 'this.append("SELECT ").append(term.trim())', "query", True),
            ("assemble", 'appendLine(); append("SELECT "); appendLine(term)', "query", True),
            ("buildString", 'append("SELECT "); if (term.isNotBlank()) { append(term) }', "query", True),
            ("buildString", 'append("SELECT "); if (term.isNotBlank()) append("1") else append("2")', "query", False),
            ("buildString", 'append("SELECT "); if (false) append(term) else append("1")', "query", False),
            ("buildString", 'val term = "title"; append("SELECT "); append(term)', "query", False),
            ("buildString", 'val part = term.trim(); append("SELECT "); append(part)', "query", True),
            ("buildString", 'append("SELECT ?"); audit.append(term)', "query, term", False),
            ("buildString", 'append("SELECT "); append(term); clear(); append("SELECT 1")', "query", False),
            ("buildString", 'append("SELECT "); append(term); val reset = clear(); append("SELECT 1")', "query", False),
            ("buildString", 'append("SELECT "); append(term); append(clear().toString())', "query", False),
            ("buildString", 'append("Report: "); append("SELECT "); append(term)', "query", False),
            ("buildString", 'append(term)', '"SELECT " + query', True),
        ]:
            with self.subTest(builder=builder, statements=statements, arguments=arguments):
                src = ('import org.springframework.jdbc.core.JdbcTemplate\nimport kotlin.text.buildString as assemble\n'
                       'class Library(val db: JdbcTemplate) {\n fun search(@RequestParam term: String, audit: StringBuilder) {\n'
                       f'  val query = {builder} {{ {statements} }}\n  db.queryForList({arguments})\n }}\n}}')
                rows = findings("sast", "Library.kt", src)
                self.assertEqual([(r["class"], r["line"]) for r in rows], [("sql-injection", 6)] if expected else [])

    def test_custom_build_string_is_not_a_kotlin_builder(self):
        for prefix, factory in [
            ("import sample.render.buildString\n", "buildString"),
            ("", "renderer.buildString"),
            ('private fun buildString(block: StringBuilder.() -> Unit) = "SELECT 1"\n', "buildString"),
        ]:
            with self.subTest(prefix=prefix, factory=factory):
                src = ('import org.springframework.jdbc.core.JdbcTemplate\n' + prefix +
                       'fun search(db: JdbcTemplate, @RequestParam term: String) {\n'
                       f' val sql = {factory} {{ append("SELECT "); append(term) }}\n db.queryForList(sql)\n}}')
                self.assertEqual(findings("sast", "Library.kt", src), [])

    def test_append_shadowed_by_a_local_function(self):
        src = '''import org.springframework.jdbc.core.JdbcTemplate
fun search(db: JdbcTemplate, @RequestParam term: String) {
 fun append(text: String) = Unit
 val query = buildString { this.append("SELECT 1"); append(term) }
 db.queryForList(query)
}'''
        self.assertEqual(findings("sast", "Library.kt", src), [])

    def test_inline_builder_at_typed_database_calls(self):
        for typ, method in [("org.springframework.jdbc.core.simple.JdbcClient", "sql"),
                            ("jakarta.persistence.EntityManager", "createQuery"), ("example.View", "sql")]:
            with self.subTest(typ=typ):
                src = (f'import {typ} as Target\nfun search(db: Target, @RequestParam term: String) {{\n'
                       f' db.{method}(buildString {{ append("SELECT "); append(term) }})\n}}')
                self.assertEqual([r["line"] for r in findings("sast", "Inline.kt", src)],
                                 [] if typ == "example.View" else [3])

    def test_sql_through_a_private_helper(self):
        for helper, query, expected in [
            ("= term.trim()", '"SELECT label FROM items WHERE label = " + label(input)', True),
            ("{ return term.trim() }", '"SELECT label FROM items WHERE label = ${label(input)}"', True),
            ("= term.trim()", '"SELECT label FROM items WHERE label = ?", label(input)', False),
            ('= "fixed"', '"SELECT label FROM items WHERE label = " + label(input)', False),
            ("= label(term)", '"SELECT label FROM items WHERE label = " + label(input)', False),
            ("= term.trim()\n private fun label(term: Int) = term.toString()", '"SELECT " + label(input)', False),
        ]:
            with self.subTest(helper=helper, query=query):
                src = ('import org.springframework.jdbc.core.JdbcTemplate\nclass Items(val db: JdbcTemplate) {\n'
                       ' private fun label(term: String): String ' + helper + '\n'
                       ' fun get(@RequestParam input: String) {\n  db.queryForList(' + query + ')\n }\n}')
                rows = findings("sast", "Items.kt", src)
                self.assertEqual([(r["class"], r["line"]) for r in rows], [("sql-injection", 5)] if expected else [])

    def test_secret_used_only_as_an_environment_name(self):
        for use, expected in [
            ("System.getenv(ENV_API_KEY)", False),
            ("java.lang.System.getenv(ENV_API_KEY)", False),
            ("headers.setBearerAuth(ENV_API_KEY)", True),
            ("System.getenv(ENV_API_KEY); headers.setBearerAuth(ENV_API_KEY)", True),
            ('System.getenv(ENV_API_KEY); emit("value=$ENV_API_KEY")', True),
            ("System.getenv(ENV_API_KEY); emit(ENV_API_KEY)", True),
            ("custom.getenv(ENV_API_KEY)", True),
            ("", True),
        ]:
            with self.subTest(use=use):
                src = ('import org.springframework.http.HttpHeaders\nprivate const val ENV_API_KEY = "CATALOG_API_KEY"\n'
                       'fun use(headers: HttpHeaders) { ' + use + ' }')
                rows = findings("secrets", "Config.kt", src)
                self.assertEqual([(r["class"], r["line"]) for r in rows], [("api-key", 2)] if expected else [])

    def test_secret_name_uses_respect_visibility_and_shadowing(self):
        for code, lines in [
            ('fun read() {\n val apiKey = "MY_SETTING"\n System.getenv(apiKey)\n}', []),
            ('val apiKey = "MY_SETTING"\nfun read() = System.getenv(apiKey)', [1]),
            ('fun read(System: Labels) {\n val apiKey = "MY_SETTING"\n System.getenv(apiKey)\n}', [2]),
            ('import display.System\nprivate val apiKey = "MY_SETTING"\nfun read() = System.getenv(apiKey)', [2]),
            ('fun read() {\n val apiKey = "MY_SETTING"\n run { val apiKey = loadKey(); System.getenv(apiKey) }\n}', [2]),
        ]:
            with self.subTest(code=code):
                self.assertEqual([r["line"] for r in findings("secrets", "Env.kt", code)], lines)

    def test_sql_local_function_shadows_the_class_method(self):
        for result, expected in [('term.trim()', True), ('"constant"', False)]:
            with self.subTest(result=result):
                src = ('import org.springframework.jdbc.core.JdbcTemplate\nclass Items(val db: JdbcTemplate) {\n'
                       ' private fun label(term: String) = term.trim()\n fun get(@RequestParam input: String) {\n'
                       '  fun label(term: String) = ' + result + '\n  db.queryForList("SELECT " + label(input))\n }\n}')
                self.assertEqual([r["line"] for r in findings("sast", "Items.kt", src)], [6] if expected else [])

    def test_bearer_auth_requires_a_spring_receiver(self):
        src = '''import org.springframework.http.HttpHeaders as Headers
class Labels {
    fun setBearerAuth(caption: String) = caption
}
fun write(headers: Headers?, labels: Labels) {
    val caption = "display-" + "only"
    labels.setBearerAuth("a heading")
    val heading = "another-" + "heading"
    labels.setBearerAuth(heading)
    headers?.setBearerAuth("fixture-only")
    Headers().apply { setBearerAuth(caption) }
    labels.apply { setBearerAuth("another heading") }
    run {
        val headers = Labels()
        headers.setBearerAuth("local heading")
    }
}'''
        rows = findings("secrets", "Writer.kt", src)
        self.assertCountEqual([(r["class"], r["line"]) for r in rows],
                              [("configuration-token", 10), ("recoverable-token", 6)])
        for receiver, expected in [("org.springframework.http.HttpHeaders()", True), ("Labels()", False)]:
            with self.subTest(receiver=receiver):
                src = 'fun write() = ' + receiver + '.setBearerAuth("fixture-only")'
                rows = findings("secrets", "Writer.kt", src)
                self.assertEqual([r["class"] for r in rows], ["configuration-token"] if expected else [])

    def test_bearer_receiver_in_fields_and_lambdas(self):
        src = '''import org.springframework.http.HttpHeaders as Headers
class Writer(private val labels: Labels) {
    val field = Headers()
    fun write(field: Labels) {
        this.field.setBearerAuth("fixture")
        field.setBearerAuth("heading")
        this.field.also { it.setBearerAuth("fixture") }
        Headers().also { h -> h.setBearerAuth("fixture") }
        labels.also { h -> h.setBearerAuth("heading") }
        Headers().apply { labels.apply { setBearerAuth("heading") } }
    }
}'''
        self.assertEqual([r["line"] for r in findings("secrets", "Writer.kt", src)], [5, 7, 8])
        local_type = '''import org.springframework.http.*
class HttpHeaders {
    fun setBearerAuth(caption: String) = caption
}
fun write(labels: HttpHeaders) = labels.setBearerAuth("heading")
'''
        self.assertEqual(findings("secrets", "Writer.kt", local_type), [])

    def test_api_key_header_uses_the_visible_receiver_type(self):
        src = '''import org.springframework.http.HttpHeaders as Headers
class Export(private val sink: Headers) {
    fun build() {
        sink.add("x-api-key", "training-only")
        run {
            val sink = mutableMapOf<String, String>()
            sink.set("x-api-key", "column label")
        }
        val h = Headers()
        h.set("X-API-KEY", "training-only-local")
    }
    fun renamed(sink: MutableMap<String, String>) {
        sink.set("x-api-key", "field name")
    }
}'''
        rows = findings("secrets", "Export.kt", src)
        self.assertEqual([(r["class"], r["line"]) for r in rows], [("api-key", 4), ("api-key", 10)])
        self.assertNotIn("training-only", str(rows))

    def test_sql_parameter_annotation_origin(self):
        for path, expected in [("org.springframework.web.bind.annotation.RequestHeader", 1),
                               ("example.display.RequestParam", 0)]:
            with self.subTest(path=path):
                src = ('import org.springframework.jdbc.core.JdbcTemplate\nimport ' + path + ' as RequestParam\n'
                       'class Listing(val db: JdbcTemplate) {\n fun list(@RequestParam name: String) =\n'
                       ' db.queryForList("SELECT title FROM books WHERE title = \'$name\'")\n}')
                self.assertEqual(len(findings("sast", "Listing.kt", src)), expected)

    def test_jvm_property_credential_defaults(self):
        for expression, count in [
            ('java.lang.System.getProperty("lab.key", "fixture-only")', 1),
            ('System.getProperty("lab.key", System.getenv("LAB_BACKUP"))', 0),
            ('System.getProperty("lab.key") ?: "  "', 0),
            ('example.getProperty("lab.key", "fixture-only")', 0),
        ]:
            with self.subTest(expression=expression):
                rows = findings("secrets", "Lab.kt", 'val apiKey = ' + expression)
                self.assertEqual([r["class"] for r in rows], ["secret-fallback"] * count)
                self.assertNotIn("fixture-only", str(rows))

    def test_spring_value_fallback(self):
        for annotation, expression, expected in [
            ("Setting", r'"\${auth.api-key:fixture-only}"', True),
            ("param:Setting", r'"\${auth.api-key:\${BACKUP:fixture-only}}"', True),
            ("org.springframework.beans.factory.annotation.Value", r'"\${auth.token:fixture-only}"', True),
            ("Setting", r'"\${auth.api-key:\${BACKUP}}"', False),
            ("Setting", r'"\${auth.api-key:}"', False),
            ("Setting", r'"\${auth.api-key:#{null}}"', False),
            ("Setting", "\"\"\"${'$'}{auth.api-key:fixture-only}\"\"\"", True),
            ("Setting", r'"\${client.label:fixture-only}"', False),
            ("Value", r'"\${auth.api-key:fixture-only}"', False),
        ]:
            with self.subTest(annotation=annotation, expression=expression):
                code = ('import org.springframework.beans.factory.annotation.Value as Setting\n'
                        'import example.Value\nclass Config(\n    @' + annotation + '(' + expression + ') val v: String\n)')
                rows = findings("secrets", "Config.kt", code)
                self.assertEqual([(r["class"], r["line"]) for r in rows], [("secret-fallback", 4)] if expected else [])
                self.assertNotIn("fixture-only", str(rows))

    def test_kotlin_authorize_dsl_and_matcher_scope(self):
        for registry, first, second, expected in [
            ("authorizeHttpRequests", 'authorize(HttpMethod.GET, "/notes/view", permitAll)',
             'authorize("/notes/**", hasRole("STAFF"))', True),
            ("authorizeHttpRequests", 'authorize(HttpMethod.POST, "/notes/view", permitAll)',
             'authorize(HttpMethod.GET, "/notes/**", authenticated)', False),
            ("authorizeHttpRequests", 'authorize("/notes/**", "/app", permitAll)',
             'authorize("/notes/view", "/other", authenticated)', False),
            ("authorizeHttpRequests", 'authorize("/notes/**", "/app", permitAll)',
             'authorize("/notes/view", "/app", authenticated)', True),
            ("authorizeHttpRequests", 'authorize("/notes/**", authenticated)',
             'authorize("/notes/view", permitAll)', False),
            ("authorizeHttpRequests", 'authorize("/notes/**", authenticated)\nauthorize("/notes/view", permitAll)',
             'authorize("/notes/view", hasRole("STAFF"))', False),
            ("authorizeHttpRequests", 'authorize(HttpMethod.GET, "/notes/**", authenticated)\nauthorize("/notes/**", permitAll)',
             'authorize(HttpMethod.GET, "/notes/view", hasRole("STAFF"))', False),
            ("authorizeHttpRequests", 'it.requestMatchers("/a", "/b", "/c", "/d", "/notes/**").permitAll()',
             'it.requestMatchers("/notes/view").authenticated()', True),
            ("also", 'it.requestMatchers("/notes/**").permitAll()',
             'it.requestMatchers("/notes/view").authenticated()', False),
        ]:
            with self.subTest(first=first, second=second):
                if first.startswith("authorize("):
                    block = 'http { authorizeHttpRequests {\n' + first + '\n' + second + '\n} }'
                else:
                    block = 'http.' + registry + ' {\n' + first + '\n' + second + '\n}'
                code = ('import org.springframework.security.config.annotation.web.builders.HttpSecurity\n'
                        'import org.springframework.security.config.annotation.web.invoke\n'
                        'fun rules(http: HttpSecurity) { ' + block + ' }')
                rows = findings("sast", "Web.kt", code)
                self.assertEqual([(r["class"], r["line"]) for r in rows], [("route-authorization", 4)] if expected else [])

    def test_direct_owner_read_and_checked_handler(self):
        repo = Source(path="Store.kt", text='''package demo.data
@Repository class Store(val db: JdbcTemplate) {
 fun find(k: Long) = db.queryForMap("SELECT title, owner_id FROM notes WHERE id = ?", k)
}''')
        for body, expected in [
            ("return ResponseEntity.ok(store.find(key))", True),
            ("require(owns(key, principal)); return ResponseEntity.ok(store.find(key))", False),
            ("return ResponseEntity.ok(store.find(currentAccountRecord(principal)))", False),
        ]:
            with self.subTest(body=body):
                src = ('package demo.web\nimport demo.data.*\n@RestController class Notes(val store: Store) {\n'
                       '@RequestMapping(method = [RequestMethod.GET]) fun get(@PathVariable key: Long, principal: Principal) {\n'
                       + body + '\n}\n}')
                rows = findings("sast", "Notes.kt", src, repo)
                self.assertEqual([r["class"] for r in rows], ["object-authorization"] if expected else [])

    def test_owner_read_under_spring_method_security(self):
        security = "org.springframework.security.access.prepost"
        login = '@PreAuthorize("isAuthenticated()")'
        owns = '@PreAuthorize("isAuthenticated() and @access.owns(#id, authentication)")'
        post = '@PostAuthorize("returnObject.owner == authentication.name")'
        for on_class, on_handler, on_reader, read, expected in [
            ("", login, "", "find(id)", True),
            (login, "", "", "find(id)", True),
            ("", "", login, "find(id)", True),
            (owns, login, "", "find(id)", True),
            (login, owns, "", "find(id)", False),
            (post, login, "", "find(id)", False),
            ("", f'@{security}.PreAuthorize("isAuthenticated()")', "", "find(id)", True),
            ("", '@Check(value = " isAuthenticated( ) ")', "", "find(id)", True),
            ("", '@Check("isAuthenticated() and @access.owns(#id, authentication)")', "", "find(id)", False),
            ("", '@PreAuthorize(ACCESS_POLICY)', "", "find(id)", False),
            ("", login, post, "find(id)", False),
            ("", login, "", "owned(id, principal.name)", False),
        ]:
            with self.subTest(on_class=on_class, on_handler=on_handler, on_reader=on_reader, read=read):
                repo = Source(path="Store.kt", text=f'''package demo
import {security}.*
@Repository class Store(val db: JdbcTemplate) {{
 {on_reader} fun find(id: Long) = db.queryForMap("SELECT owner_id FROM notes WHERE id = ?", id)
 fun owned(id: Long, name: String) = db.queryForMap("SELECT owner_id FROM notes WHERE id = ? AND owner_id = ?", id, name)
}}''')
                src = f'''package demo
import {security}.*
import {security}.PreAuthorize as Check
{on_class} @RestController class Notes(val store: Store) {{
 {on_handler} @GetMapping("/notes/{{id}}")
 fun get(@PathVariable id: Long, principal: Principal) = store.{read}
}}'''
                rows = findings("sast", "Notes.kt", src, repo)
                self.assertEqual([(r["class"], r["line"]) for r in rows],
                                 [("object-authorization", 6)] if expected else [])

    def test_cors_receivers_and_overrides(self):
        for settings, vulnerable in [
            ('val c = CorsConfiguration().apply { setAllowCredentials(true); addAllowedOriginPattern("*") }', True),
            ('val c = CorsConfiguration().also { cfg -> cfg.allowedOriginPatterns = listOf("*"); cfg.allowCredentials = true }', True),
            ('val c = CorsConfiguration(); c.setAllowedOriginPatterns(listOf("*")); c.allowCredentials = true', True),
            ('val c = CorsConfiguration().apply { allowedOriginPatterns = listOf("*"); allowCredentials = true; allowCredentials = false }', False),
            ('val c = CorsConfiguration().apply { allowedOriginPatterns = listOf("*"); allowCredentials = true; allowedOriginPatterns = listOf("https://local.test") }', False),
            ('val c = CorsConfiguration(); val d = CorsConfiguration(); c.addAllowedOriginPattern("*"); d.allowCredentials = true', False),
        ]:
            with self.subTest(settings=settings):
                src = 'import org.springframework.web.cors.CorsConfiguration\nfun configure() { ' + settings + ' }'
                self.assertEqual([r["class"] for r in findings("sast", "Cors.kt", src)], ["credentialed-cors"] if vulnerable else [])

    def test_authorization_order(self):
        for first, second, expected in [
            ('"/reports/**"', '"/reports/private"', True),
            ('GET, "/reports/**"', 'POST, "/reports/private"', False),
            ('"/reports/**"', '"/reports-v2/private"', False),
            ('"/health"', '"/**"', False),
        ]:
            with self.subTest(first=first, second=second):
                src = ('import org.springframework.security.config.annotation.web.builders.HttpSecurity\n'
                       'fun rules(http: HttpSecurity) { http.authorizeHttpRequests { rules ->\n'
                       f'rules.requestMatchers({first}).permitAll()\nrules.requestMatchers({second}).authenticated()\n'
                       '} }')
                self.assertEqual([(r["class"], r["line"]) for r in findings("sast", "Web.kt", src)],
                                 [("route-authorization", 3)] if expected else [])

    def test_hostname_verifier_setter(self):
        for body, expected in [("true", True), ("host == expected", False)]:
            with self.subTest(body=body):
                src = ('import javax.net.ssl.HttpsURLConnection\nfun configure(conn: HttpsURLConnection) {\n'
                       ' conn.setHostnameVerifier { host, session -> ' + body + ' }\n}')
                self.assertEqual([r["class"] for r in findings("sast", "Network.kt", src)], ["tls-verification"] if expected else [])

    def test_jdbc_argument_flow(self):
        for method in ("queryForList", "queryForMap", "update"):
            for expr, args, expected in [
                ('"SELECT label FROM items WHERE label = " + part', 'query', True),
                ('"""SELECT label FROM items WHERE label = $part""".trimIndent()', 'query', True),
                ('"SELECT label FROM items WHERE label = ?"', 'query, part', False),
                ('"SELECT label FROM items WHERE label = :label"', 'query, mapOf("label" to part)', False),
                ('"SELECT label FROM items WHERE id = " + id', 'query', False),
            ]:
                with self.subTest(method=method, expr=expr):
                    src = ('import org.springframework.jdbc.core.JdbcTemplate\n'
                           'class Items(val db: JdbcTemplate) {\n'
                           ' fun list(@RequestParam input: String, @RequestParam id: Int) {\n'
                           '  val part = input.trim()\n  val query = ' + expr + '\n'
                           '  db.' + method + '(' + args + ')\n }\n}')
                    rows = findings("sast", "Items.kt", src)
                    self.assertEqual([(r["class"], r["line"]) for r in rows], [("sql-injection", 6)] if expected else [])

    def test_parameter_shadow(self):
        src = '''import org.springframework.jdbc.core.JdbcTemplate
class Report(val db: JdbcTemplate) {
 fun list(@RequestParam term: String) {
   run { val term = "internal"; db.queryForList("SELECT $term FROM items") }
   db.queryForList("SELECT $term FROM items")
 }
}'''
        self.assertEqual([(r["class"], r["line"]) for r in findings("sast", "Report.kt", src)], [("sql-injection", 5)])

    def test_named_parameter_template_and_import_alias(self):
        src = '''import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate as Database
class Names(val db: Database) {
 fun get(@RequestHeader who: String) {
  val stmt = "SELECT name FROM users WHERE name = $who"
  db.queryForMap(stmt, emptyMap())
  db.queryForMap("SELECT name FROM users WHERE name = :name", mapOf("name" to who))
 }
}'''
        self.assertEqual([(r["class"], r["line"]) for r in findings("sast", "Names.kt", src)], [("sql-injection", 5)])

    def test_spring_authentication_arguments(self):
        for call, classification in [
            ('h.setBearerAuth("fixture-only")', "configuration-token"),
            ('h.setBasicAuth("user", "fixture-only")', "password"),
            ('h.setBearerAuth(System.getenv("ACCESS"))', None),
            ('h.setBasicAuth("user", external)', None),
        ]:
            with self.subTest(call=call):
                src = 'import org.springframework.http.HttpHeaders\nfun headers(h: HttpHeaders, external: String) {\n' + call + '\n}'
                rows = findings("secrets", "Headers.kt", src)
                self.assertEqual([r["class"] for r in rows], [classification] if classification else [])
                self.assertNotIn("fixture-only", str(rows))

    def test_basic_auth_overloads_select_the_credential_argument(self):
        for call, expected in [
            ('h.setBasicAuth("dHJhaW5pbmc6ZGVtbw==")', "recoverable-token"),
            ('h.setBasicAuth(user.trim(), "fixture-only")', "password"),
            ('h.setBasicAuth(user.trim(), "fixture-only", Charsets.UTF_8)', "password"),
            ('Headers().apply { setBasicAuth(user, "fixture-only", Charsets.UTF_8) }', "password"),
            ('h.setBasicAuth("fixed-user", external, Charsets.UTF_8)', None),
            ('h.setBasicAuth(System.getenv("BASIC_CREDENTIALS"))', None),
            ('h.setBasicAuth(user, System.getenv("BASIC_PASSWORD"), Charsets.UTF_8)', None),
            ('h.setBasicAuth("example label")', None),
            ('h.setBasicAuth("dHJhaW5pbmc6")', None),  # Empty password.
        ]:
            with self.subTest(call=call):
                src = ('import org.springframework.http.HttpHeaders as Headers\n'
                       'fun write(h: Headers, user: String, external: String) {\n' + call + '\n}')
                rows = findings("secrets", "Client.kt", src)
                self.assertEqual([(r["class"], r["line"]) for r in rows], [(expected, 3)] if expected else [])
                self.assertNotIn("fixture-only", str(rows))
                self.assertNotIn("dHJhaW5pbmc6ZGVtbw==", str(rows))

    def test_basic_auth_only_trusts_the_visible_spring_receiver(self):
        src = '''import org.springframework.http.HttpHeaders
class Labels {
    fun setBasicAuth(left: String, right: String) = left + right
}
fun write(h: HttpHeaders, labels: Labels) {
    val caption = "column-" + "title"
    labels.setBasicAuth("left", "right")
    labels.setBasicAuth("left", caption)
    val stored = "fixture-only"
    h.setBasicAuth("user", stored, Charsets.UTF_8)
    run {
        val h = Labels()
        h.setBasicAuth("left", "right")
    }
}'''
        rows = findings("secrets", "Client.kt", src)
        self.assertEqual([(r["class"], r["line"]) for r in rows], [("password", 9)])
        qualified = 'fun write(h: org.springframework.http.HttpHeaders) = h.setBasicAuth("user", "fixture-only")'
        self.assertEqual([r["class"] for r in findings("secrets", "Client.kt", qualified)], ["password"])

    def test_basic_auth_resolves_the_visible_encoded_value(self):
        src = '''import org.springframework.http.HttpHeaders
fun write(h: HttpHeaders, inputs: List<String>) {
    val saved = "dHJhaW5pbmc6ZGVtbw=="
    h.setBasicAuth(saved)
    h.setBasicAuth(saved)
    val field = "dHJhaW5pbmc6ZGVtbw=="
    inputs.forEach { field -> h.setBasicAuth(field) }
}'''
        rows = findings("secrets", "Client.kt", src)
        self.assertEqual([(r["class"], r["line"]) for r in rows], [("recoverable-token", 3)])

    def test_kotlin_credentials(self):
        for rhs, expected in [
            ('/* source */ "fixture-only"', "api-key"),
            ('System.getenv("ACCESS") ?: "fixture-only"', "secret-fallback"),
            ('System.getenv("ACCESS") ?: error("missing")', None),
            ('"prefix-" + System.getenv("ACCESS")', None),
            ('"fixture" + "-only"', "recoverable-token"),
            ('System.getenv("ACCESS")', None),
        ]:
            with self.subTest(rhs=rhs):
                rows = findings("secrets", "Config.kt", 'val apiKey: String = ' + rhs)
                self.assertEqual([r["class"] for r in rows], [expected] if expected else [])
                self.assertNotIn("fixture", str(rows))

    def test_multiline_spring_properties_keep_the_key_location(self):
        slash = chr(92)
        src = "\r\n".join([
            "# ignored " + slash, "  api-" + slash, "    key=fixture-only",
            "password=" + slash, "    ${DB_PASSWORD}",
            "service.token=\u0024{TOKEN:" + slash, "    fixture-only}",
            "example=literal" + slash * 2, "secret=fixture-only",
            "manual=some text" + slash, "    password=fixture-only",
        ])
        rows = findings("secrets", "application.properties", src)
        self.assertEqual([(r["line"], r["class"]) for r in rows],
                         [(2, "api-key"), (6, "secret-fallback"), (9, "embedded-secret")])
        self.assertNotIn("fixture-only", str(rows))

    def test_config_defaults_and_yaml_positions(self):
        for path in ("application-dev.properties", "application-prod.yaml"):
            for value, expected in [
                ("${PRIMARY}", None), ("${PRIMARY:}", None), ("${PRIMARY:${BACKUP}}", None),
                ("${PRIMARY:fixture-only}", "secret-fallback"),
                ("${PRIMARY:${BACKUP:fixture-only}}", "secret-fallback"),
            ]:
                with self.subTest(path=path, value=value):
                    sep = "=" if path.endswith("properties") else ": "
                    rows = findings("secrets", path, "# ignored\nclient.api-key" + sep + value)
                    self.assertEqual([(r["class"], r["line"]) for r in rows], [(expected, 2)] if expected else [])
                    self.assertNotIn("fixture-only", str(rows))
        yaml = 'description: |\n  password: fixture-only\n"api-key": |\n  fixture-only\n'
        self.assertEqual([(r["class"], r["line"]) for r in findings("secrets", "app.yml", yaml)], [("api-key", 3)])


@patch.dict("os.environ", {"GARDEN_EXTENDED_SCA": "1"})
class GradleVariants(unittest.TestCase):
    def test_direct_versions_are_scoped_to_the_locked_classpath(self):
        module = "org.apache.commons:commons-text"
        build = Source(path="build.gradle.kts", text=f'''dependencies {{
 compileOnly("{module}")
 add("runtimeOnly", "{module}")
 implementation("{module}")
 testCompileOnly("{module}:1.10.0")
}}''')
        lock = Source(path="gradle.lockfile", text=f"{module}:1.9=runtimeClasspath\n{module}:1.10.0=compileClasspath")
        for extended in ("0", "1"):
            with self.subTest(extended=extended), patch.dict("os.environ", {"GARDEN_EXTENDED_SCA": extended}):
                result = analyze("sca", [build, lock], "*")
                self.assertEqual([(p.line, p.version, p.status, p.source) for p in result.packages], [
                    (2, "1.10.0", "checked", "gradle.lockfile"), (3, "1.9", "checked", "gradle.lockfile"),
                    (4, None, "unresolved", "gradle.lockfile"), (5, "1.10.0", "checked", "declaration")])
                self.assertEqual([(f.line, f.dependency.version, f.advisory) for f in result.findings],
                                 [(3, "1.9", "CVE-2022-42889")])
                self.assertEqual(len(result.issues), 1)

    def test_conflicting_rows_in_one_lock_configuration_stay_unresolved(self):
        module = "org.apache.commons:commons-text"
        build = Source(path="build.gradle.kts", text=f'dependencies {{ runtimeOnly("{module}:1.9") }}')
        for second, expected in [("1.9", "1.9"), ("1.10.0", None)]:
            with self.subTest(second=second):
                lock = Source(path="gradle.lockfile", text=f"{module}:1.9=testRuntimeClasspath,runtimeClasspath\n"
                              f"{module}:{second}=runtimeClasspath")
                result = analyze("sca", [lock, build], "*")
                self.assertEqual([p.version for p in result.packages], [expected])
                self.assertEqual(bool(result.findings), expected is not None)
                self.assertEqual(bool(result.issues), expected is None)

    def test_project_property_versions_and_fallback(self):
        for expression, properties, expected in [
            ('project.findProperty("v") as? String ?: "1.9"', "", "1.9"),
            ('project.findProperty("v") as? String ?: "1.9"', "v=1.10.0", "1.10.0"),
            ('project.property("v") as String', "v=1.9", "1.9"),
            ('(project.property("v") as String).reversed()', "v=1.9", None),
        ]:
            with self.subTest(expression=expression, properties=properties):
                build = Source(path="build.gradle.kts", text='val release = ' + expression +
                               '\ndependencies { implementation("org.apache.commons:commons-text:$release") }')
                result = analyze("sca", [build, Source(path="gradle.properties", text=properties)], "*")
                self.assertEqual(len(result.packages), 1)
                package = result.packages[0]
                self.assertEqual(package.status, "checked" if expected else "unresolved")
                if expected:
                    self.assertEqual(package.version, expected)
                self.assertEqual([f.advisory for f in result.findings], ["CVE-2022-42889"] if expected == "1.9" else [])

    def test_provider_fallbacks_and_unresolved_transforms(self):
        for expr, props, status, version, count in [
            ('getOrElse("1.9")', "", "checked", "1.9", 1),
            ('orElse("1.9").get()', "release=1.10.0", "checked", "1.10.0", 0),
            ('orElse("1.9").get()', "", "checked", "1.9", 1),
            ('map { "1.10.0" }.get()', "release=1.9", "unresolved", None, 0),
            ('getOrElse("1.9").replace("1.9", "1.10.0")', "release=1.9", "unresolved", None, 0),
            ('get()', "", "unresolved", None, 0),
        ]:
            with self.subTest(expr=expr, props=props):
                build = Source(path="build.gradle.kts", text='val v = providers.gradleProperty("release").' + expr +
                               '\ndependencies { implementation("org.apache.commons:commons-text:$v") }')
                sources = [build, Source(path="gradle.properties", text=props)]
                with patch.dict("os.environ", {"GARDEN_EXTENDED_SCA": "0"}):
                    result = analyze("sca", sources, "*")
                self.assertEqual(len(result.findings), count)
                self.assertEqual(bool(result.issues), status == "unresolved")
                self.assertEqual([p.status for p in result.packages], [status])
                if version:
                    self.assertEqual(result.packages[0].version, version)

    def test_incomplete_analysis_keeps_known_findings(self):
        build = Source(path="build.gradle.kts", text='''dependencies {
 implementation("training.demo:example-lib:1.1")
 runtimeOnly("training.demo:example-lib:1.+")
}''')
        result = analyze("sca", [build], "*")
        self.assertEqual([r.advisory for r in result.findings], ["DEMO-001"])
        self.assertEqual(len(result.issues), 1)
        sources = [Source(path="Malformed.kt", text="fun ("), Source(path="Fine.kt", text='val password = "fixture-only"')]
        result = analyze("secrets", sources, "*")
        self.assertEqual([r.path for r in result.findings], ["Fine.kt"])
        self.assertEqual((result.checked, len(result.issues)), (1, 1))

    def test_alias_bundle_and_lock(self):
        catalog = Source(path="gradle/libs.versions.toml", text='''
[versions]
old = "1.1"
[libraries]
example-core = {module = "training.demo:example-lib", version.ref = "old"}
unused = "training.demo:example-lib:1.0"
[bundles]
legacy = ["example-core"]
''')
        for arg in ["libs.example.core", "libs.bundles.legacy"]:
            for version, count in [("1.1", 1), ("1.2", 0)]:
                with self.subTest(arg=arg, version=version):
                    lock = Source(path="backend/gradle.lockfile", text=f"training.demo:example-lib:{version}=runtimeClasspath")
                    rows = findings("sca", "backend/build.gradle.kts", f"dependencies {{ implementation({arg}) }}", catalog, lock)
                    self.assertEqual([(r["path"], r["version"], r["advisoryId"]) for r in rows],
                                     [("backend/build.gradle.kts", version, "DEMO-001")] * count)
        self.assertEqual(findings("sca", "build.gradle.kts", "dependencies { }", catalog), [])
        self.assertEqual(len(findings("sca", "build.gradle.kts", "dependencies { api(libs.example.core) }", catalog)), 1)

    def test_declarations_and_constraints(self):
        for body, expected in [
            ('api(group = "training.demo", name = "example-lib", version = release)', True),
            ('implementation("training.demo:example-lib:" + release)', True),
            ('constraints { implementation("training.demo:example-lib:1.1") }', False),
            ('implementation("training.demo:example-lib:1.2")', False),
        ]:
            with self.subTest(body=body):
                rows = findings("sca", "build.gradle.kts", 'val release: String = "1.1"\ndependencies { ' + body + ' }')
                self.assertEqual([r["version"] for r in rows], ["1.1"] if expected else [])
