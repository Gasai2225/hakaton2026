import unittest

from garden.models import Source
from garden.scanners import analyze


JDBC = "org.springframework.jdbc.core.JdbcTemplate"
NAMED = "org.springframework.jdbc.core.namedparam.NamedParameterJdbcOperations"
QUERY = "SELECT d.owner_id AS owner, d.title FROM app.docs AS d WHERE d.id = ? LIMIT 1"
SIMPLE = "SELECT owner_id, title FROM docs WHERE id = ?"


def source(name, text):
    return Source(path=name + ".kt", text=text)


def repo(sql=QUERY, *, driver=JDBC, bind="key", extra="", use_this=False):
    field = "this.db" if use_this else "db"
    imported = driver if driver == JDBC else driver + " as Driver"
    typ = "JdbcTemplate" if driver == JDBC else "Driver"
    return source("Docs", f'''package db
import {imported}
import org.springframework.stereotype.Repository
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource
@Repository class Docs(private val db: {typ}) {{
 fun read(key: Long) = {field}.queryForMap("""{sql}""", {bind})
 {extra}
}}''')


def api(*, typ="db.Docs", call="store.read(id)", source_param="PathVariable", extra_import=""):
    return source("Api", f'''package web
import {typ} as Store
import org.springframework.web.bind.annotation.*
{extra_import}
@RestController class Api(private val store: Store) {{
 @GetMapping fun get(@{source_param} id: Long) = {call}
}}''')


class DatabaseOwnership(unittest.TestCase):
    def check(self, files, expected):
        for inputs in (files, list(reversed(files))):
            result = analyze("sast", inputs, "Api.kt")
            self.assertEqual(result.issues, [])
            self.assertEqual([(h.classification, h.path, h.line) for h in result.findings],
                             [("object-authorization", "Api.kt", 6)] if expected else [])

    def test_query_projection_and_restrictions(self):
        for sql, flagged in [
            (QUERY, True), (SIMPLE, True),
            ('SELECT "owner_id", title FROM docs WHERE "id" = ?', True),
            ("SELECT 'owner_id' AS title FROM docs WHERE id = ?", False),
            ("SELECT title AS owner_id FROM docs WHERE id = ?", False),
            ("SELECT COUNT(owner_id) FROM docs WHERE id = ?", False),
            ("SELECT title /* owner_id */ FROM docs WHERE id = ?", False),
            ("SELECT owner_id FROM docs WHERE owner_id = ?", False),
            ("SELECT owner_id FROM docs WHERE id = ? AND public = true", False),
        ]:
            with self.subTest(sql=sql):
                self.check([repo(sql), api()], flagged)

    def test_named_bindings(self):
        sql = QUERY.replace("?", ":lookup")
        for bind, flagged in [
            ('mapOf("lookup" to key)', True), ('MapSqlParameterSource("lookup", key)', True),
            ('mapOf("lookup" to 12L)', False), ('mapOf("other" to key)', False),
        ]:
            with self.subTest(bind=bind):
                self.check([repo(sql, driver=NAMED, bind=bind), api()], flagged)
        reader = repo(sql, driver=NAMED, bind='mapOf("lookup" to key)')
        for modifier, flagged in [("", False), ("private ", True)]:
            with self.subTest(modifier=modifier):
                custom = source("Bindings", "package db\n" + modifier
                                + "infix fun String.to(key: Long) = Pair(this, 1L)")
                self.check([custom, reader, api()], flagged)

    def test_jdbc_client_owner_row(self):
        for driver, query, binding, result, flagged in [
            ("org.springframework.jdbc.core.simple.JdbcClient", QUERY, "key", "singleRow()", True),
            ("org.springframework.jdbc.core.simple.JdbcClient", QUERY, "1, key", "singleRow()", True),
            ("org.springframework.jdbc.core.simple.JdbcClient", QUERY.replace("?", ":lookup"), '"lookup", key', "singleRow()", True),
            ("org.springframework.jdbc.core.simple.JdbcClient", QUERY.replace("?", ":lookup"), '"other", key', "singleRow()", False),
            ("org.springframework.jdbc.core.simple.JdbcClient", QUERY, "2, key", "singleRow()", False),
            ("org.springframework.jdbc.core.simple.JdbcClient", QUERY, "12L", "singleRow()", False),
            ("org.springframework.jdbc.core.simple.JdbcClient", QUERY.replace("d.id =", "d.owner_id ="), "key", "singleRow()", False),
            ("org.springframework.jdbc.core.simple.JdbcClient", SIMPLE, "key", "singleColumn()", False),
            ("example.JdbcClient", QUERY, "key", "singleRow()", False),
        ]:
            with self.subTest(driver=driver, binding=binding, result=result, query=query):
                row = repo(query, driver=driver)
                fluent = row.text.replace('db.queryForMap("""' + query + '""", key)',
                                          'db.sql("""' + query + '""").param(' + binding + ').query().' + result)
                self.check([source("Docs", fluent), api()], flagged)

    def test_static_query_in_repository_local(self):
        declaration = 'val stmt = """' + QUERY + '"""'
        old = 'fun read(key: Long) = db.queryForMap("""' + QUERY + '""", key)'
        for prelude, returned, flagged in [
            (declaration, "db.queryForMap(stmt, key)", True),
            (declaration + "; check(owns(key))", "db.queryForMap(stmt, key)", False),
            ('val stmt = statementsFor(currentUser)', "db.queryForMap(stmt, key)", False),
        ]:
            with self.subTest(prelude=prelude):
                body = 'fun read(key: Long): Map<String, Any> { ' + prelude + '; return ' + returned + ' }'
                self.check([source("Docs", repo().text.replace(old, body)), api()], flagged)

    def test_result_mapper_must_return_row_data(self):
        for mapper, flagged in [
            ('{ row, _ -> row.getString("title") }', True),
            ('{ _, _ -> "public" }', False),
            ('{ row, _ -> if (allowed(row, SecurityContextHolder.getContext())) row.getString("title") else null }', False),
        ]:
            with self.subTest(mapper=mapper):
                old = 'db.queryForMap("""' + QUERY + '""", key)'
                query = 'db.query("""' + QUERY + '""", ' + mapper + ', key).firstOrNull()'
                self.check([source("Docs", repo().text.replace(old, query)), api()], flagged)

    def test_dispatch_and_user_controlled_arguments(self):
        self.check([repo(use_this=True), api(call="this.store.read(key = id)", source_param="RequestParam")], True)
        self.check([repo(), api(source_param="CurrentUser", extra_import="import demo.CurrentUser")], False)
        self.check([repo(SIMPLE, driver="example.JdbcTemplate"), api()], False)
        # An unqualified third-party JdbcTemplate with the same API is not Spring JDBC.
        fake = repo(SIMPLE).text.replace(JDBC, "example.JdbcTemplate")
        self.check([source("Docs", fake), api()], False)
        self.check([repo(extra='fun read(key: String) = "public"'), api()], False)

    def test_transparent_service_chain_and_guards(self):
        bridge = source("Reports", '''package domain
import db.Docs as Rows
import org.springframework.stereotype.Service
@Service class Reports(val rows: Rows) {
 fun lookup(id: Long) = rows.read(key = id)
}''')
        outer = source("Service", '''package web
import domain.Reports
import org.springframework.stereotype.Service
@Service class Feed(val reports: Reports) {
 fun get(num: Long) = reports.lookup(num)
}''')
        controller = api(typ="web.Feed", call="store.get(id)")
        for method, flagged in [
            ("= rows.read(key = id)", True), ("= rows.read(key = 12L)", False),
            ("{ check(owns(id)); return rows.read(id) }", False),
        ]:
            with self.subTest(method=method):
                self.check([repo(), source("Reports", bridge.text.replace("= rows.read(key = id)", method)), outer, controller], flagged)
        guarded = bridge.text.replace("fun lookup", '@org.springframework.security.access.prepost.PreAuthorize("@acl.owns(#id)") fun lookup')
        self.check([repo(), source("Reports", guarded), outer, controller], False)

    def test_branch_through_inherited_http_and_service_contracts(self):
        http = source("Http", '''package web
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.*
interface Http {
 @GetMapping("/{key}")
 fun card(@PathVariable("key") key: Long, @RequestParam("preview") preview: Boolean): ResponseEntity<*>
}''')
        port = source("Gallery", '''package domain
import db.Docs
import org.springframework.stereotype.Service
interface GalleryPort { fun preview(item: Long): Map<String, Any> }
@Service class Gallery(val docs: Docs): GalleryPort {
 override fun preview(record: Long) = docs.read(record)
}''')
        handler = '''package web
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.*
import domain.GalleryPort
@RestController class Api(val gallery: GalleryPort): Http {
 ANNOTATION override fun card(id: Long, include: Boolean): ResponseEntity<*> =
     ResponseEntity.ok(if (CONDITION) gallery.preview(item = id) else null)
 fun owns(id: Long): Boolean = TODO()
}'''
        for annotation, condition, flagged in [
            ("", "include", True),
            ("", "owns(id) && include", False),
            ("", "owns(id) || include", True),
            ('@PostMapping("/{id}")', "include", False),
        ]:
            with self.subTest(annotation=annotation, condition=condition):
                endpoint = source("Api", handler.replace("ANNOTATION", annotation).replace("CONDITION", condition))
                files = [repo(), http, port, endpoint]
                for inputs in (files, list(reversed(files))):
                    result = analyze("sast", inputs, "*")
                    self.assertEqual(result.issues, [])
                    self.assertEqual([(h.classification, h.path, h.line) for h in result.findings],
                                     [("object-authorization", "Api.kt", 7)] if flagged else [])

    def test_identifier_selected_in_a_branch(self):
        handler = api().text.replace(
            '@PathVariable id: Long) = store.read(id)',
            '@PathVariable id: Long, @RequestParam preview: Boolean): Any {\n'
            '  val selected = if (preview) CHOICE else 42L\n  return store.read(key = selected)\n }',
        )
        for choice, flagged in [("id", True), ("12L", False)]:
            with self.subTest(choice=choice):
                result = analyze("sast", [repo(), source("Api", handler.replace("CHOICE", choice))], "*")
                self.assertEqual(result.issues, [])
                self.assertEqual([(h.path, h.line) for h in result.findings], [("Api.kt", 8)] if flagged else [])

    def test_compact_contract_and_real_syntax_error(self):
        good = source("Port", '\n  interface Port { fun get(id: Long): String }\nclass Marker')
        bad = source("Broken", 'interface Port { fun get(id: ): String }\nclass Marker')
        self.assertEqual(analyze("sast", [good], "*").issues, [])
        self.assertEqual(len(analyze("sast", [bad], "*").issues), 1)

    def test_broken_repository_cannot_supply_a_method_to_another_file(self):
        repository = repo()
        controller = api()
        self.check([repository, controller], True)
        repository.text += "\nfun ("
        result = analyze("sast", [repository, controller], "*")
        self.assertEqual(result.issues, ["Ошибка синтаксического разбора Kotlin в Docs.kt"])
        self.assertEqual(result.findings, [])

    def test_shared_inherited_handler_reports_the_declaring_file_once(self):
        parent = source("BaseApi", '''package web
import db.Docs
import org.springframework.web.bind.annotation.*
abstract class BaseApi(private val docs: Docs) {
 @GetMapping fun get(@PathVariable id: Long) = docs.read(id)
}''')
        controllers = source("Apis", '''package web
import db.Docs
import org.springframework.web.bind.annotation.*
@RestController @RequestMapping("/one") class First(docs: Docs): BaseApi(docs)
@RestController @RequestMapping("/two") class Second(docs: Docs): BaseApi(docs)
''')
        for files in ([repo(), parent, controllers], [controllers, parent, repo()]):
            result = analyze("sast", files, "*")
            self.assertEqual(result.issues, [])
            self.assertEqual([(h.path, h.line, h.classification) for h in result.findings],
                             [("BaseApi.kt", 5, "object-authorization")])
