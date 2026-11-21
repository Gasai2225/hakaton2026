import unittest

from garden.models import Source
from garden.scanners import analyze
from garden.submission import row


QUERY = 'internal fun statement(term: String) = "SELECT label FROM entries ORDER BY " + term'
BOUND = 'internal fun statement(term: String) = "SELECT label FROM entries WHERE label = ?"'


def endpoint(package, imports, argument):
    return (f'package {package}\nimport org.springframework.jdbc.core.JdbcTemplate\n'
            'import org.springframework.web.bind.annotation.RequestParam\n' + imports + '\n'
            f'fun list(db: JdbcTemplate, @RequestParam term: String) = db.queryForList({argument})')


class ProjectSql(unittest.TestCase):
    def check(self, files, locations, pattern="*"):
        for order in (files, reversed(files)):
            result = analyze("sast", [Source(path=path, text=text) for path, text in order], pattern)
            self.assertEqual(result.issues, [])
            self.assertCountEqual([(row(hit)["class"], hit.path, hit.line, hit.severity) for hit in result.findings],
                                  [("sql-injection", path, line, "high") for path, line in locations])

    def test_helpers_in_other_files(self):
        for package, imports, call, helper, flagged in [
            ("store", "", "statement(term)", QUERY, True),
            ("web", "import store.statement as build", "build(term)", QUERY, True),
            ("web", "import store.*", "statement(term)", QUERY, True),
            ("web", "", "store.statement(term)", QUERY, True),
            ("web", "import store.statement", "statement(term), term", BOUND, False),
            ("web", "import store.statement", 'statement("label")', QUERY, False),
            ("web", "import store.statement", '"SELECT ?", statement(term)', QUERY, False),
            ("web", "", "statement(term)", QUERY, False),
            ("store", "", "statement(term)", QUERY.replace("internal", "private"), False),
        ]:
            with self.subTest(imports=imports, call=call, helper=helper):
                handler = endpoint(package, imports, call)
                self.check([("storage/Builder.kt", "package store\n" + helper), ("views/List.kt", handler)],
                           [("views/List.kt", len(handler.splitlines()))] if flagged else [], "views/*")

    def test_imports_overloads_and_shadowing(self):
        for imports, call, other, flagged in [
            ("import store.*\nimport other.*", "statement(term)", QUERY, False),
            ("import store.*\nimport other.statement", "statement(term)", BOUND, False),
            ("import other.*\nimport store.statement", "statement(term)", BOUND, True),
            ("import store.*\nimport unknown.statement", "statement(term)", QUERY, False),
            ("import store.*\nprivate fun statement(q: String) = \"SELECT 1\"", "statement(term)", QUERY, False),
        ]:
            with self.subTest(imports=imports):
                handler = endpoint("web", imports, call)
                self.check([("one.kt", "package store\n" + QUERY), ("two.kt", "package other\n" + other), ("web.kt", handler)],
                           [("web.kt", len(handler.splitlines()))] if flagged else [])
        handler = endpoint("store", "", "statement(term)")
        self.check([("one.kt", "package store\n" + QUERY), ("two.kt", "package store\nfun statement(term: Int) = term"),
                    ("web.kt", handler)], [])

    def test_forwarder_uses_the_defining_files_format_import(self):
        handler = endpoint("web", "import bridge.wrapper", "wrapper(term)")
        bridge = "package bridge\nimport store.statement as make\nfun wrapper(input: String) = make(input)"
        helper = ('package store\nimport kotlin.text.format as fmt\n'
                  'fun statement(term: String) = "SELECT label FROM entries ORDER BY %s".fmt(term)')
        self.check([("db.kt", helper), ("bridge.kt", bridge), ("web.kt", handler)], [("web.kt", 5)])
        self.check([("db.kt", helper.replace("kotlin.text.format", "unknown.format")),
                    ("bridge.kt", bridge), ("web.kt", handler)], [])

    def test_production_does_not_resolve_helpers_from_other_source_sets_or_modules(self):
        handler = endpoint("store", "", "statement(term)")
        web = "app/src/main/kotlin/web.kt"
        for helper, expected in [
            ("app/src/main/kotlin/query.kt", True),
            ("app/src/test/kotlin/query.kt", False),
            ("separate/src/main/kotlin/query.kt", False),
        ]:
            with self.subTest(helper=helper):
                self.check([(web, handler), (helper, "package store\n" + QUERY)], [(web, 5)] if expected else [])

    def test_controller_service_repository_flow_points_to_database_call(self):
        web = ('package web\nimport domain.Listings as Catalog\nimport org.springframework.web.bind.annotation.*\n'
               '@RestController class Api(private val catalog: Catalog) {\n'
               ' @GetMapping fun list(@RequestParam order: String) = catalog.list(order)\n}')
        service = ('package domain\nimport storage.Records\nclass Listings(val records: Records) {\n'
                   ' fun list(value: String) = records.sorted(column = value.trim())\n}')
        for sql, alteration, expected in [
            ('"SELECT label FROM entries ORDER BY " + column', "", True),
            ('"SELECT label FROM entries WHERE label = ?", column', "", False),
            ('"SELECT label FROM entries ORDER BY " + column', "constant", False),
            ('"SELECT label FROM entries ORDER BY " + column', "foreign", False),
            ('"SELECT label FROM entries ORDER BY " + column', "uncalled", False),
            ('"SELECT label FROM entries ORDER BY " + column', "overloaded", False),
        ]:
            with self.subTest(sql=sql, alteration=alteration):
                store = ('package storage\nimport org.springframework.jdbc.core.JdbcTemplate\n'
                         'class Records(private val db: JdbcTemplate) {\n'
                         f' fun sorted(column: String) = db.queryForList({sql})\n'
                         + (' fun sorted(column: Int) = emptyList<String>()\n' if alteration == "overloaded" else '') + '}')
                bridge = service.replace("value.trim()", '"label"') if alteration == "constant" else service
                if alteration == "foreign":
                    bridge = bridge.replace("import storage.Records", "import other.Records")
                handler = web.replace("catalog.list(order)", "emptyList<String>()") if alteration == "uncalled" else web
                files = [("web.kt", handler), ("service.kt", bridge), ("store.kt", store)]
                self.check(files, [("store.kt", 4)] if expected else [], "store.kt")

    def test_passed_query_text_and_parameter_binding_differ(self):
        handler = ('package demo\nimport org.springframework.web.bind.annotation.*\n'
                   'class Api(private val store: Reader) {\n'
                   ' fun search(@RequestParam text: String) = store.run("SELECT " + text, text)\n}')
        for call, expected in [('db.queryForList(stmt)', True), ('db.queryForList("SELECT ?", filter)', False)]:
            with self.subTest(call=call):
                store = ('package demo\nimport org.springframework.jdbc.core.JdbcTemplate\n'
                         f'class Reader(val db: JdbcTemplate) {{\n fun run(stmt: String, filter: String) = {call}\n}}')
                self.check([("Api.kt", handler), ("Reader.kt", store)], [("Reader.kt", 4)] if expected else [])

    def test_field_shadows_package_prefix(self):
        web = ('package web\nimport org.springframework.jdbc.core.JdbcTemplate\n'
               'import org.springframework.web.bind.annotation.RequestParam\n'
               'class Labels {\n fun statement(term: String) = "SELECT 1"\n}\n'
               'class Api(val db: JdbcTemplate) {\n val store = Labels()\n'
               ' fun search(@RequestParam term: String) = db.queryForList(store.statement(term))\n}')
        self.check([("Api.kt", web), ("Compose.kt", "package store\n" + QUERY)], [])

    def test_injected_port_requires_a_unique_known_implementation(self):
        web = ('package demo\nimport org.springframework.web.bind.annotation.*\n'
               '@RestController class Api(val port: SearchPort) {\n'
               ' @GetMapping fun list(@RequestParam term: String) = port.find(term)\n}')
        interface = 'package demo\ninterface SearchPort {\n fun find(text: String): List<Map<String, Any>>\n}'
        impl = ('package store\nimport demo.SearchPort as Port\nimport org.springframework.stereotype.Repository\n'
                'import org.springframework.jdbc.core.JdbcTemplate\n@Repository class Rows(val db: JdbcTemplate) : Port {\n'
                ' override fun find(text: String) = db.queryForList("SELECT " + text)\n}')
        files = [("Web.kt", web), ("Port.kt", interface), ("Rows.kt", impl)]
        self.check(files, [("Rows.kt", 6)])
        self.check(files + [("Extra.kt", impl.replace("class Rows(", "class OtherRows("))], [])
        bean = ('package demo\nimport org.springframework.context.annotation.Bean\n'
                'class Config {\n @Bean fun alternate(): SearchPort = TODO()\n}')
        self.check(files + [("Config.kt", bean)], [])
        self.check([(p, code.replace('@Repository class Rows', 'class Rows')) for p, code in files], [])

    def test_defaults_and_named_arguments_use_the_declared_signature(self):
        web = ('package demo\nimport org.springframework.web.bind.annotation.RequestParam\n'
               'class Api(val reader: Port) {\n fun list(@RequestParam term: String) = reader.find(CALL)\n}')
        port = ('package demo\ninterface Port {\n'
                ' fun find(label: String, sort: String = "name"): List<Map<String, Any>>\n}')
        reader = ('package demo\nimport org.springframework.stereotype.Repository\n'
                  'import org.springframework.jdbc.core.JdbcTemplate\n@Repository class Reader(val db: JdbcTemplate): Port {\n'
                  ' override fun find(label: String, order: String) = db.queryForList("SELECT name FROM items ORDER BY " + order + " LIMIT ?", label)\n}')
        for call, flagged in [('sort = term, label = "10"', True), ('"10", term', True), ('label = term', False)]:
            with self.subTest(call=call):
                self.check([("Api.kt", web.replace("CALL", call)), ("Port.kt", port), ("Reader.kt", reader)],
                           [("Reader.kt", 5)] if flagged else [])
        direct = (reader.replace(": Port {", " {").replace("override fun", "fun")
                  .replace("label: String, order: String", 'order: String, label: String = "10"'))
        self.check([("Api.kt", web.replace("reader: Port", "reader: Reader").replace("CALL", "term")),
                    ("Reader.kt", direct)], [("Reader.kt", 5)])
        inherited = port.replace('sort: String = "name"', 'sort: String = label')
        self.check([("Api.kt", web.replace("CALL", "term")), ("Port.kt", inherited), ("Reader.kt", reader)], [("Reader.kt", 5)])
        extension = 'package demo\nfun Reader.find(value: String) = emptyList<String>()'
        required = direct.replace('label: String = "10"', 'label: String')
        self.check([("Api.kt", web.replace("reader: Port", "reader: Reader").replace("CALL", "term")),
                    ("Reader.kt", required), ("Extension.kt", extension)], [])

    def test_alternatives_and_validated_sort_columns(self):
        for condition, column, expected in [
            ("", 'if (sort.isBlank()) "name" else sort', True),
            ("", 'if (sort in setOf("name", "year")) sort else "name"', False),
            ("", 'if (false) sort else "name"', False),
            ('require(sort in setOf("name", "year"))', 'sort', False),
            ('require(sort !in setOf("name", "year"))', 'sort', True),
            ('if (enabled) require(sort in setOf("name", "year"))', 'sort', True),
            ('fun require(value: Boolean) = Unit\n require(sort in setOf("name", "year"))', 'sort', True),
            ('require(sort in setOf("name", sort))', 'sort', True),
            ("", 'when (sort) {\n "name", "year" -> sort\n else -> "name"\n }', False),
            ("", 'when (sort) {\n "default" -> "name"\n else -> sort\n }', True),
        ]:
            with self.subTest(condition=condition, column=column):
                code = ('import org.springframework.jdbc.core.JdbcTemplate\n'
                        'import org.springframework.web.bind.annotation.RequestParam\n'
                        'fun page(db: JdbcTemplate, @RequestParam sort: String, enabled: Boolean) {\n'
                        + condition + '\n val column = ' + column + '\n db.queryForList("SELECT name FROM entries ORDER BY $column")\n}')
                self.check([("Sort.kt", code)], [("Sort.kt", len(code.splitlines()) - 1)] if expected else [])
