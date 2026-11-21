import unittest

from garden.models import Source
from garden.scanners import analyze


CLIENT = "org.springframework.r2dbc.core.DatabaseClient"
TEMPLATE = "org.springframework.data.r2dbc.core.R2dbcEntityTemplate"
OPERATIONS = "org.springframework.data.r2dbc.core.R2dbcEntityOperations"
REQUEST = "org.springframework.web.bind.annotation.RequestParam"


class ReactiveSqlChecks(unittest.TestCase):
    def check(self, files, expected, pattern="*"):
        result = analyze("sast", [Source(path=k, text=v) for k, v in files.items()], pattern)
        self.assertEqual(result.issues, [])
        self.assertCountEqual([(f.path, f.line, f.classification) for f in result.findings],
                              [(path, line, "sql-injection") for path, line in expected])

    def test_database_client_sql_and_bound_values(self):
        for imports, db, statement, expected in [
            (f"import {CLIENT} as Query", "Query", 'db.sql("SELECT title FROM labs ORDER BY " + sort).fetch().all()', True),
            ("", CLIENT, 'db.sql("SELECT title FROM labs ORDER BY $sort").fetch().all()', True),
            ("import org.springframework.r2dbc.core.*", "DatabaseClient", 'db.sql(sort).fetch().one()', True),
            (f"import {CLIENT}", "DatabaseClient", 'db.sql("SELECT title FROM labs WHERE id = :id").bind("id", sort).fetch().one()', False),
            (f"import {CLIENT}", "DatabaseClient", 'db.sql("SELECT title FROM labs WHERE id = ?").bind(0, sort).fetch().all()', False),
            (f"import {CLIENT}", "DatabaseClient", 'db.sql("SELECT title FROM labs ORDER BY " + sort + " LIMIT :n").bind("n", 5).fetch().all()', True),
            ("import org.springframework.r2dbc.core.*\nimport app.tracing.DatabaseClient", "DatabaseClient", 'db.sql("SELECT " + sort)', False),
            ("import org.springframework.r2dbc.core.*\nclass DatabaseClient {\n fun sql(text: String) = text.length\n}", "DatabaseClient", 'db.sql("SELECT " + sort)', False),
            (f"import {CLIENT}\nfun DatabaseClient.sql(text: String, audit: Boolean) = text.length", "DatabaseClient", 'db.sql("SELECT " + sort, audit = true)', False),
        ]:
            with self.subTest(db=db, statement=statement):
                code = (f'import {REQUEST}\n{imports}\n'
                        f'fun report(db: {db}, @RequestParam sort: String) =\n {statement}')
                self.check({"Lab.kt": code}, [("Lab.kt", len(code.splitlines()))] if expected else [])

    def test_database_client_from_r2dbc_entity_operations(self):
        for imported, ref, getter, expression, expected in [
            (TEMPLATE, "Template", "this.store.databaseClient", '"SELECT " + label', True),
            (OPERATIONS, "Template", "store.getDatabaseClient()", '"SELECT title FROM labs ORDER BY $label"', True),
            (TEMPLATE, "Template", "store.databaseClient", '"SELECT title FROM labs WHERE title = :term"', False),
            ("app.tracing.R2dbcEntityTemplate", "Template", "store.databaseClient", '"SELECT " + label', False),
            (OPERATIONS, "Template", "store.getDatabaseClient(false)", '"SELECT " + label', False),
        ]:
            with self.subTest(imported=imported, getter=getter, expression=expression):
                code = (f'import {REQUEST}\nimport {imported} as {ref}\n'
                        f'class Lab(val store: {ref}) {{\n fun refresh(@RequestParam label: String) {{\n'
                        f'  val reader = {getter}\n  reader.sql({expression}).fetch().all()\n }}\n}}')
                self.check({"Lab.kt": code}, [("Lab.kt", 6)] if expected else [])

    def test_sql_supplier_has_only_its_own_returned_text(self):
        for expr, expected in [
            ('db.sql { "SELECT title FROM labs ORDER BY " + sort }.fetch().all()', True),
            ('db.sql({ "SELECT title FROM labs ORDER BY $sort" }).fetch().all()', True),
            ('db.sql { "SELECT title FROM labs WHERE title = :q" }.bind("q", sort).fetch().all()', False),
            ('db.sql { audit(sort); "SELECT title FROM labs" }.fetch().all()', False),
        ]:
            with self.subTest(expr=expr):
                code = (f'import {REQUEST}\nimport {CLIENT}\n'
                        f'fun all(db: DatabaseClient, @RequestParam sort: String) =\n {expr}')
                self.check({"Lab.kt": code}, [("Lab.kt", 4)] if expected else [])

    def test_cross_file_source_and_sink_mask(self):
        api = f'''package lab
import {REQUEST}
class Api(val store: Feed) {{
    fun sorted(@RequestParam field: String) = store.sorted(field)
}}'''
        store = f'''package lab
import {OPERATIONS} as Ops
class Feed(val operations: Ops) {{
    fun sorted(column: String) = operations.databaseClient.sql(
        "SELECT title FROM labs ORDER BY " + column
    ).fetch().all()
}}'''
        files = {"src/main/kotlin/lab/Api.kt": api, "src/main/kotlin/lab/Feed.kt": store}
        self.check(files, [("src/main/kotlin/lab/Feed.kt", 5)], "*Feed.kt")
        self.check(files, [], "*Api.kt")

    def test_receiver_shadow_extensions_and_foreign_source(self):
        for annotation, body in [
            (REQUEST, 'db.trim().sql("SELECT " + label)'),
            (REQUEST, 'val db = Audit()\n db.sql("SELECT " + label)'),
            ("app.audit.RequestParam", 'db.sql("SELECT " + label)'),
        ]:
            with self.subTest(annotation=annotation, body=body):
                code = (f'import {annotation}\nimport {CLIENT}\n'
                        'class Audit {\n fun sql(text: String) = text.length\n}\n'
                        'fun DatabaseClient.trim() = Audit()\n'
                        'fun view(db: DatabaseClient, @RequestParam label: String) {\n'
                        f' {body}\n}}')
                self.check({"Audit.kt": code}, [])
