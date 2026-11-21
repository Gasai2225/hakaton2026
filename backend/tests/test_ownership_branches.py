import unittest

from garden.models import Source
from garden.scanners import analyze


QUERY = 'db.queryForMap("SELECT owner_id, title FROM docs WHERE id = ?", key)'
READ = "store.load(key)"


class OwnershipBranches(unittest.TestCase):
    def test_transitive_id_comparisons_control_which_return_is_reachable(self):
        for test, expected in [
            ("other == key && other == 2L && key == 2L", [0]),
            ("other == key && other == 2L && key == 3L", []),
            ("other == 2L && key != 2L && other == key", []),
            ("other == 2L && key > 2L && other == key", []),
            ("other == 2L && key >= 2L && other == key", [0]),
        ]:
            with self.subTest(test=test):
                self.scan(f"= if ({test}) store.load(key) else null", expected)

    def scan(self, handler, expected_calls=(), *, query="= " + QUERY, service=None):
        store = '''package sample
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.stereotype.Repository
@Repository class Store(private val db: JdbcTemplate) {
    fun load(key: Long): Any? BODY
}'''.replace("BODY", query)
        web = '''package sample
import org.springframework.web.bind.annotation.*
import org.springframework.http.ResponseEntity
import java.security.Principal
@RestController class Api(private val store: TYPE) {
    @GetMapping fun get(@PathVariable key: Long, @RequestParam preview: Boolean,
                        @RequestParam other: Long, user: Principal): Any? BODY
}'''.replace("BODY", handler).replace("TYPE", "Bridge" if service else "Store")
        files = [Source(path="Store.kt", text=store), Source(path="Api.kt", text=web)]
        if service:
            files.append(Source(path="Service.kt", text='''package sample
import org.springframework.stereotype.Service
@Service class Bridge(private val store: Store) {
    fun load(key: Long): Any? BODY
}'''.replace("BODY", service)))
        result = analyze("sast", files, "Api.kt")
        self.assertEqual(result.issues, [])
        rows = [(h.classification, h.line) for h in result.findings]
        start = 7
        self.assertCountEqual(rows, [("object-authorization", start + offset) for offset in expected_calls])

    def test_if_conditions_and_returns(self):
        for handler, expected in [
            ("= if (preview) store.load(key) else null", [0]),
            ("= if (owns(key)) store.load(key) else null", []),
            ("= if (!acl.owns(key)) store.load(key) else null", [0]),
            ("= if (owns(key) || preview) store.load(key) else null", [0]),
            ("= if (owns(key) && preview) store.load(key) else null", []),
            ("= if (owns(other)) store.load(key) else null", [0]),
            ("= if (owns(1L)) store.load(key) else null", [0]),
            ("= if (key == 1L && owns(1L)) store.load(key) else null", []),
            ("= if (owns(other) && key == other) store.load(key) else null", []),
            ("{ val allowed = owns(key); if (allowed || preview) return store.load(key); return null }", [0]),
            ("{ if (key <= 0) return null; return store.load(key) }", [0]),
            ("{ if (!owns(key)) throw Forbidden(); return store.load(key) }", []),
            ("{ if (preview) { if (!owns(key)) return null; return store.load(key) };\n return store.load(key) }", [1]),
            ("{ require(owns(key)); return store.load(key) }", []),
            ("{ require(key > 0); return store.load(key) }", [0]),
            ("{ val approval = authorize(key); return store.load(key) }", []),
            ("{ val approval = authorize(key) == key; return store.load(key) }", []),
            ('{ val result = if (preview) { val store = "public"; store.load(key) } else null; return result }', []),
            ("= if (customPolicy(key)) store.load(key) else null", []),
            ("{ if (preview) return null; if (preview) return store.load(key); return null }", []),
            ("{ if (preview == false) return null; if (!preview) return store.load(key); return null }", []),
            ("= if (2 < 1) store.load(key) else null", []),
            ("= if (key > 9L && key < 3L) store.load(key) else null", []),
            ("= if (key >= 3L && key <= 3L) store.load(key) else null", [0]),
            ("= if (key == 1L && key > 2L) store.load(key) else null", []),
            ("= if (key == other && key == 2L) store.load(key) else null", [0]),
        ]:
            with self.subTest(handler=handler):
                self.scan(handler, expected)

    def test_when_conditions_subject_and_precedence(self):
        for handler, expected in [
            ("= when { !owns(key) -> null; else -> store.load(key) }", []),
            ("= when { owns(key) -> null; else -> store.load(key) }", [0]),
            ("= when { true -> null; preview -> store.load(key); else -> null }", []),
            ("= when (preview) { true -> store.load(key); else -> null }", [0]),
            ("= when (owns(key)) { false -> null; else -> store.load(key) }", []),
            ("= when (key) { 1L, 2L -> null; 2L -> store.load(key); else -> null }", []),
            ("= when (key) { 1L, 2L -> null; 3L -> store.load(key); else -> null }", [0]),
        ]:
            with self.subTest(handler=handler):
                self.scan(handler, expected)

    def test_row_comparison_locals_and_wrappers(self):
        for body, expected in [
            ('if (row["owner_id"] != user.name) return null; return row', []),
            ('if (row["owner_id"] == user.name) return null; return row', [0]),
            ('if (user.name == row.ownerId) return row; return null', []),
            ('if (user.name != row.ownerId) return row; return null', [0]),
            ('if (!isOwner(row)) return null; return row', []),
            ('if (row.isOwnedBy(user)) return row; return null', []),
            ('if (!row.isOwnedBy(user)) return row; return null', [0]),
            ('if (row.ownerId == user.unknownMapping()) return null; return row', []),
            ('if (isOwner(row)) return null; return ResponseEntity.ok(row)', [0]),
            ('if (checkOpaquePolicy(row)) return row; return null', []),
        ]:
            with self.subTest(body=body):
                self.scan("{ val row = store.load(key); " + body + " }", expected)
        self.scan("= ResponseEntity.ok(if (preview) store.load(key) else null)", [0])
        self.scan("{ val row = if (owns(key)) store.load(key) else null; return ResponseEntity.ok(row) }", [])

    def test_early_returns_in_repository_and_service(self):
        for conditional, expected in [
            ("{ if (key <= 0) return null; return VALUE }", [0]),
            ("{ if (!owns(key)) return null; return VALUE }", []),
            ("= when { owns(key) -> null; else -> VALUE }", [0]),
        ]:
            with self.subTest(conditional=conditional):
                self.scan("= " + READ, expected, query=conditional.replace("VALUE", QUERY))
                self.scan("= " + READ, expected, service=conditional.replace("VALUE", READ))

    def test_alias_widening_does_not_select_the_long_member(self):
        for local_type, expected in [("Any", []), ("Long", [0])]:
            with self.subTest(local_type=local_type):
                self.scan("{ val selected: " + local_type + " = if (preview) key else 3L; return store.load(selected) }", expected)
        query = '{ val sql: String = """SELECT owner_id, title FROM docs WHERE id = ?"""; return db.queryForMap(sql, key) }'
        self.scan("= " + READ, [0], query=query)
