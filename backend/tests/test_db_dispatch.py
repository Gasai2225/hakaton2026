import unittest

from garden.models import Source
from garden.scanners import analyze


class OwnershipDispatch(unittest.TestCase):
    def check(self, repo_type, http_type, expected, *, bridge_type=None, extra=None):
        support = '''package lookup
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.stereotype.Repository
import kotlin.String as TextKey
import kotlin.Long as NumericKey
@Repository class Shelf(private val db: JdbcTemplate) {
    fun label(code: REPO_TYPE) = db.queryForMap("select title, tenant_id from entries where slug = ?", code)
}'''.replace("REPO_TYPE", repo_type)
        service = '''package lookup
import org.springframework.stereotype.Service
import kotlin.String as TextKey
import kotlin.Long as NumericKey
@Service class Lookup(private val shelf: Shelf) {
    fun find(tag: BRIDGE_TYPE) = shelf.label(code = tag)
}'''
        controller = '''package lookup
import org.springframework.web.bind.annotation.*
import kotlin.String as TextKey
import kotlin.Long as NumericKey
@RestController class Api(private val source: TARGET) {
    @GetMapping("/entries/{id}")
    fun display(@PathVariable id: HTTP_TYPE) = source.METHOD(id)
}'''
        controller = (controller.replace("HTTP_TYPE", http_type)
                      .replace("TARGET", "Lookup" if bridge_type else "Shelf")
                      .replace("METHOD", "find" if bridge_type else "label"))
        files = {"Api.kt": controller, "Shelf.kt": support, **(extra or {})}
        if bridge_type:
            files["Lookup.kt"] = service.replace("BRIDGE_TYPE", bridge_type)
        result = analyze("sast", [Source(path=k, text=v) for k, v in files.items()], "Api.kt")
        self.assertEqual(result.issues, [])
        self.assertEqual([(h.path, h.line, h.classification) for h in result.findings],
                         [("Api.kt", 7, "object-authorization")] if expected else [])

    def test_extension_is_selected_only_for_incompatible_member_parameter(self):
        for repo, web, bridge, expected in [
            ("String", "kotlin.String", None, True),
            ("TextKey", "NumericKey", None, False),
            ("kotlin.String", "TextKey", "String", True),
            ("String", "Long", "NumericKey", False),
            ("String", "kotlin.Long", "TextKey", False),
        ]:
            with self.subTest(repo=repo, web=web, bridge=bridge):
                extension = {"Extensions.kt": 'package lookup\nfun Shelf.label(code: Long) = mapOf("public" to code)'}
                if bridge:
                    extension["Extensions.kt"] += '\nfun Lookup.find(tag: Long) = mapOf("public" to tag)'
                self.check(repo, web, expected, bridge_type=bridge, extra=extension)

    def test_custom_classes_with_same_short_name(self):
        extra = {"Public.kt": "package publicsite\nclass Code",
                 "Domain.kt": "package membership\nclass Code",
                 "Extensions.kt": 'package lookup\nfun Shelf.label(code: publicsite.Code) = mapOf("public" to code)'}
        self.check("membership.Code", "membership.Code", True, extra=extra)
        self.check("membership.Code", "publicsite.Code", False, extra=extra)

    def test_nullable_and_builtin_supertypes(self):
        nullable = {"Extensions.kt": 'package lookup\nfun Shelf.label(code: String?) = mapOf("public" to code)'}
        self.check("TextKey", "String?", False, extra=nullable)
        self.check("kotlin.String?", "TextKey", True, extra=nullable)
        self.check("kotlin.CharSequence", "TextKey", True)
        self.check("Number", "NumericKey", True)
