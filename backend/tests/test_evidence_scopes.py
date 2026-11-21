import unittest

from garden.models import Source
from garden.scanners import analyze


class EvidenceScopes(unittest.TestCase):
    def check(self, kind, code, expected):
        result = analyze(kind, [Source(path="Workshop.kt", text=code)], "*")
        self.assertEqual(result.issues, [])
        self.assertEqual([(hit.classification, hit.line) for hit in result.findings], expected)

    def test_spring_value_uses_the_annotation_visible_at_each_site(self):
        for imported in ("*", "Value", "Value as Setting"):
            name = "Setting" if " as " in imported else "Value"
            expression = '@' + name + r'("\${workshop.token:classroom-marker}") val text: String'
            code = (f"import org.springframework.beans.factory.annotation.{imported}\n"
                    f"class Notes {{\n annotation class {name}(val value: String)\n"
                    f" class Local({expression})\n}}\nclass Settings({expression})")
            with self.subTest(imported=imported):
                self.check("secrets", code, [("secret-fallback", 6)])

    def test_system_property_reader_in_a_sibling_scope(self):
        self.check("secrets", '''class Labels {
 fun getProperty(key: String, default: String) = key
}
fun read(System: Labels) = System.getProperty("workshop.token", "classroom-marker")
fun real() = System.getProperty("workshop.token", "classroom-marker")
''', [("secret-fallback", 5)])

    def test_cors_registration_escapes_only_when_its_binding_is_passed(self):
        head = '''import org.springframework.web.servlet.config.annotation.CorsRegistry
fun configure(routes: CorsRegistry) {
    val setting = routes.addMapping("/notebook").allowedOriginPatterns("*").allowCredentials(true)
'''
        for tail, finding in [
            ('listOf("art").map { setting -> setting.length }', True),
            ('run { val setting = "art"; println(setting) }', True),
            ('listOf("art").forEach { label -> consume(setting) }', False),
            ('run { val setting = copySetting(setting); consume(setting) }', False),
            ('setting.allowCredentials(false)', False),
        ]:
            with self.subTest(tail=tail):
                helpers = "\n}\nfun consume(value: Any) = Unit\nfun copySetting(value: Any) = value"
                self.check("sast", head + tail + helpers, [("credentialed-cors", 3)] if finding else [])

    def test_kotlin_security_dsl_on_an_immutable_builder_alias(self):
        for selected, expected in (("server", True), ("notes", False)):
            code = ('''import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.invoke
fun configure(server: HttpSecurity, notes: Notebook) {
    val copy = (''' + selected + ''')
    val active = copy
    active { authorizeHttpRequests { authorize(anyRequest, permitAll) } }
}
class Notebook {
    val anyRequest = 1
    val permitAll = 2
    operator fun invoke(block: Notebook.() -> Unit) { block() }
    fun authorizeHttpRequests(block: Notebook.() -> Unit) { block() }
    fun authorize(matcher: Int, access: Int) = Unit
}''')
            with self.subTest(selected=selected):
                self.check("sast", code, [("route-authorization", 6)] if expected else [])
