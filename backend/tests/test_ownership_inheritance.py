import unittest

from garden.models import Source
from garden.scanners import analyze


CONTRACT = """package app
import org.springframework.security.access.prepost.PreAuthorize
interface Key
open class BaseKey : Key
class ParcelKey : BaseKey()
class UnrelatedKey
interface Rows {
    fun read(key: Key): Map<String, Any>
}
interface ParcelRows : Rows
"""
READER = """package app
import org.springframework.stereotype.Repository
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.context.annotation.Primary
import org.springframework.context.annotation.Profile
import org.springframework.security.access.prepost.PreAuthorize
import app.ParcelRows as Port
@Repository class SqlRows(val jdbc: JdbcTemplate) : Port {
    override fun read(value: Key) = jdbc.queryForMap("SELECT owner_id, title FROM parcels WHERE id = ?", value)
}
"""
SAFE = """package app
import org.springframework.stereotype.Repository
@Repository class PublicRows : Rows {
    override fun read(key: Key) = mapOf<String, Any>("public" to key)
}
"""
API = """package app
import org.springframework.web.bind.annotation.*
import org.springframework.beans.factory.annotation.Qualifier
@RestController class EntryApi(val src: Rows) {
    @GetMapping("/entries/{id}")
    fun get(@PathVariable id: ParcelKey) = src.read(key = id)
}
"""


class OwnershipInheritance(unittest.TestCase):
    def check(self, contract=CONTRACT, repo=READER, controller=API, extra="", expected=True):
        files = {"Api.kt": controller, "Contract.kt": contract, "Reader.kt": repo, "Extra.kt": extra}
        sources = [Source(path=p, text=code) for p, code in files.items() if code]
        for variant in (sources, list(reversed(sources))):
            result = analyze("sast", variant, "Api.kt")
            self.assertEqual(result.issues, [])
            self.assertEqual([(f.path, f.line, f.classification) for f in result.findings],
                             [("Api.kt", 6, "object-authorization")] if expected else [])

    def test_inherited_contract_and_subtype_parameter(self):
        self.check()
        self.check(controller=API.replace("val src: Rows", "val src: ParcelRows"))
        self.check(controller=API.replace("val src: Rows", "val src: SqlRows").replace("key = id", "value = id"))
        self.check(controller=API.replace("ParcelKey)", "UnrelatedKey)").replace("key = id", "id"),
                   extra='package app\nfun Rows.read(id: UnrelatedKey) = "public"', expected=False)

    def test_inherited_method_security(self):
        annotation = '@PreAuthorize("@acl.owns(#key)") '
        for static_type, named in [("Rows", "key"), ("SqlRows", "value")]:
            gui = API.replace("val src: Rows", "val src: " + static_type).replace("key = id", named + " = id")
            with self.subTest(static_type=static_type):
                self.check(contract=CONTRACT.replace("    fun read", "    " + annotation + "fun read"), controller=gui, expected=False)
                self.check(contract=CONTRACT.replace("interface ParcelRows", annotation + "interface ParcelRows"),
                           controller=gui, expected=False)
        self.check(contract=CONTRACT.replace("    fun read", "    " + annotation + "fun read"),
                   repo=READER.replace("override fun read", '@PreAuthorize("permitAll()") override fun read'))

    def test_multiple_beans_and_known_selection(self):
        self.check(extra=SAFE, expected=False)
        self.check(extra=SAFE, repo=READER.replace("@Repository class SqlRows", "@Primary @Repository class SqlRows"))
        self.check(extra=SAFE, controller=API.replace("val src", '@Qualifier("sqlRows") val src'))
        self.check(extra=SAFE, controller=API.replace("val src", '@Qualifier("publicRows") val src'), expected=False)
        self.check(repo=READER.replace("@Repository class SqlRows", '@Profile("dev") @Repository class SqlRows'), expected=False)
        factory = """package app
import org.springframework.context.annotation.*
@Configuration class ExtraConfig {
    @Bean fun additional(): Rows = configuredRows()
}
"""
        self.check(extra=factory, expected=False)

    def test_inherited_concrete_body_and_safe_override(self):
        abstract = READER.replace("@Repository class SqlRows", "abstract class BaseRows")
        self.check(repo=abstract + "@Repository class SqlRows(db: JdbcTemplate) : BaseRows(db)\n")
        override = """@Repository class SqlRows(db: JdbcTemplate) : BaseRows(db) {
    override fun read(value: Key) = mapOf<String, Any>("public" to value)
}
"""
        self.check(repo=abstract + override, expected=False)
        self.check(repo=abstract.replace("override fun read", '@PreAuthorize("@acl.owns(#value)") override fun read')
                      + "@Repository class SqlRows(db: JdbcTemplate) : BaseRows(db)\n", expected=False)

    def test_own_method_independent_of_generic_parent(self):
        repo = READER.replace("import app.ParcelRows as Port", "interface Tagged<T>")
        repo = repo.replace(": Port {", ": Tagged<String> {").replace("override fun read", "fun read")
        self.check(repo=repo, controller=API.replace("val src: Rows", "val src: SqlRows").replace("key = id", "value = id"))

    def test_member_extension_in_base_does_not_override_an_ordinary_call(self):
        repo = READER.replace("@Repository class SqlRows", "abstract class Base")
        repo = repo.replace(": Port {", "{").replace("override fun read", "fun String.read")
        repo += '@Repository class SqlRows(db: JdbcTemplate): Base(db)\nfun SqlRows.read(value: Key) = "public"\n'
        self.check(repo=repo, controller=API.replace("val src: Rows", "val src: SqlRows").replace("key = id", "value = id"),
                   expected=False)

    def test_inherited_service_constructor_binding(self):
        service = """package app
import org.springframework.stereotype.Service
interface Lookup {
    fun find(value: Key): Map<String, Any>
}
abstract class Services(val rows: Rows) : Lookup {
    override fun find(value: Key) = rows.read(value)
}
@Service class ParcelLookup(input: ParcelRows) : Services(rows = input)
"""
        web = API.replace("src: Rows", "src: Lookup").replace("src.read(key = id)", "src.find(id)")
        self.check(extra=service, controller=web)
        self.check(extra=service.replace("rows = input", "rows = manuallyChosenRows()"), controller=web, expected=False)
        named_call = service.replace("rows.read(value)", "rows.read(key = value)")
        self.check(extra=named_call.replace("input: ParcelRows", "input: SqlRows"), controller=web)
        virtual = service.replace("Services(val rows", "Services(open val rows")
        virtual = virtual.replace("Services(rows = input)", "Services(rows = input) {\n"
                                  " override val rows: Rows get() = manuallyChosenRows()\n}")
        self.check(extra=virtual, controller=web, expected=False)
