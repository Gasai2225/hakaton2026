import unittest

from garden.models import Source
from garden.scanners import analyze


class SpringSqlDispatch(unittest.TestCase):
    def check(self, *, risky="@Repository", safe="@Repository", injection="", fields=None, extra="", build="", expected=False):
        header = '''package search
import org.springframework.stereotype.Repository
import org.springframework.context.annotation.*
import org.springframework.beans.factory.annotation.Qualifier as Pick
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.web.bind.annotation.*
'''
        port = 'interface Index {\n fun list(order: String = "id"): List<Map<String, Any>>\n}'
        risky_body = ('class SQLIndex(val db: JdbcTemplate): Index {\n'
                      ' override fun list(order: String) = db.queryForList("SELECT name FROM cats ORDER BY " + order)\n}')
        safe_body = ('class BoundIndex(val db: JdbcTemplate): Index {\n'
                     ' override fun list(order: String) = db.queryForList("SELECT name FROM cats WHERE name = ?", order)\n}')
        api = fields or (f'@RestController class Api({injection} private val index: Index) {{\n'
                         ' @GetMapping fun read(@RequestParam sort: String) = index.list(order = sort)\n}')
        source = {"Index.kt": port, "Risky.kt": risky + "\n" + risky_body,
                  "Api.kt": api, "Config.kt": extra}
        if safe is not None:
            source["Bound.kt"] = safe + "\n" + safe_body
        files = [Source(path=path, text=header + body) for path, body in source.items()]
        if build:
            files.append(Source(path="build.gradle.kts", text=build))
        run = analyze("sast", files, "*")
        self.assertEqual(run.issues, [])
        self.assertEqual([(hit.path, hit.line, hit.classification) for hit in run.findings],
                         [("Risky.kt", len((header + risky).splitlines()) + 2, "sql-injection")] if expected else [])

    def test_qualified_component_beans_and_primary(self):
        for risky, safe, injection, expected in [
            ('@Primary @Repository', '@Repository', '', True),
            ('@Primary @Repository', '@Primary @Repository', '', False),
            ('@Repository("archive")', '@Primary @Repository("live")', '@Pick("archive")', True),
            ('@Primary @Repository("archive")', '@Repository("live")', '@Pick("live")', False),
            ('@Repository', '@Repository', '@param:Pick(value = "SQLIndex")', True),
            ('@Repository @Pick("archive")', '@Repository @Pick("live")', '@Pick("archive")', True),
            ('@Repository @Pick("archive")', '@Repository @Pick("archive")', '@Pick("archive")', False),
            ('@Primary @Repository @Pick("archive")', '@Repository @Pick("archive")', '@Pick("archive")', True),
            ('@Primary @Repository', '@Repository', '@Pick("missing")', False),
            ('@Repository', '@Repository', '', False),
            ('@Repository', None, '@Pick("missing")', False),
            ('@Repository', None, '@Pick(DYNAMIC_LABEL)', False),
            ('@Repository', '@Repository', '@field:Pick("SQLIndex")', False),
        ]:
            with self.subTest(risky=risky, safe=safe, injection=injection):
                self.check(risky=risky, safe=safe, injection=injection, expected=expected)

    def test_unknown_profile_and_explicit_factories(self):
        for risky, safe, extra, injection, expected in [
            ('@Profile("legacy") @Repository', None, '', '', False),
            ('@Profile("legacy") @Primary @Repository', '@Repository', '', '', False),
            ('@Repository', '@Profile("trial") @Primary @Repository', '', '', False),
            ('@Primary @Repository', '@Profile("trial") @Repository', '', '', True),
            ('@Repository', '@Profile("trial") @Repository', '', '@Pick("SQLIndex")', True),
            ('@Repository', '@Profile("trial") @Repository', '', '', False),
            ('@Primary @Repository', '@Repository', '@Configuration class Factories {\n @Primary @Bean fun another(db: JdbcTemplate) = BoundIndex(db)\n}', '', False),
            ('@Repository', '@Repository', '@Configuration class Factories {\n @Bean fun arbitrary(): Index = TODO()\n}', '', False),
        ]:
            with self.subTest(risky=risky, safe=safe, extra=extra, injection=injection):
                self.check(risky=risky, safe=safe, extra=extra, injection=injection, expected=expected)

    def test_selection_belongs_to_each_injection_point(self):
        api = '''@RestController class Api(@Pick("archive") val logs: Index, @Pick("live") val search: Index) {
 @GetMapping fun read(@RequestParam sort: String) = CALL
}'''
        for call, expected in [('search.list(sort)', False), ('logs.list(sort)', True), ('logs.list()', False)]:
            with self.subTest(call=call):
                self.check(risky='@Repository("archive")', safe='@Repository("live")',
                           fields=api.replace("CALL", call), expected=expected)

    def test_bean_factories_and_aliases(self):
        for declaration, factory, selection, expected in [
            ('@Bean(name = ["legacy", "old"])', 'fun answer(db: JdbcTemplate): Index = SQLIndex(db)', '@Pick("old")', True),
            ('@Bean @Primary', 'fun answer(db: JdbcTemplate) = SQLIndex(db)', '', True),
            ('@Bean @Primary @Profile("night")', 'fun answer(db: JdbcTemplate) = SQLIndex(db)', '', False),
            ('@Bean @Pick("map")', 'fun answer(db: JdbcTemplate): Index = SQLIndex(db)', '@Pick("map")', True),
            ('@Bean', 'fun answer(): Index = chooseAtRuntime()', '@Pick("answer")', False),
            ('@Bean(autowireCandidate = false) @Primary', 'fun answer(db: JdbcTemplate) = SQLIndex(db)', '', False),
        ]:
            with self.subTest(declaration=declaration, factory=factory, selection=selection):
                self.check(risky="// supplied by the configuration", injection=selection,
                           extra=f'@Configuration class Setup {{\n {declaration} {factory}\n}}', expected=expected)

    def test_field_target_requires_actual_injection(self):
        for override, expected in [
            ('@Autowired @field:Pick("archive") lateinit var index: Index', True),
            ('@field:Autowired @Pick("archive") lateinit var index: Index', True),
            ('@field:Autowired @Pick("live") lateinit var index: Index', False),
            ('@Pick("archive") lateinit var index: Index', False),
        ]:
            with self.subTest(override=override):
                self.check(risky='@Repository("archive")', safe='@Repository("live")', expected=expected,
                           fields=('@RestController class Api {\n ' + override + '\n'
                                   ' @GetMapping fun read(@RequestParam sort: String) = index.list(sort)\n}'))

    def test_implicit_name_requires_a_real_bean_name_and_parameter_metadata(self):
        reflect = 'dependencies { implementation(kotlin("reflect")) }'
        for risky, safe, build, field, expected in [
            ('@Repository("archive")', '@Repository', '', True, True),
            ('@Repository @Pick("archive")', '@Repository', '', True, False),
            ('@Repository("archive")', '@Primary @Repository', '', True, False),
            ('@Repository("archive")', '@Repository("archive")', '', True, False),
            ('@Repository("archive") @Primary', '@Repository("archive")', '', True, False),
            ('@Repository("archive")', '@Repository', '', False, False),
            ('@Repository("archive")', '@Repository', reflect, False, True),
            ('@Repository("archive")', '@Repository', 'dependencies { testImplementation(kotlin("reflect")) }', False, False),
            ('@Repository("archive")', '@Repository', 'kotlin { compilerOptions { javaParameters.set(true) } }', False, True),
            ('@Repository("archive")', '@Repository', 'kotlin { compilerOptions { javaParameters.set(false) } }', False, False),
            ('@Profile("trial") @Repository("archive")', '@Repository', reflect, False, False),
        ]:
            with self.subTest(risky=risky, safe=safe, build=build, field=field):
                definition = ('class Api {\n @Autowired lateinit var archive: Index' if field
                              else 'class Api(val archive: Index) {')
                self.check(risky=risky, safe=safe, build=build, expected=expected,
                           fields='@RestController ' + definition + '\n @GetMapping fun run(@RequestParam q: String) = archive.list(q)\n}')

    def test_fallback_and_priority(self):
        for risky, safe, expected in [
            ('@Repository', '@Repository @Fallback', True),
            ('@Fallback @Repository', '@Repository', False),
            ('@jakarta.annotation.Priority(3) @Repository', '@jakarta.annotation.Priority(8) @Repository', True),
            ('@jakarta.annotation.Priority(3) @Repository', '@jakarta.annotation.Priority(3) @Repository', False),
            ('@jakarta.annotation.Priority(3) @Repository', '@Primary @Repository', False),
        ]:
            with self.subTest(risky=risky, safe=safe):
                self.check(risky=risky, safe=safe, expected=expected)

    def test_multi_candidate_dispatch_requires_a_spring_consumer(self):
        self.check(risky='@Primary @Repository',
                   fields='class Api(val index: Index) {\n fun read(@RequestParam sort: String) = index.list(sort)\n}')

    def test_conditional_wildcard_import_and_custom_qualifier(self):
        self.check(risky='import org.springframework.boot.autoconfigure.condition.*\n@ConditionalOnWebApplication @Primary @Repository')
        self.check(risky='@Primary @Repository', safe='@Archive @Repository', injection='@Archive',
                   extra='@Pick\n@Target(AnnotationTarget.CLASS, AnnotationTarget.VALUE_PARAMETER)\nannotation class Archive')

    def test_name_overrides_priority_only_with_evidence(self):
        fields = ('@RestController class Api(val online: Index) {\n'
                  ' @GetMapping fun run(@RequestParam sort: String) = online.list(sort)\n}')
        for build in ['', 'dependencies { implementation(kotlin("reflect")) }']:
            with self.subTest(build=build):
                self.check(risky='@jakarta.annotation.Priority(1) @Repository("old")', safe='@Repository("online")',
                           fields=fields, build=build)
