import unittest

from garden.models import Source
from garden.scanners import analyze


class SpringApiVariants(unittest.TestCase):
    def test_wildcard_must_survive_origin_list_construction(self):
        for value, wide in [
            ('listOf("*" + ".example.org")', False),
            ('listOf("*").filter { false }', False),
            ('listOf("https://app.example", "*")', True),
        ]:
            for setter in [f"allowedOriginPatterns = {value}", f"setAllowedOriginPatterns({value})"]:
                with self.subTest(setter=setter):
                    code = ('import org.springframework.web.cors.CorsConfiguration\n'
                            'fun policy() = CorsConfiguration().apply {\n'
                            f' allowCredentials = true\n {setter}\n}}')
                    self.assertEqual(self.locations(code), [("credentialed-cors", 4)] if wide else [])

    def test_sql_sink_only_in_reachable_statement_branch(self):
        for flag, expected in [("false", False), ("true", True), ("flag", True)]:
            with self.subTest(flag=flag):
                code = ('import org.springframework.jdbc.core.JdbcTemplate\n'
                        'import org.springframework.web.bind.annotation.RequestParam\n'
                        'fun show(db: JdbcTemplate, @RequestParam term: String, flag: Boolean) {\n'
                        f' val enabled = {flag}\n'
                        ' if (enabled) db.queryForList("SELECT " + term)\n}')
                self.assertEqual(self.locations(code), [("sql-injection", 5)] if expected else [])

    def test_sql_when_branch_uses_immutable_boolean_value(self):
        for predicate, expected in [("enabled", False), ("!enabled", True), ("flag", True)]:
            for expression in [f"when ({predicate}) {{ true -> CALL; else -> emptyList() }}",
                               f"when {{ {predicate} -> CALL; else -> emptyList() }}"]:
                with self.subTest(expression=expression):
                    code = ('import org.springframework.jdbc.core.JdbcTemplate\n'
                            'import org.springframework.web.bind.annotation.RequestParam\n'
                            'fun show(db: JdbcTemplate, @RequestParam term: String, flag: Boolean) {\n'
                            ' val enabled = false\n ' + expression.replace("CALL", 'db.queryForList("SELECT " + term)') + '\n}')
                    self.assertEqual(self.locations(code), [("sql-injection", 5)] if expected else [])

    def test_cors_domain_list_factory_with_local_homonym(self):
        for declaration, factory, expected in [
            ("", "listOf", True),
            ('fun listOf(item: String) = kotlin.collections.listOf("https://example.org")', "listOf", False),
            ('fun listOf(item: String) = kotlin.collections.listOf("https://example.org")', "kotlin.collections.listOf", True),
        ]:
            with self.subTest(declaration=declaration, factory=factory):
                code = ('import org.springframework.web.cors.CorsConfiguration\n' + declaration +
                        '\nfun policy() = CorsConfiguration().apply {\n'
                        f' allowedOriginPatterns = {factory}("*")\n allowCredentials = true\n}}')
                self.assertEqual(self.locations(code), [("credentialed-cors", 4)] if expected else [])

    def locations(self, source):
        result = analyze("sast", [Source(path="Catalog.kt", text=source)], "*")
        self.assertEqual(result.issues, [])
        return [(hit.classification, hit.line) for hit in result.findings]

    def test_jdbc_through_private_forwarders(self):
        for helper, sink, expected in [
            ('private fun next(value: String) = order(value)', 'db.queryForList(lookup(term))', True),
            ('private fun next(value: String) = order("label")', 'db.queryForList(lookup(term))', False),
            ('private fun next(value: String) = order(value)', 'db.queryForList("SELECT ?", lookup(term))', False),
            ('private fun next(value: String): String = lookup(value)', 'db.queryForList(lookup(term))', False),
            ('private fun next(value: String) = order(value)\nprivate fun next(value: Number) = value.toString()',
             'db.queryForList(lookup(term))', False),
        ]:
            with self.subTest(helper=helper, sink=sink):
                code = ('import org.springframework.jdbc.core.JdbcTemplate\n'
                        'import org.springframework.web.bind.annotation.RequestParam\n'
                        'private fun lookup(text: String): String = next(text)\n' + helper + '\n'
                        'private fun order(input: String) = "SELECT label FROM entries ORDER BY " + input\n'
                        'fun list(db: JdbcTemplate, @RequestParam term: String) = ' + sink)
                self.assertEqual(self.locations(code), [("sql-injection", len(code.splitlines()))] if expected else [])

    def test_sql_database_types_and_request_origins(self):
        mvc = "org.springframework.web.bind.annotation.RequestParam"
        jdbc = "org.springframework.jdbc.core"
        for imports, db, annotation, value_type, sql, expected in [
            ("", jdbc + ".JdbcTemplate", mvc, "kotlin.String", '"SELECT " + term', True),
            ("import " + jdbc + ".simple.JdbcClient as Client", "Client", mvc, "String?", '"SELECT $term"', True),
            ("import " + jdbc + ".*\nimport example.JdbcTemplate", "JdbcTemplate", mvc, "String", '"SELECT $term"', False),
            ("import " + jdbc + ".*\nclass JdbcTemplate", "JdbcTemplate", mvc, "String", '"SELECT $term"', False),
            ("import " + jdbc + ".*\nannotation class RequestParam", "JdbcTemplate", "RequestParam", "String", '"SELECT $term"', False),
            ("", jdbc + ".JdbcTemplate", mvc, "String", '"SELECT ?", term', False),
        ]:
            with self.subTest(db=db, imports=imports, sql=sql):
                method = "sql" if db == "Client" else "queryForList"
                code = (imports + f'\nclass Catalog(private val db: {db}) {{\n'
                        f' fun list(@{annotation} term: {value_type}) =\n  db.{method}({sql})\n}}')
                self.assertEqual(self.locations(code), [("sql-injection", len(code.splitlines()) - 1)] if expected else [])

    def test_cors_annotation(self):
        path = "org.springframework.web.bind.annotation.CrossOrigin"
        for imports, annotation, patterns, credentials, expected in [
            ("import " + path + " as Cors", "Cors", '["https://portal.example", "*"]', '"true"', True),
            ("", path, '["*"]', '"true"', True),
            ("import org.springframework.web.bind.annotation.*", "CrossOrigin", '["*"]', '"true"', True),
            ("import " + path, "CrossOrigin", '["https://*.example.org"]', '"true"', False),
            ("import " + path, "CrossOrigin", '["*"]', '"false"', False),
            ("import " + path, "CrossOrigin", '["*"]', r'"\${cors.credentials}"', False),
            ("import example.CrossOrigin", "CrossOrigin", '["*"]', '"true"', False),
            ("import org.springframework.web.bind.annotation.*\nannotation class CrossOrigin",
             "CrossOrigin", '["*"]', '"true"', False),
        ]:
            with self.subTest(imports=imports, patterns=patterns, credentials=credentials):
                code = (imports + f'\n@{annotation}(allowCredentials = {credentials},\n'
                        f' originPatterns = {patterns})\nclass Catalog')
                self.assertEqual(self.locations(code), [("credentialed-cors", len(code.splitlines()) - 1)] if expected else [])

    def test_cors_configuration_type(self):
        spring = "org.springframework.web.cors"
        for prefix, typ, expected in [
            ("import " + spring + ".CorsConfiguration as Policy", "Policy", True),
            ("", spring + ".CorsConfiguration", True),
            ("import " + spring + ".*\nimport example.CorsConfiguration", "CorsConfiguration", False),
            ("import " + spring + ".*\nclass CorsConfiguration", "CorsConfiguration", False),
        ]:
            with self.subTest(prefix=prefix, typ=typ):
                code = (prefix + f'\nfun policy() = {typ}().apply {{\n'
                        ' addAllowedOriginPattern("*")\n allowCredentials = true\n}')
                self.assertEqual(self.locations(code), [("credentialed-cors", len(code.splitlines()) - 2)] if expected else [])

    def test_cors_registry_tracks_each_registration_and_its_final_settings(self):
        mvc = "org.springframework.web.servlet.config.annotation.CorsRegistry"
        flux = "org.springframework.web.reactive.config.CorsRegistry"
        mapping = 'routes.addMapping("/jobs/**")'
        wide = '.allowedOriginPatterns("*")'
        credentials = '.allowCredentials(true)'
        for typ, body, offset in [
            ("Routes", mapping + '\n .allowedOriginPatterns("https://app.example", "*")' + credentials, 1),
            (flux, mapping + credentials + '.allowedMethods("GET")\n ' + wide, 1),
            ("Routes", 'val jobs = ' + mapping + '\n jobs' + wide + '\n jobs' + credentials, 1),
            ("Routes", mapping + wide + credentials + '.allowCredentials(false)', None),
            ("Routes", mapping + credentials + wide + '.allowedOriginPatterns("https://example.org")', None),
            ("Routes", mapping + '.allowedOrigins("*")' + credentials, None),
            ("Routes", mapping + '.allowedOrigins("*")' + wide + credentials, None),
            ("Routes", mapping + wide + credentials + '\n ' + mapping + '.allowCredentials(false)', None),
            ("Routes", mapping + wide + '\n routes.addMapping("/other")' + credentials, None),
            ("Routes", mapping + wide + credentials + '\n routes.addMapping("/other").allowCredentials(false)', 0),
            ("Routes", 'val jobs = ' + mapping + wide + credentials + '\n configurePolicy(jobs)', None),
            ("example.CorsRegistry", mapping + wide + credentials, None),
        ]:
            with self.subTest(typ=typ, body=body):
                code = (f'import {mvc} as Routes\nfun configure(routes: {typ}) {{\n'
                        + body + '\n}')
                self.assertEqual(self.locations(code), [("credentialed-cors", 3 + offset)] if offset is not None else [])
