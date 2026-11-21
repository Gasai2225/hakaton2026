import unittest

from garden.models import Source
from garden.scanners import analyze


class SpringAccessVariants(unittest.TestCase):
    def test_servlet_matching_requires_spring_builder_type(self):
        for typ, expected in [("Builder", True), ("Notebook", False)]:
            with self.subTest(typ=typ):
                code = ('import org.springframework.security.config.annotation.web.builders.HttpSecurity as Builder\n'
                        f'fun setup(http: {typ}) = http.authorizeHttpRequests {{ rules ->\n'
                        ' rules.requestMatchers("/records/demo").permitAll()\n'
                        ' rules.requestMatchers("/records/**").authenticated()\n}')
                self.assertEqual(self.scan(("Policy.kt", code)), [("route-authorization", "Policy.kt", 3)] if expected else [])

    def test_open_default_belongs_to_a_reachable_spring_rule(self):
        for typ, body, expected in [
            ("Builder", "it.anyRequest().permitAll()", 3),
            ("Notebook", "it.anyRequest().permitAll()", None),
            ("Builder", "val unused = { it.anyRequest().permitAll() }", None),
            ("Builder", 'it.requestMatchers("/**").authenticated()\n it.anyRequest().permitAll()', None),
            ("Builder", 'it.requestMatchers("/staff/**").authenticated()\n it.anyRequest().permitAll()', 4),
        ]:
            with self.subTest(typ=typ, body=body):
                code = ('import org.springframework.security.config.annotation.web.builders.HttpSecurity as Builder\n'
                        f'fun setup(http: {typ}) = http.authorizeHttpRequests {{\n {body}\n}}')
                self.assertEqual(self.scan(("Policy.kt", code)),
                                 [("route-authorization", "Policy.kt", expected)] if expected else [])

    def scan(self, *files):
        result = analyze("sast", [Source(path=path, text=code) for path, code in files], "*")
        self.assertEqual(result.issues, [])
        return [(hit.classification, hit.path, hit.line) for hit in result.findings]

    def test_first_matching_route_across_path_segments(self):
        for public, restricted, earlier, expected in [
            ("/jobs/{id}/log", "/jobs/pending/log", "", True),
            ("/jobs/*/log", "/jobs/staff/{view}", "", True),
            ("/jobs/{id}/**", "/jobs/staff", "", True),
            ("/jobs/public", "/jobs/{*path}", "", True),
            ("/jobs/{id}/log", "/jobs/pending/extra/log", "", False),
            ("/jobs/{id}/log", "/jobs/pending/log", "/jobs/*/log", False),
            ("/jobs/*/log", "/jobs/staff/{view}", "/jobs/staff/log", False),
            ("/jobs/{id}/log", "/jobs/pending/log", "/jobs/other/log", True),
            ("/jobs/public", "/{*path}", "", False),
            ("/jobs/report-*.csv", "/jobs/**", "", True),
            ("/jobs/{id}", "/jobs/12", "/jobs/{number:[0-9]+}", False),
            ("/jobs/*", "/jobs/", "", False),
        ]:
            with self.subTest(public=public, restricted=restricted, earlier=earlier):
                code = ('import org.springframework.security.config.annotation.web.builders.HttpSecurity\n'
                        'fun setup(http: HttpSecurity) = http.authorizeHttpRequests { rules ->\n')
                if earlier:
                    code += f' rules.requestMatchers("{earlier}").denyAll()\n'
                code += (f' rules.requestMatchers("{public}").permitAll()\n'
                         f' rules.requestMatchers("{restricted}").authenticated()\n}}')
                self.assertEqual(self.scan(("Policy.kt", code)),
                                 [("route-authorization", "Policy.kt", 4 if earlier else 3)] if expected else [])

    def test_only_first_reachable_public_matcher_is_reported(self):
        code = '''import org.springframework.security.config.annotation.web.builders.HttpSecurity
fun setup(http: HttpSecurity) = http.authorizeHttpRequests { rules ->
    rules.requestMatchers("/jobs/**").permitAll()
    rules.requestMatchers("/jobs/report").permitAll()
    rules.requestMatchers("/jobs/report").hasRole("STAFF")
}'''
        self.assertEqual(self.scan(("Policy.kt", code)), [("route-authorization", "Policy.kt", 3)])

    def test_webflux_fluent_rules_are_scoped_to_the_registry_and_http_verb(self):
        server = "org.springframework.security.config.web.server.ServerHttpSecurity"
        for typ, public, restricted, prior, expected in [
            ("Server", 'HttpMethod.GET, "/about", "/tasks/{id}"', 'HttpMethod.GET, "/tasks/staff"', "", True),
            (server, '"/tasks/log"', '"/tasks/**"', "", True),
            ("Server", 'HttpMethod.GET, "/tasks/log"', 'HttpMethod.POST, "/tasks/**"', "", False),
            ("Server", '"/ping"', '"/tasks/**"', "", False),
            ("Server", '"/tasks/{id}"', '"/tasks/staff"', 'rules.pathMatchers("/tasks/staff").authenticated()', False),
            ("example.Console", '"/tasks/log"', '"/tasks/**"', "", False),
        ]:
            with self.subTest(typ=typ, public=public, restricted=restricted, prior=prior):
                code = (f'import {server} as Server\nimport org.springframework.http.HttpMethod\n'
                        f'fun configure(http: {typ}) = http.authorizeExchange {{ rules ->\n'
                        f' {prior}\n rules.pathMatchers({public}).permitAll()\n'
                        f' rules.pathMatchers({restricted}).hasRole("STAFF")\n}}')
                self.assertEqual(self.scan(("Web.kt", code)), [("route-authorization", "Web.kt", 5)] if expected else [])

    def test_webflux_dsl_default_access_and_registry_boundaries(self):
        for typ, body, expected_line in [
            ("ServerHttpSecurity", 'authorize("/jobs/list", permitAll)\n authorize("/jobs/**")', 4),
            ("ServerHttpSecurity", 'authorize("/jobs/{id}", permitAll)\n authorize("/jobs/list", hasRole("STAFF"))', 4),
            ("ServerHttpSecurity", 'authorize(access = permitAll, antPattern = "/jobs/list")\n authorize(antPattern = "/jobs/**")', 4),
            ("ServerHttpSecurity", 'authorize("/jobs/**")\n authorize("/jobs/list", permitAll)', None),
            ("ServerHttpSecurity", 'authorize("/ping", permitAll)\n authorize("/jobs/**", authenticated)', None),
            ("ServerHttpSecurity", 'authorize("/jobs/list", permitAll)\n }\n authorizeExchange { authorize("/jobs/**")', None),
            ("example.Console", 'authorize("/jobs/list", permitAll)\n authorize("/jobs/**")', None),
        ]:
            with self.subTest(typ=typ, body=body):
                code = ('import org.springframework.security.config.web.server.ServerHttpSecurity\n'
                        'import org.springframework.security.config.web.server.invoke\n'
                        f'fun setup(http: {typ}) = http {{ authorizeExchange {{\n {body}\n }} }}')
                self.assertEqual(self.scan(("Web.kt", code)),
                                 [("route-authorization", "Web.kt", expected_line)] if expected_line else [])

    def test_webflux_fluent_registry_chain(self):
        code = '''import org.springframework.security.config.web.server.ServerHttpSecurity
fun configure(http: ServerHttpSecurity) = http.authorizeExchange {
    it.pathMatchers("/tasks/public").permitAll()
        .pathMatchers("/tasks/**").hasAuthority("tasks:read")
}'''
        self.assertEqual(self.scan(("Web.kt", code)), [("route-authorization", "Web.kt", 3)])

    def test_object_read_only_when_unchecked_row_reaches_response(self):
        query = 'db.queryForMap("SELECT owner_id, label FROM jobs WHERE id = ?", id)'
        for reader, handler, guard, line in [
            (f'= {query}', '= store.read(id)', '@PreAuthorize("permitAll")', 6),
            (f'= {query}', '= store.read(id)', '@PreAuthorize("isFullyAuthenticated()")', 6),
            (f'= {query}', '= store.read(id)', '@PreAuthorize("denyAll")', None),
            (f'= {query}', '{\n val entry = store.read(id)\n return entry\n }', '', 7),
            (f'{{ val r = {query}; return r }}', '= store.read(id)', '', 6),
            (f'= {query}.takeIf {{ owns(it) }}', '= store.read(id)', '', None),
            (f'{{ val r = {query}; require(owns(r)); return r }}', '= store.read(id)', '', None),
            (f'{{ {query}; return "public" }}', '= store.read(id)', '', None),
            (f'= {query}', '{ val r = store.read(id); require(owns(r)); return r }', '', None),
        ]:
            with self.subTest(reader=reader, handler=handler, guard=guard):
                store = ('package demo\nimport org.springframework.stereotype.Repository\n'
                         'import org.springframework.jdbc.core.JdbcTemplate\n@Repository class Jobs(val db: JdbcTemplate) {\n'
                         f' fun read(id: Long) {reader}\n}}')
                web = ('package demo\nimport org.springframework.web.bind.annotation.*\n'
                       'import org.springframework.security.access.prepost.PreAuthorize\n'
                       '@RestController class JobsApi(val store: Jobs) {\n'
                       f' {guard} @GetMapping("/jobs/{{id}}")\n fun job(@PathVariable id: Long) {handler}\n}}')
                self.assertEqual(self.scan(("Jobs.kt", store), ("JobsApi.kt", web)),
                                 [("object-authorization", "JobsApi.kt", line)] if line else [])
