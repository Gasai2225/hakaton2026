"""Static Spring policies. Each case specifies the complete expected set of findings."""
import unittest

from garden.models import Source
from garden.scanners import analyze


class SpringPolicyMatrix(unittest.TestCase):
    def check(self, code, classification, expected):
        result = analyze("sast", [Source(path="Policy.kt", text=code)], "*")
        self.assertEqual(result.issues, [])
        self.assertEqual([(f.path, f.classification) for f in result.findings],
                         [("Policy.kt", classification)] if expected else [])

    def test_static_origin_lists(self):
        for origins, pattern, credentials, expected in [
            ("https://site.example", "*", True, True),
            ("https://site.example", "*", False, False),
            ("https://site.example", "https://*.school.example:[*]", True, False),
            ("https://site.example", "https://*.school.example:[8080,8081],https://staff.example", True, False),
            ("https://site.example", "https://*.school.example:[8080,8081], *", True, True),
            ("https://site.example", "*, https://staff.example", True, True),
            ("*", "*", True, False),
            ("https://site.example, *", "*", True, False),
        ]:
            flag = str(credentials).lower()
            formulas = {
                "configuration": ('import org.springframework.web.cors.CorsConfiguration\n'
                                  'fun policy() = CorsConfiguration().apply {\n'
                                  f' allowedOrigins = listOf("{origins}")\n addAllowedOriginPattern("{pattern}")\n'
                                  f' allowCredentials = {flag}\n}}'),
                "registry": ('import org.springframework.web.servlet.config.annotation.CorsRegistry\n'
                             'fun policy(reg: CorsRegistry) { reg.addMapping("/cards/**")\n'
                             f' .allowedOrigins("{origins}").allowedOriginPatterns("{pattern}").allowCredentials({flag})\n}}'),
                "annotation": ('import org.springframework.web.bind.annotation.CrossOrigin\n'
                               f'@CrossOrigin(origins = ["{origins}"], originPatterns = ["{pattern}"], '
                               f'allowCredentials = "{flag}")\nclass Cards'),
            }
            for api, code in formulas.items():
                with self.subTest(api=api, origins=origins, pattern=pattern, credentials=credentials):
                    self.check(code, "credentialed-cors", expected)

    def test_final_configuration_after_builder(self):
        for builder, receiver, parameter in [("apply", "", ""), ("also", "cfg.", " cfg ->")]:
            for adjustments, expected in [
                ("cfg.allowCredentials = false", False),
                ('cfg.allowedOriginPatterns = listOf("https://site.example")', False),
                ('val same = cfg\n same.setAllowedOriginPatterns(listOf("https://site.example"))', False),
                ('val independent = CorsConfiguration()\n independent.allowCredentials = false', True),
                ('cfg.allowedHeaders = listOf("X-Cards")', True),
                ('cfg.allowedOrigins = listOf("https://site.example")', True),
                ('val plain: Any = cfg\n plain.setAllowedOriginPatterns(listOf("https://site.example"))', True),
                ('return cfg\n cfg.allowCredentials = false', True),
            ]:
                with self.subTest(builder=builder, adjustments=adjustments):
                    code = ('import org.springframework.web.cors.CorsConfiguration\n'
                            'fun Any.setAllowedOriginPatterns(notes: List<String>) {}\n'
                            f'fun policy(): CorsConfiguration {{\n val cfg = CorsConfiguration().{builder} {{{parameter}\n'
                            f' {receiver}allowCredentials = true\n {receiver}addAllowedOriginPattern("*")\n }}\n'
                            f' {adjustments}\n return cfg\n}}')
                    self.check(code, "credentialed-cors", expected)

    def test_registry_alias_identity(self):
        for typ in ("", ": CorsRegistry"):
            for initializer, replacement_path, expected in [
                ("routes", "/cards/**", False),
                ("routes", "/notes/**", True),
                ("second", "/cards/**", True),
            ]:
                with self.subTest(typ=typ, initializer=initializer, replacement_path=replacement_path):
                    code = ('import org.springframework.web.servlet.config.annotation.CorsRegistry\n'
                            'fun policy(routes: CorsRegistry, second: CorsRegistry) {\n'
                            ' routes.addMapping("/cards/**").allowedOriginPatterns("*").allowCredentials(true)\n'
                            f' val alias{typ} = {initializer}\n'
                            f' alias.addMapping("{replacement_path}").allowedOrigins("https://site.example")\n}}')
                    self.check(code, "credentialed-cors", expected)

    def test_method_wide_prior_rule_precedes_grouped_paths(self):
        for earlier, expected in [("HttpMethod.GET", False), ("HttpMethod.POST", True),
                                  ("READ", False), ("WRITE", True),
                                  ('HttpMethod.GET, "/cards/list", "/cards/public"', False),
                                  ('HttpMethod.GET, "/notes/**", "/cards/staff"', True)]:
            with self.subTest(earlier=earlier):
                code = ('import org.springframework.security.config.annotation.web.builders.HttpSecurity\n'
                        'import org.springframework.http.HttpMethod\n'
                        'import org.springframework.http.HttpMethod.GET as READ\n'
                        'import org.springframework.http.HttpMethod.POST as WRITE\n'
                        'fun policy(http: HttpSecurity) = http.authorizeHttpRequests { rules ->\n'
                        f' rules.requestMatchers({earlier}).authenticated()\n'
                        ' rules.requestMatchers(HttpMethod.GET, "/cards/list", "/cards/public").permitAll()\n'
                        ' rules.requestMatchers("/cards/**").hasRole("STAFF")\n}')
                self.check(code, "route-authorization", expected)

    def test_local_http_method_with_aliased_class(self):
        for earlier, expected in [("Verb.GET", False), ("Verb.POST", True), ("org.springframework.http.HttpMethod.GET", False)]:
            for prior in ["selected", "copy"]:
                with self.subTest(earlier=earlier, prior=prior):
                    code = ('import org.springframework.security.config.annotation.web.builders.HttpSecurity\n'
                            'import org.springframework.http.HttpMethod as Verb\n'
                            'fun policy(http: HttpSecurity) = http.authorizeHttpRequests { rules ->\n'
                            f' val selected: Verb = {earlier}\n val copy = selected\n'
                            f' rules.requestMatchers({prior}).authenticated()\n'
                            ' rules.requestMatchers(Verb.GET, "/cards/index").permitAll()\n'
                            ' rules.requestMatchers("/cards/**").hasRole("STAFF")\n}')
                    self.check(code, "route-authorization", expected)
