import unittest

from garden.models import Source
from garden.scanners import analyze
from garden.submission import row


USER = "org.springframework.security.core.userdetails.User"


class SpringUserPasswords(unittest.TestCase):
    def check(self, code, expected):
        result = analyze("secrets", [Source(path="Accounts.kt", text=code)], "*")
        self.assertEqual(result.issues, [])
        self.assertEqual([(f.line, f.classification) for f in result.findings], expected)
        for finding in result.findings:
            self.assertNotIn("synthetic-value", finding.model_dump_json())
            self.assertNotIn("synthetic-value", str(row(finding)))

    def test_default_encoder_requires_a_literal(self):
        for expr, expected in [
            ('"synthetic-value"', [(4, "password")]),
            ('System.getenv("ACCOUNT_CREDENTIAL")', []),
            ('"from-${System.getenv(\"ACCOUNT_CREDENTIAL\")}"', []),
        ]:
            with self.subTest(expr=expr):
                code = f'import {USER} as Person\nfun account() = Person.withDefaultPasswordEncoder()\n' \
                       f'    .username("sample")\n    .password({expr})\n    .roles("USER").build()'
                self.check(code, expected)

    def test_only_plaintext_in_preencoded_builders(self):
        for expr, expected in [
            ('"{noop}synthetic-value"', [(2, "password")]),
            ('"{pbkdf2}' + "a" * 80 + '"', []),
            ('System.getenv("ACCOUNT_HASH")', []),
        ]:
            with self.subTest(expr=expr):
                self.check(f'fun make() = {USER}.withUsername("sample")\n    .password({expr})', expected)

    def test_unrelated_user_and_shadowed_factory(self):
        chain = 'User.withDefaultPasswordEncoder().username("sample").password("synthetic-value")'
        for code in [
            f'import demo.User\nfun make() = {chain}',
            f'import {USER}\nfun make(User: demo.AccountFactory) = {chain}',
            f'import {USER}\nfun make() {{\n val User = demo.AccountFactory()\n {chain}\n}}',
        ]:
            with self.subTest(code=code):
                self.check(code, [])

    def test_noop_password_on_typed_builder_and_external_field(self):
        self.check(f'import {USER}.UserBuilder as Builder\nfun configure(user: Builder) {{\n'
                   ' user.password("{noop}synthetic-value")\n}', [(3, "password")])
        self.check('import demo.UserBuilder as Builder\nfun configure(user: Builder) {\n'
                   ' user.password("{noop}synthetic-value")\n}', [])

    def test_named_secret_source_has_one_finding(self):
        self.check(f'import {USER}\nval dbPassword = "synthetic-value"\n'
                   'fun make() = User.withDefaultPasswordEncoder().password(dbPassword)', [(2, "password")])
