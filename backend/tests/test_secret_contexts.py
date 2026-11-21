import unittest

from garden.models import Source
from garden.scanners import analyze


class SecretContextTests(unittest.TestCase):
    def check(self, path, text, expected):
        result = analyze("secrets", [Source(path=path, text=text)], "*")
        self.assertEqual(result.issues, [])
        self.assertEqual([(f.classification, f.line) for f in result.findings], expected)
        self.assertNotIn("fixture-private", str(result.findings))

    def test_logging_levels_are_settings_even_for_a_logger_named_token(self):
        self.check("application.properties", "logging.level.demo.SessionToken=DEBUG\nclient.token=DEBUG",
                   [("configuration-token", 2)])
        self.check("application.yml", "logging:\n  level:\n    demo.SessionToken: '${LEVEL:INFO}'\n"
                   "client:\n  token: fixture-private", [("configuration-token", 5)])

    def test_github_permissions_do_not_hide_credentials_in_job_inputs(self):
        self.check(".github/workflows/check.yml", "permissions:\n  id-token: none\njobs:\n  report:\n"
                   "    permissions:\n      id-token: write\n    env:\n      SERVICE_TOKEN: fixture-private",
                   [("configuration-token", 8)])
        self.check("application.yml", "permissions:\n  id-token: write", [("configuration-token", 2)])

    def test_java_properties_decoding_precedes_spring_default_resolution(self):
        text = r"client.api-key=\u0024{CLIENT_KEY}" + "\n" + r"client.token=\t" + "\n" + r"client.password=\u0024{PASS:fixture-private}"
        self.check("application.properties", text, [("secret-fallback", 3)])
        self.check("application.properties", r"client.password=\\u0024{PASS}", [("password", 1)])

    def test_jdk_resource_bundle_key_is_only_a_lookup_key(self):
        text = 'import java.util.ResourceBundle as Messages\nfun caption(messages: Messages) {\n' \
               '    val password = "form.password"\n    messages.getString(password)\n}'
        self.check("Captions.kt", text, [])
        self.check("Captions.kt", text.replace("messages.getString(password)", "send(password)"), [("password", 3)])
        self.check("Captions.kt", text.replace("java.util.ResourceBundle", "example.ResourceBundle"), [("password", 3)])
        self.check("Captions.kt", text.replace("messages.getString(password)", "messages.getString(password); send(password)"),
                   [("password", 3)])

    def test_gradle_version_catalog_uses_dependency_aliases(self):
        code = ('import org.gradle.api.artifacts.VersionCatalog as Catalog\n'
                'fun dependency(catalog: Catalog) {\n val token = "library.token"\n catalog.findLibrary(token)\n}')
        self.check("build.gradle.kts", code, [])
        self.check("build.gradle.kts", code.replace("findLibrary", "findVersion"), [])
        self.check("build.gradle.kts", code.replace("org.gradle.api.artifacts.VersionCatalog", "example.Catalog"),
                   [("configuration-token", 3)])
        self.check("build.gradle.kts", code.replace("catalog.findLibrary(token)", "send(token)"),
                   [("configuration-token", 3)])
