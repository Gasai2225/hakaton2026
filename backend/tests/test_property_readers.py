"""Kotlin property names and synthetic default values in Spring and JDK lookups."""
import unittest

from garden.models import Source
from garden.scanners import analyze


class PropertyReaders(unittest.TestCase):
    def check(self, typ, statements, expected):
        code = (f"import {typ} as Settings\n"
                "fun sample(settings: Settings, external: String) {\n" + statements + "\n}")
        result = analyze("secrets", [Source(path="src/main/kotlin/Workshop.kt", text=code)], "*")
        self.assertEqual(result.issues, [])
        self.assertEqual([(hit.classification, hit.line) for hit in result.findings], expected)
        self.assertNotIn("workshop-marker", str(result.findings))

    def test_spring_lookup_keys_and_string_defaults(self):
        cases = [
            ("settings.getProperty(apiKey)", []),
            ("settings.getRequiredProperty(apiKey)", []),
            ("settings.containsProperty(apiKey)", []),
            ("settings.getProperty(apiKey, String::class.java)", []),
            ("settings.getRequiredProperty(apiKey, String::class.java)", []),
            ('settings.getProperty(apiKey, "workshop-marker")', [("secret-fallback", 4)]),
            ('settings.getProperty(apiKey, kotlin.String::class.java, "workshop-marker")', [("secret-fallback", 4)]),
            ('settings.getProperty(apiKey, "")', []),
            ('settings.getProperty(apiKey, String::class.java, external)', []),
            ("settings.getProperty(apiKey); println(apiKey)", [("api-key", 3)]),
        ]
        for typ in ("Environment", "PropertyResolver", "ConfigurableEnvironment"):
            for use, expected in cases:
                with self.subTest(typ=typ, use=use):
                    self.check("org.springframework.core.env." + typ, 'val apiKey = "workshop.api-key"\n' + use, expected)

    def test_properties_and_generic_methods_are_distinct(self):
        for typ, calls, expected in [
            ("java.util.Properties", "settings.getProperty(password)", []),
            ("java.util.Properties", 'settings.getProperty(password, "workshop-marker")', [("secret-fallback", 4)]),
            ("java.util.Properties", "println(password); settings.getProperty(password)", [("password", 3)]),
            ("workshop.Notebook", 'settings.getProperty(password, "workshop-marker")', [("password", 3)]),
            ("workshop.Notebook", "settings.getRequiredProperty(password)", [("password", 3)]),
        ]:
            with self.subTest(typ=typ, calls=calls):
                self.check(typ, 'val password = "workshop.password"\n' + calls, expected)

    def test_fallback_classification_requires_a_sensitive_key_and_a_real_reader(self):
        for typ in ("org.springframework.core.env.Environment", "java.util.Properties", "workshop.Notebook"):
            for key in ("workshop.password", "workshop.title"):
                for default in ('"workshop-marker"', "external"):
                    with self.subTest(typ=typ, key=key, default=default):
                        flagged = typ != "workshop.Notebook" and key.endswith("password") and default.startswith('"')
                        self.check(typ, f'settings.getProperty("{key}", {default})',
                                   [("secret-fallback", 3)] if flagged else [])

    def test_named_key_constants_preserve_the_sensitive_property_name(self):
        for typ in ("org.springframework.core.env.Environment", "java.util.Properties", "workshop.Notebook"):
            for key in ("workshop.password", "workshop.title"):
                with self.subTest(typ=typ, key=key):
                    self.check(typ, f'val propertyName = "{key}"\nsettings.getProperty(propertyName, "workshop-marker")',
                               [("secret-fallback", 4)] if typ != "workshop.Notebook" and key.endswith("password") else [])
