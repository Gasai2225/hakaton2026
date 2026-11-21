import unittest

from garden.models import Source
from garden.scanners import analyze


class ComposePrecision(unittest.TestCase):
    def check(self, command, expected, *, image="mysql:8.4", extra=""):
        source = Source(path="compose.yaml", text=(
            "services:\n  example:\n    image: " + image + "\n" + command + extra
            + "    environment:\n      MYSQL_ALLOW_EMPTY_PASSWORD: 'yes'\n"
        ))
        result = analyze("sast", [source], "*")
        self.assertEqual(result.issues, [])
        self.assertEqual([f.classification for f in result.findings],
                         ["empty-database-root-password"] if expected else [])

    def test_server_initialization_requires_a_server_command(self):
        for command, expected in [
            ("", True), ("null", True), ("[]", False), ('""', False),
            ('["mysql", "--version"]', False), ('["mysqld", "--help"]', False),
            ('"--print-defaults"', False), ('"mysqld -V"', False),
            ('[mysqld, "--max-connections=42"]', True),
            ('"--max-connections=42"', True),
            ('["/bin/echo", "mysqld"]', False), ('["${SERVER_COMMAND}"]', False),
        ]:
            with self.subTest(command=command):
                self.check("    command: " + command + "\n" if command else "", expected)

    def test_build_may_replace_the_official_image_entrypoint(self):
        self.check("", False, extra="    build: .\n")
        self.check("", True)

    def test_reset_override_removes_credential_values(self):
        for key, value, kind in [("SERVICE_PASSWORD", "classroom-marker", "secrets"),
                                 ("MYSQL_ALLOW_EMPTY_PASSWORD", "'yes'", "sast")]:
            for env_tag, value_tag in [("", ""), (" !reset", ""), ("", "!reset ")]:
                with self.subTest(key=key, env_tag=env_tag, value_tag=value_tag):
                    content = f"services:\n  db:\n    image: mysql:8.4\n    environment:{env_tag}\n      {key}: {value_tag}{value}"
                    report = analyze(kind, [Source(path="compose.override.yml", text=content)], "*")
                    self.assertEqual(report.issues, [])
                    self.assertEqual(len(report.findings), int(not (env_tag or value_tag)))

    def test_legacy_service_requires_a_service_definition(self):
        for service_fields, expected in [("", 0), ("  image: classroom\n", 1), ("  build: .\n", 1)]:
            with self.subTest(service_fields=service_fields):
                text = "example:\n" + service_fields + "  environment:\n    SERVICE_PASSWORD: classroom-marker"
                result = analyze("secrets", [Source(path="compose-data.yml", text=text)], "*")
                self.assertEqual(len(result.findings), expected)
