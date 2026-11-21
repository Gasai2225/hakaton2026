import unittest

from garden.models import Source
from garden.scanners import analyze
from garden.submission import row


class SecretVariants(unittest.TestCase):
    def scan(self, path, code):
        result = analyze("secrets", [Source(path=path, text=code)], "*")
        self.assertEqual(result.issues, [])
        rows = [row(hit) for hit in result.findings]
        self.assertNotIn("fixture", str(rows))
        return [(hit["class"], hit["line"]) for hit in rows]

    def test_spring_composed_defaults(self):
        for value, expected in [
            ("Bearer ${CLIENT_TOKEN:fixture-only}", True),
            ("${PREFIX:fix}${SUFFIX:ture}", True),
            ("${OUTER:${LEFT:fix}-${RIGHT:ture}}", True),
            ("Bearer ${CLIENT_TOKEN}", False),
            ("Bearer ${CLIENT_TOKEN:}", False),
            ("${PREFIX:fixture-}${REQUIRED}", False),
            ("${OUTER:${INNER}}", False),
            ("${PRIMARY:#{null}}", False),
        ]:
            for path, separator in [("app.properties", "="), ("app.yaml", ": ")]:
                with self.subTest(path=path, value=value):
                    code = "# configuration\nclient.authorization" + separator + value
                    self.assertEqual(self.scan(path, code), [("secret-fallback", 2)] if expected else [])

    def test_jvm_property_keys_and_default_values(self):
        for uses, expected in [
            ("System.getProperty(apiKey)", False),
            ('java.lang.System.getProperty(apiKey, "")', False),
            ('System.getProperty("service.setting", apiKey)', True),
            ("custom.getProperty(apiKey)", True),
            ("System.getProperty(apiKey); send(apiKey)", True),
        ]:
            with self.subTest(uses=uses):
                code = 'fun read() {\n val apiKey = "client.fixture-key"\n ' + uses + '\n}'
                self.assertEqual(self.scan("Settings.kt", code), [("api-key", 2)] if expected else [])

    def test_star_imported_spring_value_respects_shadowing(self):
        annotation = r'@Value("\${client.password:fixture-only}")'
        for declarations, expected in [
            ("", True),
            ("import other.Value\n", False),
            ("annotation class Value(val value: String)\n", False),
        ]:
            with self.subTest(declarations=declarations):
                code = "import org.springframework.beans.factory.annotation.*\n" + declarations
                line = code.count("\n") + 1
                code += f"class Config({annotation} val value: String)"
                self.assertEqual(self.scan("Config.kt", code), [("secret-fallback", line)] if expected else [])

    def test_jvm_default_identified_by_property_key(self):
        for args, expected in [
            ('"client.api-key", "fixture-only"', True),
            ('apiKey, "fixture-only"', True),
            ('"client.timeout", "fixture-only"', False),
            ('apiKey, System.getenv("REPLACEMENT")', False),
            ('apiKey, "  "', False),
        ]:
            with self.subTest(args=args):
                prefix = ('private val apiKey = "client.api-key"\n' if "apiKey" in args else "\n")
                code = prefix + 'fun read() = java.lang.System.getProperty(' + args + ')'
                self.assertEqual(self.scan("Config.kt", code), [("secret-fallback", 2)] if expected else [])

        shadowed = 'fun read(System: Labels) = System.getProperty("client.api-key", "fixture-only")'
        self.assertEqual(self.scan("Config.kt", shadowed), [])
        named = 'val apiKey = System.getProperty("client.api-key", "fixture-only")'
        self.assertEqual(self.scan("Config.kt", named), [("secret-fallback", 1)])

    def test_only_literal_dollars_are_embedded_credentials(self):
        for declaration, expected in [
            (r'val password = "fixture\$NAME"', "password"),
            ('val apiKey = """fixture${\'$\'}name"""', "api-key"),
            ('val token = "fixture$9"', "configuration-token"),
            (r'val token = System.getenv("EXTERNAL") ?: "fixture\$key"', "secret-fallback"),
            (r'val token = "fixture\$part" + "-two"', "recoverable-token"),
            ('val token = "prefix-$external"', None),
            ('val token = "prefix-${external.value}"', None),
            (r'val token = "prefix-\\$external"', None),
            (r'val token = """prefix-\$external"""', None),
            (r'val token = "prefix-\$literal-$external"', None),
        ]:
            with self.subTest(declaration=declaration):
                self.assertEqual(self.scan("Client.kt", declaration), [(expected, 1)] if expected else [])

    def test_dollar_in_spring_authorization_header(self):
        source = r'''import org.springframework.http.HttpHeaders
fun headers(h: HttpHeaders, external: String) {
    h.setBearerAuth("fixture\$key")
    h.setBearerAuth("prefix-$external")
}'''
        self.assertEqual(self.scan("Client.kt", source), [("configuration-token", 3)])

    def test_jdk_builder_header_sinks(self):
        for expr, expected in [
            ('R.newBuilder().header("X-Api-Key", "fixture-one")', "api-key"),
            ('R.newBuilder().GET().setHeader("Authorization", "Bearer fixture")', "configuration-token"),
            ('builder.setHeader("x-api-key", "fixture-two")', "api-key"),
            ('builder.setHeader("Authorization", "Bearer $runtime")', None),
            ('builder.header("Content-Type", "fixture-three")', None),
            ('builder.header("Authorization", "Bearer ")', None),
            ('labels.header("Authorization", "Bearer fixture")', None),
            ('labels.setHeader("X-Api-Key", "fixture-four")', None),
            ('builder.build().toString()', None),
        ]:
            with self.subTest(expr=expr):
                src = ('import java.net.http.HttpRequest as R\nimport org.springframework.http.HttpHeaders\n'
                       'fun make(builder: R.Builder, labels: Labels, runtime: String) {\n ' + expr + '\n}')
                self.assertEqual(self.scan("Client.kt", src), [(expected, 4)] if expected else [])

    def test_jdk_builder_batch_and_reused_source(self):
        src = '''import java.net.http.HttpRequest
import java.net.URI
fun make(uri: URI, runtime: String) {
    val client = HttpRequest.newBuilder(uri)
    val saved = "fixture-shared"
    client.header("X-Api-Key", saved)
    client.setHeader("X-Api-Key", saved)
    client.headers("Accept", "application/json",
        "Authorization", "Bearer fixture-auth",
        "X-Api-Key", "fixture-second")
    client.header("X-Api-Key", runtime)
}'''
        self.assertCountEqual(self.scan("Client.kt", src), [
            ("api-key", 5), ("configuration-token", 9), ("api-key", 10),
        ])

    def test_only_complete_authorization_templates_are_recoverable(self):
        for expr, expected in [
            ('"Bearer $piece"', True), ('"Bearer ${piece}"', True),
            ('"Bearer $piece-$runtime"', False), ('"Bearer ${piece + runtime}"', False),
            ('"Bearer $runtime"', False),
        ]:
            with self.subTest(expr=expr):
                src = ('import java.net.http.HttpRequest.Builder as RequestBuilder\n'
                       'fun make(b: RequestBuilder, runtime: String) {\n val piece = "fixture-part"\n'
                       ' b.header("Authorization", ' + expr + ')\n}')
                self.assertEqual(self.scan("Client.kt", src), [("configuration-token", 3)] if expected else [])

    def test_builder_factory_lookalikes(self):
        for imports, params in [
            ("import demo.HttpRequest", ""),
            ("import java.net.http.*\nclass HttpRequest", ""),
            ("import java.net.http.HttpRequest", "HttpRequest: Labels"),
        ]:
            code = (imports + "\nfun make(" + params + ') = HttpRequest.newBuilder().header("X-Api-Key", "fixture")')
            with self.subTest(code=code):
                self.assertEqual(self.scan("Client.kt", code), [])

    def test_builder_outside_function_and_basic_credentials(self):
        for literal, expected in [
            ("Basic Zml4dHVyZTpzYW1wbGU=", True),
            ("Basic Zml4dHVyZTo=", False),  # A username with an empty password.
            ("Basic Zml4dHVyZQ==", False),  # No username/password separator.
            ("Basic invalid*", False),
        ]:
            with self.subTest(literal=literal):
                src = ('import java.net.http.HttpRequest\nclass Store {\n val call = HttpRequest.newBuilder()\n'
                       '     .header("Authorization", "' + literal + '")\n}')
                self.assertEqual(self.scan("Client.kt", src), [("recoverable-token", 4)] if expected else [])
        src = ('val request = java.net.http.HttpRequest.newBuilder()\n'
               '    .header("X-Api-Key", "fixture")')
        self.assertEqual(self.scan("Client.kt", src), [("api-key", 2)])

    def test_spring_rest_client_header_keeps_typed_calls(self):
        for receiver, expected in [("client.get().uri(\"/health\")", True),
                                   ("RestClient.create().get()", True), ("labels.get()", False)]:
            with self.subTest(receiver=receiver):
                src = ('import org.springframework.web.client.RestClient\n'
                       'fun send(client: RestClient, labels: Labels) =\n'
                       f'    {receiver}.header("Authorization", "Bearer fixture")')
                self.assertEqual(self.scan("Client.kt", src), [("configuration-token", 3)] if expected else [])

    def test_complete_compound_values_at_header_sinks(self):
        for call, expected in [
            ('b.header("X-Api-Key", prefix + suffix)', True),
            ('b.setHeader("Authorization", "Bearer " + (prefix + suffix))', True),
            ('h.setBearerAuth("${prefix}.$suffix")', True),
            ('h.set("X-Api-Key", "v1-$prefix$suffix")', True),
            ('b.header("Authorization", "Bearer ${prefix + suffix}")', True),
            ('h.setBearerAuth("$prefix-$runtime")', False),
            ('b.header("X-Api-Key", prefix + runtime)', False),
            ('b.header("Authorization", "Bearer ${prefix + runtime}")', False),
            ('h.set("X-Api-Key", "${provider()}-$suffix")', False),
            ('b.header("Accept", prefix + suffix)', False),
        ]:
            with self.subTest(call=call):
                src = ('import java.net.http.HttpRequest\nimport org.springframework.http.HttpHeaders\n'
                       'fun send(b: HttpRequest.Builder, h: HttpHeaders, runtime: String) {\n'
                       ' val prefix = "fixture-"\n val suffix = "suffix"\n ' + call + '\n}')
                self.assertEqual(self.scan("Client.kt", src), [("recoverable-token", 6)] if expected else [])

    def test_compound_alias_deduplication_and_file_constant_shadowing(self):
        src = '''import org.springframework.http.HttpHeaders
private const val SERIES = "fixture-"
fun send(h: HttpHeaders) {
    val end = "postfix"
    val saved = "${SERIES}$end"
    h.setBearerAuth(saved)
    h.set("X-Api-Key", saved)
}
fun other(h: HttpHeaders, SERIES: String) {
    h.setBearerAuth(SERIES + "-tail")
}'''
        self.assertEqual(self.scan("Client.kt", src), [("recoverable-token", 5)])
        relocated = src.replace('private const val SERIES = "fixture-"\n', '') + '\nprivate const val SERIES = "fixture-"'
        self.assertEqual(self.scan("Client.kt", relocated), [("recoverable-token", 4)])

    def test_enclosing_inputs_and_custom_operators_are_dynamic(self):
        prefix = 'import org.springframework.http.HttpHeaders\nprivate const val PART = "fixture"\n'
        for body in [
            'class Sender(val PART: String) {\n fun send(h: HttpHeaders) { h.setBearerAuth(PART + "x") }\n}',
            'fun outer(PART: String) {\n fun send(h: HttpHeaders) { h.setBearerAuth(PART + "x") }\n}',
            'fun outer(input: String) {\n val PART = input\n fun send(h: HttpHeaders) { h.setBearerAuth(PART + "x") }\n}',
            'operator fun Any.plus(tail: String): String = loadCredential()\n'
            'fun send(h: HttpHeaders) {\n val piece: Any = "fixture"\n h.setBearerAuth(piece + "x")\n}',
        ]:
            with self.subTest(body=body):
                self.assertEqual(self.scan("Client.kt", prefix + body), [])
