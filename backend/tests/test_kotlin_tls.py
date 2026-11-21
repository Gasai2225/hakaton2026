import unittest

from garden.models import Source
from garden.scanners import analyze
from garden.submission import row


class KotlinCertificateChecks(unittest.TestCase):
    def test_static_receiver_alias_can_be_shadowed_by_a_value(self):
        for params, local, expected in [
            ("", "", True),
            ("Channel: Notebook", "", False),
            ("book: Notebook", "val Channel = book", False),
        ]:
            with self.subTest(params=params, local=local):
                code = ('import javax.net.ssl.HttpsURLConnection as Channel\n'
                        'class Notebook { fun setDefaultHostnameVerifier(record: (String, String) -> Boolean) {} }\n'
                        f'fun configure({params}) {{\n {local}\n'
                        ' Channel.setDefaultHostnameVerifier { _, _ -> true }\n}')
                self.assertEqual([(r["class"], r["line"]) for r in self.scan(code)],
                                 [("tls-verification", 5)] if expected else [])
        code = ('import javax.net.ssl.HttpsURLConnection as Channel\n'
                'fun note(Channel: Notebook) = Channel.toString()\n'
                'fun setup() = Channel.setDefaultHostnameVerifier { _, _ -> true }')
        self.assertEqual([(r["class"], r["line"]) for r in self.scan(code)], [("tls-verification", 3)])

    def scan(self, code):
        result = analyze("sast", [Source(path="Policy.kt", text=code)], "*")
        self.assertEqual(result.issues, [])
        return [row(hit) for hit in result.findings]

    def test_hostname_verifier_requires_jsse_receiver_and_direct_predicate(self):
        for prefix, typ, statement, expected in [
            ("import javax.net.ssl.HttpsURLConnection as Conn\nimport javax.net.ssl.HostnameVerifier as Verifier",
             "Conn", "c.hostnameVerifier = Verifier { _, _ -> true }", True),
            ("", "javax.net.ssl.HttpsURLConnection", "c.setHostnameVerifier { _, _ -> true }", True),
            ("import javax.net.ssl.*", "HttpsURLConnection",
             "HttpsURLConnection.setDefaultHostnameVerifier(HostnameVerifier { _, _ -> true })", True),
            ("import javax.net.ssl.*", "Audit", "c.setHostnameVerifier { _, _ -> true }", False),
            ("import javax.net.ssl.*", "Audit", "c.hostnameVerifier = HostnameVerifier { _, _ -> true }", False),
            ("import javax.net.ssl.*", "HttpsURLConnection",
             "c.setHostnameVerifier(policy.withAudit { _, _ -> true })", False),
            ("import javax.net.ssl.*", "HttpsURLConnection",
             "c.setHostnameVerifier { host, session -> delegate.verify(host, session) }", False),
        ]:
            with self.subTest(prefix=prefix, typ=typ, statement=statement):
                code = prefix + f"\nfun configure(c: {typ}) {{\n {statement}\n}}"
                self.assertEqual([(r["class"], r["line"]) for r in self.scan(code)],
                                 [("tls-verification", len(code.splitlines()) - 1)] if expected else [])

    def test_empty_checks_and_delegation(self):
        for body, expected in [
            ("{ /* validation pending */ }", True),
            ("{ return }", True),
            ("= Unit", True),
            ("{ return kotlin.Unit }", True),
            ("= delegate.checkServerTrusted(chain, auth)", False),
            ('{ throw CertificateException("untrusted") }', False),
            ('= TODO("configure trust store")', False),
        ]:
            with self.subTest(body=body):
                code = ('import javax.net.ssl.X509TrustManager as Trust\nimport java.security.cert.*\n'
                        'abstract class Policy(val delegate: Trust) : Trust {\n'
                        ' override fun checkServerTrusted(chain: Array<out X509Certificate>?, auth: String?) ' + body + '\n}')
                rows = self.scan(code)
                self.assertEqual([(r["class"], r["line"]) for r in rows], [("tls-verification", 4)] if expected else [])
                if expected:
                    self.assertIn("checkServerTrusted", rows[0]["description"])

    def test_extended_overloads_and_unrelated_types(self):
        for base, params, expected in [
            ("javax.net.ssl.X509ExtendedTrustManager()", "chain: Array<Cert>, auth: String, socket: java.net.Socket?", True),
            ("javax.net.ssl.X509ExtendedTrustManager()", "chain: kotlin.Array<out Cert>, auth: String, engine: SSLEngine", True),
            ("javax.net.ssl.X509TrustManager", "chain: Array<Cert>, auth: String, engine: SSLEngine", False),
            ("javax.net.ssl.X509TrustManager", "chain: List<Cert>, auth: String", False),
            ("javax.net.ssl.X509TrustManager", "chain: Array<Cert>, auth: Int", False),
            ("example.X509TrustManager", "chain: Array<Cert>, auth: String", False),
        ]:
            with self.subTest(base=base, params=params):
                code = ('import java.security.cert.X509Certificate as Cert\nimport javax.net.ssl.*\n'
                        f'abstract class Policy : {base} {{\n override fun checkClientTrusted({params}) {{}}\n}}')
                self.assertEqual([r["line"] for r in self.scan(code)], [4] if expected else [])

    def test_anonymous_manager_and_clean_issuer_list(self):
        code = '''import java.security.cert.X509Certificate
fun policy(delegate: javax.net.ssl.X509TrustManager) = object : javax.net.ssl.X509TrustManager {
    override fun checkClientTrusted(chain: Array<X509Certificate>, auth: String) = Unit
    override fun checkServerTrusted(chain: Array<X509Certificate>, auth: String) = delegate.checkServerTrusted(chain, auth)
    override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
}'''
        self.assertEqual([(r["class"], r["line"]) for r in self.scan(code)], [("tls-verification", 3)])

    def test_certificate_failure_must_propagate_or_be_revalidated(self):
        for catch, recovery, tail, expected in [
            ("CertificateException", "/* ignored */", "", True),
            ("Exception", "return", "", True),
            ("CertificateException", "throw problem", "", False),
            ("CertificateException", "backup.checkServerTrusted(chain, auth)", "", False),
            ("IllegalArgumentException", "", "", False),
            ("CertificateException", "", " finally { backup.checkServerTrusted(chain, auth) }", False),
            ("CertificateException", "", "\n backup.checkServerTrusted(chain, auth)", False),
        ]:
            with self.subTest(catch=catch, recovery=recovery, tail=tail):
                code = ('import javax.net.ssl.X509TrustManager\nimport java.security.cert.*\n'
                        'abstract class Policy(val primary: X509TrustManager, val backup: X509TrustManager) : X509TrustManager {\n'
                        ' override fun checkServerTrusted(chain: Array<X509Certificate>, auth: String) {\n'
                        f'  try {{ primary.checkServerTrusted(chain, auth) }} catch (problem: {catch}) {{ {recovery} }}{tail}\n }}\n}}')
                rows = self.scan(code)
                self.assertEqual([(r["class"], r["line"]) for r in rows], [("tls-verification", 5)] if expected else [])

    def test_lookalike_and_shadowed_names(self):
        code = '''import java.security.cert.X509Certificate
import javax.net.ssl.*
abstract class Policy : X509TrustManager {
    override fun checkServerTrusted(chain: Array<X509Certificate>, auth: String) = Unit
}'''
        for variant in [
            code.replace("abstract class", "import example.X509TrustManager\nabstract class"),
            code.replace("abstract class", "val Unit: kotlin.Unit get() = error(\"no trust store\")\nabstract class"),
            code.replace("abstract class", "interface X509TrustManager {\n"
                         " fun checkServerTrusted(chain: Array<X509Certificate>, auth: String)\n}\nabstract class"),
        ]:
            with self.subTest(variant=variant):
                self.assertEqual(self.scan(variant), [])
