"""Repair the public Repair Desk cases in memory and compare each complete report with its labels."""
import json
import re
import unittest

from garden.models import Source
from garden.scanners import analyze
from garden.scenarios import sources
from garden.submission import submission
from tests.compare_submission import matches
from tests.test_training import TRAINING


PROJECT = TRAINING / "training-project"
KOTLIN = "src/main/kotlin/lab/repairdesk/"
BUILD = "build.gradle.kts"
LOCK = "gradle.lockfile"
READER = KOTLIN + "repair/RepairTicketReader.kt"
CONTROLLER = KOTLIN + "repair/RepairTicketController.kt"

# Use anchored declarations to avoid storing the original training credentials in this test.
SECRET_REPAIRS = {
    "A-SEC-01": (r'(private val legacyImportPassword = )"[^"\n]+"',
                 r'\1requireNotNull(System.getenv("PARTS_IMPORT_PASSWORD"))'),
    "A-SEC-02": (r'(private val pricingApiKey = )"[^"\n]+"',
                 r'\1requireNotNull(System.getenv("PRICING_API_KEY"))'),
    "A-SEC-03": (r'^([ \t]*authorization:)[^\n]+$', r'\1 "Bearer ${PICKUP_CALLBACK_TOKEN}"'),
    "A-SEC-04": (r'val access = System\.getenv\("DEPOT_STATUS_TOKEN"\) \?: "[^"\n]+"',
                 'val access = requireNotNull(System.getenv("DEPOT_STATUS_TOKEN"))'),
    "A-SEC-05": (r'val series = "[^"\n]+"\n[ \t]*val grant = "[^"\n]+"\n[ \t]*val access = series \+ grant',
                 'val access = requireNotNull(System.getenv("WARRANTY_TOKEN"))'),
}

SAST_REPAIRS = {
    "A-SAST-01": [(KOTLIN + "repair/RepairLookupController.kt", """frame_tag = '$frameTag'", String::class.java)""",
                   'frame_tag = ?", String::class.java, frameTag)')],
    "A-SAST-02": [(KOTLIN + "integration/SupplierHttpsClient.kt", "import javax.net.ssl.HostnameVerifier\n", ""),
                  (KOTLIN + "integration/SupplierHttpsClient.kt",
                   "            hostnameVerifier = HostnameVerifier { _, _ -> true }\n", "")],
    "A-SAST-03": [(KOTLIN + "config/RepairCors.kt", 'allowedOriginPatterns = listOf("*")',
                   'allowedOrigins = listOf("https://customers.repairdesk.invalid")')],
    "A-SAST-04": [(KOTLIN + "config/RepairSecurity.kt", 'requestMatchers(GET, "/api/pickup/export").permitAll()',
                   'requestMatchers(GET, "/api/pickup/export").hasRole("MECHANIC")')],
    "A-SAST-05": [(CONTROLLER, "getTicket(@PathVariable ticketId: Long)",
                   "getTicket(@PathVariable ticketId: Long, principal: Principal)"),
                  (CONTROLLER, "reader.read(ticketId)", "reader.read(ticketId, principal.name)"),
                  (READER, "fun read(ticketId: Long)", "fun read(ticketId: Long, customerId: String)"),
                  (READER, 'WHERE ticket_id = ?"', 'WHERE ticket_id = ? AND customer_id = ?"'),
                  (READER, "        ticketId,\n", "        ticketId, customerId,\n")],
}

# Pin the declaration and the matching runtimeClasspath lock record together.
SCA_REPAIRS = {
    "A-SCA-01": (BUILD, "org.apache.commons:commons-text:1.9", "1.10.0"),
    "A-SCA-02": (BUILD, "org.jsoup:jsoup:1.14.1", "1.14.2"),
    "A-SCA-03": (BUILD, 'val archiveFormatVersion = "1.25.0"', "1.26.0"),
    "A-SCA-04": (BUILD, "commons-net:commons-net:3.8.0", "3.9.0"),
    "A-SCA-05": ("gradle.properties", "legacyManifestJsonVersion=20230227", "20231013"),
}


@unittest.skipUnless(PROJECT.is_dir(), "Требуется открытый набор Repair Desk")
class RepairIsolation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        gold = json.loads((TRAINING / "ground-truth/training-findings.json").read_bytes())
        cls.references = {item["id"]: item for item in gold["findings"]}
        cls.controls = gold["controls"]
        cls.original = {f.path: f.text for f in sources(PROJECT, read_parent_catalog=False)}
        # README is a labelled documentation control outside the normal source extension filter.
        cls.original["README.md"] = (PROJECT / "README.md").read_text(encoding="utf-8")

    def corrected(self, fixed):
        texts = self.original.copy()

        def replace(path, before, after):
            self.assertEqual(texts[path].count(before), 1, path)
            texts[path] = texts[path].replace(before, after)

        for case in sorted(fixed):
            ref = self.references[case]
            if case in SECRET_REPAIRS:
                pattern, replacement = SECRET_REPAIRS[case]
                path = ref["path"]
                texts[path], n = re.subn(pattern, replacement, texts[path], flags=re.MULTILINE)
                self.assertEqual(n, 1, case)
            elif case in SAST_REPAIRS:
                for path, before, after in SAST_REPAIRS[case]:
                    replace(path, before, after)
            else:
                path, declaration, version = SCA_REPAIRS[case]
                old = ref["version"]
                replace(path, declaration, declaration.replace(old, version))
                coordinate = ref["group"] + ":" + ref["artifact"] + ":"
                replace(LOCK, coordinate + old + "=runtimeClasspath", coordinate + version + "=runtimeClasspath")
        return texts

    def check_variant(self, expected):
        fixed = self.references.keys() - expected
        texts = self.corrected(fixed)
        for control in self.controls:
            path = control["path"]
            lines = slice(control["line"] - 1, control["endLine"])
            original = self.original[path].splitlines()[lines]
            self.assertEqual(len(original), lines.stop - lines.start, control["id"])
            self.assertTrue(texts[path].splitlines()[lines] == original, control["id"])
        files = [Source(path=p, text=t) for p, t in texts.items()]
        findings = []
        for kind in ("secrets", "sast", "sca"):
            result = analyze(kind, files, "*", extended_sca=False)
            self.assertEqual(result.issues, [])
            self.assertGreater(result.checked, 0)
            findings.extend(result.findings)
        rows = submission(findings)["findings"]
        found = []
        for row in rows:
            matched = [case for case, ref in self.references.items() if matches(row, ref)]
            self.assertEqual(len(matched), 1, (row["category"], row["path"]))
            self.assertEqual(row["severity"], self.references[matched[0]]["severity"])
            found.extend(matched)
            self.assertFalse(any(matches(row, control) for control in self.controls))
        self.assertCountEqual(found, expected)

        # Check resolved declarations without a lock as well as the lock record itself.
        declared = analyze("sca", [f for f in files if f.path != LOCK], "*", extended_sca=False)
        self.assertEqual(declared.issues, [])
        versions = {p.package: p.version for p in declared.packages}
        for case, (_, _, new_version) in SCA_REPAIRS.items():
            ref = self.references[case]
            package = ref["group"] + ":" + ref["artifact"]
            want = new_version if case in fixed else ref["version"]
            self.assertEqual(versions[package], want, case)
            self.assertEqual([line for line in texts[LOCK].splitlines() if line.startswith(package + ":")],
                             [f"{package}:{want}=runtimeClasspath"], case)

    def test_all_fixed_and_unmodified(self):
        self.assertEqual(set(self.references), SECRET_REPAIRS.keys() | SAST_REPAIRS.keys() | SCA_REPAIRS.keys())
        self.assertEqual((len(self.references), len(self.controls)), (15, 6))
        for expected in (set(), set(self.references)):
            with self.subTest(remaining=len(expected)):
                self.check_variant(expected)

    def test_each_fix_removes_only_its_label(self):
        for case in self.references:
            with self.subTest(fixed=case):
                self.check_variant(self.references.keys() - {case})

    def test_each_label_in_isolation(self):
        for case in self.references:
            with self.subTest(remaining=case):
                self.check_variant({case})
