import os
import unittest
from unittest.mock import patch

import httpx

from garden.models import Source
from garden.osv_client import OsvAdvisory, OsvResult
from garden.scanners import analyze
from garden.submission import submission


TEXT = ("org.apache.commons:commons-text", "1.9")
SENSOR = ("museum.lab:sensor", "3.4.0")
CLEAN = ("junit:junit", "4.13.2")
LOCKED = ("museum.lab:frame", "4.1.113.Final")
BUILD = Source(path="station/build.gradle.kts", text='''dependencies {
    implementation("org.apache.commons:commons-text:1.9")
    implementation("museum.lab:sensor:3.4.0")
    testImplementation("junit:junit:4.13.2")
    runtimeOnly("museum.lab:unknown:latest.release")
}''')
LOCK = Source(path="station/gradle.lockfile", text='''org.apache.commons:commons-text:1.9=runtimeClasspath
museum.lab:sensor:3.4.0=runtimeClasspath
museum.lab:frame:4.1.113.Final=runtimeClasspath
''')


def advisory(identifier, aliases=(), severity="high", fixed_version=None):
    return OsvAdvisory(id=identifier, aliases=aliases, severity=severity, fixed_version=fixed_version,
                       url=f"https://osv.dev/vulnerability/{identifier}")


@patch.dict(os.environ, {"GARDEN_EXTENDED_SCA": "0", "GARDEN_CATALOG": ""})
class OnlineMavenScan(unittest.TestCase):
    def test_offline_requires_no_osv_even_for_extended_catalog(self):
        with patch("garden.osv_client.check_maven") as query:
            for extended in (False, True, None):
                result = analyze("sca", [BUILD, LOCK], "*", extended)
                self.assertTrue(all(p.osv_status is None for p in [*result.packages, *result.lockfile.packages]))
                self.assertEqual(len(result.findings), 1)
            for kind in ("sast", "secrets"):
                analyze(kind, [BUILD, LOCK], "*", online_cve=True)
            analyze("sca", [], "*", online_cve=True)
            query.assert_not_called()

    def test_alias_dedup_separate_lockfile_and_unknown_exact_versions(self):
        mirror = advisory("GHSA-599f-7c49-w659", ("EXAMPLE-MIRROR",))
        same = advisory("CVE-2022-42889", ("EXAMPLE-MIRROR",))
        remote = advisory("GHSA-example-sensor", ("CVE-2099-1001",), severity="critical", fixed_version="3.5.0")
        extra = advisory("CVE-2099-1002", severity=None)
        locked = advisory("CVE-2099-1003", severity=None)
        results = {TEXT: OsvResult(advisories=(mirror, same)), SENSOR: OsvResult(advisories=(remote, extra)),
                   LOCKED: OsvResult(advisories=(locked,)), CLEAN: OsvResult()}
        original, = analyze("sca", [BUILD, LOCK], "*", True).findings
        with patch("garden.osv_client.check_maven", return_value=results) as query:
            result = analyze("sca", [BUILD, LOCK], "*", False, online_cve=True)
        query.assert_called_once_with(sorted(results))
        self.assertEqual(result.checked_packages, 3)
        self.assertEqual([(p.status, p.osv_status) for p in result.packages], [
            ("checked", "checked"), ("outside-catalog", "checked"), ("outside-catalog", "checked"),
            ("outside-catalog", "skipped")])
        self.assertEqual(len(result.issues), 1)
        self.assertIn("museum.lab:unknown", result.issues[0])
        self.assertEqual(result.lockfile.issues, [])
        self.assertEqual(result.lockfile.checked, 1)
        transit, = result.lockfile.packages
        self.assertEqual((transit.package, transit.scope, transit.status, transit.osv_status),
                         (LOCKED[0], "transitive", "outside-catalog", "checked"))
        lock_hit, = transit.advisories
        self.assertEqual((lock_hit.id, lock_hit.advisory_url, lock_hit.severity_estimated), (locked.id, locked.url, True))
        self.assertCountEqual([f.advisory for f in result.findings], [original.advisory, remote.id, extra.id])
        old, = [f for f in result.findings if f.id == original.id]
        self.assertEqual((old.fixed_version, old.severity, old.advisory), (original.fixed_version, original.severity, original.advisory))
        self.assertIn(old.advisory_url, {mirror.url, same.url})
        strong, = [f for f in result.findings if f.advisory == remote.id]
        self.assertEqual((strong.severity, strong.fixed_version, strong.advisory_url, strong.severity_estimated),
                         ("critical", remote.fixed_version, remote.url, False))
        estimate, = [f for f in result.findings if f.advisory == extra.id]
        self.assertTrue(estimate.severity_estimated)
        exported = submission(result.findings)["findings"]
        self.assertTrue(all(r["category"] == "SCA" and r["path"] == BUILD.path for r in exported))
        self.assertFalse(any(r["advisoryId"] == locked.id for r in exported))

    def test_incomplete_or_missing_response_keeps_confirmed_findings_and_local_status(self):
        hit = advisory("CVE-2099-1004")
        results = {TEXT: OsvResult(error="timeout"), SENSOR: OsvResult(advisories=(hit,), error="incomplete page"), CLEAN: OsvResult()}
        with patch("garden.osv_client.check_maven", return_value=results):
            result = analyze("sca", [BUILD, LOCK], "*", online_cve=True)
        self.assertEqual(result.checked_packages, 2)
        self.assertEqual([p.osv_status for p in result.packages], ["incomplete", "incomplete", "checked", "skipped"])
        self.assertCountEqual([f.advisory for f in result.findings], ["CVE-2022-42889", hit.id])
        self.assertEqual(result.lockfile.packages[0].osv_status, "incomplete")
        self.assertEqual(result.lockfile.checked, 0)
        self.assertTrue(any("неполная" in s and LOCKED[0] in s for s in result.lockfile.issues))

    def test_network_outage_preserves_offline_finding(self):
        with patch("garden.osv_client.check_maven", side_effect=httpx.ConnectError("offline")):
            result = analyze("sca", [BUILD], "*", online_cve=True)
        self.assertEqual([f.advisory for f in result.findings], ["CVE-2022-42889"])
        self.assertEqual(len(result.issues), 4)
        self.assertEqual(result.checked_packages, 1)

    def test_exact_version_unsupported_by_local_ranges_preserves_lock_scope(self):
        package, ver = "org.jsoup:jsoup", "v1.3"
        build = Source(path="build.gradle.kts", text=f'dependencies {{ implementation("{package}:{ver}") }}')
        lock = Source(path="gradle.lockfile", text=f'{package}:{ver}=runtimeClasspath\n{LOCKED[0]}:{LOCKED[1]}=runtimeClasspath')
        for complete in (True, False):
            with self.subTest(complete=complete):
                reply = OsvResult() if complete else OsvResult(error="incomplete page")
                with patch("garden.osv_client.check_maven", return_value={(package, ver): reply, LOCKED: OsvResult()}):
                    result = analyze("sca", [build, lock], "*", online_cve=True)
                self.assertEqual(result.packages[0].status, "unresolved")
                self.assertEqual(result.packages[0].osv_status, "checked" if complete else "incomplete")
                self.assertEqual(result.checked_packages, int(complete))
                self.assertEqual(result.lockfile.packages[0].scope, "transitive")
                self.assertEqual(result.lockfile.issues, [])
                self.assertEqual(bool(result.issues), not complete)
                if not complete:
                    self.assertIn("incomplete page", result.issues[0])

    def test_one_query_per_coordinate_across_locations_with_a_row_for_each_declaration(self):
        old = Source(path="export/build.gradle.kts", text='''dependencies {
 implementation("museum.lab:sensor:3.4.0")
 testImplementation("museum.lab:sensor:3.4.0")
}''')
        other = Source(path="archive/build.gradle.kts", text='dependencies { runtimeOnly("museum.lab:sensor:3.4.0") }')
        hit = advisory("CVE-2099-1005", ("GHSA-alias",))
        echo = advisory("GHSA-alias")
        with patch("garden.osv_client.check_maven", return_value={SENSOR: OsvResult(advisories=(hit, echo))}) as query:
            result = analyze("sca", [old, other], "*", online_cve=True)
        query.assert_called_once_with([SENSOR])
        self.assertCountEqual([(f.path, f.line) for f in result.findings], [(old.path, 2), (old.path, 3), (other.path, 1)])
        self.assertEqual(len({f.id for f in result.findings}), 3)
