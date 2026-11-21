import json
import unittest
from unittest.mock import patch

import httpx

from garden.osv_client import check_maven, exact_version


MODIFIED = "2026-11-20T15:01:00Z"
COMPONENT = ("sample:library", "1.5")
CLEAN = ("sample:fixed", "2.0")
KEY = "GHSA-aaaa-bbbb-cccc"
CVE = "CVE-2025-10000"


def stub(key):
    return {"id": key, "modified": MODIFIED}


def record(key=KEY):
    return {**stub(key), "aliases": [CVE], "database_specific": {"severity": "MODERATE"},
            "affected": [{"package": {"name": COMPONENT[0], "ecosystem": "Maven"},
                          "ranges": [{"type": "ECOSYSTEM", "events": [{"fixed": "2.0"}, {"introduced": "1.0"}]}]}]}


class OsvClientTests(unittest.TestCase):
    def run_scan(self, handler, coords=(COMPONENT,)):
        self.requests = []

        def request(req):
            self.assertEqual((req.url.scheme, req.url.host), ("https", "api.osv.dev"))
            self.requests.append(req)
            answer = handler(req)
            return answer if isinstance(answer, httpx.Response) else httpx.Response(200, json=answer)

        return check_maven(coords, transport=httpx.MockTransport(request))

    def test_verified_findings_and_complete_empty_are_distinct(self):
        def handler(req):
            if req.method == "POST":
                self.assertEqual(req.url.path, "/v1/querybatch")
                self.assertEqual(json.loads(req.content), {"queries": [
                    {"package": {"ecosystem": "Maven", "name": p}, "version": v} for p, v in (COMPONENT, CLEAN)
                ]})
                return {"results": [{"vulns": [stub(KEY)]}, {}]}
            self.assertEqual(req.url.path, "/v1/vulns/" + KEY)
            return record()

        result = self.run_scan(handler, (COMPONENT, COMPONENT, CLEAN))
        self.assertTrue(all(r.complete for r in result.values()))
        self.assertEqual(result[CLEAN].advisories, ())
        (a,) = result[COMPONENT].advisories
        self.assertEqual((a.id, a.aliases, a.severity, a.fixed_version, a.url),
                         (CVE, (CVE, KEY), "medium", "2.0", "https://osv.dev/vulnerability/" + KEY))
        self.assertEqual(len(self.requests), 2)

    def test_per_coordinate_pagination_even_when_first_page_empty(self):
        def handler(req):
            if req.method == "GET":
                return record()
            queries = json.loads(req.content)["queries"]
            if len(queries) == 2:
                return {"results": [{"next_page_token": "continue"}, {"vulns": []}]}
            self.assertEqual([(q["version"], q["page_token"]) for q in queries], [("1.5", "continue")])
            return {"results": [{"vulns": [stub(KEY)]}]}

        rows = self.run_scan(handler, (COMPONENT, CLEAN))
        self.assertTrue(all(r.complete for r in rows.values()))
        self.assertEqual(rows[COMPONENT].advisories[0].id, CVE)

    def test_broken_later_page_preserves_verified_advisory_and_unrelated_result(self):
        def handler(req):
            if req.method == "GET":
                return record()
            if len(json.loads(req.content)["queries"]) == 2:
                return {"results": [{"vulns": [stub(KEY)], "next_page_token": "one"}, {}]}
            return {"results": [{"next_page_token": "one"}]}

        rows = self.run_scan(handler, (COMPONENT, CLEAN))
        self.assertFalse(rows[COMPONENT].complete)
        self.assertEqual(rows[COMPONENT].advisories[0].id, CVE)
        self.assertTrue(rows[CLEAN].complete)
        self.assertEqual(len(self.requests), 3)

    def test_network_and_invalid_results_are_incomplete(self):
        def timed_out(req):
            raise httpx.ReadTimeout("timeout", request=req)
        for response in (timed_out, {"results": []}, {"results": [None]}, {"results": [{"unexpected": []}]},
                         {"results": [{"vulns": None}]}, {"results": [{"vulns": [{"id": "../bad"}]}]},
                         {"results": [{"vulns": [{"id": KEY}]}]}, httpx.Response(503), httpx.Response(302),
                         httpx.Response(200, content=b"{")):
            with self.subTest(response=response):
                result = self.run_scan(response if callable(response) else lambda req: response)
                self.assertFalse(result[COMPONENT].complete)
                self.assertEqual(len(self.requests), 1)

    def test_withdrawn_and_incomplete_details(self):
        for details, complete in [({**stub(KEY), "withdrawn": MODIFIED}, True),
                                  ({**stub(KEY), "withdrawn": "yes"}, False), (stub(KEY), False),
                                  ({**record(), "id": "different"}, False),
                                  ({**record(), "affected": [{"package": {"name": COMPONENT[0], "ecosystem": "npm"}}]}, False),
                                  ({**record(), "affected": [{"package": {"name": COMPONENT[0], "ecosystem": "Maven"},
                                                              "versions": ["9"]}]}, False), (httpx.Response(404), False)]:
            with self.subTest(details=details):
                result = self.run_scan(lambda req: {"results": [{"vulns": [stub(KEY)]}]} if req.method == "POST" else details)
                self.assertEqual(result[COMPONENT].complete, complete)
                self.assertFalse(result[COMPONENT].advisories)

    def test_only_confirmed_aliases_are_merged(self):
        other = "GHSA-dddd-eeee-ffff"
        unrelated = "OSV-2026-123"
        extra = "CVE-2026-51234"
        records = {KEY: record(), other: {**record(other), "aliases": [KEY, extra]},
                   unrelated: {**record(unrelated), "aliases": [], "related": [KEY]}}
        result = self.run_scan(lambda req: {"results": [{"vulns": [stub(k) for k in records]}]} if req.method == "POST"
                               else records[req.url.path.rsplit("/", 1)[1]])[COMPONENT]
        self.assertTrue(result.complete)
        self.assertEqual([(a.id, set(a.aliases)) for a in result.advisories],
                         [(CVE, {CVE, KEY, other, extra}), (unrelated, {unrelated})])

    def test_cvss_and_unproven_upgrade(self):
        detail = record()
        detail.pop("database_specific")
        detail["severity"] = [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]
        item = detail["affected"][0]
        item["ranges"][0]["events"] = [{"introduced": "1.5"}, {"last_affected": "1.5"}]
        result = self.run_scan(lambda req: {"results": [{"vulns": [stub(KEY)]}]} if req.method == "POST" else detail)[COMPONENT]
        self.assertTrue(result.complete)
        self.assertEqual((result.advisories[0].severity, result.advisories[0].fixed_version), ("critical", None))

    def test_snapshot_requires_both_exact_and_base_answers(self):
        snapshot = ("sample:library", "1.5-20261120.131500-5")
        unpinned = (snapshot[0], "1.5-SNAPSHOT")
        for base, complete in [({}, True), ({"error": "unavailable"}, False)]:
            with self.subTest(base=base):
                def handler(req):
                    queries = json.loads(req.content)["queries"]
                    self.assertEqual([q["version"] for q in queries], [snapshot[1], unpinned[1]])
                    return {"results": [{}, base]}
                result = self.run_scan(handler, (snapshot, unpinned))
                self.assertEqual(result[snapshot].complete, complete)
                self.assertFalse(result[unpinned].complete)

    def test_limits_do_not_turn_failures_into_clean_checks(self):
        with patch("garden.osv_client.MAX_REQUESTS", 1):
            result = self.run_scan(lambda req: {"results": [{"vulns": [stub(KEY)]}]})[COMPONENT]
            self.assertFalse(result.complete)
            self.assertEqual(len(self.requests), 1)
        with patch("garden.osv_client.MAX_BYTES", 3):
            self.assertFalse(self.run_scan(lambda req: {"results": [{}]})[COMPONENT].complete)

    def test_exact_coordinates_only(self):
        for value in ("4.1.113.Final", "v1.3", "32.1.3-jre", "0", "1.0.0+build.2"):
            self.assertTrue(exact_version(value), value)
        for value in (None, "", "[1.0,2.0)", "+", "1.+", "latest.release", "1.2-SNAPSHOT", "${myVersion}", "file:///v1"):
            self.assertFalse(exact_version(value), value)
        result = self.run_scan(lambda req: self.fail("unexpected external request"), (("https://example.org:lib", "1.0"),))
        self.assertFalse(next(iter(result.values())).complete)
