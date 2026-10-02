import base64
import contextlib
import io
import tempfile
import unittest
from pathlib import Path

from soc_toolkit.common.http import Response
from soc_toolkit.common.msapi import DefenderApi, LogAnalyticsApi
from soc_toolkit.ioc_enrich import cli
from soc_toolkit.ioc_enrich.cache import Cache
from soc_toolkit.ioc_enrich.engine import Policy, enrich
from soc_toolkit.ioc_enrich.extract import Indicator, classify, defang, extract, is_non_routable, refang
from soc_toolkit.ioc_enrich.models import ProviderResult, aggregate
from soc_toolkit.ioc_enrich.providers import (
    OTX, AbuseIPDB, DefenderIndicators, GreyNoise, MalwareBazaar, Provider, RateLimiter, SentinelTI, ThreatFox,
    URLhaus, VirusTotal,
)
from tests.fakes import FakeTransport, StaticCredential, body_form, body_json, json_response, query_params

SHA256 = "a" * 63 + "b"
MD5 = "0123456789abcdef0123456789abcdef"


def run_quiet(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli.main(argv)
    return code, out.getvalue(), err.getvalue()


class ExtractTests(unittest.TestCase):
    def test_refang_and_extract_everything(self):
        text = ("C2 at hxxps://evil[.]example[.]com/a/b?x=1, also 203.0.113[.]5 and 2001:db8::1.\n"
                f"hash {SHA256} md5 {MD5.upper()} sha1 {'c' * 39 + 'd'}\n"
                "sender bad-domain[.]top; see script.py, notes.md and v1.2.3 at 12:30:45\n")
        found = extract(text)
        self.assertEqual(found[0], Indicator("url", "https://evil.example.com/a/b?x=1"))
        types = {(i.type, i.value) for i in found}
        self.assertIn(("ipv4", "203.0.113.5"), types)
        self.assertIn(("ipv6", "2001:db8::1"), types)
        self.assertIn(("sha256", SHA256), types)
        self.assertIn(("md5", MD5), types)  # lower-cased
        self.assertIn(("sha1", "c" * 39 + "d"), types)
        self.assertIn(("domain", "bad-domain.top"), types)
        values = {i.value for i in found}
        for noise in ("script.py", "notes.md", "evil.example.com", "12:30:45", "v1.2.3"):
            self.assertNotIn(noise, values)

    def test_url_hosts_option_and_trailing_punctuation(self):
        found = extract("See (https://a.example.org/path).", url_hosts=True)
        self.assertEqual(found, [Indicator("url", "https://a.example.org/path"), Indicator("domain", "a.example.org")])

    def test_single_token_lines_are_classified_permissively(self):
        self.assertEqual(extract("update.zip\n"), [Indicator("domain", "update.zip")])
        self.assertEqual(classify("hxxp://1.2.3.4/x"), Indicator("url", "http://1.2.3.4/x"))
        self.assertIsNone(classify("not an ioc"))
        self.assertIsNone(classify("999.1.1.1"))

    def test_code_and_times_are_not_ipv6(self):
        self.assertEqual(extract("std::move and a::b at 10:20:30"), [])

    def test_defang_and_non_routable(self):
        self.assertEqual(defang(Indicator("url", "https://x.example/a")), "hxxps://x[.]example/a")
        self.assertEqual(defang(Indicator("ipv6", "2001:db8::1")), "2001[:]db8[:][:]1")
        self.assertEqual(refang("1[.]2(.)3{.}4"), "1.2.3.4")
        self.assertTrue(is_non_routable("10.1.2.3"))
        self.assertTrue(is_non_routable("fe80::1"))
        self.assertFalse(is_non_routable("203.0.113.5"))  # documentation range is still looked up
        self.assertFalse(is_non_routable("example.com"))


class AggregateTests(unittest.TestCase):
    def r(self, verdict, score, status="hit", **details):
        return ProviderResult("p", status, verdict, score, details=details)

    def test_rules(self):
        self.assertEqual(aggregate([]), ("unknown", 0))
        self.assertEqual(aggregate([self.r("malicious", 80), self.r("malicious", 75)]), ("malicious", 90))
        self.assertEqual(aggregate([self.r("suspicious", 40)]), ("suspicious", 40))
        self.assertEqual(aggregate([self.r("harmless", 0, "clean")]), ("harmless", 0))
        self.assertEqual(aggregate([self.r("unknown", None, "clean")]), ("unknown", 0))
        self.assertEqual(aggregate([self.r("suspicious", 40), self.r("harmless", 0, "clean", benign_service=True)]),
                         ("harmless", 20))
        self.assertEqual(aggregate([self.r("malicious", 95), self.r("harmless", 0, "clean", benign_service=True)]),
                         ("malicious", 95))
        self.assertEqual(aggregate([ProviderResult("p", "error", summary="x")]), ("unknown", 0))


class ProviderTests(unittest.TestCase):
    def test_virustotal(self):
        url = "https://bad.example/x"
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        fake = FakeTransport()
        fake.add("GET", f"/files/{SHA256}", json_response({"data": {"attributes": {
            "last_analysis_stats": {"malicious": 40, "suspicious": 0, "harmless": 0, "undetected": 30},
            "popular_threat_classification": {"suggested_threat_label": "trojan.lockbit"},
            "first_submission_date": 1758000000}}}))
        fake.add("GET", f"/urls/{url_id}$", json_response({"data": {"attributes": {
            "last_analysis_stats": {"malicious": 0, "suspicious": 0, "harmless": 70, "undetected": 20}}}}))
        fake.add("GET", "/domains/", Response(404, b""))
        vt = VirusTotal(fake.client(), "key", per_minute=0)
        hit = vt.lookup(Indicator("sha256", SHA256))
        self.assertEqual((hit.status, hit.verdict, hit.score), ("hit", "malicious", 100))
        self.assertIn("trojan.lockbit", hit.tags)
        self.assertEqual(fake.calls[0].headers["x-apikey"], "key")
        self.assertEqual(vt.lookup(Indicator("url", url)).verdict, "harmless")
        self.assertEqual(vt.lookup(Indicator("domain", "nope.example")).status, "not_found")

    def test_api_key_errors_are_explained(self):
        fake = FakeTransport().add("GET", "virustotal", Response(401, b'{"error": {"code": "WrongCredentialsError"}}'))
        with self.assertRaisesRegex(Exception, "rejected the API key"):
            VirusTotal(fake.client(), "bad", per_minute=0).lookup(Indicator("ipv4", "1.1.1.1"))

    def test_abuseipdb(self):
        fake = FakeTransport().add("GET", "api.abuseipdb.com", lambda req: json_response({"data": {
            "abuseConfidenceScore": {"1.1.1.1": 0, "2.2.2.2": 30, "3.3.3.3": 100}[query_params(req)["ipAddress"]],
            "totalReports": 0 if "1.1.1.1" in req.url else 50, "isTor": "3.3.3.3" in req.url}}))
        p = AbuseIPDB(fake.client(), "k", per_minute=0)
        self.assertEqual(p.lookup(Indicator("ipv4", "1.1.1.1")).verdict, "unknown")
        self.assertEqual(p.lookup(Indicator("ipv4", "2.2.2.2")).verdict, "suspicious")
        mal = p.lookup(Indicator("ipv4", "3.3.3.3"))
        self.assertEqual((mal.verdict, mal.score), ("malicious", 100))
        self.assertIn("tor", mal.tags)

    def test_otx(self):
        fake = FakeTransport()
        fake.add("GET", "/domain/good.example/general", json_response({"validation": [{"source": "majestic"}], "pulse_info": {"count": 50}}))
        fake.add("GET", "/IPv4/9.9.9.9/general", json_response({"pulse_info": {"count": 6, "pulses": [
            {"name": "C2 list", "malware_families": [{"display_name": "Cobalt Strike"}]}]}}))
        fake.add("GET", "/file/", Response(404, b""))
        p = OTX(fake.client(), "k", per_minute=0)
        good = p.lookup(Indicator("domain", "good.example"))
        self.assertEqual(good.verdict, "harmless")
        self.assertTrue(good.details["benign_service"])
        bad = p.lookup(Indicator("ipv4", "9.9.9.9"))
        self.assertEqual((bad.verdict, bad.score), ("suspicious", 55))
        self.assertIn("Cobalt Strike", bad.tags)
        self.assertEqual(p.lookup(Indicator("md5", MD5)).status, "not_found")

    def test_greynoise(self):
        fake = FakeTransport()
        fake.add("GET", "community/8.8.8.8", json_response({"noise": False, "riot": True, "classification": "benign", "name": "Google"}))
        fake.add("GET", "community/5.5.5.5", json_response({"noise": True, "riot": False, "classification": "malicious"}))
        fake.add("GET", "community/6.6.6.6", Response(404, b'{"message": "IP not observed"}'))
        p = GreyNoise(fake.client(), "", per_minute=0)
        riot = p.lookup(Indicator("ipv4", "8.8.8.8"))
        self.assertTrue(riot.details["benign_service"])
        self.assertNotIn("key", fake.calls[0].headers)
        self.assertEqual(p.lookup(Indicator("ipv4", "5.5.5.5")).verdict, "malicious")
        self.assertEqual(p.lookup(Indicator("ipv4", "6.6.6.6")).status, "not_found")

    def test_abuse_ch_feeds(self):
        fake = FakeTransport()
        fake.add("POST", "mb-api.abuse.ch", lambda req: json_response(
            {"query_status": "ok", "data": [{"sha256_hash": SHA256, "signature": "LockBit", "tags": ["exe"]}]}
            if body_form(req)["hash"] == SHA256 else {"query_status": "hash_not_found"}))
        fake.add("POST", "urlhaus-api.abuse.ch/v1/url/", json_response(
            {"query_status": "ok", "url_status": "online", "threat": "malware_download", "tags": ["Emotet"]}))
        fake.add("POST", "urlhaus-api.abuse.ch/v1/host/", json_response(
            {"query_status": "ok", "url_count": "3", "urls": [{"url_status": "offline"}],
             "blacklists": {"spamhaus_dbl": "not listed", "surbl": "not listed"}}))
        fake.add("POST", "urlhaus-api.abuse.ch/v1/payload/", json_response({"query_status": "no_results"}))
        fake.add("POST", "threatfox-api.abuse.ch", lambda req: json_response(
            {"query_status": "ok", "data": [{"id": 7, "ioc": "4.4.4.4:443", "malware_printable": "QakBot",
                                             "threat_type": "botnet_cc", "confidence_level": 75},
                                            {"id": 8, "ioc": "4.4.4.40:80", "malware_printable": "Other",
                                             "threat_type": "botnet_cc", "confidence_level": 100}]}))
        mb = MalwareBazaar(fake.client(), "k", per_minute=0)
        self.assertEqual(mb.lookup(Indicator("sha256", SHA256)).score, 95)
        self.assertEqual(mb.lookup(Indicator("md5", MD5)).status, "not_found")
        self.assertEqual(fake.calls[0].headers["Auth-Key"], "k")
        uh = URLhaus(fake.client(), "k", per_minute=0)
        self.assertEqual(uh.lookup(Indicator("url", "http://x.example/a")).score, 95)
        self.assertEqual(uh.lookup(Indicator("domain", "x.example")).verdict, "suspicious")
        self.assertEqual(uh.lookup(Indicator("md5", MD5)).status, "not_found")
        tf = ThreatFox(fake.client(), "k", per_minute=0)
        hit = tf.lookup(Indicator("ipv4", "4.4.4.4"))
        self.assertEqual(hit.tags, ["QakBot"])  # 4.4.4.40 is not 4.4.4.4
        self.assertEqual(hit.score, 75)
        self.assertFalse(body_json(fake.calls[-1])["exact_match"])

    def test_sentinel_ti_batches_and_escapes(self):
        captured = {}

        def respond(req):
            captured["query"] = body_json(req)["query"]
            return json_response({"tables": [{"columns": [{"name": "Value"}, {"name": "Confidence"},
                                                          {"name": "SourceSystem"}, {"name": "Name"}],
                                              "rows": [["evil.example", 90, "Microsoft Defender Threat Intelligence", "phish kit"],
                                                       ["1.2.3.4", 20, "MISP", ""]]}]})

        fake = FakeTransport().add("POST", "loganalytics", respond)
        http = fake.client()
        ti = SentinelTI(http, LogAnalyticsApi(http, StaticCredential()), "ws-id")
        inds = [Indicator("domain", "Evil.Example"), Indicator("ipv4", "1.2.3.4"), Indicator("url", 'https://x.example/"]);evil')]
        out = ti.lookup_many(inds)
        self.assertEqual(len(fake.calls), 1)
        self.assertEqual(out[inds[0]].verdict, "malicious")
        self.assertEqual(out[inds[1]].verdict, "suspicious")
        self.assertEqual(out[inds[2]].status, "not_found")
        self.assertIn('\\"]);evil', captured["query"])  # quote is escaped, the value stays a string
        self.assertIn("ThreatIntelIndicators", captured["query"])
        legacy = SentinelTI(http, LogAnalyticsApi(http, StaticCredential()), "ws", "ThreatIntelligenceIndicator")
        self.assertIn("mv-expand", legacy.query(["a"]))
        with self.assertRaises(ValueError):
            SentinelTI(http, LogAnalyticsApi(http, StaticCredential()), "ws", "Bogus")

    def test_defender_indicators(self):
        def respond(req):
            value = query_params(req)["$filter"]
            if "blocked" in value:
                return json_response({"value": [{"action": "AlertAndBlock", "expirationTime": "2026-10-04T00:00:00Z"}]})
            if "trusted" in value:
                return json_response({"value": [{"action": "Allowed"}]})
            return json_response({"value": []})

        fake = FakeTransport().add("GET", "/api/indicators", respond)
        http = fake.client()
        p = DefenderIndicators(http, DefenderApi(http, StaticCredential()))
        self.assertEqual(p.lookup(Indicator("domain", "blocked.example")).verdict, "malicious")
        trusted = p.lookup(Indicator("domain", "trusted.example"))
        self.assertTrue(trusted.details["benign_service"])
        self.assertEqual(p.lookup(Indicator("domain", "o'neil.example")).status, "not_found")
        self.assertIn("o''neil", query_params(fake.calls[-1])["$filter"])

    def test_rate_limiter_spaces_calls(self):
        now = [0.0]
        sleeps = []

        def sleep(s):
            sleeps.append(s)
            now[0] += s

        limiter = RateLimiter(4, clock=lambda: now[0], sleep=sleep)
        for _ in range(3):
            limiter.acquire()
        self.assertEqual(sleeps, [15.0, 15.0])


class FixedProvider(Provider):
    def __init__(self, name, answers, types=("ipv4", "domain", "url", "md5", "sha1", "sha256"), boom=False):
        super().__init__(FakeTransport().client())
        self.name, self.answers, self.types, self.boom, self.seen = name, answers, frozenset(types), boom, []

    def lookup(self, ind):
        self.seen.append(ind)
        if self.boom:
            raise RuntimeError("feed down")
        return self.answers.get(ind.value) or self.not_found()


class EngineTests(unittest.TestCase):
    def test_policy_isolation_and_errors(self):
        good = FixedProvider("good", {"203.0.113.9": ProviderResult("good", "hit", "malicious", 90)})
        broken = FixedProvider("broken", {}, boom=True)
        sentinel = FixedProvider("sentinel_ti", {})
        inds = [Indicator("ipv4", "203.0.113.9"), Indicator("ipv4", "10.0.0.5"),
                Indicator("domain", "login.microsoftonline.com"), Indicator("domain", "intranet.contoso.com")]
        policy = Policy(allow_domains={"microsoftonline.com"}, internal_domains={"contoso.com"})
        out = {e.indicator.value: e for e in enrich(inds, [good, broken, sentinel], policy=policy)}
        self.assertEqual(out["203.0.113.9"].verdict, "malicious")
        self.assertIn("error", {r.status for r in out["203.0.113.9"].results})
        self.assertIn("non-routable", out["10.0.0.5"].note)
        self.assertIn("allowlisted", out["login.microsoftonline.com"].note)
        # internal domains go only to your own Microsoft TI
        self.assertNotIn(Indicator("domain", "intranet.contoso.com"), good.seen)
        self.assertIn(Indicator("domain", "intranet.contoso.com"), sentinel.seen)
        self.assertIn("internal domain", out["intranet.contoso.com"].note)

    def test_cache_round_trip_and_ttl(self):
        with tempfile.TemporaryDirectory() as tmp:
            now = [1000.0]
            cache = Cache(Path(tmp) / "c.sqlite3", ttl_hours=1, clock=lambda: now[0])
            feed = FixedProvider("feed", {"203.0.113.1": ProviderResult("feed", "hit", "malicious", 80)})
            ind = Indicator("ipv4", "203.0.113.1")
            enrich([ind], [feed], cache=cache)
            enrich([ind], [feed], cache=cache)
            self.assertEqual(len(feed.seen), 1)
            self.assertTrue(enrich([ind], [feed], cache=cache)[0].results[0].cached)
            now[0] += 3601
            enrich([ind], [feed], cache=cache)
            self.assertEqual(len(feed.seen), 2)
            # errors are never cached
            broken = FixedProvider("broken", {}, boom=True)
            enrich([ind], [broken], cache=cache)
            enrich([ind], [broken], cache=cache)
            self.assertEqual(len(broken.seen), 2)
            cache.close()


class CliTests(unittest.TestCase):
    def setUp(self):
        self.notes = Path(__file__).resolve().parent.parent / "examples" / "incident-notes.txt"

    def test_demo_table_and_fail_on(self):
        code, out, _ = run_quiet(["--demo", str(self.notes), "--env-file", "/x", "--quiet"])
        self.assertEqual(code, 0)
        self.assertIn("malicious", out)
        self.assertIn("skipped: private or non-routable address", out)
        code, _, _ = run_quiet(["--demo", str(self.notes), "--fail-on", "malicious", "--env-file", "/x", "--quiet"])
        self.assertEqual(code, 1)

    def test_demo_file_outputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            for ext in ("md", "csv", "json"):
                path = Path(tmp) / f"r.{ext}"
                code, _, _ = run_quiet(["--demo", str(self.notes), "--out", str(path), "--defang", "--env-file", "/x"])
                self.assertEqual(code, 0)
                self.assertTrue(path.read_text(encoding="utf-8"))
            self.assertIn("micros0ft-support[.]com", (Path(tmp) / "r.md").read_text(encoding="utf-8"))

    def test_extract_only_and_errors(self):
        code, out, _ = run_quiet(["--demo", "--ioc", "hxxp://a[.]example/x", "--extract-only", "--env-file", "/x"])
        self.assertEqual((code, out.strip()), (0, "url\thttp://a.example/x"))
        self.assertEqual(run_quiet(["--demo", "--ioc", "nonsense", "--env-file", "/x"])[0], 2)
        self.assertEqual(run_quiet(["--demo", "--providers", "nope", "--ioc", "1.2.3.4", "--env-file", "/x"])[0], 2)
        self.assertEqual(run_quiet(["--demo", "--format", "csv", "--ioc", "1.2.3.4", "--env-file", "/x"])[0], 2)

    def test_list_providers_without_keys(self):
        import os
        from unittest import mock
        with mock.patch.dict(os.environ, {}, clear=True):
            code, out, _ = run_quiet(["--list-providers", "--env-file", "/x"])
        self.assertEqual(code, 0)
        self.assertIn("greynoise            configured", out)
        self.assertIn("virustotal           not configured: set VIRUSTOTAL_API_KEY", out)


if __name__ == "__main__":
    unittest.main()
