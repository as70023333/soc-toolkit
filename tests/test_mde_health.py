import json
import tempfile
import unittest
from importlib import resources
from pathlib import Path

from soc_toolkit.common.msapi import DefenderApi
from soc_toolkit.mde_health import cli
from soc_toolkit.mde_health.analyze import HealthConfig, analyze, config_query
from tests.fakes import FakeTransport, StaticCredential, body_json, json_response

def quiet_main(argv):
    import contextlib
    import io
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        return cli.main(argv)



def demo_fleet() -> dict:
    return json.loads(resources.files("soc_toolkit.mde_health").joinpath("demo_fleet.json").read_text(encoding="utf-8"))


class AnalyzeTests(unittest.TestCase):
    def setUp(self):
        self.result = analyze(demo_fleet(), HealthConfig(exclude_tags={"Retired"}))

    def by(self, check):
        return {f.target: f.severity for f in self.result.findings if f.check == check}

    def test_every_issue_type_is_found(self):
        self.assertEqual(self.by("not_onboarded"), {"printer-3f.contoso.local": "high"})
        self.assertEqual(self.by("unsupported_device"), {"iot-cam-lobby": "low"})
        self.assertEqual(set(self.by("inactive_device")), {"wks-mkt-009.contoso.local", "wks-old-003.contoso.local"})
        self.assertEqual(set(self.by("sensor_unhealthy")), {"srv-web-02.contoso.local", "wks-sales-011.contoso.local"})
        self.assertEqual(self.by("av_signatures_outdated"),
                         {"wks-hr-004.contoso.local": "medium", "lnx-build-01.contoso.local": "medium"})
        self.assertEqual(self.by("realtime_protection_off"), {"wks-dev-022.contoso.local": "high"})
        self.assertEqual(self.by("tamper_protection_off"), {"wks-dev-022.contoso.local": "medium"})

    def test_high_value_devices_are_raised(self):
        self.assertEqual(self.by("av_not_active"), {"srv-dc01.contoso.local": "critical"})
        self.assertEqual(self.by("network_protection_off"),
                         {"wks-fin-017.contoso.local": "medium", "srv-sql-prd01.contoso.local": "high"})

    def test_retired_tag_excluded_and_likely_retired_wording(self):
        self.assertEqual(self.result.stats["devices_excluded_by_tag"], 1)
        self.assertNotIn("wks-lab-007.contoso.local", {f.target for f in self.result.findings})
        old = next(f for f in self.result.findings if f.target == "wks-old-003.contoso.local")
        self.assertIn("Likely offboarded", old.detail)
        recent = next(f for f in self.result.findings if f.target == "wks-mkt-009.contoso.local")
        self.assertNotIn("Likely offboarded", recent.detail)

    def test_inactive_devices_skip_config_checks(self):
        flagged = {f.target for f in self.result.findings if f.check.endswith("_off") or f.check.startswith("av_")}
        self.assertNotIn("wks-old-003.contoso.local", flagged)

    def test_stats(self):
        s = self.result.stats
        self.assertEqual((s["devices_total"], s["onboarded"], s["not_onboarded"]), (14, 12, 1))
        self.assertEqual(s["onboarding_coverage_pct"], 92.3)
        self.assertEqual(s["healthy_active_devices"], 2)

    def test_string_compliance_values_and_missing_config(self):
        fleet = demo_fleet()
        for row in fleet["config_assessments"]:
            row["IsCompliant"] = "1" if row["IsCompliant"] else "0"
        result = analyze(fleet, HealthConfig())
        self.assertIn("srv-dc01.contoso.local", {f.target for f in result.findings if f.check == "av_not_active"})
        fleet["config_assessments"] = []
        result = analyze(fleet, HealthConfig())
        self.assertTrue(any("checks did not run" in n for n in result.notes))

    def test_config_validation_and_query(self):
        with self.assertRaises(ValueError):
            HealthConfig(inactive_days=10, retire_days=5)
        self.assertIn('ConfigurationId in ("scid-96")', config_query(("scid-96",)))


class CollectTests(unittest.TestCase):
    def test_collect_pages_machines_and_runs_hunting(self):
        fleet = demo_fleet()
        fake = FakeTransport()
        fake.add("GET", r"/api/machines\?\$skip", json_response({"value": fleet["machines"][7:]}))
        fake.add("GET", r"/api/machines$", json_response({"value": fleet["machines"][:7], "@odata.nextLink":
                 "https://api.securitycenter.microsoft.com/api/machines?$skip=7"}))

        def hunting(req):
            query = body_json(req)["Query"]
            rows = [r for r in fleet["config_assessments"] if f'"{r["ConfigurationId"]}"' in query]
            return json_response({"Schema": [], "Results": rows})

        fake.add("POST", r"/api/advancedqueries/run", hunting)
        api = DefenderApi(fake.client(), StaticCredential())
        data = cli.collect(api, lambda _m: None)
        self.assertEqual(len(data["machines"]), 15)
        self.assertEqual(len(data["config_assessments"]), len(fleet["config_assessments"]))
        self.assertEqual(len(fake.requests_to("advancedqueries")), 6)

    def test_hunting_permission_error_is_recorded(self):
        fake = FakeTransport()
        fake.add("GET", r"/api/machines", json_response({"value": demo_fleet()["machines"]}))
        fake.add("POST", r"/api/advancedqueries/run", json_response({"error": {"code": "Forbidden", "message": "no"}}, 403))
        data = cli.collect(DefenderApi(fake.client(), StaticCredential()), lambda _m: None)
        self.assertIn("AdvancedQuery.Read.All", data["errors"]["config_assessments"])
        self.assertEqual(data["config_assessments"], [])


class CliTests(unittest.TestCase):
    def test_demo(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(quiet_main(["--demo", "--out", tmp, "--quiet", "--env-file", "/x"]), 1)
            names = sorted(p.name for p in Path(tmp).iterdir())
            self.assertIn("mde-health-2026-10-01-devices.csv", names)
            self.assertIn("mde-health-2026-10-01.md", names)
            self.assertEqual(quiet_main(["--demo", "--out", tmp, "--quiet", "--fail-on", "none", "--env-file", "/x"]), 0)
            self.assertEqual(quiet_main(["--demo", "--inactive-days", "40", "--retire-days", "10", "--env-file", "/x"]), 2)


if __name__ == "__main__":
    unittest.main()
