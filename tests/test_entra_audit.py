import copy
import json
import tempfile
import unittest
from importlib import resources
from pathlib import Path

from soc_toolkit.common.http import Response
from soc_toolkit.common.msapi import GraphApi
from soc_toolkit.entra_audit import cli
from soc_toolkit.entra_audit.analyze import AuditConfig, analyze
from soc_toolkit.entra_audit.collect import collect
from tests.fakes import FakeTransport, StaticCredential, body_json, json_response

def quiet_main(argv):
    import contextlib
    import io
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        return cli.main(argv)



def demo_snapshot() -> dict:
    return json.loads(resources.files("soc_toolkit.entra_audit").joinpath("demo_tenant.json").read_text(encoding="utf-8"))


def by_check(result, check):
    return [f for f in result.findings if f.check == check]


class AnalyzeDemoTenantTests(unittest.TestCase):
    def setUp(self):
        self.result = analyze(demo_snapshot(), AuditConfig(break_glass={"BreakGlass01@contoso.com"}))

    def targets(self, check):
        return {f.target for f in by_check(self.result, check)}

    def test_stale_and_never_signed_in(self):
        self.assertEqual(self.targets("stale_account"), {"bob.legacy@contoso.com"})
        self.assertEqual(self.targets("never_signed_in"), {"svc-backup@contoso.com"})
        stale_guest = by_check(self.result, "stale_guest")
        self.assertEqual(len(stale_guest), 1)
        self.assertEqual(stale_guest[0].severity, "high")  # privileged guest is raised
        self.assertEqual(self.targets("pending_guest_invite"), {"newhire_gmail.com#EXT#@contoso.onmicrosoft.com"})

    def test_disabled_and_break_glass_are_not_stale(self):
        stale = self.targets("stale_account") | self.targets("never_signed_in")
        self.assertNotIn("frank.former@contoso.com", stale)
        self.assertNotIn("breakglass01@contoso.com", stale)

    def test_mfa(self):
        self.assertEqual(self.targets("no_mfa"), {"dave@contoso.com", "svc-backup@contoso.com"})
        self.assertEqual(self.targets("weak_mfa_only"), {"bob.legacy@contoso.com"})
        self.assertEqual(self.targets("admin_not_phishing_resistant"),
                         {"carol.admin@contoso.com", "erin.exchange@contoso.com"})
        # passkey and FIDO2 holders, and guests, are not flagged
        everything = {f.target for f in self.result.findings if f.check.startswith(("no_mfa", "weak", "admin_not"))}
        self.assertNotIn("grace.secops@contoso.com", everything)
        self.assertNotIn("vendor_x_fabrikam.com#EXT#@contoso.onmicrosoft.com", everything)

    def test_consents(self):
        apps = {f.target.split(" (")[0]: f for f in by_check(self.result, "risky_app_permission")}
        self.assertEqual(set(apps), {"MailSync Pro", "Contoso Automation"})
        self.assertEqual(apps["MailSync Pro"].severity, "critical")  # third party, unverified, mailbox access
        self.assertEqual(apps["Contoso Automation"].severity, "high")  # own app with takeover permission
        delegated = by_check(self.result, "risky_delegated_consent")
        self.assertEqual([f.target.split(" (")[0] for f in delegated], ["PDF Converter Online"])
        self.assertEqual(delegated[0].evidence["users"], 3)
        # Microsoft first-party (Teams) and low-risk apps (Calendar Helper, HR Portal) are skipped
        all_targets = " ".join(f.target for f in self.result.findings)
        for name in ("Microsoft Teams", "Calendar Helper", "HR Portal"):
            self.assertNotIn(name, all_targets)

    def test_roles(self):
        standing = {f.target: f.severity for f in by_check(self.result, "standing_privileged_role")}
        self.assertEqual(standing, {"carol.admin@contoso.com": "critical", "erin.exchange@contoso.com": "high",
                                    "heidi@contoso.com": "medium"})  # heidi's role is scoped to an AU
        self.assertEqual(self.targets("guest_privileged_role"), {"vendor_x_fabrikam.com#EXT#@contoso.onmicrosoft.com"})
        self.assertEqual(self.targets("synced_privileged_account"), {"erin.exchange@contoso.com"})
        self.assertEqual(self.targets("disabled_user_with_role"), {"frank.former@contoso.com"})
        self.assertEqual(self.targets("group_privileged_role"), {"SG-Helpdesk-Admins"})
        self.assertEqual(len(by_check(self.result, "service_principal_privileged_role")), 1)
        self.assertEqual(self.targets("break_glass_account"), {"breakglass01@contoso.com"})
        # grace only has a time-bound PIM activation; Global Reader (alice) is not privileged
        self.assertNotIn("grace.secops@contoso.com", set(standing))
        self.assertNotIn("alice@contoso.com", {f.target for f in self.result.findings})
        self.assertFalse(by_check(self.result, "too_many_global_admins") or by_check(self.result, "too_few_global_admins"))

    def test_stats(self):
        self.assertEqual(self.result.stats["users_total"], 12)
        self.assertEqual(self.result.stats["mfa_registered_pct"], 77.8)


class AnalyzeEdgeCaseTests(unittest.TestCase):
    def test_no_sign_in_activity_skips_stale_with_a_note(self):
        snap = demo_snapshot()
        snap["sign_in_activity_available"] = False
        result = analyze(snap, AuditConfig(checks=("stale",)))
        self.assertFalse(by_check(result, "stale_account"))
        self.assertTrue(any("stale-account checks were skipped" in n for n in result.notes))

    def test_unverified_third_party_bumps_and_owned_internal_does_not(self):
        snap = demo_snapshot()
        mailsync = next(sp for sp in snap["service_principals"] if sp["displayName"] == "MailSync Pro")
        mailsync["verifiedPublisher"]["verifiedPublisherId"] = "999"
        result = analyze(snap, AuditConfig(checks=("consent",)))
        app = next(f for f in result.findings if f.target.startswith("MailSync Pro"))
        self.assertEqual(app.severity, "high")

    def test_too_many_global_admins(self):
        snap = demo_snapshot()
        for n, user in enumerate(snap["users"][:6]):
            snap["role_assignments"].append({"principalId": user["id"], "roleDefinitionId":
                                             "62e90394-69f5-4237-9190-012177145e10", "assignmentType": "Assigned",
                                             "memberType": "Direct", "source": "pim", "directoryScopeId": "/"})
        result = analyze(snap, AuditConfig(checks=("roles",)))
        self.assertTrue(by_check(result, "too_many_global_admins"))

    def test_pim_unavailable_marks_everything_standing(self):
        snap = demo_snapshot()
        for a in snap["role_assignments"]:
            a["source"] = "direct"
        snap["pim_available"] = False
        result = analyze(snap, AuditConfig(checks=("roles",)))
        self.assertIn("grace.secops@contoso.com", {f.target for f in by_check(result, "standing_privileged_role")})

    def test_config_validation(self):
        with self.assertRaises(ValueError):
            AuditConfig(stale_days=0)


class CollectTests(unittest.TestCase):
    """collect() against a fake Graph: permission fallbacks and section isolation."""

    def build(self, users_status=403, pim_status=403):
        snap = demo_snapshot()
        fake = FakeTransport()
        fake.add("GET", r"/v1.0/organization", json_response({"value": [snap["tenant"]]}))

        def users(req):
            if "signInActivity" in req.url and users_status != 200:
                return json_response({"error": {"code": "Authorization_RequestDenied", "message": "no"}}, users_status)
            plain = copy.deepcopy(snap["users"])
            if "signInActivity" not in req.url:
                for u in plain:
                    u.pop("signInActivity", None)
            return json_response({"value": plain})

        fake.add("GET", r"/v1.0/users\?", users)
        fake.add("GET", r"userRegistrationDetails", json_response({"value": snap["registration"]}))
        fake.add("GET", r"/v1.0/servicePrincipals\?", json_response({"value": snap["service_principals"]}))
        fake.add("GET", r"/v1.0/oauth2PermissionGrants", json_response({"value": snap["oauth2_grants"]}))
        fake.add("GET", r"/servicePrincipals/sp-graph/appRoleAssignedTo",
                 json_response({"value": [a for a in snap["app_role_assignments"] if a["resourceId"] == "sp-graph"]}))
        fake.add("GET", r"/servicePrincipals/sp-exo/appRoleAssignedTo",
                 json_response({"value": [a for a in snap["app_role_assignments"] if a["resourceId"] == "sp-exo"]}))
        fake.add("GET", r"/servicePrincipals/sp-graph\?", json_response(
            {"id": "sp-graph", "appRoles": [{"id": k, "value": v} for k, v in snap["resource_app_roles"]["sp-graph"].items()]}))
        fake.add("GET", r"/servicePrincipals/sp-exo\?", json_response(
            {"id": "sp-exo", "appRoles": [{"id": k, "value": v} for k, v in snap["resource_app_roles"]["sp-exo"].items()]}))
        fake.add("GET", r"roleDefinitions", json_response({"value": snap["role_definitions"]}))
        if pim_status == 200:
            fake.add("GET", r"roleAssignmentScheduleInstances", json_response({"value": snap["role_assignments"]}))
        else:
            fake.add("GET", r"roleAssignmentScheduleInstances", json_response({"error": {"code": "AadPremiumLicenseRequired"}}, pim_status))
        fake.add("GET", r"roleManagement/directory/roleAssignments\?", json_response(
            {"value": [{k: a[k] for k in ("principalId", "roleDefinitionId", "directoryScopeId")} for a in snap["role_assignments"]]}))

        def get_by_ids(req):
            ids = body_json(req)["ids"]
            return json_response({"value": [snap["principals"][i] for i in ids if i in snap["principals"]]})

        fake.add("POST", r"directoryObjects/getByIds", get_by_ids)
        return fake

    def test_fallbacks_and_full_analysis(self):
        fake = self.build(users_status=403, pim_status=403)
        snap = collect(GraphApi(fake.client(), StaticCredential()))
        self.assertFalse(snap["sign_in_activity_available"])
        self.assertIn("sign_in_activity", snap["errors"])
        self.assertFalse(snap["pim_available"])
        self.assertIn("pim", snap["errors"])
        self.assertEqual(len(snap["role_assignments"]), 10)
        self.assertIn("grp-helpdesk", snap["principals"])
        result = analyze(snap, AuditConfig(now=demo_snapshot_time()))
        checks = {f.check for f in result.findings}
        self.assertIn("risky_app_permission", checks)
        self.assertIn("standing_privileged_role", checks)
        self.assertNotIn("stale_account", checks)

    def test_happy_path_uses_sign_in_activity_and_pim(self):
        snap = collect(GraphApi(self.build(users_status=200, pim_status=200).client(), StaticCredential()))
        self.assertTrue(snap["sign_in_activity_available"])
        self.assertTrue(snap["pim_available"])
        self.assertEqual(snap["errors"], {})

    def test_section_failure_is_isolated(self):
        fake = self.build(users_status=200, pim_status=200)
        fake.routes.insert(0, ("GET", __import__("re").compile("userRegistrationDetails"),
                               json_response({"error": {"code": "Forbidden", "message": "x"}}, 403)))
        snap = collect(GraphApi(fake.client(), StaticCredential()))
        self.assertIsNone(snap["registration"])
        self.assertIn("AuditLog.Read.All", snap["errors"]["registration"])
        self.assertTrue(snap["users"])


def demo_snapshot_time():
    from soc_toolkit.common.timeutil import parse_time
    return parse_time(demo_snapshot()["captured_at"])


class CliTests(unittest.TestCase):
    def test_demo_writes_reports_and_exit_codes(self):
        with tempfile.TemporaryDirectory() as tmp:
            code = quiet_main(["--demo", "--out", tmp, "--quiet", "--env-file", "/nonexistent"])
            self.assertEqual(code, 1)
            names = sorted(p.name for p in Path(tmp).iterdir())
            self.assertEqual(names, ["entra-audit-2026-10-01.csv", "entra-audit-2026-10-01.json", "entra-audit-2026-10-01.md"])
            report = json.loads((Path(tmp) / "entra-audit-2026-10-01.json").read_text(encoding="utf-8"))
            self.assertEqual(report["tool"], "entra-audit")
            self.assertTrue(report["findings"])
            self.assertEqual(quiet_main(["--demo", "--out", tmp, "--quiet", "--fail-on", "none", "--env-file", "/x"]), 0)

    def test_snapshot_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            snap = Path(tmp) / "snap.json"
            quiet_main(["--demo", "--out", tmp, "--quiet", "--format", "json", "--save-snapshot", str(snap), "--env-file", "/x"])
            self.assertEqual(quiet_main(["--snapshot", str(snap), "--out", tmp, "--quiet", "--checks", "mfa",
                                       "--format", "md", "--env-file", "/x"]), 1)

    def test_bad_arguments(self):
        self.assertEqual(quiet_main(["--demo", "--checks", "nope", "--env-file", "/x"]), 2)
        self.assertEqual(quiet_main(["--demo", "--format", "pdf", "--env-file", "/x"]), 2)


if __name__ == "__main__":
    unittest.main()
