import contextlib
import io
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from soc_toolkit.secrets_scan import cli
from soc_toolkit.secrets_scan.gitutil import parse_diff
from soc_toolkit.secrets_scan.rules import RuleError, load_ruleset
from soc_toolkit.secrets_scan.scanner import Scanner, is_placeholder, redact, shannon_entropy

REPO = Path(__file__).resolve().parent.parent

# Test secrets are assembled at runtime so this file never contains a literal secret
# (and never trips this scanner, GitHub push protection or anyone else's).
def j(*parts):
    return "".join(parts)


ALNUM = "Q7mK2pX9vR4tL8wN3zB6cJ1hF5dS0gYa"   # 32 mixed characters
POSITIVE = {
    "private-key": j("-----BEGIN ", "RSA PRIVATE KEY-----"),
    "aws-access-key-id": j('key = "AK', 'IA', 'Q3EGRZPW7KXHT5ND"'),
    "aws-secret-access-key": j("aws_secret_access_key = ", "wJalrXUtnFEMIK7MDENGbPxRfiCY9xQ2mK7pLs4v"),
    "github-token": j("token: gh", "p_", ALNUM, "A1b2"),
    "github-fine-grained-token": j("github", "_pat_", "11ABCDEFG0", "abcdefghijKLMNOPQRstuv_", ALNUM * 2)[:93],
    "gitlab-token": j("glp", "at-", "aB3dE5fG7hJ9kL1mN3pQ"),
    "slack-token": j("xo", "xb-", "1234567890-0987654321-", ALNUM[:24]),
    "slack-webhook": j("https://hooks.slack", ".com/services/", "T0ABCDEFG/B0HIJKLMN/", ALNUM[:24]),
    "teams-webhook": j("https://contoso.webhook", ".office.com/webhookb2/", "3f6c8a2e-1b4d-4e9f-a7c5-2d8b6e0f1a3c@", "tenant/IncomingWebhook/abc"),
    "signed-workflow-url": j("https://prod-27.westus.logic", ".azure.com:443/workflows/abc123/triggers/manual/paths/invoke",
                             "?api-version=2016-06-01&sp=%2Ftriggers&sv=1.0&sig=", "Ab3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5bC7dE9"),
    "azure-storage-key": j("DefaultEndpointsProtocol=https;AccountName=x;AccountKey=", "Ab3dE5fG7hJ9kL1mN3pQ" * 4, "Ab3dE5", "=="),
    "azure-sas-token": j("https://x.blob.core.windows.net/c?sv=2023-11-03&se=2026-12-01&sig=", "Ab3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5bC7dE9", "%3D"),
    "entra-client-secret": j("client_secret: ", "abc", "8Q~", "Xy7zA1bC2dE3fG4hJ5kL6mN7pQ8rS9tU0v"),
    "anthropic-api-key": j("sk-", "ant-", "api03-", ALNUM * 3),
    "openai-api-key": j("sk-", "proj-", ALNUM * 2),
    "google-api-key": j("AI", "za", "SyD3", "Ab3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1x"),
    "stripe-live-key": j("sk", "_live_", ALNUM[:24]),
    "sendgrid-api-key": j("SG", ".", "Ab3dE5fG7hJ9kL1mN3pQ5r", ".", "Ab3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5bC7dE9f"),
    "npm-token": j("np", "m_", ALNUM, "Xy7z"),
    "pypi-token": j("py", "pi-AgEIcHlwaS5vcmc", ALNUM * 2),
    "discord-webhook": j("https://discord", ".com/api/webhooks/123456789012345678/", ALNUM * 2),
    "jwt": j("ey", "JhbGciOiJIUzI1NiJ9", ".", "ey", "JzdWIiOiIxMjM0NTY3ODkwIn0", ".", "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"),
    "url-credentials": j("postgres://admin:", "Hunter2Strong", "@db.internal.example:5432/app"),
    "connection-string-password": j("Server=sql01;Database=app;User Id=svc;Password=", "Tr0ub4dor&3x;"),
    "generic-secret-assignment": j('client_secret = "', "Zx9Qw3Er7Ty1Ui5Op2As", '"'),
}
NEGATIVE = [
    'key = "AKIAIOSFODNN7EXAMPLE"',                       # AWS documentation key
    "token = os.environ['GITHUB_TOKEN']",
    'password = "${DB_PASSWORD}"',
    'api_key = "your-api-key-here"',
    "postgres://user:password@localhost/db",
    'secret = "aaaaaaaaaaaaaaaaaaaa"',                    # no entropy
    "The private key goes in Key Vault.",
    "Password= in the connection string is required",
]


def scanner(config=None, baseline=()):
    return Scanner(load_ruleset(config), baseline)


class RuleTests(unittest.TestCase):
    def test_every_built_in_rule_has_a_positive_case(self):
        ruleset = load_ruleset()
        builtin = {r.id for r in ruleset.rules if r.source == "built-in"} - {"env-secret-assignment"}
        self.assertEqual(builtin, set(POSITIVE), "add a POSITIVE example for each new rule")

    def test_positives(self):
        s = scanner()
        for rule_id, line in POSITIVE.items():
            with self.subTest(rule=rule_id):
                findings = s.scan_line("app/config.py", 1, line)
                self.assertIn(rule_id, [f.rule for f in findings], line)

    def test_negatives(self):
        s = scanner()
        for line in NEGATIVE:
            with self.subTest(line=line):
                self.assertEqual(s.scan_line("app/config.py", 1, line), [])

    def test_env_rule_only_runs_on_env_like_files(self):
        line = j("export API_TOKEN=", "Zx9Qw3Er7Ty1Ui5Op2AsDf")
        s = scanner()
        self.assertEqual([f.rule for f in s.scan_line("deploy.sh", 1, line)], ["env-secret-assignment"])
        self.assertEqual(s.scan_line("notes.txt", 1, line), [])

    def test_specific_rule_wins_over_generic_and_sas(self):
        s = scanner()
        rules = [f.rule for f in s.scan_line("x.py", 1, j('token = "', POSITIVE["github-token"][7:], '"'))]
        self.assertEqual(rules, ["github-token"])
        rules = [f.rule for f in s.scan_line("x.json", 1, POSITIVE["signed-workflow-url"])]
        self.assertEqual(rules, ["signed-workflow-url"])

    def test_inline_allow_and_redaction(self):
        s = scanner()
        self.assertEqual(s.scan_line("x.py", 1, POSITIVE["github-token"] + "  # secrets-scan: allow"), [])
        self.assertEqual(s.scan_line("x.py", 1, POSITIVE["github-token"] + "  # pragma: allowlist secret"), [])
        finding = s.scan_line("x.py", 3, POSITIVE["github-token"])[0]
        self.assertEqual((finding.line, finding.column), (3, 8))
        self.assertTrue(finding.redacted.startswith("ghp_****("))
        self.assertNotIn(ALNUM, json.dumps(finding.to_dict()))

    def test_file_rules(self):
        s = scanner()
        self.assertEqual([f.rule for f in s.check_filename("config/.env")], ["env-file"])
        self.assertEqual(s.check_filename(".env.example"), [])
        self.assertEqual([f.rule for f in s.check_filename("keys/server.pfx")], ["private-key-file"])
        self.assertEqual([f.rule for f in s.check_filename("infra/terraform.tfstate")], ["terraform-state"])

    def test_helpers(self):
        self.assertTrue(is_placeholder("<your-token>"))
        self.assertTrue(is_placeholder("changeme"))
        self.assertFalse(is_placeholder("myS3cr3tP4ssw0rd"))
        self.assertEqual(redact("short"), "****(5 chars)")
        self.assertGreater(shannon_entropy("Zx9Qw3Er7Ty1Ui5Op2As"), 4)


class ConfigTests(unittest.TestCase):
    def write(self, text):
        tmp = tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False, encoding="utf-8")
        tmp.write(text)
        tmp.close()
        self.addCleanup(os.unlink, tmp.name)
        return Path(tmp.name)

    def test_repo_org_rules_pass_their_examples(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = cli.main(["--test-rules", "--config", str(REPO / ".secrets-scan.toml")])
        self.assertEqual(code, 0, out.getvalue())
        self.assertIn("0 failure(s)", out.getvalue())

    def test_custom_rules_run_first_and_disable_works(self):
        cfg = self.write('disable = ["jwt"]\n[[rule]]\nid = "acme"\ndescription = "Acme key"\n'
                         "regex = '''\\b(acme_[a-z0-9]{20})\\b'''\nkeywords = [\"acme_\"]\n")
        ruleset = load_ruleset(cfg)
        self.assertEqual(ruleset.rules[0].id, "acme")
        self.assertNotIn("jwt", {r.id for r in ruleset.rules})
        s = Scanner(ruleset)
        self.assertEqual([f.rule for f in s.scan_line("x", 1, "k = acme_" + "q1w2e3r4t5y6u7i8o9p0")], ["acme"])

    def test_invalid_configs_fail_fast(self):
        bad = {
            "unknown field": '[[rule]]\nid = "x"\ndescription = "d"\nregex = "a"\nbogus = 1\n',
            "bad regex": '[[rule]]\nid = "x"\ndescription = "d"\nregex = "(unclosed"\n',
            "bad severity": '[[rule]]\nid = "x"\ndescription = "d"\nregex = "a"\nseverity = "urgent"\n',
            "unknown disable": 'disable = ["no-such-rule"]\n',
            "duplicate": '[[rule]]\nid = "x"\ndescription = "d"\nregex = "a"\n[[rule]]\nid = "x"\ndescription = "d"\nregex = "b"\n',
            "toml syntax": "[[rule]\n",
            "allowlist key": "[allowlist]\nfiles = []\n",
        }
        for name, text in bad.items():
            with self.subTest(case=name):
                with self.assertRaises(RuleError):
                    load_ruleset(self.write(text))

    def test_allowlist(self):
        cfg = self.write('[allowlist]\npaths = ["fixtures/**"]\nstopwords = ["testkey"]\n')
        s = scanner(cfg)
        self.assertTrue(s.path_allowed("fixtures/a/b.txt"))
        self.assertEqual(s.scan_line("x", 1, j('secret = "Zx9Qw3Er7', 'TestKey', 'Ui5Op2As"')), [])


class DiffParserTests(unittest.TestCase):
    def test_added_lines_with_numbers(self):
        diff = "\n".join([
            "diff --git a/app.py b/app.py", "index 1..2 100644", "--- a/app.py", "+++ b/app.py",
            "@@ -1,0 +2,2 @@", "+first", "++plus-line looks like a header", "@@ -10 +20 @@", "-old", "+changed",
            "diff --git a/gone.txt b/gone.txt", "deleted file mode 100644", "--- a/gone.txt", "+++ /dev/null",
            "@@ -1 +0,0 @@", "-bye",
            'diff --git "a/caf\\303\\251.txt" "b/caf\\303\\251.txt"', "new file mode 100644", "--- /dev/null",
            '+++ "b/caf\\303\\251.txt"', "@@ -0,0 +1 @@", "+hello", "\\ No newline at end of file", ""])
        files = parse_diff(diff)
        self.assertEqual(files["app.py"], [(2, "first"), (3, "+plus-line looks like a header"), (20, "changed")])
        self.assertNotIn("gone.txt", files)
        self.assertEqual(files["café.txt"], [(1, "hello")])


@unittest.skipUnless(shutil.which("git"), "git is not installed")
class GitIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)
        for args in (["init", "-q"], ["config", "user.email", "t@example.com"], ["config", "user.name", "t"],
                     ["config", "commit.gpgsign", "false"]):
            subprocess.run(["git", *args], cwd=self.repo, check=True)
        self.old = os.getcwd()
        os.chdir(self.repo)
        self.addCleanup(os.chdir, self.old)

    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(list(argv))
        return code, out.getvalue() + err.getvalue()

    def test_staged_only_reports_added_lines(self):
        (self.repo / "old.py").write_text(POSITIVE["github-token"] + "\n", encoding="utf-8")
        subprocess.run(["git", "add", "old.py"], cwd=self.repo, check=True)
        subprocess.run(["git", "commit", "-qm", "seed", "--no-verify"], cwd=self.repo, check=True)
        (self.repo / "old.py").write_text(POSITIVE["github-token"] + "\nsafe = 1\n", encoding="utf-8")
        (self.repo / "new.py").write_text("x = 1\n" + POSITIVE["aws-access-key-id"] + "\n", encoding="utf-8")
        (self.repo / ".env").write_text("A=1\n", encoding="utf-8")
        subprocess.run(["git", "add", "old.py", "new.py", ".env"], cwd=self.repo, check=True)
        code, output = self.run_cli("--staged", "--no-color")
        self.assertEqual(code, 1)
        self.assertIn("new.py:2:", output)
        self.assertIn("env-file", output)
        self.assertNotIn("old.py", output)  # the pre-existing secret is not a new addition
        code, output = self.run_cli("--staged", "--format", "sarif")
        sarif = json.loads(output[: output.rindex("}") + 1])
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertEqual({r["ruleId"] for r in sarif["runs"][0]["results"]}, {"aws-access-key-id", "env-file"})

    def test_all_baseline_and_hook(self):
        (self.repo / "a.py").write_text(POSITIVE["stripe-live-key"] + "\n", encoding="utf-8")
        subprocess.run(["git", "add", "a.py"], cwd=self.repo, check=True)
        self.assertEqual(self.run_cli("--all")[0], 1)
        self.assertEqual(self.run_cli("--all", "--update-baseline")[0], 0)
        baseline = (self.repo / ".secrets-baseline.json").read_text(encoding="utf-8")
        self.assertNotIn(ALNUM[:24], baseline)  # only fingerprints are stored
        code, output = self.run_cli("--all")
        self.assertEqual(code, 0)
        self.assertIn("suppressed by the baseline", output)
        code, output = self.run_cli("--install-hook")
        self.assertEqual(code, 0)
        hook = self.repo / ".git" / "hooks" / "pre-commit"
        self.assertIn("soc_toolkit.secrets_scan --staged", hook.read_text(encoding="utf-8"))
        self.assertEqual(self.run_cli("--install-hook")[0], 0)  # re-install over our own hook is fine
        hook.write_text("#!/bin/sh\necho custom\n", encoding="utf-8")
        self.assertEqual(self.run_cli("--install-hook")[0], 2)  # never clobber someone else's hook
        self.assertEqual(self.run_cli("--install-hook", "--force")[0], 0)

    def test_paths_mode_and_missing_path(self):
        (self.repo / "dir").mkdir()
        (self.repo / "dir" / "k.txt").write_text(POSITIVE["sendgrid-api-key"] + "\n", encoding="utf-8")
        (self.repo / "dir" / "bin.dat").write_bytes(b"\x00\x01" + POSITIVE["sendgrid-api-key"].encode())
        (self.repo / "node_modules").mkdir()
        (self.repo / "node_modules" / "x.js").write_text(POSITIVE["npm-token"] + "\n", encoding="utf-8")
        code, output = self.run_cli(".", "--format", "json")
        data = json.loads(output[: output.rindex("}") + 1])
        self.assertEqual([f["path"] for f in data["findings"]], ["dir/k.txt"])
        self.assertEqual(self.run_cli("does-not-exist")[0], 2)
        self.assertEqual(self.run_cli()[0], 2)


if __name__ == "__main__":
    unittest.main()
