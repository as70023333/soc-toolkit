import json
import tempfile
import unittest
from pathlib import Path

from soc_toolkit.kql_catalog import cli
from soc_toolkit.kql_catalog.catalog import (
    CATALOG_END, CATALOG_START, load_library, parse, render_catalog, strip_comments_and_strings, update_readme,
)

ROOT = Path(__file__).resolve().parent.parent / "kql"

GOOD = """// Title: Example
// Id: KQL-TA0006-009
// Tactic: TA0006 Credential Access
// Techniques: T1110.003
// Platform: Sentinel
// Tables: SigninLogs
// Severity: Medium
// Lookback: 1d
// Description: Finds things.
//   More words on a second line.
// False positives: Some.
// Tuning: Adjust.
// Response: Act.
let Lookback = 1d;
SigninLogs
| where TimeGenerated > ago(Lookback)
| where UserPrincipalName has "a|b" and ResultType == "50126"   // a comment with ( and "
| project TimeGenerated
"""

def quiet_main(argv):
    import contextlib
    import io
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        return cli.main(argv)



class LibraryTests(unittest.TestCase):
    def test_whole_library_is_clean(self):
        docs = load_library(ROOT)
        self.assertGreaterEqual(len(docs), 38)
        problems = {d.path.name: d.problems for d in docs if d.problems}
        self.assertEqual(problems, {})

    def test_every_tactic_folder_is_covered(self):
        tactics = {d.meta["Tactic"].split()[0] for d in load_library(ROOT)}
        self.assertEqual(tactics, {"TA0001", "TA0002", "TA0003", "TA0004", "TA0005", "TA0006", "TA0007", "TA0008",
                                   "TA0009", "TA0010", "TA0011", "TA0040"})

    def test_catalog_in_readme_is_current(self):
        readme = ROOT / "README.md"
        self.assertEqual(update_readme(readme, render_catalog(load_library(ROOT), ROOT)),
                         readme.read_text(encoding="utf-8"), "run: kql-catalog build")


class LinterTests(unittest.TestCase):
    def lint_text(self, text, folder="TA0006-credential-access"):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / folder / "q.kql"
            path.parent.mkdir()
            path.write_text(text, encoding="utf-8")
            return load_library(Path(tmp))[0].problems

    def test_good_query_and_continuation_lines(self):
        self.assertEqual(self.lint_text(GOOD), [])
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "q.kql"
            path.write_text(GOOD, encoding="utf-8")
            self.assertEqual(parse(path).meta["Description"], "Finds things. More words on a second line.")

    def assert_problem(self, text, fragment, folder="TA0006-credential-access"):
        problems = self.lint_text(text, folder)
        self.assertTrue(any(fragment in p for p in problems), f"expected '{fragment}' in {problems}")

    def test_catches_common_mistakes(self):
        self.assert_problem(GOOD.replace("| project TimeGenerated", "| project TimeGenerated\n|"), "dangling pipe")
        self.assert_problem(GOOD.replace("| project TimeGenerated", '| where Note == "open\n| project TimeGenerated'),
                            "unterminated string")
        self.assert_problem(GOOD.replace("ago(Lookback)", "ago(Lookback"), "unclosed '('")
        self.assert_problem(GOOD.replace('has "a|b"', "has “a”"), "non-ASCII")
        self.assert_problem(GOOD.replace("Tables: SigninLogs", "Tables: SigninLogs, AuditLogs"), "not used")
        self.assert_problem(GOOD.replace("SigninLogs\n|", "SigninLogs\n| join AuditLogs on X\n|"), "undeclared")
        self.assert_problem(GOOD.replace("Platform: Sentinel", "Platform: Defender XDR"), "Platform should be")
        self.assert_problem(GOOD.replace("T1110.003", "T999"), "invalid ATT&CK")
        self.assert_problem(GOOD.replace("// Tuning: Adjust.\n", ""), "missing header field 'Tuning'")
        self.assert_problem(GOOD.replace("> ago(Lookback)", "> datetime(2026-01-01)"), "no time filter")
        self.assert_problem(GOOD, "belongs in folder", folder="TA0001-initial-access")
        self.assert_problem(GOOD.replace("KQL-TA0006-009", "KQL-TA0001-009"), "Id tactic")
        self.assert_problem(GOOD.replace("| project", "\t| project"), "tab character")
        self.assert_problem(GOOD.replace("SigninLogs\n|", "SigninLogs  \n|"), "trailing whitespace")

    def test_verbatim_strings_with_doubled_quotes(self):
        code, problems = strip_comments_and_strings('T | where x matches regex @"a""(b" and y == \'c\\\'d\'')
        self.assertEqual(problems, [])
        self.assertNotIn("(b", code)


class CliTests(unittest.TestCase):
    def test_lint_export_and_check(self):
        self.assertEqual(quiet_main(["lint", "--root", str(ROOT)]), 0)
        self.assertEqual(quiet_main(["check", "--root", str(ROOT)]), 0)
        import contextlib
        import io
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(cli.main(["export", "--root", str(ROOT)]), 0)
        index = json.loads(out.getvalue())
        self.assertTrue(all(item["query"] and item["false_positives"] for item in index))
        self.assertEqual(quiet_main(["lint", "--root", "/no/such/folder"]), 2)

    def test_build_writes_between_markers(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            folder = root / "TA0006-credential-access"
            folder.mkdir()
            (folder / "q.kql").write_text(GOOD, encoding="utf-8")
            (root / "README.md").write_text(f"intro\n{CATALOG_START}\nold\n{CATALOG_END}\noutro\n", encoding="utf-8")
            self.assertEqual(quiet_main(["check", "--root", tmp]), 1)
            self.assertEqual(quiet_main(["build", "--root", tmp]), 0)
            text = (root / "README.md").read_text(encoding="utf-8")
            self.assertIn("KQL-TA0006-009", text)
            self.assertTrue(text.startswith("intro\n") and text.endswith("outro\n"))
            self.assertEqual(quiet_main(["check", "--root", tmp]), 0)


if __name__ == "__main__":
    unittest.main()
