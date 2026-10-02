"""secrets-scan: find secrets before they are committed."""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from soc_toolkit import __version__
from soc_toolkit.common.cli import EXIT_ERROR, EXIT_FINDINGS, EXIT_OK, base_parser
from soc_toolkit.common.findings import severity_rank
from soc_toolkit.common.output import color_enabled, paint, write_text
from soc_toolkit.secrets_scan.gitutil import (
    GitError, install_hook, repo_root, staged_additions, staged_files, tracked_files,
)
from soc_toolkit.secrets_scan.rules import RuleError, Ruleset, load_ruleset
from soc_toolkit.secrets_scan.scanner import Finding, Scanner, iter_files

CONFIG_NAME = ".secrets-scan.toml"
BASELINE_NAME = ".secrets-baseline.json"
SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}

EPILOG = """modes:
  secrets-scan FILE|DIR ...        scan files (what the pre-commit framework passes)
  secrets-scan --staged            scan only lines added in the staged diff (native git hook)
  secrets-scan --all               scan every file tracked by git
  secrets-scan --install-hook      install the native pre-commit hook in this repository
  secrets-scan --list-rules        show active rules
  secrets-scan --test-rules        check the examples in your .secrets-scan.toml rules

false positives: add "secrets-scan: allow" in a comment on the line, or record the current
findings as accepted with:  secrets-scan --all --update-baseline

exit codes: 0 clean, 1 secrets found, 2 error"""


def build_parser():
    parser = base_parser("secrets-scan", "Find secrets (API keys, tokens, private keys, connection strings) "
                         "before they reach git history.", EPILOG)
    parser.add_argument("paths", nargs="*", help="files or directories to scan")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--staged", action="store_true", help="scan lines added in staged changes")
    mode.add_argument("--all", action="store_true", help="scan all git-tracked files")
    mode.add_argument("--install-hook", action="store_true", help="install the git pre-commit hook")
    mode.add_argument("--list-rules", action="store_true", help="list active rules")
    mode.add_argument("--test-rules", action="store_true", help="verify examples in custom rules")
    parser.add_argument("--force", action="store_true", help="with --install-hook: replace an existing hook")
    parser.add_argument("--config", metavar="FILE", help=f"rules file (default: {CONFIG_NAME} in the repo root)")
    parser.add_argument("--no-default-rules", action="store_true", help="use only the rules in --config")
    parser.add_argument("--baseline", metavar="FILE", help=f"accepted findings (default: {BASELINE_NAME} if present)")
    parser.add_argument("--update-baseline", action="store_true", help="write current findings to the baseline")
    parser.add_argument("--format", choices=("text", "json", "sarif"), default="text", help="output format")
    parser.add_argument("--output", metavar="FILE", help="write the report to a file")
    parser.add_argument("--max-size", type=float, default=2.0, metavar="MB", help="skip larger files (default 2)")
    return parser


def _find_config(explicit: str | None, root: Path) -> Path | None:
    if explicit:
        return Path(explicit)
    for candidate in (root / CONFIG_NAME, Path.cwd() / CONFIG_NAME):
        if candidate.is_file():
            return candidate
    return None


def _load_baseline(path: Path) -> set[str]:
    if not path.is_file():
        return set()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return {str(item["fingerprint"]) for item in data.get("findings", [])}
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise RuleError(f"cannot read baseline {path}: {exc}") from exc


def _relative(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def _test_rules(ruleset: Ruleset, scanner: Scanner) -> int:
    failures = 0
    tested = 0
    for rule in ruleset.rules:
        if not rule.examples and not rule.not_examples:
            continue
        tested += 1
        for sample in rule.examples:
            hits = [f for f in scanner.scan_line("example.txt", 1, sample, [rule]) if f.rule == rule.id]
            if not hits:
                failures += 1
                print(f"FAIL {rule.id}: should match: {sample[:80]}")
        for sample in rule.not_examples:
            hits = [f for f in scanner.scan_line("example.txt", 1, sample, [rule]) if f.rule == rule.id]
            if hits:
                failures += 1
                print(f"FAIL {rule.id}: should not match: {sample[:80]}")
    print(f"{tested} rule(s) with examples tested, {failures} failure(s)")
    return EXIT_FINDINGS if failures else EXIT_OK


def to_sarif(findings: list[Finding], ruleset: Ruleset) -> dict:
    used = sorted({f.rule for f in findings})
    descriptions = {r.id: (r.description, r.severity) for r in ruleset.rules}
    descriptions.update({r.id: (r.description, r.severity) for r in ruleset.file_rules})
    rules = [{"id": rid, "name": rid, "shortDescription": {"text": descriptions.get(rid, (rid, "high"))[0]},
              "defaultConfiguration": {"level": SARIF_LEVEL.get(descriptions.get(rid, ("", "high"))[1], "error")}}
             for rid in used]
    results = []
    for f in findings:
        region = {"startLine": max(1, f.line)}
        if f.column:
            region["startColumn"] = f.column
        results.append({
            "ruleId": f.rule, "level": SARIF_LEVEL.get(f.severity, "error"),
            "message": {"text": f"{f.description}: {f.redacted}"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.path}, "region": region}}],
            "partialFingerprints": {"secretFingerprint/v1": f.fingerprint},
        })
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "secrets-scan", "version": __version__,
                                          "informationUri": "https://github.com/as70023333/soc-toolkit",
                                          "rules": rules}},
                      "results": results}]}


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = repo_root() or Path.cwd()
    try:
        config = _find_config(args.config, root)
        ruleset = load_ruleset(config, use_defaults=not args.no_default_rules)
        baseline_path = Path(args.baseline) if args.baseline else root / BASELINE_NAME
        baseline = set() if args.update_baseline else _load_baseline(baseline_path)
    except RuleError as exc:
        print(f"secrets-scan: {exc}", file=sys.stderr)
        return EXIT_ERROR
    scanner = Scanner(ruleset, baseline, int(args.max_size * 1_000_000))

    if args.list_rules:
        for r in ruleset.rules:
            print(f"{r.severity:<9} {r.id:<32} {r.description}  [{r.source}]")
        for r in ruleset.file_rules:
            print(f"{r.severity:<9} {r.id:<32} {r.description} (file name)  [{r.source}]")
        return EXIT_OK
    if args.test_rules:
        return _test_rules(ruleset, scanner)
    if args.install_hook:
        try:
            hook = install_hook(sys.executable, force=args.force)
        except GitError as exc:
            print(f"secrets-scan: {exc}", file=sys.stderr)
            return EXIT_ERROR
        print(f"Installed {hook}. Every commit is now checked for secrets.")
        return EXIT_OK

    own_files = {p for p in (config, baseline_path) if p is not None}
    own = {_relative(p, root) for p in own_files}
    findings: list[Finding] = []
    try:
        if args.staged:
            additions = staged_additions(root)
            for name in staged_files(root):
                if name not in own and not scanner.path_allowed(name):
                    findings += scanner.check_filename(name)
            for name, lines in additions.items():
                if name in own or scanner.path_allowed(name):
                    continue
                findings += scanner.scan_lines(name, lines)
        else:
            if args.all:
                targets = [(root / name, name) for name in tracked_files(root)]
            elif args.paths:
                targets = []
                for raw in args.paths:
                    base = Path(raw)
                    if not base.exists():
                        print(f"secrets-scan: no such file or directory: {raw}", file=sys.stderr)
                        return EXIT_ERROR
                    targets += [(f, _relative(f, root)) for f in iter_files(base)]
            else:
                print("secrets-scan: nothing to scan. Pass paths, --staged or --all (see --help).", file=sys.stderr)
                return EXIT_ERROR
            for file, display in targets:
                if display in own or not file.is_file():
                    continue
                findings += scanner.scan_file(file, display)
    except GitError as exc:
        print(f"secrets-scan: {exc}", file=sys.stderr)
        return EXIT_ERROR

    findings.sort(key=lambda f: (f.path, f.line, severity_rank(f.severity)))

    if args.update_baseline:
        data = {"tool": "secrets-scan", "version": __version__,
                "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "note": "Accepted findings. Only fingerprints are stored, never the secrets.",
                "findings": [{"fingerprint": f.fingerprint, "rule": f.rule, "path": f.path, "line": f.line}
                             for f in findings]}
        write_text(baseline_path, json.dumps(data, indent=2))
        print(f"Baseline written to {baseline_path} with {len(findings)} accepted finding(s).")
        return EXIT_OK

    if args.format == "json":
        body = json.dumps({"tool": "secrets-scan", "version": __version__, "findings": [f.to_dict() for f in findings],
                           "suppressed_by_baseline": scanner.suppressed, "skipped": scanner.skipped}, indent=2)
    elif args.format == "sarif":
        body = json.dumps(to_sarif(findings, ruleset), indent=2)
    else:
        use_color = color_enabled(sys.stderr if not args.output else None, args.no_color) and not args.output
        lines = []
        if findings:
            lines.append(paint("high", f"secrets-scan: {len(findings)} potential secret(s) found", use_color))
            for f in findings:
                where = f"{f.path}:{f.line}:{f.column}" if f.line else f.path
                lines.append(f"  {where}  {paint(f.severity, f'[{f.severity}]', use_color)} {f.rule}: "
                             f"{f.description}  {f.redacted}")
            lines += ["",
                      "Fix: remove the secret and ROTATE it - assume anything that reached a commit is exposed.",
                      "Load it from the environment, a .env file that git ignores, or a vault instead.",
                      'False positive? Add "secrets-scan: allow" in a comment on that line, or accept it with',
                      "  secrets-scan --all --update-baseline"]
        else:
            lines.append("secrets-scan: no secrets found")
        if scanner.suppressed:
            lines.append(f"  ({scanner.suppressed} known finding(s) suppressed by the baseline)")
        for skipped in scanner.skipped:
            lines.append(f"  skipped: {skipped}")
        body = "\n".join(lines)
    if args.output:
        write_text(Path(args.output), body)
        print(f"Report: {args.output} ({len(findings)} finding(s))", file=sys.stderr)
    else:
        stream = sys.stderr if args.format == "text" and findings else sys.stdout
        print(body, file=stream)
    return EXIT_FINDINGS if findings else EXIT_OK
