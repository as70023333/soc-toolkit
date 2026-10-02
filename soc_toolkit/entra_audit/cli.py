"""entra-audit: Entra ID hygiene audit."""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from importlib import resources
from pathlib import Path

from soc_toolkit import __version__
from soc_toolkit.common.auth import AuthError, credential_from_env
from soc_toolkit.common.cli import EXIT_FINDINGS, EXIT_OK, add_report_args, base_parser, die, load_env
from soc_toolkit.common.env import env_int, env_list, env_str
from soc_toolkit.common.findings import meets_threshold
from soc_toolkit.common.http import HttpClient, HttpError
from soc_toolkit.common.msapi import GraphApi
from soc_toolkit.common.output import color_enabled, paint, parse_formats, to_json, write_text
from soc_toolkit.common.report import print_summary, render_markdown, write_reports
from soc_toolkit.entra_audit.analyze import AuditConfig, analyze
from soc_toolkit.entra_audit.collect import CHECKS, collect

EPILOG = """examples:
  entra-audit --demo                         run against a built-in sample tenant
  entra-audit                                audit your tenant (credentials from .env or az login)
  entra-audit --checks mfa,roles --fail-on critical
  entra-audit --save-snapshot snap.json      keep the raw Graph data for later re-analysis
  entra-audit --snapshot snap.json           re-analyse a saved snapshot offline

exit codes: 0 no finding at or above --fail-on, 1 findings at or above --fail-on, 2 error"""


def build_parser():
    parser = base_parser("entra-audit", "Read-only Entra ID hygiene audit: stale accounts, MFA gaps, "
                         "risky app consents and standing privileged access.", EPILOG)
    add_report_args(parser)
    parser.add_argument("--demo", action="store_true", help="use the built-in sample tenant (no credentials)")
    parser.add_argument("--snapshot", metavar="FILE", help="analyse a snapshot saved with --save-snapshot")
    parser.add_argument("--save-snapshot", metavar="FILE", help="also save the raw collected data as JSON")
    parser.add_argument("--checks", default=",".join(CHECKS), help=f"comma-separated subset of {', '.join(CHECKS)}")
    parser.add_argument("--stale-days", type=int, default=None, help="days without sign-in for members (default 90)")
    parser.add_argument("--guest-stale-days", type=int, default=None, help="days without sign-in for guests (default 90)")
    parser.add_argument("--break-glass", default=None, metavar="UPNS",
                        help="comma-separated emergency-access UPNs (expected Global Admins)")
    parser.add_argument("--exclude", default=None, metavar="UPNS",
                        help="comma-separated UPNs to skip in stale and MFA checks (e.g. sync accounts)")
    parser.add_argument("--quiet", action="store_true", help="print only the report paths")
    return parser


def _split(value: str | None, env_name: str) -> set[str]:
    if value is None:
        return set(env_list(env_name))
    return {v.strip() for v in value.split(",") if v.strip()}


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    load_env(args)
    try:
        formats = parse_formats(args.format, ("md", "csv", "json"))
        checks = tuple(c.strip() for c in args.checks.split(",") if c.strip())
        unknown = [c for c in checks if c not in CHECKS]
        if unknown:
            raise ValueError(f"unknown check(s) {', '.join(unknown)}; choose from {', '.join(CHECKS)}")
        config = AuditConfig(
            stale_days=args.stale_days or env_int("ENTRA_STALE_DAYS", 90),
            guest_stale_days=args.guest_stale_days or env_int("ENTRA_GUEST_STALE_DAYS", 90),
            break_glass=_split(args.break_glass, "ENTRA_BREAK_GLASS_UPNS"),
            exclude=_split(args.exclude, "ENTRA_EXCLUDE_UPNS"),
            checks=checks,
        )
    except ValueError as exc:
        return die(str(exc))

    use_color = color_enabled(disabled=args.no_color)
    log = (lambda _m: None) if args.quiet else (lambda m: print(f"  {m}", file=sys.stderr))

    if args.demo:
        snapshot = json.loads(resources.files("soc_toolkit.entra_audit").joinpath("demo_tenant.json")
                              .read_text(encoding="utf-8"))
        if args.break_glass is None and not env_list("ENTRA_BREAK_GLASS_UPNS"):
            config.break_glass = {"breakglass01@contoso.com"}
        source = "built-in demo tenant (fictional data)"
    elif args.snapshot:
        try:
            snapshot = json.loads(Path(args.snapshot).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            return die(f"cannot read snapshot {args.snapshot}: {exc}")
        source = f"snapshot {args.snapshot}"
    else:
        http = HttpClient(timeout=float(env_int("HTTP_TIMEOUT_SECONDS", 30)))
        try:
            graph = GraphApi(http, credential_from_env(http), env_str("GRAPH_BASE_URL", "https://graph.microsoft.com"))
            if not args.quiet:
                print("Collecting from Microsoft Graph (read-only)...", file=sys.stderr)
            snapshot = collect(graph, checks, log)
        except (AuthError, HttpError) as exc:
            return die(str(exc))
        source = "Microsoft Graph"
        if not snapshot["users"] and "users" in snapshot["errors"]:
            return die(f"could not list users: {snapshot['errors']['users']}")
    snapshot["checks"] = list(checks)

    if args.save_snapshot:
        write_text(Path(args.save_snapshot), to_json(snapshot))

    try:
        result = analyze(snapshot, config)
    except ValueError as exc:
        return die(str(exc))
    tenant = snapshot.get("tenant") or {}
    s = result.stats
    meta = [("Tenant", f"{tenant.get('displayName', '')} ({tenant.get('id', 'unknown')})"),
            ("Data captured", snapshot.get("captured_at")), ("Source", source),
            ("Checks", ", ".join(checks))]
    stats = [("Users (enabled / total)", f"{s['users_enabled']} / {s['users_total']}"),
             ("Guests", s["guests"]),
             ("Enabled members registered for MFA", f"{s['mfa_registered_pct']}%" if s["mfa_registered_pct"]
              is not None else None),
             ("Service principals", s["service_principals"]),
             ("Privileged role assignments", s["privileged_assignments"]),
             ("PIM data available", "yes" if s["pim_available"] else "no"),
             ("Sign-in activity available", "yes" if s["sign_in_activity_available"] else "no"),
             ("Stale threshold (members / guests)", f"{config.stale_days} / {config.guest_stale_days} days")]
    markdown = render_markdown("Entra ID hygiene audit", meta, stats, result.findings, result.notes, "entra-audit")
    payload = {"tool": "entra-audit", "version": __version__,
               "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
               "tenant": tenant, "captured_at": snapshot.get("captured_at"), "source": source,
               "stats": result.stats, "notes": result.notes, "findings": [f.to_dict() for f in result.findings]}
    stamp = (snapshot.get("captured_at") or "")[:10] or datetime.now(timezone.utc).strftime("%Y-%m-%d")
    paths = write_reports(Path(args.out), f"entra-audit-{stamp}", formats, markdown, payload, result.findings)

    if not args.quiet:
        print_summary(result.findings, lambda sev, text: paint(sev, text, use_color))
        for note in result.notes:
            print(f"  note: {note}", file=sys.stderr)
    for p in paths:
        print(f"Report: {p}")
    return EXIT_FINDINGS if meets_threshold(result.findings, args.fail_on) else EXIT_OK
