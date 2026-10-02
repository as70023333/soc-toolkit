"""mde-health: Defender for Endpoint device-health report."""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from importlib import resources
from pathlib import Path
from typing import Any, Callable

from soc_toolkit import __version__
from soc_toolkit.common.auth import AuthError, credential_from_env
from soc_toolkit.common.cli import EXIT_FINDINGS, EXIT_OK, add_report_args, base_parser, die, load_env
from soc_toolkit.common.env import env_int, env_list, env_str
from soc_toolkit.common.findings import meets_threshold
from soc_toolkit.common.http import HttpClient, HttpError
from soc_toolkit.common.msapi import DefenderApi
from soc_toolkit.common.output import color_enabled, paint, parse_formats, to_json, write_csv, write_text
from soc_toolkit.common.report import print_summary, render_markdown, write_reports
from soc_toolkit.common.timeutil import iso, utcnow
from soc_toolkit.mde_health.analyze import CONFIG_QUERY_GROUPS, HealthConfig, analyze, config_query

EPILOG = """examples:
  mde-health --demo                         run against a built-in sample fleet
  mde-health                                report on your tenant (credentials from .env)
  mde-health --inactive-days 14 --fail-on critical
  mde-health --exclude-tag retired --exclude-tag lab

exit codes: 0 no finding at or above --fail-on, 1 findings at or above --fail-on, 2 error"""

DEVICE_FIELDS = ("device", "platform", "os_version", "onboarding", "health", "last_seen", "device_value",
                 "device_group", "issues", "device_id")


def collect(api: DefenderApi, log: Callable[[str], None]) -> dict[str, Any]:
    fleet: dict[str, Any] = {"captured_at": iso(utcnow()), "machines": [], "config_assessments": [], "errors": {}}
    fleet["machines"] = api.get_all("/api/machines")
    log(f"devices: {len(fleet['machines'])}")
    rows: list[dict] = []
    for ids in CONFIG_QUERY_GROUPS:
        try:
            rows.extend(api.run_hunting(config_query(ids)))
        except HttpError as exc:
            hint = " - grant AdvancedQuery.Read.All" if exc.status in (401, 403) else ""
            fleet["errors"]["config_assessments"] = f"{exc}{hint}"
            log(f"secure configuration: skipped ({exc})")
            rows = []
            break
    fleet["config_assessments"] = rows
    log(f"secure-configuration rows: {len(rows)}")
    return fleet


def build_parser():
    parser = base_parser("mde-health", "Defender for Endpoint device-health report: inactive or offboarded "
                         "devices, unhealthy sensors, outdated or disabled antivirus, network protection off, "
                         "and devices that were never onboarded.", EPILOG)
    add_report_args(parser)
    parser.add_argument("--demo", action="store_true", help="use the built-in sample fleet (no credentials)")
    parser.add_argument("--inactive-days", type=int, default=None, help="days without a report before a device "
                        "counts as inactive (default 7)")
    parser.add_argument("--retire-days", type=int, default=None, help="days after which an inactive device is "
                        "called likely retired (default 30)")
    parser.add_argument("--exclude-tag", action="append", default=None, metavar="TAG",
                        help="skip devices carrying this Defender device tag (repeatable)")
    parser.add_argument("--save-raw", metavar="FILE", help="also save the raw API data as JSON")
    parser.add_argument("--raw", metavar="FILE", help="analyse raw data saved with --save-raw")
    parser.add_argument("--quiet", action="store_true", help="print only the report paths")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    load_env(args)
    try:
        formats = parse_formats(args.format, ("md", "csv", "json"))
        config = HealthConfig(
            inactive_days=args.inactive_days or env_int("MDE_INACTIVE_DAYS", 7),
            retire_days=args.retire_days or env_int("MDE_RETIRE_DAYS", 30),
            exclude_tags=set(args.exclude_tag if args.exclude_tag is not None else env_list("MDE_EXCLUDE_TAGS")),
        )
    except ValueError as exc:
        return die(str(exc))
    use_color = color_enabled(disabled=args.no_color)
    log = (lambda _m: None) if args.quiet else (lambda m: print(f"  {m}", file=sys.stderr))

    if args.demo:
        fleet = json.loads(resources.files("soc_toolkit.mde_health").joinpath("demo_fleet.json")
                           .read_text(encoding="utf-8"))
        if args.exclude_tag is None and not env_list("MDE_EXCLUDE_TAGS"):
            config.exclude_tags = {"retired"}
        source = "built-in demo fleet (fictional data)"
    elif args.raw:
        try:
            fleet = json.loads(Path(args.raw).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            return die(f"cannot read {args.raw}: {exc}")
        source = f"saved data {args.raw}"
    else:
        http = HttpClient(timeout=float(env_int("HTTP_TIMEOUT_SECONDS", 60)))
        try:
            api = DefenderApi(http, credential_from_env(http),
                              env_str("MDE_API_BASE", "https://api.securitycenter.microsoft.com"))
            if not args.quiet:
                print("Collecting from the Defender for Endpoint API (read-only)...", file=sys.stderr)
            fleet = collect(api, log)
        except (AuthError, HttpError) as exc:
            hint = " - grant WindowsDefenderATP Machine.Read.All" if isinstance(exc, HttpError) and exc.status in (401, 403) else ""
            return die(f"{exc}{hint}")
        source = "Defender for Endpoint API"
    if args.save_raw:
        write_text(Path(args.save_raw), to_json(fleet))

    try:
        result = analyze(fleet, config)
    except ValueError as exc:
        return die(str(exc))
    s = result.stats
    meta = [("Data captured", fleet.get("captured_at")), ("Source", source),
            ("Inactive after", f"{config.inactive_days} days")]
    stats = [("Devices in inventory", s["devices_total"]),
             ("Onboarded / never onboarded", f"{s['onboarded']} / {s['not_onboarded']}"),
             ("Onboarding coverage", f"{s['onboarding_coverage_pct']}%" if s["onboarding_coverage_pct"] is not None
              else None),
             ("Active onboarded devices", s["active_onboarded"]),
             ("Onboarded devices with no issue", s["healthy_active_devices"]),
             ("Excluded by tag", s["devices_excluded_by_tag"]),
             ("Platforms", ", ".join(f"{k} {v}" for k, v in s["by_platform"].items()))]
    markdown = render_markdown("Defender for Endpoint device health", meta, stats, result.findings,
                               result.notes, "mde-health")
    payload = {"tool": "mde-health", "version": __version__,
               "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
               "captured_at": fleet.get("captured_at"), "source": source, "stats": s, "notes": result.notes,
               "findings": [f.to_dict() for f in result.findings], "devices": result.devices}
    stamp = (fleet.get("captured_at") or "")[:10] or datetime.now(timezone.utc).strftime("%Y-%m-%d")
    out = Path(args.out)
    paths = write_reports(out, f"mde-health-{stamp}", formats, markdown, payload, result.findings)
    if "csv" in formats:
        device_csv = out / f"mde-health-{stamp}-devices.csv"
        write_csv(device_csv, result.devices, DEVICE_FIELDS)
        paths.append(device_csv)
    if not args.quiet:
        print_summary(result.findings, lambda sev, text: paint(sev, text, use_color))
        for note in result.notes:
            print(f"  note: {note}", file=sys.stderr)
    for p in paths:
        print(f"Report: {p}")
    return EXIT_FINDINGS if meets_threshold(result.findings, args.fail_on) else EXIT_OK
