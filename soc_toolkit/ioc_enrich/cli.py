"""ioc-enrich: bulk IOC enrichment from the command line."""

from __future__ import annotations

import json
import sys
from importlib import resources
from pathlib import Path

from soc_toolkit.common.auth import AuthError, credential_from_env
from soc_toolkit.common.cli import EXIT_ERROR, EXIT_FINDINGS, EXIT_OK, base_parser, die, load_env
from soc_toolkit.common.env import env_bool, env_int, env_list, env_str
from soc_toolkit.common.http import HttpClient
from soc_toolkit.common.msapi import DefenderApi, LogAnalyticsApi
from soc_toolkit.common.output import color_enabled, paint, write_csv, write_text
from soc_toolkit.ioc_enrich.cache import Cache, default_cache_path
from soc_toolkit.ioc_enrich.engine import Policy, enrich
from soc_toolkit.ioc_enrich.extract import Indicator, classify, extract
from soc_toolkit.ioc_enrich.providers import (
    EXTERNAL_PROVIDERS, DefenderIndicators, DemoProvider, GreyNoise, Provider, SentinelTI,
)
from soc_toolkit.ioc_enrich.report import (
    CSV_FIELDS, csv_rows, print_table, render_json, render_markdown, sort_enrichments,
)

EPILOG = """examples:
  ioc-enrich --demo examples/incident-notes.txt     offline demo with sample threat intel
  ioc-enrich notes.txt                              every IOC in a file (defanged text is fine)
  ioc-enrich --ioc 203.0.113.66 --ioc evil.example  specific indicators
  pbpaste | ioc-enrich -                            from the clipboard (stdin)
  ioc-enrich iocs.txt --out report.md --defang      shareable Markdown report
  ioc-enrich iocs.csv --providers virustotal,threatfox --fail-on malicious

exit codes: 0 nothing at or above --fail-on, 1 an indicator at or above --fail-on, 2 error"""


def build_parser():
    parser = base_parser("ioc-enrich", "Extract indicators (IPs, domains, URLs, hashes) from any text and check "
                         "them against threat-intel feeds in parallel.", EPILOG)
    parser.add_argument("inputs", nargs="*", metavar="FILE", help="text files to read ('-' for stdin)")
    parser.add_argument("--ioc", action="append", default=[], metavar="VALUE", help="an indicator (repeatable)")
    parser.add_argument("--demo", action="store_true", help="use the offline demo feeds (no API keys)")
    parser.add_argument("--providers", metavar="LIST", help="comma-separated feeds to use (default: all configured)")
    parser.add_argument("--list-providers", action="store_true", help="show feeds and whether they are configured")
    parser.add_argument("--extract-only", action="store_true", help="print the indicators found and stop")
    parser.add_argument("--url-hosts", action="store_true", help="also enrich the host of every URL")
    parser.add_argument("--include-private", action="store_true", help="also look up private/non-routable IPs")
    parser.add_argument("--format", choices=("table", "json", "csv", "md"), default=None,
                        help="output format (default: table, or from the --out file extension)")
    parser.add_argument("--out", metavar="FILE", help="write the report to a file instead of stdout")
    parser.add_argument("--defang", action="store_true", help="defang indicators in the output (safe to paste)")
    parser.add_argument("--fail-on", choices=("malicious", "suspicious", "none"), default="none",
                        help="exit 1 when any indicator reaches this verdict (default: none)")
    parser.add_argument("--no-cache", action="store_true", help="do not read or write the local result cache")
    parser.add_argument("--cache-ttl", type=float, default=None, metavar="HOURS", help="cache lifetime (default 24)")
    parser.add_argument("--workers", type=int, default=8, help="parallel requests (default 8)")
    parser.add_argument("--quiet", action="store_true", help="no progress output")
    return parser


def configured_providers(http: HttpClient) -> tuple[list[Provider], dict[str, str]]:
    """Feeds with credentials present, plus a reason for each one that is not available."""
    providers: list[Provider] = []
    missing: dict[str, str] = {}
    for name, cls in EXTERNAL_PROVIDERS.items():
        key = env_str(cls.key_env)
        rate_env = {"virustotal": "VT_RATE_PER_MIN"}.get(name)
        per_minute = float(env_int(rate_env, 0)) if rate_env and env_str(rate_env) else None
        if key or getattr(cls, "key_optional", False):
            providers.append(cls(http, key, per_minute))
        else:
            missing[name] = f"set {cls.key_env}"
    workspace = env_str("SENTINEL_WORKSPACE_ID")
    use_ms = workspace or env_bool("DEFENDER_INDICATORS")
    credential = None
    if use_ms:
        try:
            credential = credential_from_env(http)
        except AuthError as exc:
            missing["sentinel_ti"] = missing["defender_indicators"] = str(exc)
    if credential and workspace:
        providers.append(SentinelTI(http, LogAnalyticsApi(http, credential), workspace,
                                    env_str("SENTINEL_TI_TABLE", "ThreatIntelIndicators")))
    elif "sentinel_ti" not in missing:
        missing["sentinel_ti"] = "set SENTINEL_WORKSPACE_ID (and Azure credentials)"
    if credential and env_bool("DEFENDER_INDICATORS"):
        providers.append(DefenderIndicators(http, DefenderApi(
            http, credential, env_str("MDE_API_BASE", "https://api.securitycenter.microsoft.com"))))
    elif "defender_indicators" not in missing:
        missing["defender_indicators"] = "set DEFENDER_INDICATORS=true (and Azure credentials)"
    return providers, missing


def demo_providers() -> list[Provider]:
    data = json.loads(resources.files("soc_toolkit.ioc_enrich").joinpath("demo_intel.json").read_text(encoding="utf-8"))
    return [DemoProvider(name, spec["types"], spec["results"]) for name, spec in data["providers"].items()]


def _read_inputs(args) -> str | None:
    chunks: list[str] = []
    sources = list(args.inputs)
    if not sources and not args.ioc and not sys.stdin.isatty():
        sources = ["-"]
    for src in sources:
        if src == "-":
            chunks.append(sys.stdin.read())
        else:
            try:
                chunks.append(Path(src).read_text(encoding="utf-8", errors="replace"))
            except OSError as exc:
                print(f"error: cannot read {src}: {exc}", file=sys.stderr)
                return None
    return "\n".join(chunks)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    load_env(args)
    http = HttpClient(timeout=float(env_int("HTTP_TIMEOUT_SECONDS", 20)), retries=2)

    if args.demo:
        providers: list[Provider] = demo_providers()
        missing: dict[str, str] = {}
    else:
        providers, missing = configured_providers(http)

    if args.list_providers:
        names = [p.name for p in providers]
        for name in names:
            print(f"  {name:<20} configured")
        for name, reason in missing.items():
            print(f"  {name:<20} not configured: {reason}")
        return EXIT_OK

    if args.providers:
        wanted = [p.strip() for p in args.providers.split(",") if p.strip()]
        known = {p.name for p in providers} | set(missing)
        unknown = [w for w in wanted if w not in known]
        if unknown:
            return die(f"unknown feed(s): {', '.join(unknown)}. Run --list-providers.")
        not_ready = [w for w in wanted if w in missing]
        if not_ready:
            return die("; ".join(f"{w}: {missing[w]}" for w in not_ready))
        providers = [p for p in providers if p.name in wanted]

    text = _read_inputs(args)
    if text is None:
        return EXIT_ERROR
    indicators: list[Indicator] = []
    for value in args.ioc:
        ind = classify(value)
        if not ind:
            return die(f"not a recognisable indicator: {value!r}")
        indicators.append(ind)
    indicators += extract(text, url_hosts=args.url_hosts)
    indicators = list(dict.fromkeys(indicators))
    if not indicators:
        return die("no indicators found. Pass files, --ioc values, or pipe text on stdin.")

    if args.extract_only:
        for ind in indicators:
            print(f"{ind.type}\t{ind.value}")
        return EXIT_OK
    if not providers:
        return die("no threat-intel feed is configured. Add API keys to .env (see --list-providers) or try --demo.")

    policy = Policy(include_private=args.include_private,
                    allow_domains=set(env_list("IOC_ALLOWLIST_DOMAINS")) | ({"microsoftonline.com", "microsoft.com"}
                                                                              if args.demo else set()),
                    internal_domains=set(env_list("IOC_INTERNAL_DOMAINS")))
    cache = None
    if not args.no_cache and not args.demo:
        ttl = args.cache_ttl if args.cache_ttl is not None else float(env_int("IOC_CACHE_TTL_HOURS", 24))
        cache = Cache(default_cache_path(), ttl)
    quiet = args.quiet or not sys.stderr.isatty()

    def progress(done: int, total: int) -> None:
        if not quiet:
            print(f"\r  {done}/{total} lookups", end="" if done < total else "\n", file=sys.stderr, flush=True)

    if not args.quiet:
        print(f"Enriching {len(indicators)} indicator(s) with {', '.join(p.name for p in providers)}...",
              file=sys.stderr)
    try:
        results = sort_enrichments(enrich(indicators, providers, policy=policy, cache=cache,
                                          workers=args.workers, progress=progress))
    finally:
        if cache:
            cache.close()

    fmt = args.format
    if fmt is None and args.out:
        fmt = {".json": "json", ".csv": "csv", ".md": "md"}.get(Path(args.out).suffix.lower(), "table")
    fmt = fmt or "table"
    names = [p.name for p in providers]
    if fmt == "table" and not args.out:
        print_table(results, lambda v, t: paint(v, t, color_enabled(disabled=args.no_color)), args.defang)
    else:
        if fmt == "csv":
            if not args.out:
                return die("--format csv needs --out FILE")
            write_csv(Path(args.out), csv_rows(results, args.defang), CSV_FIELDS)
        else:
            if fmt == "json":
                body = render_json(results, args.defang)
            elif fmt == "md":
                body = render_markdown(results, names, args.defang)
            else:
                from io import StringIO
                from contextlib import redirect_stdout
                buffer = StringIO()
                with redirect_stdout(buffer):
                    print_table(results, lambda v, t: t, args.defang)
                body = buffer.getvalue()
            if args.out:
                write_text(Path(args.out), body)
            else:
                print(body)
        if args.out:
            print(f"Report: {args.out}", file=sys.stderr)

    errors = sorted({r.provider for e in results for r in e.results if r.status == "error"})
    if errors and not args.quiet:
        print(f"  note: some lookups failed ({', '.join(errors)}); see the report for details.", file=sys.stderr)
    if args.fail_on != "none":
        levels = ("malicious",) if args.fail_on == "malicious" else ("malicious", "suspicious")
        if any(e.verdict in levels for e in results):
            return EXIT_FINDINGS
    return EXIT_OK
