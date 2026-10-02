"""Argument helpers shared by every command-line tool."""

from __future__ import annotations

import argparse
import sys

from soc_toolkit import __version__
from soc_toolkit.common.env import load_dotenv
from soc_toolkit.common.findings import SEVERITIES

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


def base_parser(prog: str, description: str, epilog: str = "") -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog=prog, description=description, epilog=epilog,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--env-file", default=".env", metavar="PATH",
                        help="load settings from this .env file if it exists (default: .env)")
    parser.add_argument("--no-color", action="store_true", help="disable coloured terminal output")
    return parser


def add_report_args(parser: argparse.ArgumentParser, default_formats: str = "md,csv,json") -> None:
    parser.add_argument("--out", metavar="DIR", default="reports",
                        help="directory for report files (default: reports)")
    parser.add_argument("--format", default=default_formats, metavar="LIST",
                        help=f"comma-separated report formats: md, csv, json (default: {default_formats})")
    parser.add_argument("--fail-on", default="high", choices=[*SEVERITIES, "none"],
                        help="exit with code 1 when a finding is at or above this severity (default: high)")


def load_env(args: argparse.Namespace) -> None:
    load_dotenv(args.env_file)


def die(message: str) -> int:
    print(f"error: {message}", file=sys.stderr)
    return EXIT_ERROR
