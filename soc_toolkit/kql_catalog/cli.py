"""kql-catalog: lint the hunting library and keep its catalog current."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from soc_toolkit.common.cli import EXIT_ERROR, EXIT_FINDINGS, EXIT_OK, base_parser
from soc_toolkit.kql_catalog.catalog import load_library, render_catalog, technique_link, update_readme

EPILOG = """commands:
  kql-catalog lint      check every query header and body (CI runs this)
  kql-catalog build     regenerate the catalog table in kql/README.md
  kql-catalog check     fail if the catalog in kql/README.md is out of date
  kql-catalog export    print a JSON index of all queries (for tooling or a Sentinel import script)"""


def build_parser():
    parser = base_parser("kql-catalog", "Lint and catalog the KQL hunting library.", EPILOG)
    parser.add_argument("command", choices=("lint", "build", "check", "export"))
    parser.add_argument("--root", default="kql", help="library folder (default: kql)")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = Path(args.root)
    if not root.is_dir():
        print(f"kql-catalog: folder not found: {root}", file=sys.stderr)
        return EXIT_ERROR
    docs = load_library(root)
    if not docs:
        print(f"kql-catalog: no queries found under {root}/TA*/", file=sys.stderr)
        return EXIT_ERROR

    if args.command == "lint":
        bad = [d for d in docs if d.problems]
        for d in bad:
            print(f"{d.path.as_posix()}:")
            for problem in d.problems:
                print(f"  - {problem}")
        print(f"{len(docs)} queries checked, {len(bad)} with problems")
        return EXIT_FINDINGS if bad else EXIT_OK

    if args.command == "export":
        index = [{"id": d.meta.get("Id"), "title": d.meta.get("Title"), "tactic": d.meta.get("Tactic"),
                  "techniques": [{"id": t, "url": technique_link(t)} for t in d.techniques],
                  "platform": d.meta.get("Platform"), "tables": d.tables, "severity": d.meta.get("Severity"),
                  "lookback": d.meta.get("Lookback"), "description": d.meta.get("Description"),
                  "false_positives": d.meta.get("False positives"), "tuning": d.meta.get("Tuning"),
                  "response": d.meta.get("Response"), "path": d.path.as_posix(), "query": d.body}
                 for d in docs]
        print(json.dumps(index, indent=2))
        return EXIT_OK

    readme = root / "README.md"
    try:
        updated = update_readme(readme, render_catalog(docs, root))
    except (OSError, ValueError) as exc:
        print(f"kql-catalog: {exc}", file=sys.stderr)
        return EXIT_ERROR
    current = readme.read_text(encoding="utf-8")
    if args.command == "check":
        if updated != current:
            print("kql-catalog: kql/README.md catalog is out of date; run 'kql-catalog build'", file=sys.stderr)
            return EXIT_FINDINGS
        print("kql-catalog: catalog is up to date")
        return EXIT_OK
    readme.write_text(updated, encoding="utf-8")
    print(f"kql-catalog: wrote the catalog for {len(docs)} queries to {readme}")
    return EXIT_OK
