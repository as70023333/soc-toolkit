"""Parse, lint and catalog the hunting queries.

Each .kql file starts with a comment header:

    // Title: Password spray against Entra ID
    // Id: KQL-TA0006-001
    // Tactic: TA0006 Credential Access
    // Techniques: T1110.003
    // Platform: Sentinel
    // Tables: SigninLogs
    // Severity: Medium
    // Lookback: 1d
    // Description: What the query finds, in plain words.
    //   Continuation lines are indented.
    // False positives: When it fires on benign activity, and how to tell.
    // Tuning: Thresholds and allowlists to adjust.
    // Response: What to do when it fires.

The linter checks the header, the ATT&CK IDs, that the declared tables match the tables the query
uses and the platform they live on, and catches the mistakes that break KQL when queries are
copied around: unbalanced brackets, unterminated strings, smart quotes and dashes, dangling pipes.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

TACTICS: dict[str, tuple[str, str]] = {
    "TA0043": ("Reconnaissance", "reconnaissance"),
    "TA0042": ("Resource Development", "resource-development"),
    "TA0001": ("Initial Access", "initial-access"),
    "TA0002": ("Execution", "execution"),
    "TA0003": ("Persistence", "persistence"),
    "TA0004": ("Privilege Escalation", "privilege-escalation"),
    "TA0005": ("Defense Evasion", "defense-evasion"),
    "TA0006": ("Credential Access", "credential-access"),
    "TA0007": ("Discovery", "discovery"),
    "TA0008": ("Lateral Movement", "lateral-movement"),
    "TA0009": ("Collection", "collection"),
    "TA0011": ("Command and Control", "command-and-control"),
    "TA0010": ("Exfiltration", "exfiltration"),
    "TA0040": ("Impact", "impact"),
}
# Kill-chain order for the catalog.
TACTIC_ORDER = ("TA0043", "TA0042", "TA0001", "TA0002", "TA0003", "TA0004", "TA0005", "TA0006", "TA0007",
                "TA0008", "TA0009", "TA0011", "TA0010", "TA0040")

XDR_TABLES = frozenset({
    "DeviceProcessEvents", "DeviceNetworkEvents", "DeviceFileEvents", "DeviceRegistryEvents", "DeviceEvents",
    "DeviceLogonEvents", "DeviceImageLoadEvents", "DeviceInfo", "DeviceNetworkInfo", "DeviceFileCertificateInfo",
    "EmailEvents", "EmailAttachmentInfo", "EmailUrlInfo", "EmailPostDeliveryEvents", "UrlClickEvents",
    "IdentityLogonEvents", "IdentityQueryEvents", "IdentityDirectoryEvents", "IdentityInfo", "CloudAppEvents",
    "AlertInfo", "AlertEvidence", "DeviceTvmSecureConfigurationAssessment", "DeviceTvmSoftwareVulnerabilities",
})
SENTINEL_TABLES = frozenset({
    "SigninLogs", "AADNonInteractiveUserSignInLogs", "AADServicePrincipalSignInLogs", "AuditLogs",
    "SecurityEvent", "OfficeActivity", "AzureActivity", "CommonSecurityLog", "Syslog", "ThreatIntelIndicators",
    "ThreatIntelligenceIndicator", "SecurityAlert", "SecurityIncident", "BehaviorAnalytics", "IdentityInfo",
})
KNOWN_TABLES = XDR_TABLES | SENTINEL_TABLES
PLATFORMS = ("Defender XDR", "Sentinel", "Both")
SEVERITIES = ("High", "Medium", "Low", "Informational")
REQUIRED = ("Title", "Id", "Tactic", "Techniques", "Platform", "Tables", "Severity", "Lookback", "Description",
            "False positives", "Tuning", "Response")
KEYS = REQUIRED + ("References",)

_KEY_LINE = re.compile(r"^//\s*(" + "|".join(re.escape(k) for k in KEYS) + r"):\s*(.*)$")
_TECHNIQUE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
_ID = re.compile(r"^KQL-(TA\d{4})-(\d{3})$")
_FOLDER = re.compile(r"^(TA\d{4})-[a-z-]+$")


@dataclass
class QueryDoc:
    path: Path
    meta: dict[str, str]
    body: str
    problems: list[str] = field(default_factory=list)

    @property
    def techniques(self) -> list[str]:
        return [t.strip() for t in self.meta.get("Techniques", "").split(",") if t.strip()]

    @property
    def tables(self) -> list[str]:
        return [t.strip() for t in self.meta.get("Tables", "").split(",") if t.strip()]


def parse(path: Path) -> QueryDoc:
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines()
    meta: dict[str, str] = {}
    last: str | None = None
    index = 0
    for index, line in enumerate(lines):
        if not line.startswith("//"):
            break
        match = _KEY_LINE.match(line)
        if match:
            last = match.group(1)
            meta[last] = match.group(2).strip()
        elif last is not None:
            extra = line[2:].strip()
            if extra:
                meta[last] = f"{meta[last]} {extra}".strip()
    else:
        index = len(lines)
    body = "\n".join(lines[index:]).strip("\n")
    return QueryDoc(path, meta, body)


def strip_comments_and_strings(kql: str) -> tuple[str, list[str]]:
    """Blank out comments and string literals; report unterminated strings."""
    out: list[str] = []
    problems: list[str] = []
    i, n = 0, len(kql)
    line = 1
    while i < n:
        ch = kql[i]
        if ch == "\n":
            line += 1
            out.append(ch)
            i += 1
        elif kql.startswith("//", i):
            end = kql.find("\n", i)
            end = n if end == -1 else end
            out.append(" " * (end - i))
            i = end
        elif ch in ("'", '"') or (ch == "@" and i + 1 < n and kql[i + 1] in ("'", '"')):
            verbatim = ch == "@"
            quote = kql[i + 1] if verbatim else ch
            start_line = line
            j = i + (2 if verbatim else 1)
            closed = False
            while j < n:
                c = kql[j]
                if c == "\n":
                    break  # KQL string literals cannot span lines
                if not verbatim and c == "\\":
                    j += 2
                    continue
                if c == quote:
                    if verbatim and j + 1 < n and kql[j + 1] == quote:
                        j += 2  # doubled quote inside a verbatim string
                        continue
                    closed = True
                    j += 1
                    break
                j += 1
            if not closed:
                problems.append(f"unterminated string starting on body line {start_line}")
            out.append('""' + " " * max(0, j - i - 2))
            i = j
        else:
            out.append(ch)
            i += 1
    return "".join(out), problems


def _check_balance(code: str) -> list[str]:
    pairs = {")": "(", "]": "[", "}": "{"}
    stack: list[tuple[str, int]] = []
    problems = []
    for lineno, line in enumerate(code.splitlines(), start=1):
        for ch in line:
            if ch in "([{":
                stack.append((ch, lineno))
            elif ch in pairs:
                if not stack or stack[-1][0] != pairs[ch]:
                    problems.append(f"unmatched '{ch}' on body line {lineno}")
                    return problems
                stack.pop()
    for ch, lineno in stack:
        problems.append(f"unclosed '{ch}' from body line {lineno}")
    return problems


def lint(doc: QueryDoc) -> list[str]:
    problems: list[str] = []
    meta = doc.meta
    for key in REQUIRED:
        if not meta.get(key):
            problems.append(f"missing header field '{key}'")
    folder = doc.path.parent.name
    folder_match = _FOLDER.match(folder)
    tactic_value = meta.get("Tactic", "")
    tactic_id = tactic_value.split(" ", 1)[0]
    if tactic_id and tactic_id not in TACTICS:
        problems.append(f"unknown tactic '{tactic_value}'")
    elif tactic_id:
        expected_name = TACTICS[tactic_id][0]
        if tactic_value != f"{tactic_id} {expected_name}":
            problems.append(f"tactic should read '{tactic_id} {expected_name}'")
        if not folder_match or folder != f"{tactic_id}-{TACTICS[tactic_id][1]}":
            problems.append(f"file belongs in folder '{tactic_id}-{TACTICS[tactic_id][1]}'")
    id_match = _ID.match(meta.get("Id", ""))
    if meta.get("Id") and not id_match:
        problems.append("Id must look like KQL-TA0006-001")
    elif id_match and tactic_id and id_match.group(1) != tactic_id:
        problems.append("Id tactic does not match the Tactic field")
    for technique in doc.techniques:
        if not _TECHNIQUE.match(technique):
            problems.append(f"invalid ATT&CK technique id '{technique}'")
    if meta.get("Platform") and meta["Platform"] not in PLATFORMS:
        problems.append(f"Platform must be one of {', '.join(PLATFORMS)}")
    if meta.get("Severity") and meta["Severity"] not in SEVERITIES:
        problems.append(f"Severity must be one of {', '.join(SEVERITIES)}")
    unknown_tables = [t for t in doc.tables if t not in KNOWN_TABLES]
    if unknown_tables:
        problems.append(f"unknown table(s) {', '.join(unknown_tables)} (add them to KNOWN_TABLES if real)")
    declared = set(doc.tables)
    if declared and not unknown_tables and meta.get("Platform") in PLATFORMS:
        xdr = any(t in XDR_TABLES and t not in SENTINEL_TABLES for t in declared)
        sentinel = any(t in SENTINEL_TABLES and t not in XDR_TABLES for t in declared)
        expected = "Both" if xdr and sentinel else ("Defender XDR" if xdr else "Sentinel")
        if meta["Platform"] != expected:
            problems.append(f"Platform should be '{expected}' for tables {', '.join(sorted(declared))}")

    full_text = doc.path.read_text(encoding="utf-8")
    for lineno, line in enumerate(full_text.splitlines(), start=1):
        bad = sorted({c for c in line if ord(c) > 126})
        if bad:
            problems.append(f"line {lineno}: non-ASCII character(s) {' '.join(repr(c) for c in bad)} "
                            "(smart quotes and dashes break KQL)")
        if "\t" in line:
            problems.append(f"line {lineno}: tab character; use spaces")
        if line != line.rstrip():
            problems.append(f"line {lineno}: trailing whitespace")

    if not doc.body.strip():
        problems.append("no query body")
        return problems
    code, string_problems = strip_comments_and_strings(doc.body)
    problems += string_problems
    problems += _check_balance(code)
    used = {t for t in KNOWN_TABLES if re.search(rf"(?<![\w.]){re.escape(t)}\b", code)}
    if declared and used != declared:
        missing = sorted(used - declared)
        extra = sorted(declared - used)
        if missing:
            problems.append(f"query uses undeclared table(s): {', '.join(missing)}")
        if extra:
            problems.append(f"declared table(s) not used in the query: {', '.join(extra)}")
    if "ago(" not in code and "between" not in code:
        problems.append("no time filter (ago() or between); unbounded hunts are slow and costly")
    statements = [s for s in code.split(";") if s.strip()]
    if not statements or statements[-1].strip().startswith("let "):
        problems.append("query ends with a let statement; the last statement must be a tabular expression")
    code_lines = [l.strip() for l in code.splitlines() if l.strip()]
    if code_lines and code_lines[-1].endswith("|"):
        problems.append("dangling pipe at the end of the query")
    if code_lines and code_lines[0].startswith("|"):
        problems.append("query starts with a pipe; it needs a table or let statement first")
    if re.search(r"\|\s*\|", code):
        problems.append("empty pipe stage ('| |')")
    return problems


def load_library(root: Path) -> list[QueryDoc]:
    docs = [parse(p) for p in sorted(root.glob("TA*/*.kql"))]
    seen: dict[str, Path] = {}
    for doc in docs:
        doc.problems = lint(doc)
        qid = doc.meta.get("Id", "")
        if qid:
            if qid in seen:
                doc.problems.append(f"duplicate Id {qid} (also in {seen[qid].as_posix()})")
            seen[qid] = doc.path
    return docs


def technique_link(technique: str) -> str:
    return f"https://attack.mitre.org/techniques/{technique.replace('.', '/')}/"


CATALOG_START = "<!-- catalog:start -->"
CATALOG_END = "<!-- catalog:end -->"


def render_catalog(docs: list[QueryDoc], root: Path) -> str:
    by_tactic: dict[str, list[QueryDoc]] = {}
    for doc in docs:
        by_tactic.setdefault(doc.meta.get("Tactic", "").split(" ", 1)[0], []).append(doc)
    lines = [CATALOG_START, "",
             f"_{len(docs)} queries across {len(by_tactic)} tactics. Generated by `kql-catalog build`; "
             "do not edit by hand._", ""]
    for tactic in TACTIC_ORDER:
        items = sorted(by_tactic.get(tactic, []), key=lambda d: d.meta.get("Id", ""))
        if not items:
            continue
        name, slug = TACTICS[tactic]
        lines += [f"### {tactic} {name}", "",
                  "| Id | Query | Techniques | Platform | Severity | Tables |", "|---|---|---|---|---|---|"]
        for d in items:
            rel = d.path.relative_to(root).as_posix()
            techniques = ", ".join(f"[{t}]({technique_link(t)})" for t in d.techniques)
            lines.append(f"| {d.meta.get('Id')} | [{d.meta.get('Title')}]({rel}) | {techniques} | "
                         f"{d.meta.get('Platform')} | {d.meta.get('Severity')} | {', '.join(d.tables)} |")
        lines.append("")
    lines.append(CATALOG_END)
    return "\n".join(lines)


def update_readme(readme: Path, catalog: str) -> str:
    text = readme.read_text(encoding="utf-8")
    start = text.find(CATALOG_START)
    end = text.find(CATALOG_END)
    if start == -1 or end == -1 or end < start:
        raise ValueError(f"{readme} needs {CATALOG_START} and {CATALOG_END} markers")
    return text[:start] + catalog + text[end + len(CATALOG_END):]
