"""The scanning engine: lines in, redacted findings out. Secrets never leave memory unredacted."""

from __future__ import annotations

import hashlib
import math
import re
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable

from soc_toolkit.secrets_scan.rules import SKIP_DIRS, Rule, Ruleset, path_matches

INLINE_ALLOW = re.compile(r"(?i)(?:secrets-scan:\s*allow|pragma:\s*allowlist\s+secret|gitleaks:allow)")

_PLACEHOLDER = re.compile(
    r"(?i)^(?:x{4,}|\*{3,}|\.{3,}|-{3,}|<[^>]*>|\[[^\]]*\]|\$\{[^}]*\}|\$\([^)]*\)|\{\{[^}]*\}\}|%\([^)]*\)s|"
    r"%[A-Za-z_]+%|\$[A-Za-z_][A-Za-z0-9_]*|(?:your|my|insert|enter|put)[-_ ][a-z0-9_ -]*|"
    r"(?:your|my)(?:api)?[-_]?(?:key|token|secret|password|pass)[a-z0-9_-]*|"
    r"change[-_]?me\w*|replace[-_]?me\w*|placeholder\w*|redacted|dummy\w*|example\w*|sample\w*|"
    r"test(?:ing)?|fake\w*|none|null|nil|undefined|password|passwd|pass|pwd|secret|token|todo|tbd|"
    r"os\.environ.*|process\.env.*|env\(.*)$")


@dataclass
class Finding:
    rule: str
    description: str
    severity: str
    path: str
    line: int
    column: int
    redacted: str
    fingerprint: str

    def to_dict(self) -> dict:
        return asdict(self)


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    total = len(value)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def is_placeholder(value: str) -> bool:
    if _PLACEHOLDER.match(value.strip("'\"")):
        return True
    if "EXAMPLE" in value.upper():  # AWS documentation keys end in EXAMPLE
        return True
    return len(set(value)) <= 2  # "aaaaaaaa", "0000000000"


def redact(secret: str) -> str:
    if len(secret) < 12:
        return f"****({len(secret)} chars)"
    return f"{secret[:4]}****({len(secret)} chars)"


def fingerprint(rule_id: str, path: str, secret: str) -> str:
    return hashlib.sha256(f"{rule_id}:{path}:{secret}".encode("utf-8")).hexdigest()[:24]


class Scanner:
    def __init__(self, ruleset: Ruleset, baseline: Iterable[str] = (), max_bytes: int = 2_000_000) -> None:
        self.ruleset = ruleset
        self.baseline = set(baseline)
        self.max_bytes = max_bytes
        self.suppressed = 0
        self.skipped: list[str] = []

    def path_allowed(self, path: str) -> bool:
        return path_matches(path, self.ruleset.allow_paths)

    def check_filename(self, path: str) -> list[Finding]:
        findings = []
        for rule in self.ruleset.file_rules:
            if rule.matches(path):
                fp = fingerprint(rule.id, path, "<file>")
                if fp in self.baseline:
                    self.suppressed += 1
                    continue
                findings.append(Finding(rule.id, rule.description, rule.severity, path, 0, 0,
                                        "file should not be committed", fp))
        return findings

    def _applies(self, rule: Rule, path: str, lower: str) -> bool:
        if rule.paths and not path_matches(path, rule.paths):
            return False
        if rule.keywords and not any(k in lower for k in rule.keywords):
            return False
        if rule.require_any and not any(k in lower for k in rule.require_any):
            return False
        return True

    def scan_line(self, path: str, number: int, line: str, rules: list[Rule] | None = None) -> list[Finding]:
        if INLINE_ALLOW.search(line):
            return []
        lower = line.lower()
        claimed: list[tuple[int, int]] = []
        findings: list[Finding] = []
        for rule in rules if rules is not None else self.ruleset.rules:
            if not self._applies(rule, path, lower):
                continue
            g = rule.group()
            for match in rule.regex.finditer(line):
                secret = match.group(g)
                if not secret:
                    continue
                start, end = match.span(g)
                if any(start < e and s < end for s, e in claimed):
                    continue
                if rule.placeholder_check and is_placeholder(secret):
                    continue
                if rule.entropy and shannon_entropy(secret) < rule.entropy:
                    continue
                if any(p.search(secret) for p in self.ruleset.allow_regexes):
                    continue
                if any(word in secret.lower() for word in self.ruleset.stopwords):
                    continue
                claimed.append((start, end))
                fp = fingerprint(rule.id, path, secret)
                if fp in self.baseline:
                    self.suppressed += 1
                    continue
                findings.append(Finding(rule.id, rule.description, rule.severity, path, number, start + 1,
                                        redact(secret), fp))
        return findings

    def scan_lines(self, path: str, lines: Iterable[tuple[int, str]]) -> list[Finding]:
        findings: list[Finding] = []
        for number, line in lines:
            findings.extend(self.scan_line(path, number, line))
        return findings

    def scan_file(self, file: Path, display: str) -> list[Finding]:
        """Scan one file's name and content. ``display`` is the repo-relative path shown in output."""
        if self.path_allowed(display):
            return []
        findings = self.check_filename(display)
        try:
            size = file.stat().st_size
            if size > self.max_bytes:
                self.skipped.append(f"{display} (larger than {self.max_bytes // 1_000_000} MB)")
                return findings
            data = file.read_bytes()
        except OSError as exc:
            self.skipped.append(f"{display} ({exc.strerror or exc})")
            return findings
        if b"\x00" in data[:8192]:
            return findings  # binary: only the file-name rules apply
        text = data.decode("utf-8", errors="replace")
        findings.extend(self.scan_lines(display, enumerate(text.splitlines(), start=1)))
        return findings


def iter_files(root: Path) -> Iterable[Path]:
    """Files under ``root`` (or ``root`` itself), skipping vendored and tool directories."""
    if root.is_file():
        yield root
        return
    for path in sorted(root.rglob("*")):
        if any(part in SKIP_DIRS for part in path.relative_to(root).parts[:-1]):
            continue
        if path.is_file() and not path.is_symlink():
            yield path
