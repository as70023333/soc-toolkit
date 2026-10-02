"""Rule model and loading (built-in rules + an organization's .secrets-scan.toml)."""

from __future__ import annotations

import fnmatch
import re
import tomllib
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any

from soc_toolkit.common.findings import SEVERITIES

RULE_KEYS = {"id", "description", "regex", "severity", "secret_group", "keywords", "require_any", "entropy",
             "paths", "placeholder_check", "examples", "not_examples"}
FILE_RULE_KEYS = {"id", "description", "globs", "not_globs", "severity"}
CONFIG_KEYS = {"rule", "file_rule", "disable", "allowlist", "use_default_rules"}
ALLOWLIST_KEYS = {"paths", "regexes", "stopwords"}

# Directories never worth scanning.
SKIP_DIRS = frozenset({".git", "node_modules", ".venv", "venv", "env", "__pycache__", ".tox", ".mypy_cache",
                       ".pytest_cache", ".ruff_cache", "dist", "build", ".terraform", ".idea", ".vscode"})


class RuleError(ValueError):
    """A rules file is invalid."""


@dataclass
class Rule:
    id: str
    description: str
    regex: re.Pattern[str]
    severity: str = "high"
    secret_group: int | None = None
    keywords: tuple[str, ...] = ()
    require_any: tuple[str, ...] = ()
    entropy: float = 0.0
    paths: tuple[str, ...] = ()
    placeholder_check: bool = True
    examples: tuple[str, ...] = ()
    not_examples: tuple[str, ...] = ()
    source: str = "built-in"

    def group(self) -> int:
        if self.secret_group is not None:
            return self.secret_group
        return 1 if self.regex.groups >= 1 else 0


@dataclass
class FileRule:
    id: str
    description: str
    globs: tuple[str, ...]
    not_globs: tuple[str, ...] = ()
    severity: str = "high"
    source: str = "built-in"

    def matches(self, path: str) -> bool:
        return path_matches(path, self.globs) and not path_matches(path, self.not_globs)


@dataclass
class Ruleset:
    rules: list[Rule] = field(default_factory=list)
    file_rules: list[FileRule] = field(default_factory=list)
    allow_paths: list[str] = field(default_factory=list)
    allow_regexes: list[re.Pattern[str]] = field(default_factory=list)
    stopwords: list[str] = field(default_factory=list)


def path_matches(path: str, patterns: tuple[str, ...] | list[str]) -> bool:
    """Glob match on the repo-relative path, or on the file name for patterns without a slash."""
    posix = path.replace("\\", "/")
    name = posix.rsplit("/", 1)[-1]
    for pattern in patterns:
        if "/" in pattern:
            if fnmatch.fnmatchcase(posix, pattern) or fnmatch.fnmatchcase(posix, pattern.replace("**/", "")):
                return True
        elif fnmatch.fnmatchcase(name, pattern):
            return True
    return False


def _strings(value: Any, where: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise RuleError(f"{where} must be a list of strings")
    return tuple(value)


def _severity(value: Any, where: str) -> str:
    if value not in SEVERITIES:
        raise RuleError(f"{where}: severity must be one of {', '.join(SEVERITIES)}")
    return value


def _parse_rule(raw: dict, source: str) -> Rule:
    if not isinstance(raw, dict):
        raise RuleError(f"{source}: each [[rule]] must be a table")
    unknown = set(raw) - RULE_KEYS
    rid = raw.get("id")
    where = f"{source}: rule {rid or '?'}"
    if unknown:
        raise RuleError(f"{where}: unknown field(s) {', '.join(sorted(unknown))}")
    for required in ("id", "description", "regex"):
        if not isinstance(raw.get(required), str) or not raw[required]:
            raise RuleError(f"{where}: '{required}' is required")
    try:
        regex = re.compile(raw["regex"])
    except re.error as exc:
        raise RuleError(f"{where}: invalid regex: {exc}") from exc
    group = raw.get("secret_group")
    if group is not None and (not isinstance(group, int) or group < 0 or group > regex.groups):
        raise RuleError(f"{where}: secret_group must be between 0 and {regex.groups}")
    entropy = raw.get("entropy", 0.0)
    if not isinstance(entropy, (int, float)) or entropy < 0:
        raise RuleError(f"{where}: entropy must be a non-negative number")
    return Rule(
        id=rid, description=raw["description"], regex=regex,
        severity=_severity(raw.get("severity", "high"), where), secret_group=group,
        keywords=tuple(k.lower() for k in _strings(raw.get("keywords"), f"{where}.keywords")),
        require_any=tuple(k.lower() for k in _strings(raw.get("require_any"), f"{where}.require_any")),
        entropy=float(entropy), paths=_strings(raw.get("paths"), f"{where}.paths"),
        placeholder_check=bool(raw.get("placeholder_check", True)),
        examples=_strings(raw.get("examples"), f"{where}.examples"),
        not_examples=_strings(raw.get("not_examples"), f"{where}.not_examples"),
        source=source,
    )


def _parse_file_rule(raw: dict, source: str) -> FileRule:
    if not isinstance(raw, dict):
        raise RuleError(f"{source}: each [[file_rule]] must be a table")
    unknown = set(raw) - FILE_RULE_KEYS
    where = f"{source}: file_rule {raw.get('id') or '?'}"
    if unknown:
        raise RuleError(f"{where}: unknown field(s) {', '.join(sorted(unknown))}")
    if not raw.get("id") or not raw.get("description"):
        raise RuleError(f"{where}: 'id' and 'description' are required")
    globs = _strings(raw.get("globs"), f"{where}.globs")
    if not globs:
        raise RuleError(f"{where}: 'globs' must not be empty")
    return FileRule(raw["id"], raw["description"], globs, _strings(raw.get("not_globs"), f"{where}.not_globs"),
                    _severity(raw.get("severity", "high"), where), source)


def _load_toml(text: str, source: str) -> dict:
    try:
        return tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise RuleError(f"{source}: {exc}") from exc


def load_ruleset(config: Path | None = None, *, use_defaults: bool = True) -> Ruleset:
    """Organization rules run first (most specific), then the built-in rules."""
    builtin_text = resources.files("soc_toolkit.secrets_scan").joinpath("default_rules.toml").read_text(encoding="utf-8")
    builtin = _load_toml(builtin_text, "built-in rules")
    custom: dict = {}
    if config is not None:
        try:
            text = config.read_text(encoding="utf-8")
        except OSError as exc:
            raise RuleError(f"cannot read {config}: {exc}") from exc
        custom = _load_toml(text, str(config))
        unknown = set(custom) - CONFIG_KEYS
        if unknown:
            raise RuleError(f"{config}: unknown key(s) {', '.join(sorted(unknown))}")
        if "use_default_rules" in custom:
            use_defaults = bool(custom["use_default_rules"]) and use_defaults
    source = str(config) if config else ""
    custom_rules = [_parse_rule(r, source) for r in custom.get("rule", [])]
    custom_files = [_parse_file_rule(r, source) for r in custom.get("file_rule", [])]
    disabled = set(_strings(custom.get("disable"), "disable"))
    rules: list[Rule] = list(custom_rules)
    file_rules: list[FileRule] = list(custom_files)
    if use_defaults:
        overridden = {r.id for r in custom_rules} | {r.id for r in custom_files}
        rules += [r for r in (_parse_rule(x, "built-in") for x in builtin.get("rule", []))
                  if r.id not in overridden]
        file_rules += [r for r in (_parse_file_rule(x, "built-in") for x in builtin.get("file_rule", []))
                       if r.id not in overridden]
    known_ids = {r.id for r in rules} | {r.id for r in file_rules}
    unknown_disabled = disabled - known_ids
    if unknown_disabled:
        raise RuleError(f"disable lists unknown rule id(s): {', '.join(sorted(unknown_disabled))}")
    rules = [r for r in rules if r.id not in disabled]
    file_rules = [r for r in file_rules if r.id not in disabled]
    ids = [r.id for r in rules] + [r.id for r in file_rules]
    dupes = sorted({i for i in ids if ids.count(i) > 1})
    if dupes:
        raise RuleError(f"duplicate rule id(s): {', '.join(dupes)}")
    allow = custom.get("allowlist") or {}
    if not isinstance(allow, dict) or set(allow) - ALLOWLIST_KEYS:
        raise RuleError(f"[allowlist] supports only: {', '.join(sorted(ALLOWLIST_KEYS))}")
    try:
        allow_regexes = [re.compile(p) for p in _strings(allow.get("regexes"), "allowlist.regexes")]
    except re.error as exc:
        raise RuleError(f"allowlist.regexes: invalid regex: {exc}") from exc
    return Ruleset(rules, file_rules, list(_strings(allow.get("paths"), "allowlist.paths")), allow_regexes,
                   [s.lower() for s in _strings(allow.get("stopwords"), "allowlist.stopwords")])
