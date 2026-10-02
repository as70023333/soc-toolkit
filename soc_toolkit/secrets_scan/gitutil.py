"""Git helpers: staged additions, tracked files, hook installation."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


class GitError(RuntimeError):
    pass


def git(*args: str, cwd: Path | None = None) -> bytes:
    try:
        proc = subprocess.run(["git", *args], cwd=cwd, capture_output=True, check=False)
    except FileNotFoundError as exc:
        raise GitError("git is not installed or not on PATH") from exc
    if proc.returncode != 0:
        message = proc.stderr.decode("utf-8", errors="replace").strip().splitlines()
        raise GitError(message[0] if message else f"git {' '.join(args)} failed")
    return proc.stdout


def repo_root(cwd: Path | None = None) -> Path | None:
    try:
        return Path(git("rev-parse", "--show-toplevel", cwd=cwd).decode("utf-8").strip())
    except GitError:
        return None


def _unquote(path: str) -> str:
    """Undo git's C-style quoting of unusual paths ("caf\\303\\251.txt")."""
    if len(path) >= 2 and path[0] == '"' and path[-1] == '"':
        raw = path[1:-1].encode("latin-1", errors="backslashreplace").decode("unicode_escape")
        return raw.encode("latin-1", errors="replace").decode("utf-8", errors="replace")
    return path


def parse_diff(text: str) -> dict[str, list[tuple[int, str]]]:
    """Map each file in a unified diff (-U0) to its added lines: path -> [(line number, text)]."""
    files: dict[str, list[tuple[int, str]]] = {}
    current: str | None = None
    in_hunk = False
    new_line = 0
    for line in text.split("\n"):
        if line.startswith("diff --git "):
            current, in_hunk = None, False
            continue
        if not in_hunk:
            if line.startswith("+++ "):
                target = _unquote(line[4:].rstrip("\t"))
                if target == "/dev/null":
                    current = None
                else:
                    current = target[2:] if target.startswith("b/") else target
                    files.setdefault(current, [])
            elif line.startswith("@@"):
                match = _HUNK.match(line)
                if match:
                    new_line, in_hunk = int(match.group(1)), True
            continue
        if line.startswith("@@"):
            match = _HUNK.match(line)
            if match:
                new_line = int(match.group(1))
            continue
        if line.startswith("+"):
            if current is not None:
                files[current].append((new_line, line[1:].rstrip("\r")))
            new_line += 1
        elif line.startswith(" "):
            new_line += 1
    return files


def staged_additions(cwd: Path | None = None) -> dict[str, list[tuple[int, str]]]:
    diff = git("-c", "core.quotePath=false", "diff", "--cached", "--no-color", "--no-ext-diff", "--unified=0",
               "--diff-filter=ACMR", "--src-prefix=a/", "--dst-prefix=b/", cwd=cwd)
    return parse_diff(diff.decode("utf-8", errors="replace"))


def staged_files(cwd: Path | None = None) -> list[str]:
    out = git("diff", "--cached", "--name-only", "-z", "--diff-filter=ACMR", cwd=cwd)
    return [p for p in out.decode("utf-8", errors="replace").split("\0") if p]


def tracked_files(cwd: Path | None = None) -> list[str]:
    out = git("ls-files", "-z", cwd=cwd)
    return [p for p in out.decode("utf-8", errors="replace").split("\0") if p]


HOOK_MARKER = "# installed by soc-toolkit secrets-scan"


def install_hook(python: str, cwd: Path | None = None, force: bool = False) -> Path:
    hooks = Path(git("rev-parse", "--git-path", "hooks", cwd=cwd).decode("utf-8").strip())
    if not hooks.is_absolute():
        hooks = (cwd or Path.cwd()) / hooks
    hooks.mkdir(parents=True, exist_ok=True)
    hook = hooks / "pre-commit"
    if hook.exists() and HOOK_MARKER not in hook.read_text(encoding="utf-8", errors="replace") and not force:
        raise GitError(f"{hook} already exists and was not written by secrets-scan; use --force to replace it "
                       "or add 'secrets-scan --staged' to it yourself")
    interpreter = python.replace("\\", "/")
    hook.write_text("#!/bin/sh\n"
                    f"{HOOK_MARKER}\n"
                    "# Blocks commits that add secrets. To skip once (think twice): git commit --no-verify\n"
                    f'exec "{interpreter}" -m soc_toolkit.secrets_scan --staged\n', encoding="utf-8")
    hook.chmod(0o755)
    return hook
