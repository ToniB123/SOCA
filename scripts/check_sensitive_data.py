#!/usr/bin/env python3
"""Block commits that would expose host data or credentials.

Usage:
    python scripts/check_sensitive_data.py --staged
    python scripts/check_sensitive_data.py --tree

``--staged`` scans exactly what the next commit would contain (including file
names that should be ignored). ``--tree`` scans tracked and untracked files that
are not gitignored. The pre-commit hook uses ``--staged``.

The scanner is intentionally conservative about credentials and personal
identifiers, and treats synthetic test fixtures specially:

- documentation IP ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) are
  allowed;
- private IPs in ``test_*.py`` files are allowed (they are fixtures);
- the small set of synthetic private IPs used by the source/tests is allowed;
- runtime artifacts and local-only files are rejected by name.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKIP_DIRS = {".git", ".venv", "__pycache__", ".ruff_cache", ".idea", "archive"}
SKIP_FILES = {
    "scripts/check_sensitive_data.py",
    ".githooks/pre-commit",
    # The scanner's own tests contain synthetic personal paths/names.
    "test_sensitive_scan.py",
}
DOC_PREFIXES = ("192.0.2.", "198.51.100.", "203.0.113.")
SYNTHETIC_PRIVATE_IPS = {
    "10.0.0.0",
    "10.0.0.1",
    "10.0.0.2",
    "10.0.0.5",
}
EMAIL_ALLOW = (
    "@example.com",
    "@example.org",
    "@example.net",
    "@users.noreply.github.com",
)
USER_PATH_ALLOW = {"public", "default", "all users", "default user"}

LOCAL_ONLY_NAMES = (
    "netstat_baseline_rules.yaml",
    "CODE_REVIEW.md",
    "CLAUDE.md",
    "soc_user_allowlist.json",
    "soc_findings.jsonl",
    "soc_traffic_history.jsonl",
    "soc_verdict_cache.json",
    "soc_intel_cache.json",
    "soc_ui_agent_state.json",
    "soc_network_health.json",
    "local_soc_agent.log",
    "netstat_snapshot.log",
)
LOCAL_ONLY_SUFFIXES = (
    ".log",
    ".jsonl",
    ".tmp",
    ".bak",
    ".orig",
    ".rej",
    ".swp",
    ".pem",
    ".key",
    ".crt",
    ".p12",
    ".sqlite",
    ".db",
)
LOCAL_ONLY_PREFIXES = ("secrets", "credentials", ".env")

PRIVATE_KEY_RE = re.compile(r"BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY")
TOKEN_RES = (
    re.compile(r"\bghp_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bgho_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
)
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
MACHINE_RE = re.compile(r"\b(?:DESKTOP|LAPTOP)-[A-Z0-9]{6,}\b", re.IGNORECASE)
USERNAME_RE = re.compile(r"\boperator\b", re.IGNORECASE)
USER_PATH_RE = re.compile(r"[A-Za-z]:[\\/]Users[\\/]([^\\/\s\"']+)", re.IGNORECASE)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    kind: str
    detail: str


def _is_local_only(path: str) -> bool:
    name = Path(path).name
    return (
        name in LOCAL_ONLY_NAMES
        or name.endswith(LOCAL_ONLY_SUFFIXES)
        or name.startswith(LOCAL_ONLY_PREFIXES)
    )


def _mask(value: str) -> str:
    if len(value) <= 8:
        return "[redacted]"
    return value[:4] + "…[redacted]"


def _is_private_ip(value: str) -> bool:
    parts = value.split(".")
    if len(parts) != 4:
        return False
    try:
        octets = [int(part) for part in parts]
    except ValueError:
        return False
    if not all(0 <= octet <= 255 for octet in octets):
        return False
    if octets[0] == 10:
        return True
    if octets[0] == 172 and 16 <= octets[1] <= 31:
        return True
    return octets[0] == 192 and octets[1] == 168


def scan_text(path: str, text: str) -> list[Finding]:
    findings: list[Finding] = []
    is_test = Path(path).name.startswith("test_") and path.endswith(".py")

    def add(line: int, kind: str, detail: str) -> None:
        findings.append(Finding(path, line, kind, detail))

    for number, line in enumerate(text.splitlines(), 1):
        if PRIVATE_KEY_RE.search(line):
            add(number, "private-key", "[redacted]")
        for pattern in TOKEN_RES:
            match = pattern.search(line)
            if match:
                add(number, "token", _mask(match.group(0)))
        for match in EMAIL_RE.finditer(line):
            email = match.group(0)
            if not email.lower().endswith(EMAIL_ALLOW):
                add(number, "email", email)
        match = MACHINE_RE.search(line)
        if match:
            add(number, "machine-name", match.group(0))
        match = USERNAME_RE.search(line)
        if match:
            add(number, "personal-username", match.group(0))
        match = USER_PATH_RE.search(line)
        if match and match.group(1).strip().lower() not in USER_PATH_ALLOW:
            add(number, "personal-path", match.group(0))
        if not is_test:
            for match in IP_RE.finditer(line):
                ip = match.group(0)
                if ip.startswith(DOC_PREFIXES):
                    continue
                if ip in SYNTHETIC_PRIVATE_IPS:
                    continue
                if ip in {"127.0.0.1", "0.0.0.0", "255.255.255.255"}:
                    continue
                if _is_private_ip(ip):
                    add(number, "private-ip", ip)
    return findings


def _staged_paths() -> list[str]:
    result = subprocess.run(
        ["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        print(f"sensitive-scan: git failed: {result.stderr.strip()}", file=sys.stderr)
        return []
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def _tree_paths() -> list[str]:
    result = subprocess.run(
        ["git", "ls-files", "-co", "--exclude-standard"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode == 0:
        return [line.strip() for line in result.stdout.splitlines() if line.strip()]
    paths: list[str] = []
    for path in ROOT.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(ROOT).as_posix()
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        paths.append(rel)
    return paths


def _staged_text(path: str) -> str | None:
    result = subprocess.run(
        ["git", "show", f":{path}"],
        cwd=ROOT,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        return None
    try:
        return result.stdout.decode("utf-8")
    except UnicodeDecodeError:
        return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--staged",
        action="store_true",
        help="scan the exact content staged for the next commit",
    )
    group.add_argument(
        "--tree",
        action="store_true",
        help="scan tracked/untracked files that are not gitignored",
    )
    args = parser.parse_args(argv)

    paths = _staged_paths() if args.staged else _tree_paths()
    findings: list[Finding] = []
    for path in paths:
        if path in SKIP_FILES:
            continue
        if args.staged and _is_local_only(path):
            findings.append(
                Finding(path, 0, "local-only-file", "this file must not be committed")
            )
            continue
        if not args.staged and _is_local_only(path):
            # Expected local-only files; --tree checks what could be committed.
            continue
        if args.staged:
            text = _staged_text(path)
            if text is None:
                continue
        else:
            try:
                text = (ROOT / path).read_text(encoding="utf-8")
            except OSError, UnicodeDecodeError:
                continue
        findings.extend(scan_text(path, text))

    if not findings:
        print(f"sensitive-scan: clean ({len(paths)} file(s) checked)")
        return 0

    print(f"sensitive-scan: {len(findings)} finding(s) blocked:", file=sys.stderr)
    for finding in findings:
        where = f"{finding.path}:{finding.line}" if finding.line else finding.path
        print(f"  {where}: {finding.kind}: {finding.detail}", file=sys.stderr)
    print(
        "\nRemove or sanitize these before committing. For a local-only file, "
        "leave it gitignored and do not use `git add -f`.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
