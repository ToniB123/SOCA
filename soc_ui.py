"""SOC Agent web dashboard.

Runs checkstat.py as a subprocess (checkstat.py itself is never modified) and
serves a localhost page that streams its console output, tails
soc_traffic_history.jsonl and soc_findings.jsonl, charts live traffic
metrics, and exposes the CLI flags as form controls.

Local-only by design: binds 127.0.0.1, no external scripts, works air-gapped.

Usage:
    .venv\\Scripts\\python.exe soc_ui.py [--port 8765] [--no-browser]
"""

from __future__ import annotations

import argparse
import contextlib
import ctypes
import http.client
import json
import math
import os
import re
import secrets
import shlex
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import webbrowser
from collections import deque
from ctypes import wintypes
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml
from flask import Flask, jsonify, request, send_from_directory

import finding_chat
import install_security
import network_health
import user_allowlist

SCRIPT_DIR = Path(__file__).resolve().parent
CHECKSTAT_PATH = SCRIPT_DIR / "checkstat.py"
STATIC_DIR = SCRIPT_DIR / "static"
RULES_DEFAULT = SCRIPT_DIR / "netstat_baseline_rules.yaml"
STATE_FILE = SCRIPT_DIR / "soc_ui_agent_state.json"
NETWORK_HEALTH_FILE = SCRIPT_DIR / network_health.RESULT_FILE
NETWORK_HEALTH_MAX_BYTES = 64 * 1024

CONSOLE_CAP = 5000
CONSOLE_LINE_MAX = 8000
CONSOLE_API_DEFAULT_LINES = 200
CONSOLE_API_MAX_LINES = 500
CONSOLE_RESPONSE_MAX_BYTES = 256 * 1024
MAX_CONTENT_LENGTH = 64 * 1024
FILE_TAILER_PENDING_MAX = 1024 * 1024
FILE_TAILER_LINE_MAX = 256 * 1024
API_RESPONSE_MAX_BYTES = 512 * 1024
TRAFFIC_ROWS_MAX = 720  # mirrors traffic_detection.max_history_samples
FINDINGS_MAX = 1000
STATUS_REFRESH_SECONDS = 15.0
OLLAMA_TIMEOUT = 2.5
PS_PROBE_TIMEOUT = 6.0
DEFAULT_PORT = 8765
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})
OLLAMA_RESPONSE_MAX_BYTES = 512 * 1024
OLLAMA_URL_MAX_LENGTH = 2048

ON_WINDOWS = os.name == "nt"
CREATE_NEW_PG = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
CTRL_BREAK_KILL_CODE = 3221225786  # 0xC000013A STATUS_CONTROL_C_EXIT

STATE_STOPPED, STATE_STARTING, STATE_RUNNING, STATE_STOPPING = (
    "STOPPED",
    "STARTING",
    "RUNNING",
    "STOPPING",
)

PID_CREATION_TOLERANCE_SECONDS = 5.0
ORPHAN_POLL_SECONDS = 2.0


def _system32_tool(relative: str | Path) -> str:
    """Absolute System32 path for a Windows tool; bare name off-Windows."""
    if not ON_WINDOWS:
        return Path(relative).name
    root = os.environ.get("SYSTEMROOT") or os.environ.get("WINDIR") or r"C:\Windows"
    return str(Path(root) / "System32" / Path(relative))


POWERSHELL_EXE = _system32_tool(Path("WindowsPowerShell") / "v1.0" / "powershell.exe")
TASKKILL_EXE = _system32_tool("taskkill.exe")

FILE_INFO_NAMES = (
    "local_soc_agent.log",
    "netstat_snapshot.log",
    "soc_findings.jsonl",
    "soc_traffic_history.jsonl",
    "soc_verdict_cache.json",
    "soc_intel_cache.json",
    "soc_user_allowlist.json",
)


class DefaultsError(Exception):
    """Raised when netstat_baseline_rules.yaml cannot be read or parsed."""


# ---------------------------------------------------------------------------
# Windows process helpers (ctypes; os.kill(pid, 0) terminates on Windows)
# ---------------------------------------------------------------------------

if ON_WINDOWS:
    _k32 = ctypes.windll.kernel32
    _PROC_QUERY_LIMITED = 0x1000
    _SYNCHRONIZE = 0x00100000
    _PROCESS_TERMINATE = 0x0001
    _WAIT_TIMEOUT = 0x00000102
    _FT_OFFSET = 11644473600.0  # seconds between 1601-01-01 and 1970-01-01

    # 64-bit handles must not be truncated to the ctypes default c_int.
    _k32.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    _k32.OpenProcess.restype = wintypes.HANDLE
    _k32.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)
    _k32.WaitForSingleObject.restype = wintypes.DWORD
    _k32.CloseHandle.argtypes = (wintypes.HANDLE,)
    _k32.CloseHandle.restype = wintypes.BOOL
    _k32.TerminateProcess.argtypes = (wintypes.HANDLE, wintypes.DWORD)
    _k32.TerminateProcess.restype = wintypes.BOOL

    def process_exists(pid: int) -> bool:
        handle = _k32.OpenProcess(_SYNCHRONIZE | _PROC_QUERY_LIMITED, False, pid)
        if not handle:
            return False
        try:
            return _k32.WaitForSingleObject(handle, 0) == _WAIT_TIMEOUT
        finally:
            _k32.CloseHandle(handle)

    def process_creation_time(pid: int) -> float | None:
        """Unix time of process creation, or None if unknown."""

        class _FT(ctypes.Structure):
            _fields_ = [("lo", ctypes.c_uint32), ("hi", ctypes.c_uint32)]

        handle = _k32.OpenProcess(_PROC_QUERY_LIMITED, False, pid)
        if not handle:
            return None
        try:
            creation, exit_t, kernel, user = _FT(), _FT(), _FT(), _FT()
            if not _k32.GetProcessTimes(
                handle,
                ctypes.byref(creation),
                ctypes.byref(exit_t),
                ctypes.byref(kernel),
                ctypes.byref(user),
            ):
                return None
            return (((creation.hi << 32) | creation.lo) / 10_000_000.0) - _FT_OFFSET
        finally:
            _k32.CloseHandle(handle)

    def terminate_pid(pid: int, exit_code: int = 1, wait_ms: int = 3000) -> bool:
        handle = _k32.OpenProcess(
            _PROCESS_TERMINATE | _SYNCHRONIZE | _PROC_QUERY_LIMITED, False, pid
        )
        if not handle:
            return False
        try:
            if not _k32.TerminateProcess(handle, exit_code):
                return False
            _k32.WaitForSingleObject(handle, wait_ms)
            return True
        finally:
            _k32.CloseHandle(handle)
else:

    def process_exists(pid: int) -> bool:  # pragma: no cover - non-Windows
        try:
            os.kill(pid, 0)
        except OSError:
            return False
        return True

    def process_creation_time(pid: int) -> float | None:  # pragma: no cover
        return None

    def terminate_pid(pid: int, exit_code: int = 1, wait_ms: int = 3000) -> bool:
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError:
            return False
        return True


def human_size(n: int | float | None) -> str:
    if n is None:
        return ""
    n = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{int(n)} B"
        n /= 1024
    return f"{n:.1f} GB"


# ---------------------------------------------------------------------------
# External-instance probe (detect checkstat.py already running elsewhere)
# ---------------------------------------------------------------------------

# /api/start probes on every request while the agent is stopped and each
# probe spawns PowerShell; serialize them so parallel requests cannot start
# parallel PowerShell/WMI processes.
_EXTERNAL_PROBE_LOCK = threading.Lock()


def external_checkstat_processes(exclude_pids: tuple[int, ...] = ()) -> dict:
    """Find other local processes running checkstat.py.

    Returns {"checked": bool, "processes": [{"pid": int, "cmdline": str}]}.
    checked=False means the probe itself failed (degrade quietly).
    """
    if not ON_WINDOWS:
        return {"checked": False, "processes": []}
    excluded = set(exclude_pids) | {os.getpid()}
    ps = (
        "$ErrorActionPreference='SilentlyContinue';"
        "Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -match 'checkstat\\.py' }"
        " | Select-Object ProcessId, Name, CommandLine | ConvertTo-Json -Compress"
    )
    try:
        with _EXTERNAL_PROBE_LOCK:
            result = subprocess.run(
                [POWERSHELL_EXE, "-NoProfile", "-NonInteractive", "-Command", ps],
                capture_output=True,
                text=True,
                timeout=PS_PROBE_TIMEOUT,
                check=False,
            )
    except OSError, subprocess.SubprocessError:
        return {"checked": False, "processes": []}
    out = (result.stdout or "").strip()
    if not out:
        return {"checked": True, "processes": []}
    try:
        data = json.loads(out)
    except ValueError:
        return {"checked": False, "processes": []}
    rows = data if isinstance(data, list) else [data]
    # the agent runs under a Python interpreter; Name-filtering also drops
    # the probe's own powershell child and shell wrappers that merely carry
    # the text "checkstat.py" in an embedded script
    interpreter_names = {"python.exe", "pythonw.exe", "py.exe"}
    found = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        pid = row.get("ProcessId")
        name = (row.get("Name") or "").lower()
        cmdline = row.get("CommandLine") or ""
        if (
            isinstance(pid, int)
            and pid not in excluded
            and name in interpreter_names
            and "soc_ui.py" not in cmdline
        ):
            found.append({"pid": pid, "cmdline": cmdline[:300]})
    return {"checked": True, "processes": found}


def external_process_pids(processes: list[dict]) -> list[dict]:
    """PID-only view of WMI probe rows.

    Command lines can reveal install paths and arguments, so they stay
    server-side; callers that surface external processes to the browser
    (the 412 pre-start guard and /api/status) use this projection.
    """
    pids = []
    for row in processes:
        if not isinstance(row, dict):
            continue
        pid = row.get("pid")
        if isinstance(pid, int) and not isinstance(pid, bool):
            pids.append({"pid": pid})
    return pids


def _process_principal_matches(pid: int) -> bool:
    """Fail-closed check that ``pid`` is our interpreter, user, and session.

    The adoption probe already verifies creation time and the absolute
    ``checkstat.py`` command line. A decoy can reproduce both, so also bind
    the decision to the executable image (the venv interpreter this dashboard
    would spawn), the process owner SID, and the terminal session. Any
    unavailable probe rejects the candidate.
    """
    try:
        image = install_security.process_image_path(pid)
        if not install_security.image_matches_current_interpreter(image):
            return False
        owner = install_security.process_owner_sid(pid)
        current_user = install_security.current_user_sid()
        if not owner or not current_user or owner != current_user:
            return False
        session = install_security.process_session_id(pid)
        current_session = install_security.current_session_id()
        if session is None or current_session is None:
            return False
        return session == current_session
    except Exception:
        # Any probe failure is inconclusive; adoption and Stop must deny.
        return False


def _pid_is_checkstat(pid: int) -> bool:
    """Confirm through the WMI probe that `pid` runs this agent.

    Fails closed: an inconclusive probe (checked=False) is treated as a
    non-match so a recycled or unrelated PID is never adopted or killed.
    The command line must contain the absolute CHECKSTAT_PATH, not merely
    the basename, so a decoy `python checkstat.py` in an attacker-controlled
    directory does not qualify.
    """
    probe = external_checkstat_processes()
    if not probe.get("checked"):
        return False
    expected = str(CHECKSTAT_PATH).lower()
    for row in probe.get("processes", []):
        if row.get("pid") != pid:
            continue
        cmdline = str(row.get("cmdline") or "").lower()
        if expected in cmdline:
            return True
    return False


# ---------------------------------------------------------------------------
# Path hygiene for --file / --rules values coming from the browser
# ---------------------------------------------------------------------------


def resolve_agent_path(raw: str) -> tuple[Path | None, str | None]:
    """Resolve to an existing real file inside the project tree.

    Both sides are canonicalized with ``Path.resolve(strict=True)`` so a
    symlink or NTFS junction inside the project cannot point the agent at a
    file outside it, and containment is a path-component check rather than
    a textual ``commonpath`` comparison.
    """
    if not raw or not raw.strip():
        return None, "path is empty"
    try:
        candidate = Path(raw.strip())
        if not candidate.is_absolute():
            candidate = SCRIPT_DIR / candidate
        root = SCRIPT_DIR.resolve()
        resolved = candidate.resolve(strict=True)
    except OSError, RuntimeError, ValueError:
        return None, f"file not found: {raw.strip()}"
    if not resolved.is_relative_to(root):
        return None, "path is outside the project directory"
    if not resolved.is_file():
        return None, f"file not found: {resolved}"
    return resolved, None


def validate_rules_document(path: Path) -> str | None:
    """Return an error unless path has at least one enabled anomaly rule."""
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError, UnicodeDecodeError, yaml.YAMLError:
        # Do not echo PyYAML's parser text to the browser: it can include a
        # snippet of the local rules file.
        return "rules file could not be parsed as YAML"
    if not isinstance(doc, dict):
        return "rules file is not a mapping"
    categories = doc.get("anomaly_rules")
    if not isinstance(categories, dict):
        return "rules file has no anomaly_rules mapping"
    enabled = 0
    for category in ("high_severity", "medium_severity", "low_severity"):
        rules = categories.get(category)
        if rules is None:
            continue
        if not isinstance(rules, list):
            return f"anomaly_rules.{category} must be a list"
        for rule in rules:
            if not isinstance(rule, dict):
                return f"anomaly_rules.{category} contains a non-mapping rule"
            if rule.get("enabled", True):
                enabled += 1
    if not enabled:
        return "rules file has no enabled anomaly rules"
    return None


# ---------------------------------------------------------------------------
# YAML defaults (mtime-cached so YAML edits are picked up without restart)
# ---------------------------------------------------------------------------

_DEFAULTS_CACHE: dict = {"mtime": None, "data": None}

_D = {  # checkstat.py build_options fallbacks
    "model": "llama3.1:8b",
    "escalation_model": "qwen3.8:27b",
    "ollama_url": "http://localhost:11434/api/generate",
    "scan_interval_seconds": 300,
    "ai_timeout_seconds": 120.0,
    "max_ai_checks_per_run": 8,
    "max_escalations_per_run": 2,
    "num_ctx": 4096,
    "keep_alive": "30m",
    "cache_hours": 24,
    "escalation_timeout_seconds": 180.0,
    "think": False,
}
_YAML_ONLY_DEFAULTS = {
    "escalation_num_ctx": 4096,
    "escalation_think": False,
    "escalation_severities": ["HIGH", "CRITICAL"],
    "escalation_keep_alive": "30m",
    "alert_cooldown_minutes": 60,
    "traffic_alert_min_occurrences": 2,
    "traffic_alert_window_minutes": 30,
}
_TRAFFIC_DEFAULTS = {
    "enabled": True,
    "sample_interval_seconds": 10,
    "window_seconds": 300,
    "max_history_samples": 720,
    "thresholds": {},
}


def load_yaml_defaults(rules_path: Path = RULES_DEFAULT, force: bool = False) -> dict:
    try:
        mtime = rules_path.stat().st_mtime
    except OSError as exc:
        raise DefaultsError(
            f"rules file unreadable: {exc}; copy "
            "netstat_baseline_rules.example.yaml to netstat_baseline_rules.yaml "
            "and tune it for this host"
        ) from exc
    if not force and _DEFAULTS_CACHE["mtime"] == mtime and _DEFAULTS_CACHE["data"]:
        return dict(_DEFAULTS_CACHE["data"])
    try:
        doc = yaml.safe_load(rules_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
        raise DefaultsError(f"rules file unparseable: {exc}") from exc
    if not isinstance(doc, dict):
        raise DefaultsError("rules file is not a mapping")
    agent = doc.get("agent") if isinstance(doc.get("agent"), dict) else {}
    td = (
        doc.get("traffic_detection")
        if isinstance(doc.get("traffic_detection"), dict)
        else {}
    )
    enrich = (
        agent.get("enrichment") if isinstance(agent.get("enrichment"), dict) else {}
    )

    data = dict(_D)
    for key in data:
        if key == "think":
            data[key] = bool(agent.get("think", _D["think"]))
        elif key in agent:
            data[key] = agent[key]
    yaml_only = dict(_YAML_ONLY_DEFAULTS)
    for key in yaml_only:
        if key in agent:
            yaml_only[key] = agent[key]
    traffic = dict(_TRAFFIC_DEFAULTS)
    for key in traffic:
        if key in td:
            traffic[key] = td[key]
    raw_network = (
        doc.get("network_health") if isinstance(doc.get("network_health"), dict) else {}
    )
    network = network_health.default_options()
    for key in network:
        if key in raw_network:
            network[key] = raw_network[key]
    result = {
        "agent": data,
        "yaml_only": yaml_only,
        "traffic": traffic,
        "network_health": network,
        "enrichment": {
            k: enrich[k]
            for k in (
                "whois_enabled",
                "reverse_dns_enabled",
                "process_signature_enabled",
            )
            if k in enrich
        },
    }
    _DEFAULTS_CACHE["mtime"] = mtime
    _DEFAULTS_CACHE["data"] = result
    return dict(result)


# ---------------------------------------------------------------------------
# Flag allowlist: browser JSON -> validated argv for checkstat.py
# ---------------------------------------------------------------------------

KEEP_ALIVE_RE = r"^\d+(\.\d+)?(ms|s|m|h)?$"
MODEL_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}")


def _model_name_error(value: str) -> str | None:
    if MODEL_NAME_RE.fullmatch(value):
        return None
    return (
        "model name must start with a letter or digit and be 1-128 "
        "characters from A-Z a-z 0-9 . _ : / -"
    )


def _is_int(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _is_num(v) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


FLAG_SPEC: dict[str, dict] = {
    # key: flag, kind: value|flag|path, and a validate(value) -> str|None
    "replay_path": {
        "flag": "--file",
        "kind": "path",
        "suffixes": (".log", ".txt"),
        "help": "replay a snapshot log (one-shot)",
    },
    "interval": {
        "flag": "--interval",
        "kind": "value",
        "validate": lambda v: (
            None if _is_int(v) and 15 <= v <= 86400 else "integer 15-86400 seconds"
        ),
    },
    "rules_path": {"flag": "--rules", "kind": "path", "suffixes": (".yaml", ".yml")},
    "model": {"flag": "--model", "kind": "str", "validate": _model_name_error},
    "escalation_model": {
        "flag": "--escalation-model",
        "kind": "str",
        "validate": _model_name_error,
    },
    "no_escalation": {"flag": "--no-escalation", "kind": "flag"},
    "max_escalations": {
        "flag": "--max-escalations",
        "kind": "value",
        "validate": lambda v: None if _is_int(v) and 0 <= v <= 64 else "integer 0-64",
    },
    "escalation_timeout": {
        "flag": "--escalation-timeout",
        "kind": "value",
        "validate": lambda v: (
            None if _is_num(v) and 0 < v <= 3600 else "seconds in (0, 3600]"
        ),
    },
    "ollama_url": {"flag": "--ollama-url", "kind": "url"},
    "ai_timeout": {
        "flag": "--ai-timeout",
        "kind": "value",
        "validate": lambda v: (
            None if _is_num(v) and 0 < v <= 3600 else "seconds in (0, 3600]"
        ),
    },
    "max_ai_checks": {
        "flag": "--max-ai-checks",
        "kind": "value",
        "validate": lambda v: (
            None if _is_int(v) and 0 <= v <= 1000 else "integer 0-1000"
        ),
    },
    "num_ctx": {
        "flag": "--num-ctx",
        "kind": "value",
        "validate": lambda v: (
            None if _is_int(v) and 512 <= v <= 131072 else "integer 512-131072"
        ),
    },
    "keep_alive": {
        "flag": "--keep-alive",
        "kind": "str",
        "validate": lambda v: (
            None
            if isinstance(v, str) and _re_ok(KEEP_ALIVE_RE, v.strip())
            else "duration like 30m, 90s, 1.5h"
        ),
    },
    "think": {"flag": "--think", "kind": "flag_true"},  # quirk: CLI can't force off
    "cache_hours": {
        "flag": "--cache-hours",
        "kind": "value",
        "validate": lambda v: None if _is_num(v) and 0 <= v <= 8760 else "hours 0-8760",
    },
    "no_cache": {"flag": "--no-cache", "kind": "flag"},
    "no_ai": {"flag": "--no-ai", "kind": "flag"},
    "no_traffic": {"flag": "--no-traffic", "kind": "flag"},
    "no_whois": {"flag": "--no-whois", "kind": "flag"},
    "no_rdns": {"flag": "--no-rdns", "kind": "flag"},
    "no_process_details": {"flag": "--no-process-details", "kind": "flag"},
    "no_toast": {"flag": "--no-toast", "kind": "flag"},
    "include_private_remotes": {"flag": "--include-private-remotes", "kind": "flag"},
    "verbose": {"flag": "--verbose", "kind": "flag"},
}

BOOL_KEYS = frozenset(k for k, s in FLAG_SPEC.items() if s["kind"].startswith("flag"))
META_KEYS = frozenset({"force"})


def _re_ok(pattern: str, value: str) -> bool:
    return re.match(pattern, value) is not None


def _validate_ollama_url(
    raw: str, allow_remote: bool = False
) -> tuple[str | None, str | None]:
    """Validate an Ollama endpoint URL; return (url, error).

    Only http/https is accepted, without userinfo, query, fragment or
    unbracketed IPv6. The host must be loopback unless allow_remote is set:
    an unrestricted endpoint would let the dashboard POST to metadata and
    internal services (SSRF), so remote hosts need an explicit CLI opt-in.
    """
    text = str(raw).strip()
    if not text:
        return None, "URL is empty"
    if len(text) > OLLAMA_URL_MAX_LENGTH:
        return None, f"URL is longer than {OLLAMA_URL_MAX_LENGTH} characters"
    if chr(92) in text or any(  # backslashes confuse URL parsers
        ch.isspace() or ord(ch) < 0x20 or 0x7F <= ord(ch) <= 0x9F for ch in text
    ):
        return None, "URL contains whitespace, backslashes or control characters"
    # urlsplit() reports an empty query/fragment as "" for a trailing ? or #,
    # so check the raw text rather than the parsed components.
    if "?" in text or "#" in text:
        return None, "URL must not contain a query or fragment"
    try:
        parsed = urllib.parse.urlsplit(text)
        port = parsed.port  # raises ValueError for a malformed port
    except ValueError:
        return None, "URL is malformed or has an invalid port"
    if parsed.scheme.lower() not in ("http", "https"):
        return None, "URL must use http or https"
    if not parsed.netloc or not parsed.hostname:
        return None, "URL has no host"
    if parsed.username is not None or parsed.password is not None:
        return None, "URL must not contain userinfo"
    if parsed.netloc.endswith(":"):
        return None, "URL has an empty port"
    if parsed.fragment or parsed.query:
        return None, "URL must not contain a query or fragment"
    if port is not None and not 1 <= port <= 65535:
        return None, "URL port must be 1-65535"
    host = parsed.hostname.lower()
    if ":" in host and not parsed.netloc.startswith("["):
        return None, "IPv6 addresses must be bracketed"
    if host not in LOOPBACK_HOSTS and not allow_remote:
        return None, (
            "only loopback Ollama hosts (127.0.0.1, localhost, ::1) "
            "are allowed; use --allow-remote-ollama to permit a "
            "remote host"
        )
    return text, None


def validate_payload(
    payload: dict, allow_remote_ollama: bool = False
) -> tuple[dict, str, list[dict]]:
    """Return (flags, mode, errors). flags maps key -> cleaned value.

    allow_remote_ollama gates non-loopback Ollama URLs; it is set from the
    --allow-remote-ollama CLI flag through app.config.
    """
    errors: list[dict] = []
    flags: dict = {}

    if not isinstance(payload, dict):
        return {}, "continuous", [{"key": None, "msg": "body must be a JSON object"}]

    unknown = sorted(set(payload) - set(FLAG_SPEC) - META_KEYS)
    if unknown:
        errors.append(
            {"key": unknown[0], "msg": f"unknown key(s): {', '.join(unknown)}"}
        )

    if "force" in payload and not isinstance(payload["force"], bool):
        errors.append({"key": "force", "msg": "must be true or false (JSON boolean)"})

    for key, spec in FLAG_SPEC.items():
        if key not in payload:
            continue
        value = payload[key]
        kind = spec["kind"]

        if (
            (
                kind.startswith("flag")
                or kind == "path"
                or kind == "str"
                or kind == "url"
            )
            and key in BOOL_KEYS
            and not isinstance(value, bool)
        ):
            errors.append({"key": key, "msg": "must be true or false (JSON boolean)"})
            continue
        if kind == "path":
            if key == "replay_path" and not value:
                continue  # empty string = not replaying
            resolved, err = resolve_agent_path(str(value))
            if err:
                errors.append({"key": key, "msg": err})
                continue
            allowed = spec.get("suffixes")
            if allowed and resolved.suffix.lower() not in allowed:
                errors.append(
                    {
                        "key": key,
                        "msg": f"extension must be one of: {', '.join(allowed)}",
                    }
                )
                continue
            if key == "rules_path":
                err = validate_rules_document(resolved)
                if err:
                    errors.append({"key": key, "msg": err})
                    continue
            flags[key] = str(resolved)
        elif kind == "str":
            text = str(value).strip()
            if text:
                validator = spec.get("validate")
                err = validator(text) if validator else None
                if err:
                    errors.append({"key": key, "msg": err})
                else:
                    flags[key] = text
            # empty string -> omit, YAML/CLI default applies
        elif kind == "url":
            text = str(value).strip()
            if text:
                url, err = _validate_ollama_url(text, allow_remote=allow_remote_ollama)
                if err:
                    errors.append({"key": key, "msg": err})
                else:
                    flags[key] = url
        elif kind == "value":
            validator = spec.get("validate")
            err = validator(value) if validator else None
            if err:
                errors.append({"key": key, "msg": err})
            else:
                flags[key] = value
        elif (kind == "flag" and value is True) or (
            kind == "flag_true" and value is True
        ):
            flags[key] = True
        # flag False/absent -> omit (e.g. --think cannot be forced off via CLI)

    mode = "replay" if flags.get("replay_path") else "continuous"
    if mode == "replay":
        flags.pop("interval", None)  # checkstat ignores it in replay anyway
    return flags, mode, errors


def build_argv(flags: dict, mode: str, child_command: str | None = None) -> list[str]:
    """Build the checkstat.py argv.

    child_command is an explicit test/embedding hook, never read from the
    environment, so an inherited variable cannot redirect the child process.
    """
    if child_command:
        return shlex.split(child_command)
    argv = [sys.executable, str(CHECKSTAT_PATH)]
    if mode == "replay":
        argv += ["--file", str(flags["replay_path"])]
    for key, spec in FLAG_SPEC.items():
        if key == "replay_path":
            continue
        if key not in flags:
            continue
        value = flags[key]
        flag = spec["flag"]
        if spec["kind"] in ("flag", "flag_true"):
            argv.append(flag)
        else:
            argv += [flag, str(value)]
    return argv


# ---------------------------------------------------------------------------
# Console log (streamed child output with a monotonic cursor)
# ---------------------------------------------------------------------------

_ANSI_ESCAPE_RE = re.compile(
    r"(?:\x1b\[|\x9b)[0-?]*[ -/]*[@-~]"  # CSI (colors, cursor)
    r"|\x1b\][^\x07\x1b]*(?:\x07|\x1b\x5c)?"  # OSC (titles, links)
    r"|\x1b[@-_]"
)  # other two-char escapes
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def sanitize_console_line(line: str) -> str:
    """Remove ANSI escapes and C0/C1 controls, including CR and LF.

    Console output mixes trusted UI text with child-process and model data;
    stripping line breaks and escape sequences keeps a model name from
    forging a new console line or emitting terminal controls.
    """
    return _CONTROL_CHARS_RE.sub("", _ANSI_ESCAPE_RE.sub("", line))


class ConsoleLog:
    def __init__(self, cap: int = CONSOLE_CAP):
        self._cap = cap
        self._lock = threading.Lock()
        self._buf: deque[dict] = deque(maxlen=cap)
        self._next_index = 1

    def append(self, stream: str, line: str) -> None:
        line = sanitize_console_line(line.rstrip("\r\n"))
        if line:
            with self._lock:
                if len(line) > CONSOLE_LINE_MAX:
                    line = line[:CONSOLE_LINE_MAX] + " …[truncated]"
                self._buf.append(
                    {
                        "i": self._next_index,
                        "ts": time.time(),
                        "s": stream,
                        "line": line,
                    }
                )
                self._next_index += 1

    def since(
        self,
        index: int,
        limit: int = CONSOLE_API_DEFAULT_LINES,
        max_bytes: int = CONSOLE_RESPONSE_MAX_BYTES,
    ) -> dict:
        """Lines from `index` onward (index = last seen cursor + 1).

        At most `limit` lines and roughly `max_bytes` of line text are
        returned, so the capped console buffer can never build a
        multi-megabyte JSON payload. When older lines are dropped, gap=True
        tells the client to replace its local copy instead of appending.
        """
        with self._lock:
            buf = list(self._buf)
            oldest = buf[0]["i"] if buf else self._next_index
            # client needs lines starting at `index`; a gap means some of
            # those were evicted from the capped buffer
            gap = bool(index) and index < oldest
            selected = [entry for entry in buf if entry["i"] >= index]
            if len(selected) > limit:
                selected = selected[-limit:]
                gap = True  # oldest requested lines were dropped
            budget = max_bytes
            kept: list[dict] = []
            for entry in reversed(selected):
                # json.dumps size, not len(line): JSON escaping can
                # multiply the wire size of control-character lines.
                cost = len(json.dumps(entry)) + 1
                if kept and cost > budget:
                    gap = True  # byte budget dropped older lines
                    break
                budget -= cost
                kept.append(entry)
            if len(kept) != len(selected):
                selected = kept[::-1]
            next_index = (selected[-1]["i"] + 1) if selected else max(index, oldest)
            return {"lines": selected, "next": next_index, "gap": gap}


# ---------------------------------------------------------------------------
# JSONL tailer (byte-offset incremental read; survives torn lines + rotation)
# ---------------------------------------------------------------------------


class FileTailer:
    """Incrementally parse a JSONL file, tolerating rotation and torn lines.

    poll() is called lazily from request handlers. state is in-memory only.
    """

    def __init__(
        self,
        path: Path,
        cap: int,
        *,
        key_field: str | None = None,
        attach_seq: bool = False,
    ):
        self.path = path
        self.cap = cap
        self._key_field = key_field
        self._attach_seq = attach_seq
        self._lock = threading.Lock()
        self._offset = 0
        self._pending = b""
        self._rows: deque[dict] = deque(maxlen=cap)
        self._keys: set = set()
        self._seq = 0
        self._skipped = 0

    # -- ingestion ----------------------------------------------------------

    def poll(self) -> bool:
        """Read any new complete lines. Returns True when the file rotated
        (client should discard its local row set and refetch)."""
        with self._lock:
            reset = False
            try:
                size = self.path.stat().st_size
            except FileNotFoundError:
                if self._offset:
                    reset, self._offset, self._pending = True, 0, b""
                return reset
            except OSError:
                return False
            if size < self._offset:  # rotated (.1 rename) or pruned in place
                reset = True
                self._offset, self._pending = 0, b""
                self._rows.clear()
                self._keys.clear()
            try:
                with self.path.open("rb") as fh:
                    if self._offset:
                        fh.seek(self._offset)
                    data = fh.read()
                    self._offset += len(data)
            except FileNotFoundError, OSError:
                return reset
            if self._pending:
                data = self._pending + data
                self._pending = b""
            parts = data.split(b"\n")
            if parts and parts[-1]:
                tail = parts.pop()  # incomplete line: hold for next poll
                if len(tail) > FILE_TAILER_PENDING_MAX:
                    # A single line beyond the cap can never become a usable
                    # JSONL record; drop it instead of buffering without bound.
                    # Its remainder is re-read and discarded on the next polls.
                    self._skipped += 1
                else:
                    self._pending = tail
            elif parts:
                parts.pop()  # trailing empty element after final newline
            for raw in parts:
                line = raw.strip(b"\r")
                if not line:
                    continue
                if len(line) > FILE_TAILER_LINE_MAX:
                    # A complete record larger than the cap would be retained
                    # and re-sent on every poll; skip it like a malformed line.
                    self._skipped += 1
                    continue
                try:
                    record = json.loads(line.decode("utf-8", errors="replace"))
                except ValueError:
                    self._skipped += 1
                    continue
                if self._key_field is not None:
                    key = record.get(self._key_field)
                    if key in self._keys:
                        continue
                    self._keys.add(key)
                    if len(self._keys) > self.cap * 2:
                        self._keys = {r.get(self._key_field) for r in self._rows}
                if self._attach_seq:
                    self._seq += 1
                    record["_seq"] = self._seq
                self._rows.append(record)
            return reset

    # -- accessors ----------------------------------------------------------

    def snapshot(self) -> list[dict]:
        with self._lock:
            return list(self._rows)

    def __len__(self) -> int:
        with self._lock:
            return len(self._rows)

    def skipped(self) -> int:
        with self._lock:
            return self._skipped

    def key_range(self) -> tuple[object, object]:
        """(oldest_key, newest_key) of buffered rows (None when empty)."""
        with self._lock:
            if not self._rows:
                return None, None
            first = self._rows[0].get(self._key_field) if self._key_field else None
            last = self._rows[-1].get(self._key_field) if self._key_field else None
            return first, last

    def rows_since(self, since: float) -> tuple[list[dict], object]:
        """Chronological rows with key > since, plus the boundary row before
        the first returned row (None when there is none)."""
        with self._lock:
            if self._key_field is None:
                return [], None
            rows = list(self._rows)
            idx = 0
            while idx < len(rows) and (
                rows[idx].get(self._key_field) is None
                or rows[idx][self._key_field] <= since
            ):
                idx += 1
            prev = rows[idx - 1] if idx > 0 else None
            return rows[idx:], prev

    def records_after(self, after: int) -> tuple[list[dict], bool]:
        """Records with _seq > after. Returns (records, gap) where gap means
        `after` predates the buffer start and the caller must replace its
        local store instead of appending."""
        with self._lock:
            if not self._rows:
                return [], bool(after)
            oldest = self._rows[0]["_seq"]
            gap = bool(after) and after < oldest - 1
            selected = [r for r in self._rows if r["_seq"] > after]
            return selected, gap

    def latest_seq(self) -> int:
        with self._lock:
            return self._rows[-1]["_seq"] if self._rows else 0


def _bounded_json_records(
    records: list[dict], limit: int = API_RESPONSE_MAX_BYTES
) -> list[dict]:
    """Newest-first records bounded by serialized size.

    Row caps alone do not bound response bytes when a single record is large;
    stop adding records once the next one would exceed the budget.
    """
    out: list[dict] = []
    total = 0
    for record in records:
        try:
            size = len(json.dumps(record, ensure_ascii=False)) + 64
        except TypeError, ValueError:
            continue
        if out and total + size > limit:
            break
        out.append(record)
        total += size
    return out


# ---------------------------------------------------------------------------
# Agent process runner
# ---------------------------------------------------------------------------


def _unlink_state_if_pid(state_file: Path, pid: int | None) -> None:
    """Remove a state file only when it still describes `pid`.

    A stale watcher must not delete the pidfile written by a newer run.
    """
    if pid is None:
        return
    try:
        data = json.loads(state_file.read_text(encoding="utf-8"))
    except OSError, ValueError:
        data = None
    # A record without a pid cannot belong to a newer run; only a different,
    # explicit pid means the file was replaced in the meantime.
    if (
        isinstance(data, dict)
        and data.get("pid") is not None
        and data.get("pid") != pid
    ):
        return
    with contextlib.suppress(OSError):
        state_file.unlink(missing_ok=True)


def _write_state_file(
    pid: int, argv: list[str], started_at: float, mode: str, path: Path | None = None
) -> None:
    """Atomically publish the adopted-PID record.

    mkstemp() creates the temporary file with O_EXCL in the destination
    directory (SCRIPT_DIR by default), so a predictable ``.tmp`` name cannot
    be pre-planted as a symlink; os.replace() swaps it in atomically.
    """
    target = Path(path) if path is not None else STATE_FILE
    payload = json.dumps(
        {"pid": pid, "argv": argv, "started_at": started_at, "mode": mode}
    )
    fd, tmp_name = tempfile.mkstemp(
        prefix=target.name + ".", suffix=".tmp", dir=str(target.parent)
    )
    try:
        handle = os.fdopen(fd, "w", encoding="utf-8")
    except BaseException:
        with contextlib.suppress(OSError):
            os.close(fd)
        with contextlib.suppress(OSError):
            os.unlink(tmp_name)
        raise
    try:
        with handle:
            handle.write(payload)
        os.replace(tmp_name, target)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp_name)
        raise


class AgentRunner:
    """Owns the checkstat.py child process."""

    def __init__(self, console: ConsoleLog, child_command: str | None = None):
        self.console = console
        self.child_command = child_command
        self._lock = threading.RLock()
        self.state = STATE_STOPPED
        self.proc: subprocess.Popen | None = None
        self.pid: int | None = None
        self.argv: list[str] | None = None
        self.mode = "continuous"
        self.started_at: float | None = None
        self.stopped_at: float | None = None
        self.exit_code: int | None = None
        self.exit_kind: str | None = None
        self.attached = True
        self._stop_requested = False
        self._stop_thread: threading.Thread | None = None
        self._state_file: Path = STATE_FILE

    # -- lifecycle ----------------------------------------------------------

    def start(self, argv: list[str], mode: str) -> tuple[bool, object]:
        # The lock is held across Popen so a stop() racing a start cannot
        # observe STARTING with proc=None and be lost: it either runs before
        # this transition (state STOPPED, no-op) or after the process is
        # published (a normal stop). Popen is a short local CreateProcess.
        with self._lock:
            if self.state in (STATE_RUNNING, STATE_STARTING, STATE_STOPPING):
                return False, "agent is already running"
            self.state = STATE_STARTING
            self.mode = mode
            self._stop_requested = False
            self._stop_thread = None
            self.exit_code = self.exit_kind = None
            self.stopped_at = None
            try:
                env = {**os.environ, "PYTHONUNBUFFERED": "1"}
                self.console.append(
                    "sys", "[UI] starting: " + subprocess.list2cmdline(argv)
                )
                proc = subprocess.Popen(
                    argv,
                    cwd=str(SCRIPT_DIR),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    stdin=subprocess.DEVNULL,
                    creationflags=CREATE_NEW_PG,
                    env=env,
                )
            except Exception as exc:
                self.state = STATE_STOPPED
                self.stopped_at = time.time()
                self.console.append("sys", f"[UI] failed to start: {exc}")
                return False, f"failed to start: {exc}"
            self.proc = proc
            self.pid = proc.pid
            self.argv = argv
            self.attached = True
            self.started_at = time.time()
            self.state = STATE_RUNNING
            self._state_file = STATE_FILE
            with contextlib.suppress(OSError):
                _write_state_file(
                    proc.pid, argv, self.started_at, mode, path=self._state_file
                )
            # Start the pumps before releasing the lock so a stop() that wins
            # the next lock acquisition cannot beat the watcher into existence.
            for stream, tag in ((proc.stdout, "out"), (proc.stderr, "err")):
                threading.Thread(
                    target=self._read_loop,
                    args=(stream, tag),
                    daemon=True,
                    name=f"socui-read-{tag}",
                ).start()
            threading.Thread(
                target=self._watch_exit, daemon=True, name="socui-watch"
            ).start()
        return True, proc.pid

    def adopt(
        self,
        pid: int,
        argv: list[str],
        started_at: float,
        mode: str,
        state_file: Path = STATE_FILE,
    ) -> None:
        """Take over a child left running by a previous UI session."""
        with self._lock:
            self.state = STATE_RUNNING
            self.pid = pid
            self.argv = argv
            self.mode = mode
            self.started_at = started_at
            self.attached = False
            self.proc = None
            self._state_file = state_file
        self.console.append(
            "sys",
            f"[UI] adopted agent pid {pid} from a previous dashboard "
            f"session (output unavailable; Stop will terminate it)",
        )
        threading.Thread(
            target=self._watch_orphan,
            args=(pid,),
            daemon=True,
            name="socui-orphan-watch",
        ).start()

    def stop(self, block: bool = False, timeout: float = 10.0) -> dict:
        with self._lock:
            if self.state == STATE_STOPPED:
                return self.snapshot()
            if self.state == STATE_STOPPING:
                thread = self._stop_thread
            else:
                self.state = STATE_STOPPING
                self._stop_requested = True
                if self.attached:
                    thread = threading.Thread(
                        target=self._stop_sequence, daemon=True, name="socui-stop"
                    )
                else:
                    thread = threading.Thread(
                        target=self._stop_orphan_inline,
                        daemon=True,
                        args=(timeout,),
                        name="socui-stop-orphan",
                    )
                self._stop_thread = thread
                # Start under the lock: a second stop(block=True) must never
                # join a thread that has not been started yet.
                thread.start()
        if block and thread is not None:
            thread.join(timeout)
        return self.snapshot()

    def _stop_sequence(self) -> None:
        with self._lock:
            proc = self.proc
        if proc is None:
            self._finalize_stop(None)
            return
        try:
            method = "ctrl_break"
            try:
                proc.send_signal(signal.CTRL_BREAK_EVENT)
            except Exception as exc:  # no console / already gone
                method = f"ctrl_break_failed({exc.__class__.__name__})"
            self.console.append("sys", f"[UI] stop requested ({method})")
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                # venv python.exe is a launcher whose child runs the real
                # interpreter, so terminate() alone would orphan it: kill
                # the tree.
                self.console.append(
                    "sys", "[UI] agent still alive, killing process tree"
                )
                try:
                    subprocess.run(
                        [TASKKILL_EXE, "/PID", str(proc.pid), "/T", "/F"],
                        capture_output=True,
                        check=False,
                    )
                except Exception as exc:
                    self.console.append("sys", f"[UI] taskkill failed: {exc}")
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    with contextlib.suppress(Exception):
                        proc.kill()
        finally:
            # No failure path may leave the runner stuck in STOPPING.
            self._finalize_stop(proc)

    def _finalize_stop(self, proc: subprocess.Popen | None) -> None:
        """Reconcile a stop that may not have observed the child exit."""
        with self._lock:
            if self.state != STATE_STOPPING:
                return
            try:
                alive = proc is not None and proc.poll() is None
            except Exception:
                alive = proc is not None
            self.state = STATE_STOPPED
            self.stopped_at = time.time()
            if alive:
                # send_signal/taskkill/kill all failed: the child may still
                # be running, so report the failure instead of a clean stop.
                self.exit_code = None
                self.exit_kind = "stop_failed"
            elif proc is not None and self.exit_code is None:
                self.exit_kind = "stopped_by_ui"

    @staticmethod
    def _orphan_identity_matches(pid: int, started_at: float | None) -> bool:
        """Re-verify creation time and command line before killing a PID."""
        if started_at is None:
            return False
        creation = process_creation_time(pid)
        if creation is None:
            return False
        if abs(creation - started_at) > PID_CREATION_TOLERANCE_SECONDS:
            return False
        if not _process_principal_matches(pid):
            return False
        return _pid_is_checkstat(pid)

    def _stop_orphan_inline(self, timeout: float) -> None:
        with self._lock:
            pid = self.pid
            started_at = self.started_at
            state_file = self._state_file
        try:
            if pid is None or not process_exists(pid):
                return
            if not self._orphan_identity_matches(pid, started_at):
                self.console.append(
                    "sys",
                    f"[UI] refusing to terminate adopted pid {pid}: identity "
                    "no longer matches the recorded checkstat.py process",
                )
                with self._lock:
                    self.exit_code = None
                    self.exit_kind = "refused_identity_mismatch"
                return
            self.console.append("sys", f"[UI] terminating adopted agent pid {pid}")
            killed = False
            try:
                killed = (
                    subprocess.run(
                        [TASKKILL_EXE, "/PID", str(pid), "/T", "/F"],
                        capture_output=True,
                        check=False,
                    ).returncode
                    == 0
                )
            except OSError as exc:
                self.console.append("sys", f"[UI] taskkill failed: {exc}")
            if not killed:
                killed = terminate_pid(pid, wait_ms=int(timeout * 1000))
            with self._lock:
                self.exit_code = None
                self.exit_kind = "terminated" if killed else "stop_failed"
        finally:
            # Never leave a failed taskkill/terminate stuck in STOPPING.
            with self._lock:
                self.state = STATE_STOPPED
                self.stopped_at = time.time()
                self.proc = None
            _unlink_state_if_pid(state_file, pid)

    # -- background threads -------------------------------------------------

    def _read_loop(self, stream, tag: str) -> None:
        with contextlib.suppress(OSError, ValueError):
            for raw in iter(stream.readline, b""):
                line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
                if line:
                    self.console.append(tag, line)
        with contextlib.suppress(OSError):
            stream.close()

    def _watch_exit(self) -> None:
        with self._lock:
            proc = self.proc
            state_file = self._state_file
        if proc is None:
            return
        code = proc.wait()
        if code == 0:
            kind = "clean"
        elif self._stop_requested:
            kind = "stopped_by_ui"
        elif code == CTRL_BREAK_KILL_CODE:
            kind = "console_event"
        else:
            kind = "crashed"
        with self._lock:
            if self.proc is not proc:
                # A newer run (or a finalized stop) already owns the state;
                # never clobber it with this exited process's result.
                return
            self.exit_code = code
            self.exit_kind = kind
            self.state = STATE_STOPPED
            self.stopped_at = time.time()
            self.proc = None
        _unlink_state_if_pid(state_file, proc.pid)
        self.console.append("sys", f"[UI] agent exited (code {code}, {kind})")

    def _watch_orphan(self, pid: int) -> None:
        """Poll an adopted PID and reconcile state when it exits."""
        while True:
            time.sleep(ORPHAN_POLL_SECONDS)
            with self._lock:
                if self.state != STATE_RUNNING or self.pid != pid:
                    return
                state_file = self._state_file
            if process_exists(pid):
                continue
            with self._lock:
                if self.state != STATE_RUNNING or self.pid != pid:
                    return
                self.state = STATE_STOPPED
                self.stopped_at = time.time()
                self.exit_code = None
                self.exit_kind = "orphan_exited"
                self.proc = None
            _unlink_state_if_pid(state_file, pid)
            self.console.append("sys", f"[UI] adopted agent pid {pid} exited")
            return

    # -- reporting ----------------------------------------------------------

    def snapshot(self) -> dict:
        with self._lock:
            running = self.state in (STATE_RUNNING, STATE_STARTING)
            return {
                "state": self.state,
                "mode": self.mode,
                "pid": self.pid if running else None,
                "started_at": self.started_at,
                "uptime_seconds": round(time.time() - self.started_at, 1)
                if running and self.started_at
                else None,
                "exit_code": self.exit_code,
                "exit_kind": self.exit_kind,
                "attached": self.attached,
                "stop_requested": self._stop_requested,
            }


def try_adopt_orphan(
    runner: AgentRunner, console: ConsoleLog, state_file: Path = STATE_FILE
) -> bool:
    """Adopt a child left running by a previous dashboard session.

    The state file is only a hint: the PID must be a positive integer that is
    still alive, have a readable creation time matching started_at within 5 s,
    and be confirmed as checkstat.py by the WMI probe. Any failure deletes the
    state file so a stale or tampered record cannot be retried.
    """

    def _reject(reason: str) -> bool:
        with contextlib.suppress(OSError):
            state_file.unlink(missing_ok=True)
        console.append("sys", f"[UI] not adopting recorded agent pid: {reason}")
        return False

    try:
        data = json.loads(state_file.read_text(encoding="utf-8"))
    except OSError, ValueError:
        with contextlib.suppress(OSError):
            state_file.unlink(missing_ok=True)
        return False
    if not isinstance(data, dict):
        return _reject("state file is not a JSON object")
    pid = data.get("pid")
    started_at = data.get("started_at")
    if not _is_int(pid) or not 0 < pid <= 0xFFFFFFFF:
        return _reject(f"invalid pid {pid!r}")
    if isinstance(started_at, bool) or not isinstance(started_at, (int, float)):
        return _reject("invalid started_at")
    try:
        started_at = float(started_at)
    except OverflowError, ValueError:
        return _reject("invalid started_at")
    if not math.isfinite(started_at):
        return _reject("invalid started_at")
    if not process_exists(pid):
        return _reject(f"pid {pid} is not running")
    creation = process_creation_time(pid)
    if creation is None:
        return _reject(f"pid {pid} creation time unavailable")
    if abs(creation - started_at) > PID_CREATION_TOLERANCE_SECONDS:
        return _reject(f"pid {pid} creation time does not match state file")
    if not _process_principal_matches(pid):
        return _reject(f"pid {pid} is not the expected interpreter, user, and session")
    if not _pid_is_checkstat(pid):
        return _reject(f"pid {pid} is not a confirmed checkstat.py process")
    runner.adopt(
        pid,
        data.get("argv") or [],
        started_at,
        data.get("mode") or "continuous",
        state_file=state_file,
    )
    return True


# ---------------------------------------------------------------------------
# Status cache (Ollama reachability, file stats, traffic window)
# ---------------------------------------------------------------------------


def _ollama_base(url: str) -> str:
    url = str(url or "http://localhost:11434/api/generate").strip()
    for suffix in ("/api/generate", "/api/tags", "/api/chat"):
        if url.endswith(suffix):
            return url[: -len(suffix)]
    return url.rstrip("/")


CHAT_TIMEOUT_MIN_SECONDS = 5.0
CHAT_TIMEOUT_MAX_SECONDS = 120.0
CHAT_NUM_CTX_MIN = 512
CHAT_NUM_CTX_MAX = 32768


def _resolve_finding_chat_settings(
    defaults: dict, allow_remote_ollama: bool
) -> tuple[dict | None, str | None]:
    """Resolve and validate the escalation-model settings for finding chat.

    Returns ``(settings, error)``. The error text is generic so a rejected
    endpoint never reveals why it was rejected.
    """
    agent = defaults.get("agent") if isinstance(defaults, dict) else {}
    yaml_only = defaults.get("yaml_only") if isinstance(defaults, dict) else {}
    agent = agent if isinstance(agent, dict) else {}
    yaml_only = yaml_only if isinstance(yaml_only, dict) else {}

    raw_url = agent.get("ollama_url") or _D["ollama_url"]
    valid, _err = _validate_ollama_url(str(raw_url), allow_remote=allow_remote_ollama)
    if valid is None:
        return None, "AI endpoint is not available"

    model = str(agent.get("escalation_model") or _D["escalation_model"]).strip()
    if _model_name_error(model):
        return None, "escalation model is not configured"
    routine_model = str(agent.get("model") or _D["model"]).strip()
    if _model_name_error(routine_model):
        routine_model = str(_D["model"])

    try:
        timeout = float(
            agent.get("escalation_timeout_seconds") or _D["escalation_timeout_seconds"]
        )
    except TypeError, ValueError:
        timeout = float(_D["escalation_timeout_seconds"])
    if timeout != timeout or timeout <= 0:  # NaN or non-positive
        timeout = float(_D["escalation_timeout_seconds"])
    timeout = min(max(timeout, CHAT_TIMEOUT_MIN_SECONDS), CHAT_TIMEOUT_MAX_SECONDS)

    raw_ctx = yaml_only.get("escalation_num_ctx")
    if raw_ctx is None:
        raw_ctx = agent.get("num_ctx") or _D["num_ctx"]
    try:
        num_ctx = int(raw_ctx)
    except TypeError, ValueError:
        num_ctx = int(_D["num_ctx"])
    num_ctx = min(max(num_ctx, CHAT_NUM_CTX_MIN), CHAT_NUM_CTX_MAX)

    keep_alive = str(
        yaml_only.get("escalation_keep_alive")
        or agent.get("keep_alive")
        or _D["keep_alive"]
    ).strip()
    if not _re_ok(KEEP_ALIVE_RE, keep_alive):
        keep_alive = str(_D["keep_alive"])

    return {
        "base_url": _ollama_base(valid),
        "model": model,
        "routine_model": routine_model,
        "timeout": timeout,
        "num_ctx": num_ctx,
        "keep_alive": keep_alive,
        "think": bool(yaml_only.get("escalation_think", False)),
    }, None


def _ollama_model_names(status_cache: StatusCache) -> list[str]:
    """Installed Ollama model names from the background status cache."""
    try:
        payload = status_cache.get()
    except Exception:
        return []
    if not isinstance(payload, dict):
        return []
    ollama = payload.get("ollama")
    if not isinstance(ollama, dict):
        return []
    names: list[str] = []
    for entry in ollama.get("models") or []:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name")
        if isinstance(name, str):
            name = name.strip()
            if name and name not in names:
                names.append(name)
    return names


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse redirects so the loopback probe cannot be steered elsewhere."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class StatusCache(threading.Thread):
    """Refreshes the status panel payload every STATUS_REFRESH_SECONDS."""

    def __init__(
        self,
        get_defaults,
        traffic_tailer: FileTailer,
        allow_remote_ollama: bool = False,
        network_path: Path | None = None,
    ):
        super().__init__(daemon=True, name="socui-status")
        self._get_defaults = get_defaults
        self._traffic = traffic_tailer
        self._allow_remote_ollama = bool(allow_remote_ollama)
        self._network_path = Path(network_path or NETWORK_HEALTH_FILE)
        self._stop_event = threading.Event()
        # The dashboard polls /api/status immediately after opening; before the
        # first refresh completes, return a renderable "loading" shape rather
        # than {} (the browser would otherwise dereference missing keys).
        self._data: dict = {
            "ready": False,
            "checked_at": None,
            "ollama": {
                "reachable": False,
                "base": "",
                "models": [],
                "error": "status loading",
            },
            "files": [],
            "verdict_cache": {"entries": None},
            "traffic": {
                "rows": 0,
                "first_ts": None,
                "last_ts": None,
                "skipped_malformed": 0,
            },
            "network": {
                "available": False,
                "enabled": True,
                "stale": True,
                "verdict": "UNKNOWN",
                "label": "unknown",
                "reason": "status loading",
                "confidence": "low",
                "summary": "status loading",
                "caveat": network_health.CAVEAT,
                "source": None,
                "generated_at": None,
                "generated_iso": None,
                "age_seconds": None,
                "gateway": None,
                "gateway_status": "not_probed",
                "targets": [],
                "targets_up": 0,
                "targets_healthy": 0,
                "targets_total": 0,
                "error": None,
            },
        }

    def get(self) -> dict:
        return self._data

    def stop(self) -> None:
        self._stop_event.set()

    def run(self) -> None:
        self._refresh()
        while not self._stop_event.wait(STATUS_REFRESH_SECONDS):
            self._refresh()

    def _refresh(self) -> None:
        """Refresh the status payload; never let one bad probe kill the thread."""
        try:
            self._data = self._collect()
        except Exception as exc:
            previous = dict(self._data or {})
            previous["ready"] = bool(previous.get("ready", False))
            previous["error"] = f"status refresh failed: {type(exc).__name__}"
            self._data = previous

    def _collect(self) -> dict:
        data: dict = {"checked_at": time.time(), "ready": True}
        try:
            defaults = self._get_defaults()
            ollama_url = defaults["agent"].get("ollama_url") or _D["ollama_url"]
        except DefaultsError:
            defaults, ollama_url = {}, _D["ollama_url"]
        data["ollama"] = self._check_ollama(ollama_url)
        data["network"] = self._network_status(defaults)
        data["files"] = self._check_files()
        data["verdict_cache"] = self._check_verdict_cache()
        first, last = self._traffic.key_range()
        data["traffic"] = {
            "rows": len(self._traffic),
            "first_ts": first,
            "last_ts": last,
            "skipped_malformed": self._traffic.skipped(),
        }
        return data

    @staticmethod
    def _project_probe(probe: Any) -> dict | None:
        if not isinstance(probe, dict):
            return None

        def number(key: str) -> float | None:
            try:
                value = float(probe.get(key))
                return value if math.isfinite(value) else None
            except OverflowError, TypeError, ValueError:
                return None

        port = probe.get("port")
        if isinstance(port, bool) or not isinstance(port, int):
            port = None
        return {
            "host": str(probe.get("host") or "")[:64],
            "label": str(probe.get("label") or "")[:64],
            "port": port,
            "reachable": bool(probe.get("reachable", False)),
            "healthy": bool(probe.get("healthy", False)),
            "loss_pct": number("loss_pct"),
            "rtt_ms_avg": number("rtt_ms_avg"),
            "jitter_ms": number("jitter_ms"),
            "probe": str(probe.get("probe") or "")[:16],
            "error": str(probe.get("error") or "")[:200],
        }

    def _network_status(self, defaults: dict) -> dict:
        """Project the agent's network-health file; never runs a probe."""
        config = defaults.get("network_health") if isinstance(defaults, dict) else {}
        if not isinstance(config, dict):
            config = {}
        enabled = bool(config.get("enabled", True))
        base = {
            "available": False,
            "enabled": enabled,
            "stale": True,
            "verdict": "UNKNOWN",
            "label": "unknown",
            "reason": "no_sample",
            "confidence": "low",
            "summary": "No network-health sample yet.",
            "caveat": network_health.CAVEAT,
            "source": None,
            "generated_at": None,
            "generated_iso": None,
            "age_seconds": None,
            "gateway": None,
            "gateway_status": "not_probed",
            "targets": [],
            "targets_up": 0,
            "targets_healthy": 0,
            "targets_total": 0,
            "error": None,
        }
        if not enabled:
            base.update(
                {
                    "enabled": False,
                    "summary": "Network probes are disabled.",
                    "error": None,
                }
            )
            return base
        try:
            data = network_health.read_result(
                self._network_path, NETWORK_HEALTH_MAX_BYTES
            )
        except Exception as exc:
            base["error"] = f"network status read failed: {type(exc).__name__}"
            return base
        if data is None:
            base["error"] = "no agent sample"
            base["summary"] = "No fresh network-health sample from the agent."
            return base
        try:
            generated = float(data.get("generated_at"))
            if not math.isfinite(generated):
                raise ValueError("non-finite timestamp")
            age = max(0.0, time.time() - generated)
            interval = float(config.get("interval_seconds", 60) or 60)
            file_max_age = float(config.get("file_max_age_seconds", 180) or 180)
            stale_after = max(file_max_age, 2.0 * interval + 15.0)
            verdict = str(data.get("verdict") or "UNKNOWN")
            if verdict not in network_health.VERDICTS:
                verdict = "UNKNOWN"
            targets = [
                projected
                for projected in (
                    self._project_probe(item)
                    for item in (data.get("targets") or [])[:8]
                )
                if projected is not None
            ]
            gateway = self._project_probe(data.get("gateway"))
            return {
                **base,
                "available": True,
                "enabled": True,
                "stale": age > stale_after,
                "verdict": verdict,
                "label": verdict.lower(),
                "reason": str(data.get("reason") or "")[:80],
                "confidence": str(data.get("confidence") or "low")[:16],
                "summary": str(data.get("summary") or "")[:500],
                "caveat": str(data.get("caveat") or network_health.CAVEAT)[:500],
                "source": str(data.get("source") or "agent")[:32],
                "generated_at": generated,
                "generated_iso": str(data.get("generated_iso") or "")[:64],
                "age_seconds": round(age, 1),
                "gateway": gateway,
                "gateway_status": str(data.get("gateway_status") or "not_probed")[:24],
                "targets": targets,
                "targets_up": int(data.get("targets_up", 0) or 0),
                "targets_healthy": int(data.get("targets_healthy", 0) or 0),
                "targets_total": int(data.get("targets_total", 0) or 0),
                "error": None,
            }
        except (OverflowError, TypeError, ValueError) as exc:
            base["error"] = f"invalid network sample: {type(exc).__name__}"
            return base

    def _check_ollama(self, url: str) -> dict:
        valid, err = _validate_ollama_url(url, allow_remote=self._allow_remote_ollama)
        if err or valid is None:
            return {
                "reachable": False,
                "base": "",
                "models": [],
                "error": f"Ollama URL rejected: {err or 'invalid URL'}",
            }
        base = _ollama_base(valid)
        try:
            # Refuse redirects: the loopback policy applies to the configured
            # URL, so a local service must not be able to steer the probe to a
            # different host.
            opener = urllib.request.build_opener(_NoRedirect)
            with opener.open(base + "/api/tags", timeout=OLLAMA_TIMEOUT) as resp:
                raw = resp.read(OLLAMA_RESPONSE_MAX_BYTES + 1)
            if len(raw) > OLLAMA_RESPONSE_MAX_BYTES:
                raise ValueError(
                    f"response exceeds the {OLLAMA_RESPONSE_MAX_BYTES}-byte size limit"
                )
            payload = json.loads(raw.decode("utf-8", errors="replace"))
            if not isinstance(payload, dict):
                raise ValueError("response is not a JSON object")
            raw_models = payload.get("models")
            if not isinstance(raw_models, list):
                raw_models = []
            models = []
            for entry in raw_models:
                if not isinstance(entry, dict):
                    continue
                size = entry.get("size")
                if not isinstance(size, (int, float)) or isinstance(size, bool):
                    size = None
                models.append(
                    {
                        "name": entry.get("name") or entry.get("model"),
                        "size": size,
                        "size_human": human_size(size),
                    }
                )
            return {"reachable": True, "base": base, "models": models, "error": None}
        except (
            urllib.error.URLError,
            http.client.HTTPException,
            TimeoutError,
            OSError,
            ValueError,
            RecursionError,
        ) as exc:
            return {
                "reachable": False,
                "base": base,
                "models": [],
                "error": f"{exc.__class__.__name__}: {exc}"[:200],
            }

    @staticmethod
    def _check_files() -> list[dict]:
        out = []
        for name in FILE_INFO_NAMES:
            path = SCRIPT_DIR / name
            try:
                st = path.stat()
                out.append(
                    {
                        "name": name,
                        "size": st.st_size,
                        "size_human": human_size(st.st_size),
                        "mtime": st.st_mtime,
                    }
                )
            except OSError:
                out.append(
                    {"name": name, "size": 0, "size_human": "0 B", "mtime": None}
                )
        return out

    @staticmethod
    def _check_verdict_cache() -> dict:
        path = SCRIPT_DIR / "soc_verdict_cache.json"
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except OSError, ValueError, RecursionError:
            return {"entries": None}
        if isinstance(data, dict):
            for key in ("verdicts", "entries", "cache"):
                value = data.get(key)
                if isinstance(value, (list, dict)):
                    return {"entries": len(value)}
            return {"entries": len(data)}
        if isinstance(data, list):
            return {"entries": len(data)}
        return {"entries": None}


# ---------------------------------------------------------------------------
# Flask app
# ---------------------------------------------------------------------------

AUTH_HEADER = "X-Auth-Token"
CONTENT_SECURITY_POLICY = (
    "default-src 'self'; script-src 'self'; "
    "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
    "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'"
)


def _parse_host_header(raw: str | None) -> tuple[str, int] | None:
    """Parse a Host header into (lowercase host, port).

    Only loopback names are accepted: 127.0.0.1, localhost and ::1, each
    with an optional port. IPv6 literals must be bracketed except for the
    bare "::1" form. A missing port defaults to HTTP's port 80. Returns
    None for anything malformed or non-loopback (DNS-rebinding guard).
    """
    value = (raw or "").strip().lower()
    if not value or "," in value or any(ch.isspace() for ch in value):
        return None
    if value.startswith("["):
        end = value.find("]")
        if end < 0:
            return None
        host, rest = value[1:end], value[end + 1 :]
        if rest:
            if not rest.startswith(":"):
                return None
            port_text = rest[1:]
            if not port_text:
                return None
        else:
            port_text = ""
    elif value.count(":") > 1:
        host, port_text = value, ""  # bare IPv6 literal, e.g. ::1
    else:
        host, sep, port_text = value.partition(":")
        if sep and not port_text:
            return None
    if host not in LOOPBACK_HOSTS:
        return None
    if port_text:
        if not port_text.isdigit():
            return None
        port = int(port_text)
        if not 1 <= port <= 65535:
            return None
    else:
        port = 80
    return host, port


def _parse_origin(raw: str | None) -> tuple[str, int] | None:
    """Parse an Origin header into (lowercase host, port).

    The dashboard is served over plain HTTP, so only an http origin with
    no path, query, fragment or userinfo can match the app origin.
    """
    if not raw:
        return None
    try:
        parsed = urllib.parse.urlsplit(raw.strip())
        port = parsed.port  # raises ValueError for a malformed port
        host = parsed.hostname
        if (
            parsed.scheme.lower() != "http"
            or not host
            or parsed.path
            or parsed.query
            or parsed.fragment
            or parsed.username is not None
            or parsed.password is not None
        ):
            return None
    except ValueError:
        return None
    return host.lower(), port if port is not None else 80


def create_app(
    runner: AgentRunner,
    console: ConsoleLog,
    traffic_tailer: FileTailer,
    findings_tailer: FileTailer,
    status_cache: StatusCache,
    get_defaults=load_yaml_defaults,
    auth_token: str | None = None,
    allow_remote_ollama: bool = False,
    allowlist_path: Path | None = None,
) -> Flask:
    app = Flask("socagent-ui", static_folder=str(STATIC_DIR), static_url_path="/static")
    app.config["JSON_SORT_KEYS"] = False
    # Option payloads are a few hundred bytes at most; reject oversized
    # bodies before any route reads them (Flask raises 413 on read).
    app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH
    app.config["allow_remote_ollama"] = bool(allow_remote_ollama)
    # An omitted/empty token means "generate one"; every /api/* request
    # must then carry it in X-Auth-Token with a loopback Host and, when a
    # browser sends Origin, a same-origin value (CSRF + DNS-rebinding guard).
    app.config["auth_token"] = auth_token or secrets.token_urlsafe(32)
    allowlist_path = (
        Path(allowlist_path)
        if allowlist_path is not None
        else user_allowlist.DEFAULT_ALLOWLIST_FILE
    )
    app.config["allowlist_path"] = allowlist_path
    allowlist_slot = threading.Lock()
    app.extensions["allowlist_slot"] = allowlist_slot

    @app.before_request
    def _require_api_auth():
        if not request.path.startswith("/api/"):
            return None  # "/" and "/static/*" stay unauthenticated
        host = _parse_host_header(request.headers.get("Host"))
        if host is None:
            return jsonify(error="invalid or non-loopback Host header"), 421
        origin = request.headers.get("Origin")
        if origin is not None and _parse_origin(origin) != host:
            return jsonify(error="cross-origin request rejected"), 403
        supplied = request.headers.get(AUTH_HEADER, "")
        expected = app.config["auth_token"]
        if not secrets.compare_digest(
            supplied.encode("utf-8", "surrogateescape"), expected.encode("utf-8")
        ):
            return jsonify(error=f"missing or invalid {AUTH_HEADER} header"), 401
        return None

    @app.errorhandler(413)
    def _payload_too_large(_exc):
        return jsonify(error="request body too large"), 413

    @app.after_request
    def _headers(response):
        if request.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        else:
            response.headers["Cache-Control"] = "no-cache"
        response.headers["Content-Security-Policy"] = CONTENT_SECURITY_POLICY
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    @app.route("/")
    def index():
        return send_from_directory(STATIC_DIR, "index.html")

    @app.route("/api/state")
    def api_state():
        return jsonify(runner.snapshot())

    @app.route("/api/start", methods=["POST"])
    def api_start():
        payload = request.get_json(silent=True)
        if payload is None:
            return jsonify(error="body must be valid JSON"), 400
        flags, mode, errors = validate_payload(
            payload, allow_remote_ollama=app.config.get("allow_remote_ollama", False)
        )
        if errors:
            return jsonify(error="invalid options", fields=errors), 400

        running = runner.snapshot()
        if running["state"] not in (STATE_STOPPED,):
            return jsonify(
                error="agent is already running", state=running["state"]
            ), 409

        force = payload.get("force") is True
        if not force:
            exclude = (running["pid"],) if running.get("pid") else ()
            probe = external_checkstat_processes(exclude_pids=exclude)
            if probe["processes"]:
                return jsonify(
                    error="another checkstat.py process appears to be running",
                    external=external_process_pids(probe["processes"]),
                ), 412

        argv = build_argv(flags, mode, runner.child_command)
        ok, detail = runner.start(argv, mode)
        if not ok:
            # A second concurrent start can lose the runner lock after both
            # requests passed the snapshot check; report that as the same 409
            # the sequential path returns, not a start failure.
            if detail == "agent is already running":
                return jsonify(
                    error="agent is already running", state=runner.snapshot()["state"]
                ), 409
            # OSError text can carry install paths; AgentRunner.start has
            # already streamed the detail to the dashboard console.
            return jsonify(error="failed to start the agent; see the console"), 503
        snapshot = runner.snapshot()
        return jsonify(state=snapshot["state"], pid=snapshot["pid"], mode=mode)

    @app.route("/api/stop", methods=["POST"])
    def api_stop():
        return jsonify(**runner.stop())

    @app.route("/api/console")
    def api_console():
        raw_since = request.args.get("since", "0")
        try:
            since = max(0, int(raw_since))
        except ValueError:
            since = 0
        try:
            limit = min(
                CONSOLE_API_MAX_LINES,
                max(1, int(request.args.get("limit", str(CONSOLE_API_DEFAULT_LINES)))),
            )
        except ValueError:
            limit = CONSOLE_API_DEFAULT_LINES
        payload = console.since(since, limit)
        payload["state"] = runner.snapshot()
        return jsonify(payload)

    @app.route("/api/traffic")
    def api_traffic():
        reset = traffic_tailer.poll()
        try:
            limit = min(
                TRAFFIC_ROWS_MAX,
                max(1, int(request.args.get("limit", str(TRAFFIC_ROWS_MAX)))),
            )
        except ValueError:
            limit = TRAFFIC_ROWS_MAX
        raw_since = request.args.get("since")
        oldest, _newest = traffic_tailer.key_range()
        since = None
        if raw_since not in (None, ""):
            try:
                since = float(raw_since)
            except ValueError:
                return jsonify(error="since must be an epoch float"), 400
        if (
            since is not None
            and not reset
            and (oldest is None or since < oldest - 1e-9)
        ):
            reset = True  # client is older than the whole buffer: refetch
        if since is None or reset:
            rows = traffic_tailer.snapshot()[-limit:]
            prev = None
        else:
            rows, prev = traffic_tailer.rows_since(since)
            if len(rows) > limit:
                prev = rows[-(limit + 1)]
                rows = rows[-limit:]
        return jsonify(
            rows=_bounded_json_records(list(reversed(rows))),
            prev=prev,
            reset=reset,
            total=len(traffic_tailer),
            skipped_malformed=traffic_tailer.skipped(),
        )

    @app.route("/api/findings")
    def api_findings():
        findings_tailer.poll()
        raw_after = request.args.get("after")
        try:
            limit = min(FINDINGS_MAX, max(1, int(request.args.get("limit", "100"))))
        except ValueError:
            limit = 100
        if raw_after in (None, ""):
            records = findings_tailer.snapshot()[-limit:]
            gap = False
        else:
            try:
                after = int(raw_after)
            except ValueError:
                return jsonify(error="after must be an integer seq"), 400
            records, gap = findings_tailer.records_after(after)
            if len(records) > limit:
                records = records[-limit:]
        # Records are immutable. A finding written before an allow-list entry
        # existed has no agent disposition, so annotate it for display against
        # the currently active entries. This is display-only: the agent still
        # owns enforcement for future sightings and its live identity/co-fire
        # guards are not replayed here.
        snapshot = (
            user_allowlist.load_snapshot(app.config["allowlist_path"])
            if records else None
        )
        annotated: list[dict] = []
        for record in records:
            view = dict(record)
            # Never override an agent decision. A record with a disposition
            # was evaluated live (including identity/co-fire guards), so a
            # display-only match must not hide a finding the agent reopened.
            if snapshot is not None and not record.get("disposition"):
                entry_id = user_allowlist.match_record_for_display(
                    view, snapshot
                )
                if entry_id:
                    view["display_muted"] = True
                    view["display_allowlist_id"] = entry_id
            annotated.append(view)
        return jsonify(
            records=_bounded_json_records(list(reversed(annotated))),
            next_seq=findings_tailer.latest_seq(),
            total=len(findings_tailer),
            reset=gap,
            skipped_malformed=findings_tailer.skipped(),
        )

    # One in-flight finding-chat generation per app: a slow 27B model call
    # would otherwise let several tabs pile requests onto Ollama.
    chat_slot = threading.Lock()

    @app.route("/api/findings/chat/config", methods=["GET"])
    def api_finding_chat_config():
        try:
            settings, err = _resolve_finding_chat_settings(
                get_defaults(), app.config.get("allow_remote_ollama", False)
            )
        except DefaultsError:
            return jsonify(error="triage configuration unavailable"), 503
        if settings is None:
            return jsonify(error=err or "AI endpoint is not available"), 503
        installed = _ollama_model_names(status_cache)
        default_model = settings["model"]
        routine_model = settings.get("routine_model")
        if installed:
            if default_model not in installed:
                default_model = installed[0]
            if routine_model not in installed:
                routine_model = None
        models: list[str] = []
        for name in (default_model, routine_model, *installed):
            if isinstance(name, str) and name and name not in models:
                models.append(name)
        return jsonify(
            default_model=default_model,
            routine_model=routine_model,
            models=models,
            installed=bool(installed),
            timeout_seconds=settings["timeout"],
        )

    @app.route("/api/findings/chat", methods=["POST"])
    def api_finding_chat():
        payload = request.get_json(silent=True)
        if payload is None:
            return jsonify(error="body must be valid JSON"), 400
        try:
            req = finding_chat.validate_chat_payload(payload)
        except finding_chat.FindingChatError as exc:
            return jsonify(error=exc.message), exc.status

        # The client sends only the cursor; the server owns the evidence.
        findings_tailer.poll()
        record = next(
            (r for r in findings_tailer.snapshot() if r.get("_seq") == req["seq"]), None
        )
        if record is None:
            return jsonify(
                error="finding is no longer buffered; reload the dashboard"
            ), 404
        if str(record.get("timestamp") or "") != req["timestamp"]:
            return jsonify(error="finding changed; reload the dashboard"), 409

        try:
            settings, err = _resolve_finding_chat_settings(
                get_defaults(), app.config.get("allow_remote_ollama", False)
            )
        except DefaultsError:
            return jsonify(error="triage configuration unavailable"), 503
        if settings is None:
            return jsonify(error=err or "AI endpoint is not available"), 503

        override = req.get("model")
        model = override or settings["model"]
        installed = _ollama_model_names(status_cache)
        # Validate an explicit override against the installed set. The
        # configured default is trusted even if the status probe is stale.
        if override and installed and model not in installed:
            return jsonify(
                error=f"model {model!r} is not installed in Ollama",
                code="model_not_installed",
            ), 400

        if not chat_slot.acquire(blocking=False):
            return jsonify(
                error="another chat request is still running; try again shortly"
            ), 429
        try:
            answer = finding_chat.chat_completion(
                settings["base_url"],
                model,
                finding_chat.build_chat_messages(
                    record, req["history"], req["question"]
                ),
                timeout=settings["timeout"],
                num_ctx=settings["num_ctx"],
                keep_alive=settings["keep_alive"],
                think=settings["think"],
            )
        except finding_chat.FindingChatError as exc:
            if exc.status >= 500:
                app.logger.warning("finding chat upstream failure (%s)", exc.status)
            return jsonify(error=exc.message), exc.status
        finally:
            chat_slot.release()

        return jsonify(answer=answer, model=model)

    # ---------------------------------------------------------- allow-list ---

    def _allowlist_record(seq: int):
        findings_tailer.poll()
        return next(
            (
                record
                for record in findings_tailer.snapshot()
                if record.get("_seq") == seq
            ),
            None,
        )

    def _allowlist_thresholds() -> dict:
        try:
            defaults = get_defaults()
        except DefaultsError:
            return {}
        traffic = defaults.get("traffic") if isinstance(defaults, dict) else {}
        thresholds = traffic.get("thresholds") if isinstance(traffic, dict) else {}
        return thresholds if isinstance(thresholds, dict) else {}

    def _allowlist_entry_view(entry: dict, active_ids: set[str], now: datetime) -> dict:
        view = dict(entry)
        expires = user_allowlist._parse_iso(entry.get("expires_at"))
        view["active"] = entry.get("id") in active_ids
        remaining = None
        if expires is not None:
            remaining = max(0, int((expires - now).total_seconds()))
        view["expires_in_seconds"] = remaining
        return view

    def _prune_disabled(entries: list[dict], now: datetime) -> list[dict]:
        kept = []
        for entry in entries:
            if entry.get("enabled"):
                kept.append(entry)
                continue
            disabled = user_allowlist._parse_iso(entry.get("disabled_at"))
            if disabled is None or (now - disabled).days < 90:
                kept.append(entry)
        return kept

    def _write_allowlist(entries: list[dict], now: datetime) -> bool:
        return user_allowlist.write_allowlist_atomic(
            allowlist_path,
            {
                "schema_version": user_allowlist.SCHEMA_VERSION,
                "updated_at": now.isoformat(timespec="seconds"),
                "entries": entries,
            },
        )

    @app.route("/api/allowlist", methods=["GET"])
    def api_allowlist():
        snapshot = user_allowlist.load_snapshot(allowlist_path, force=True)
        now = datetime.now(UTC)
        active = user_allowlist.active_entries(snapshot, now)
        active_ids = {str(entry.get("id") or "") for entry in active}
        return jsonify(
            schema_version=user_allowlist.SCHEMA_VERSION,
            server_time=now.isoformat(timespec="seconds"),
            status=snapshot.status,
            invalid_entries=snapshot.invalid_entries,
            active_count=len(active),
            entries=[
                _allowlist_entry_view(entry, active_ids, now)
                for entry in snapshot.entries
            ],
        )

    @app.route("/api/allowlist/preview", methods=["GET"])
    def api_allowlist_preview():
        raw_seq = request.args.get("seq", "")
        try:
            seq = int(raw_seq)
        except TypeError, ValueError:
            return jsonify(error="seq must be a positive integer"), 400
        if seq <= 0:
            return jsonify(error="seq must be a positive integer"), 400
        timestamp = request.args.get("timestamp", "")
        if (
            not isinstance(timestamp, str)
            or not timestamp.strip()
            or len(timestamp) > 64
        ):
            return jsonify(error="timestamp is invalid"), 400
        timestamp = timestamp.strip()

        record = _allowlist_record(seq)
        if record is None:
            return jsonify(
                error="finding is no longer buffered; reload the dashboard"
            ), 404
        if str(record.get("timestamp") or "") != timestamp:
            return jsonify(error="finding changed; reload the dashboard"), 409

        derivation = user_allowlist.derive_scope_from_record(
            record, _allowlist_thresholds()
        )
        existing_id = None
        if derivation.eligible and derivation.scope is not None:
            fingerprint = user_allowlist.fingerprint_scope(derivation.scope)
            snapshot = user_allowlist.load_snapshot(allowlist_path, force=True)
            for entry in user_allowlist.active_entries(snapshot):
                if entry.get("fingerprint") == fingerprint:
                    existing_id = entry.get("id")
                    break
        rule = record.get("rule") if isinstance(record.get("rule"), dict) else {}
        return jsonify(
            eligible=derivation.eligible,
            code=derivation.code,
            reason=derivation.reason,
            severity=derivation.severity,
            rule_id=rule.get("rule_id"),
            rule_ids=rule.get("rule_ids") or [],
            kind=(derivation.scope or {}).get("kind"),
            scope=derivation.scope,
            guards=list(derivation.guards),
            warnings=list(derivation.warnings),
            ttl_options=list(user_allowlist.TTL_OPTIONS),
            default_ttl_days=user_allowlist.DEFAULT_TTL_DAYS,
            existing_entry_id=existing_id,
        )

    @app.route("/api/allowlist", methods=["POST"])
    def api_allowlist_create():
        payload = request.get_json(silent=True)
        if payload is None:
            return jsonify(error="body must be valid JSON"), 400
        req, error = user_allowlist.validate_create_request(payload)
        if error or req is None:
            return jsonify(error=error or "invalid request"), 400

        record = _allowlist_record(req["seq"])
        if record is None:
            return jsonify(
                error="finding is no longer buffered; reload the dashboard"
            ), 404
        if str(record.get("timestamp") or "") != req["timestamp"]:
            return jsonify(error="finding changed; reload the dashboard"), 409

        derivation = user_allowlist.derive_scope_from_record(
            record, _allowlist_thresholds()
        )
        if not derivation.eligible or derivation.scope is None:
            return jsonify(
                error=derivation.reason or "finding is not eligible",
                code=derivation.code,
            ), 409
        fingerprint = user_allowlist.fingerprint_scope(derivation.scope)

        if not allowlist_slot.acquire(blocking=False):
            return jsonify(error="another allow-list change is in progress"), 429
        try:
            snapshot = user_allowlist.load_snapshot(allowlist_path, force=True)
            if snapshot.status not in {"ok", "missing"} or snapshot.invalid_entries:
                return jsonify(
                    error="allow-list file is unreadable; fix or remove it"
                ), 503
            now = datetime.now(UTC)
            entries = _prune_disabled(list(snapshot.entries), now)
            current = user_allowlist.AllowlistSnapshot(
                entries=tuple(entries), revision="write", status="ok"
            )
            for entry in user_allowlist.active_entries(current, now):
                if entry.get("fingerprint") == fingerprint:
                    return jsonify(
                        error="an active mute already covers this finding",
                        code="duplicate_entry",
                        existing_id=entry.get("id"),
                    ), 409
            if len(entries) >= user_allowlist.MAX_ENTRIES:
                return jsonify(error="allow-list is full", code="allowlist_full"), 409
            try:
                entry = user_allowlist.build_entry(
                    derivation, ttl_days=req["ttl_days"], reason=req["reason"]
                )
            except ValueError as exc:
                return jsonify(error=str(exc), code="invalid_scope"), 409
            if not _write_allowlist([*entries, entry], now):
                return jsonify(error="allow-list write failed"), 503
            return jsonify(entry=entry, message="Allow-list entry created."), 201
        finally:
            allowlist_slot.release()

    @app.route("/api/allowlist/<entry_id>", methods=["DELETE"])
    def api_allowlist_delete(entry_id: str):
        try:
            parsed_id = uuid.UUID(entry_id)
        except ValueError, AttributeError, TypeError:
            return jsonify(error="entry id must be a UUID4"), 400
        if parsed_id.version != 4:
            return jsonify(error="entry id must be a UUID4"), 400
        if not allowlist_slot.acquire(blocking=False):
            return jsonify(error="another allow-list change is in progress"), 429
        try:
            snapshot = user_allowlist.load_snapshot(allowlist_path, force=True)
            if snapshot.status == "missing":
                return jsonify(error="allow-list entry not found"), 404
            if snapshot.status != "ok" or snapshot.invalid_entries:
                return jsonify(
                    error="allow-list file is unreadable; fix or remove it"
                ), 503
            entries = [dict(entry) for entry in snapshot.entries]
            target = next(
                (entry for entry in entries if entry.get("id") == str(parsed_id)), None
            )
            if target is None:
                return jsonify(error="allow-list entry not found"), 404
            if target.get("enabled"):
                now = datetime.now(UTC)
                target["enabled"] = False
                target["disabled_at"] = now.isoformat(timespec="seconds")
                target["disabled_by"] = "dashboard"
                if not _write_allowlist(entries, now):
                    return jsonify(error="allow-list write failed"), 503
            return jsonify(entry=target)
        finally:
            allowlist_slot.release()

    @app.route("/api/status")
    def api_status():
        data = dict(status_cache.get())
        _first, last = traffic_tailer.key_range()
        try:
            defaults = get_defaults()
            sample_interval = defaults["traffic"].get("sample_interval_seconds")
        except DefaultsError:
            defaults, sample_interval = {}, None
        data["sample_age"] = round(time.time() - last, 1) if last else None
        data["sample_interval"] = sample_interval
        data["runner"] = runner.snapshot()
        data["external_boot"] = app.config.get("external_boot") or []
        return jsonify(data)

    @app.route("/api/config-defaults")
    def api_config_defaults():
        try:
            return jsonify(get_defaults(force=True))
        except DefaultsError as exc:
            # YAML parser text can name local paths; keep it in the console.
            console.append("err", f"[UI] config defaults failed: {exc}")
            return jsonify(error="configuration defaults unavailable"), 500

    return app


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="SOC Agent web dashboard (runs checkstat.py for you)."
    )
    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_PORT,
        help=f"localhost port to serve on (default {DEFAULT_PORT})",
    )
    parser.add_argument(
        "--no-browser",
        action="store_true",
        help="do not open the browser automatically",
    )
    parser.add_argument(
        "--allow-remote-ollama",
        action="store_true",
        help="allow an Ollama URL on a non-loopback host "
        "(enables SSRF exposure; default: loopback only)",
    )
    args = parser.parse_args(argv)

    with socket.socket() as probe:
        try:
            probe.bind(("127.0.0.1", args.port))
        except OSError:
            print(
                f"[UI] port {args.port} is busy. "
                f"Run a different instance with: soc_ui.py --port {args.port + 1}",
                file=sys.stderr,
            )
            return 1
    if not CHECKSTAT_PATH.is_file():
        print(
            f"[UI] {CHECKSTAT_PATH} not found - run soc_ui.py from C:\\SOCAgent",
            file=sys.stderr,
        )
        return 1

    console = ConsoleLog()
    for warning in install_security.install_warnings(SCRIPT_DIR):
        console.append("sys", f"[UI] SECURITY: {warning}")
        print(f"[UI] SECURITY: {warning}", file=sys.stderr)
    traffic_tailer = FileTailer(
        SCRIPT_DIR / "soc_traffic_history.jsonl",
        TRAFFIC_ROWS_MAX,
        key_field="timestamp",
    )
    findings_tailer = FileTailer(
        SCRIPT_DIR / "soc_findings.jsonl", FINDINGS_MAX, attach_seq=True
    )
    runner = AgentRunner(console)
    try_adopt_orphan(runner, console)
    status_cache = StatusCache(
        load_yaml_defaults, traffic_tailer, allow_remote_ollama=args.allow_remote_ollama
    )
    status_cache.start()
    auth_token = secrets.token_urlsafe(32)
    app = create_app(
        runner,
        console,
        traffic_tailer,
        findings_tailer,
        status_cache,
        auth_token=auth_token,
        allow_remote_ollama=args.allow_remote_ollama,
    )
    app.config["external_boot"] = external_process_pids(
        external_checkstat_processes()["processes"]
    )
    if app.config["external_boot"]:
        console.append(
            "sys",
            "[UI] warning: another checkstat.py process is "
            "already running: "
            + ", ".join(str(p["pid"]) for p in app.config["external_boot"]),
        )

    # The token rides in the URL fragment: browsers never send fragments to
    # the server, so the secret does not appear in access logs or Referer.
    url = f"http://127.0.0.1:{args.port}/#token={auth_token}"
    print(f"[UI] SOC Agent dashboard: {url}  (Ctrl+C stops it and the agent)")
    if not args.no_browser:
        threading.Timer(0.8, webbrowser.open, (url,)).start()
    try:
        app.run(
            host="127.0.0.1",
            port=args.port,
            threaded=True,
            debug=False,
            use_reloader=False,
        )
    finally:
        status_cache.stop()
        if runner.snapshot()["state"] in (STATE_RUNNING, STATE_STOPPING):
            print("[UI] stopping agent on exit")
            runner.stop(block=True, timeout=10)
    return 0


if __name__ == "__main__":
    sys.exit(main())
