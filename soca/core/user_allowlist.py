"""Scoped, expiring user allow-list for SOCA findings.

The dashboard owns the JSON file; the agent only reads it. A muting decision
is an annotation on a finding record, never a suppression: the record is
always logged, its deterministic severity is never changed, and an entry can
only match a compound scope (rule + verified process + rate/endpoint band).

Fail-closed rules:
- an unreadable, corrupt, oversized, or unsupported file disables all mutes;
- malformed entries are ignored individually;
- inconclusive process identity, missing rate/share data, or a CRITICAL
  finding reopens the finding;
- the file's ``guards`` flags are audit data and are never trusted.
"""

from __future__ import annotations

import contextlib
import hashlib
import ipaddress
import json
import math
import os
import re
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from soca import paths

DEFAULT_ALLOWLIST_FILE = paths.DEFAULT_ALLOWLIST_FILE

SCHEMA_VERSION = 1
MAX_FILE_BYTES = 256 * 1024
MAX_ENTRIES = 200
MAX_REASON_CHARS = 200
MAX_PROCESS_NAMES = 8
MAX_PROCESS_NAME_CHARS = 260
TTL_OPTIONS = (7, 30, 90)
DEFAULT_TTL_DAYS = 30
MIN_SHARE = 0.5
DEFAULT_ABSOLUTE_FLOOR = 25000.0
DEFAULT_UDP_FLOOR = 500.0
BASELINE_DRIFT_FACTOR = 4.0
BASELINE_DRIFT_FLOOR = 1000.0
MAX_RATE = 1e9

SEVERITY_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
TRAFFIC_RULE = "NET-T10"
ROW_SCOPE_SPECS = {
    # rule -> which endpoint fields a mute must pin down
    "NET-001": {"remote_ip": False, "foreign_port": True},
    "NET-002": {"remote_ip": True, "foreign_port": True},
    "NET-007": {"remote_ip": False, "foreign_port": True},
    "NET-009": {"remote_ip": True, "foreign_port": True},
}
COFIRE_GUARD_RULES = frozenset(
    {
        "NET-T01",
        "NET-T02",
        "NET-T03",
        "NET-T04",
        "NET-T08",
        "NET-T09",
        "NET-T11",
        "NET-T12",
        "NET-T13",
        "NET-T14",
    }
)

_PROCESS_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._ -]*$")


# ---------------------------------------------------------------------------
# Time / value helpers
# ---------------------------------------------------------------------------


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _parse_iso(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(UTC)


def _iso(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="seconds")


def _finite_number(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    number = float(value)
    return number if math.isfinite(number) else None


def _int_or_none(
    value: object, *, minimum: int | None = None, maximum: int | None = None
) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    if minimum is not None and value < minimum:
        return None
    if maximum is not None and value > maximum:
        return None
    return value


def _has_control_chars(text: str) -> bool:
    return any(ord(ch) < 0x20 and ch not in "\n\r\t" for ch in text)


# ---------------------------------------------------------------------------
# Data shapes
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AllowlistSnapshot:
    entries: tuple[dict[str, Any], ...] = ()
    revision: str = "missing"
    mtime_ns: int | None = None
    status: str = "missing"
    invalid_entries: int = 0


@dataclass(frozen=True)
class ScopeDerivation:
    eligible: bool
    code: str | None
    reason: str | None
    scope: dict[str, Any] | None
    source: dict[str, Any]
    severity: str
    guards: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()


@dataclass(frozen=True)
class Observation:
    kind: str
    rule_ids: tuple[str, ...]
    severity: str
    process_name: str = ""
    pid: int | None = None
    rate: float | None = None
    baseline_rate: float | None = None
    udp_errors: float | None = None
    udp_socket_count: int | None = None
    top_owner_counts: tuple[tuple[str, int], ...] = ()
    identity_by_name: tuple[tuple[str, bool | None], ...] = ()
    cofire_rules: tuple[str, ...] = ()
    remote_ip: str | None = None
    foreign_port: int | None = None
    local_ports: tuple[int, ...] = ()
    protocols: tuple[str, ...] = ()


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def _validate_names(raw: object) -> tuple[list[str] | None, str | None]:
    if not isinstance(raw, list) or not raw:
        return None, "process_names must be a non-empty list"
    names: list[str] = []
    for value in raw:
        if not isinstance(value, str):
            return None, "process_names must contain strings"
        name = value.strip().lower()
        if not name or len(name) > MAX_PROCESS_NAME_CHARS:
            return None, "process_names contains an invalid name"
        if not _PROCESS_NAME_RE.fullmatch(name):
            return None, "process_names contains an invalid name"
        if name not in names:
            names.append(name)
    if len(names) > MAX_PROCESS_NAMES:
        return None, f"process_names must contain at most {MAX_PROCESS_NAMES} names"
    return names, None


def _validate_protocols(raw: object) -> tuple[list[str] | None, str | None]:
    if not isinstance(raw, list) or not raw:
        return None, "protocols must be a non-empty list"
    values: list[str] = []
    for value in raw:
        if not isinstance(value, str):
            return None, "protocols must contain strings"
        proto = value.strip().upper()
        if proto not in {"TCP", "UDP"}:
            return None, "protocols must be TCP or UDP"
        if proto not in values:
            values.append(proto)
    return sorted(values), None


def _validate_scope(scope: object) -> tuple[dict[str, Any] | None, str | None]:
    if not isinstance(scope, dict):
        return None, "scope must be an object"
    kind = scope.get("kind")
    raw_rules = scope.get("rule_ids")
    if not isinstance(raw_rules, list) or not raw_rules:
        return None, "scope.rule_ids must be a non-empty list"
    rules = sorted({str(value).strip() for value in raw_rules if str(value).strip()})
    if not rules:
        return None, "scope.rule_ids must be a non-empty list"

    names, err = _validate_names(scope.get("process_names"))
    if err or names is None:
        return None, err or "process_names is invalid"

    severity = str(scope.get("severity_at_mute") or "").strip().upper()
    if severity not in SEVERITY_ORDER or severity == "CRITICAL":
        return None, "severity_at_mute must be HIGH, MEDIUM, LOW or INFO"

    pids_raw = scope.get("pids_at_mute") or []
    if not isinstance(pids_raw, list):
        return None, "pids_at_mute must be a list"
    pids = []
    for value in pids_raw:
        pid = _int_or_none(value, minimum=1)
        if pid is None:
            return None, "pids_at_mute must contain positive integers"
        pids.append(pid)

    normalized: dict[str, Any] = {
        "kind": kind,
        "rule_ids": rules,
        "severity_at_mute": severity,
        "process_names": names,
        "pids_at_mute": pids,
        "remote_ip": None,
        "foreign_port": None,
        "local_port": None,
        "protocols": [],
        "min_share": None,
        "rate_min": None,
        "rate_max": None,
        "baseline_rate_at_mute": None,
        "absolute_ceiling": None,
    }

    if kind == "traffic_udp":
        if rules != [TRAFFIC_RULE]:
            return None, f"traffic_udp scope must use {TRAFFIC_RULE}"
        min_share = _finite_number(scope.get("min_share"))
        if min_share is None or not (MIN_SHARE <= min_share <= 1.0):
            return None, "min_share must be between 0.5 and 1.0"
        rate_max = _finite_number(scope.get("rate_max"))
        if rate_max is None or not (0 < rate_max < MAX_RATE):
            return None, "rate_max is invalid"
        for key in ("rate_max", "rate_min"):
            value = scope.get(key)
            if value is not None and _finite_number(value) is None:
                return None, f"{key} is invalid"
        rate_min = scope.get("rate_min")
        rate_min = _finite_number(rate_min) if rate_min is not None else None
        baseline = scope.get("baseline_rate_at_mute")
        baseline = _finite_number(baseline) if baseline is not None else None
        ceiling = _int_or_none(scope.get("absolute_ceiling"), minimum=1)
        protocols, err = _validate_protocols(scope.get("protocols"))
        if err or protocols is None or protocols != ["UDP"]:
            return None, "traffic_udp scope must include UDP only"
        for key in ("remote_ip", "foreign_port", "local_port"):
            if scope.get(key) is not None:
                return None, "traffic_udp scope must not pin an endpoint"
        normalized.update(
            {
                "min_share": min_share,
                "rate_min": rate_min,
                "rate_max": rate_max,
                "baseline_rate_at_mute": baseline,
                "absolute_ceiling": ceiling
                if ceiling is not None
                else int(DEFAULT_ABSOLUTE_FLOOR),
                "protocols": protocols,
            }
        )
        return normalized, None

    if kind == "row_endpoint":
        if not set(rules) <= set(ROW_SCOPE_SPECS):
            return None, "row_endpoint scope uses an unsupported rule"
        protocols, err = _validate_protocols(scope.get("protocols"))
        if err or protocols is None:
            return None, err or "protocols is invalid"
        remote_raw = scope.get("remote_ip")
        remote_ip = None
        if remote_raw is not None:
            if not isinstance(remote_raw, str) or not remote_raw.strip():
                return None, "remote_ip is invalid"
            try:
                remote_ip = str(ipaddress.ip_address(remote_raw.strip()))
            except ValueError:
                return None, "remote_ip is invalid"
            if not any(ROW_SCOPE_SPECS[rule]["remote_ip"] for rule in rules):
                return None, "remote_ip is not allowed for this rule"
        foreign_port = scope.get("foreign_port")
        foreign_port = (
            _int_or_none(foreign_port, minimum=1, maximum=65535)
            if foreign_port is not None
            else None
        )
        if scope.get("foreign_port") is not None and foreign_port is None:
            return None, "foreign_port is invalid"
        local_port = scope.get("local_port")
        local_port = (
            _int_or_none(local_port, minimum=1, maximum=65535)
            if local_port is not None
            else None
        )
        if scope.get("local_port") is not None and local_port is None:
            return None, "local_port is invalid"
        if remote_ip is None and foreign_port is None and local_port is None:
            return None, "row_endpoint scope must pin an endpoint"
        if (
            not any(ROW_SCOPE_SPECS[rule]["foreign_port"] for rule in rules)
            and foreign_port is not None
        ):
            return None, "foreign_port is not allowed for this rule"
        normalized.update(
            {
                "remote_ip": remote_ip,
                "foreign_port": foreign_port,
                "local_port": local_port,
                "protocols": protocols,
            }
        )
        return normalized, None

    return None, "scope.kind is unsupported"


def validate_entry(
    raw: object, now: datetime | None = None
) -> tuple[dict[str, Any] | None, str | None]:
    """Validate and normalize one allow-list entry. Never raises."""
    if not isinstance(raw, dict):
        return None, "entry must be an object"

    try:
        parsed_id = uuid.UUID(str(raw.get("id") or ""))
    except ValueError, AttributeError, TypeError:
        return None, "id must be a UUID4"
    if parsed_id.version != 4:
        return None, "id must be a UUID4"

    ttl_days = raw.get("ttl_days")
    if (
        isinstance(ttl_days, bool)
        or not isinstance(ttl_days, int)
        or ttl_days not in TTL_OPTIONS
    ):
        return None, "ttl_days must be 7, 30 or 90"

    created = _parse_iso(raw.get("created_at"))
    expires = _parse_iso(raw.get("expires_at"))
    if created is None or expires is None:
        return None, "created_at/expires_at must be ISO-8601 with a timezone"
    if created > (now or _utcnow()) + timedelta(seconds=300):
        return None, "created_at is in the future"
    if expires <= created:
        return None, "expires_at must follow created_at"
    expected = timedelta(days=ttl_days)
    if abs((expires - created) - expected) > timedelta(seconds=300):
        return None, "expires_at does not match ttl_days"

    enabled = raw.get("enabled")
    if not isinstance(enabled, bool):
        return None, "enabled must be a boolean"

    scope, err = _validate_scope(raw.get("scope"))
    if err or scope is None:
        return None, err or "scope is invalid"

    reason = raw.get("reason", "")
    if reason is None:
        reason = ""
    if not isinstance(reason, str):
        return None, "reason must be a string"
    reason = reason.strip()
    if len(reason) > MAX_REASON_CHARS:
        return None, f"reason must be at most {MAX_REASON_CHARS} characters"
    if _has_control_chars(reason):
        return None, "reason has invalid characters"

    source = raw.get("source")
    source = source if isinstance(source, dict) else {}
    guards = raw.get("guards")
    guards = guards if isinstance(guards, dict) else {}
    fingerprint = raw.get("fingerprint")
    if not isinstance(fingerprint, str) or not fingerprint.strip():
        fingerprint = fingerprint_scope(scope)

    return {
        "id": str(parsed_id),
        "created_at": _iso(created),
        "expires_at": _iso(expires),
        "ttl_days": ttl_days,
        "created_by": str(raw.get("created_by") or "dashboard")[:64],
        "enabled": enabled,
        "reason": reason,
        "fingerprint": fingerprint,
        "source": source,
        "scope": scope,
        "guards": guards,
        "disabled_at": raw.get("disabled_at")
        if isinstance(raw.get("disabled_at"), str)
        else None,
        "disabled_by": raw.get("disabled_by")
        if isinstance(raw.get("disabled_by"), str)
        else None,
    }, None


def validate_create_request(
    payload: object,
) -> tuple[dict[str, Any] | None, str | None]:
    """Validate the dashboard's create request; the client sends no scope."""
    if not isinstance(payload, dict):
        return None, "request body must be a JSON object"
    if set(payload) - {"seq", "timestamp", "ttl_days", "reason"}:
        return None, "request body has unsupported fields"
    seq = payload.get("seq")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq <= 0:
        return None, "seq must be a positive integer"
    timestamp = payload.get("timestamp")
    if not isinstance(timestamp, str):
        return None, "timestamp must be a string"
    timestamp = timestamp.strip()
    if not timestamp or len(timestamp) > 64:
        return None, "timestamp is invalid"
    ttl_days = payload.get("ttl_days", DEFAULT_TTL_DAYS)
    if isinstance(ttl_days, bool) or ttl_days not in TTL_OPTIONS:
        return None, "ttl_days must be 7, 30 or 90"
    reason = payload.get("reason", "")
    if reason is None:
        reason = ""
    if not isinstance(reason, str):
        return None, "reason must be a string"
    reason = reason.strip()
    if len(reason) > MAX_REASON_CHARS:
        return None, f"reason must be at most {MAX_REASON_CHARS} characters"
    if _has_control_chars(reason):
        return None, "reason has invalid characters"
    return {
        "seq": seq,
        "timestamp": timestamp,
        "ttl_days": ttl_days,
        "reason": reason,
    }, None


def fingerprint_scope(scope: dict[str, Any]) -> str:
    text = json.dumps(scope, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------

_CACHE_LOCK = threading.Lock()
_CACHE: dict[str, Any] = {"path": None, "key": None, "snapshot": None}


def _empty_snapshot(
    status: str,
    *,
    revision: str = "missing",
    mtime_ns: int | None = None,
    invalid: int = 0,
) -> AllowlistSnapshot:
    return AllowlistSnapshot(
        entries=(),
        revision=revision,
        mtime_ns=mtime_ns,
        status=status,
        invalid_entries=invalid,
    )


def _cache_snapshot(path: Path, key: str, snapshot: AllowlistSnapshot) -> None:
    with _CACHE_LOCK:
        _CACHE["path"] = path
        _CACHE["key"] = key
        _CACHE["snapshot"] = snapshot


def load_snapshot(
    path: Path | str | None = None, *, force: bool = False
) -> AllowlistSnapshot:
    """Return a validated snapshot; any serious problem disables all mutes."""
    target = Path(path) if path is not None else DEFAULT_ALLOWLIST_FILE

    stat = None
    for attempt in range(3):
        try:
            stat = target.stat()
            break
        except FileNotFoundError:
            snapshot = _empty_snapshot("missing")
            _cache_snapshot(target, "missing", snapshot)
            return snapshot
        except OSError:
            time.sleep(0.05 * (attempt + 1))
    if stat is None:
        return _empty_snapshot("unreadable")

    key = f"{stat.st_mtime_ns}:{stat.st_size}"
    if not force:
        with _CACHE_LOCK:
            if (
                _CACHE["path"] == target
                and _CACHE["key"] == key
                and _CACHE["snapshot"] is not None
            ):
                return _CACHE["snapshot"]

    if stat.st_size > MAX_FILE_BYTES:
        snapshot = _empty_snapshot("oversized", revision=key, mtime_ns=stat.st_mtime_ns)
        _cache_snapshot(target, key, snapshot)
        return snapshot

    raw = None
    for attempt in range(3):
        try:
            raw = target.read_bytes()
            break
        except OSError:
            time.sleep(0.05 * (attempt + 1))
    if raw is None:
        return _empty_snapshot("unreadable", revision=key, mtime_ns=stat.st_mtime_ns)

    try:
        document = json.loads(raw.decode("utf-8"))
    except UnicodeDecodeError, ValueError:
        snapshot = _empty_snapshot(
            "unreadable", revision=key, mtime_ns=stat.st_mtime_ns
        )
        _cache_snapshot(target, key, snapshot)
        return snapshot

    if not isinstance(document, dict):
        snapshot = _empty_snapshot(
            "unreadable", revision=key, mtime_ns=stat.st_mtime_ns
        )
        _cache_snapshot(target, key, snapshot)
        return snapshot
    version = document.get("schema_version")
    if version != SCHEMA_VERSION:
        status = "unsupported_version" if version is not None else "unreadable"
        snapshot = _empty_snapshot(status, revision=key, mtime_ns=stat.st_mtime_ns)
        _cache_snapshot(target, key, snapshot)
        return snapshot
    raw_entries = document.get("entries")
    if not isinstance(raw_entries, list):
        snapshot = _empty_snapshot(
            "unreadable", revision=key, mtime_ns=stat.st_mtime_ns
        )
        _cache_snapshot(target, key, snapshot)
        return snapshot

    entries: list[dict[str, Any]] = []
    invalid = 0
    for raw_entry in raw_entries:
        entry, _error = validate_entry(raw_entry)
        if entry is None:
            invalid += 1
        else:
            entries.append(entry)

    snapshot = AllowlistSnapshot(
        entries=tuple(entries),
        revision=key,
        mtime_ns=stat.st_mtime_ns,
        status="ok",
        invalid_entries=invalid,
    )
    _cache_snapshot(target, key, snapshot)
    return snapshot


def active_entries(
    snapshot: AllowlistSnapshot | None, now: datetime | None = None
) -> tuple[dict[str, Any], ...]:
    if snapshot is None:
        return ()
    moment = now or _utcnow()
    active: list[dict[str, Any]] = []
    for entry in snapshot.entries:
        if not entry.get("enabled"):
            continue
        created = _parse_iso(entry.get("created_at"))
        expires = _parse_iso(entry.get("expires_at"))
        if created is None or expires is None:
            continue
        if created > moment + timedelta(seconds=300):
            continue
        if expires <= moment:
            continue
        active.append(entry)
    return tuple(active)


def _scope_process_names(snapshot: AllowlistSnapshot | None, kind: str) -> set[str]:
    names: set[str] = set()
    for entry in active_entries(snapshot):
        scope = entry.get("scope") or {}
        if scope.get("kind") == kind:
            names.update(scope.get("process_names") or ())
    return names


def traffic_scope_process_names(snapshot: AllowlistSnapshot | None) -> set[str]:
    return _scope_process_names(snapshot, "traffic_udp")


def row_scope_process_names(snapshot: AllowlistSnapshot | None) -> set[str]:
    return _scope_process_names(snapshot, "row_endpoint")


def has_rule(snapshot: AllowlistSnapshot | None, rule_id: str) -> bool:
    return any(
        rule_id in (entry.get("scope") or {}).get("rule_ids", ())
        for entry in active_entries(snapshot)
    )


# ---------------------------------------------------------------------------
# Scope derivation
# ---------------------------------------------------------------------------


def _record_rule_ids(record: dict[str, Any]) -> list[str]:
    rule = record.get("rule")
    if not isinstance(rule, dict):
        rule = {}
    raw = rule.get("rule_ids")
    if isinstance(raw, list) and raw:
        values = [str(value).strip() for value in raw if str(value).strip()]
    else:
        single = str(rule.get("rule_id") or "").strip()
        values = [single] if single else []
    return sorted(set(values))


def _record_severity(record: dict[str, Any]) -> str:
    rule = record.get("rule")
    if not isinstance(rule, dict):
        rule = {}
    return str(rule.get("severity") or "").strip().upper()


def _ineligible(
    code: str,
    reason: str,
    *,
    severity: str = "",
    source: dict[str, Any] | None = None,
    warnings: tuple[str, ...] = (),
) -> ScopeDerivation:
    return ScopeDerivation(
        eligible=False,
        code=code,
        reason=reason,
        scope=None,
        source=source or {},
        severity=severity,
        warnings=warnings,
    )


def _number(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    number = float(value)
    return number if math.isfinite(number) else None


def derive_scope_from_record(
    record: object,
    thresholds: dict[str, Any] | None = None,
) -> ScopeDerivation:
    """Derive the exact mute scope the agent will enforce from one finding."""
    if not isinstance(record, dict):
        return _ineligible("invalid_record", "The finding record is invalid.")
    rule_ids = _record_rule_ids(record)
    severity = _record_severity(record)
    if not rule_ids:
        return _ineligible("unsupported_rule", "The finding has no rule id.")
    if severity not in SEVERITY_ORDER:
        return _ineligible(
            "unsupported_severity",
            "The finding severity is unknown.",
            severity=severity,
        )
    if severity == "CRITICAL":
        return _ineligible(
            "critical_not_mutable",
            "CRITICAL findings can never be muted.",
            severity=severity,
        )

    if rule_ids == [TRAFFIC_RULE]:
        return _derive_traffic(record, thresholds or {}, severity)
    if set(rule_ids) <= set(ROW_SCOPE_SPECS):
        return _derive_row(record, rule_ids, severity)
    return _ineligible(
        "unsupported_rule",
        "This finding type cannot be added to the allow-list.",
        severity=severity,
    )


def _parse_traffic_owners(
    traffic: dict[str, Any],
) -> list[tuple[str, int, int]]:
    """Parse (name, pid, count), dedupe by PID, and sort deterministically."""
    owners: list[tuple[str, int, int]] = []
    seen_pids: set[int] = set()
    for item in traffic.get("udp_top_pids") or ():
        if not isinstance(item, dict):
            continue
        pid = _int_or_none(item.get("pid"), minimum=1)
        count = _int_or_none(item.get("count"), minimum=1)
        name = str(item.get("process_name") or "").strip().lower()
        if pid is None or count is None or not name or name == "unknown":
            continue
        if pid in seen_pids:
            continue
        seen_pids.add(pid)
        owners.append((name, pid, count))
    owners.sort(key=lambda item: (-item[2], item[0], item[1]))
    return owners


def _aggregate_owners(
    owners: list[tuple[str, int, int]],
) -> list[dict[str, Any]]:
    """Aggregate per-PID owners by process name, ranked by total sockets."""
    by_name: dict[str, dict[str, Any]] = {}
    for name, pid, count in owners:
        entry = by_name.setdefault(
            name, {"process_name": name, "count": 0, "pids": []}
        )
        entry["count"] += count
        entry["pids"].append((pid, count))
    ranked: list[dict[str, Any]] = []
    for entry in by_name.values():
        pids = [
            pid
            for pid, _count in sorted(
                entry["pids"], key=lambda item: (-item[1], item[0])
            )
        ]
        ranked.append({
            "process_name": entry["process_name"],
            "count": entry["count"],
            "pids": pids,
        })
    ranked.sort(key=lambda item: (-item["count"], item["process_name"]))
    return ranked


def _traffic_denominator(
    traffic: dict[str, Any], owners: list[tuple[str, int, int]]
) -> tuple[int | None, str | None, bool]:
    """Return (denominator, source, approximate).

    Prefer the persisted UDP socket count; otherwise use the sampled top-3
    owners, matching the agent's observation.
    """
    persisted = _int_or_none(traffic.get("udp_socket_count"), minimum=1)
    if persisted is not None:
        return persisted, "udp_socket_count", False
    fallback = sum(count for _name, _pid, count in owners[:3])
    if fallback <= 0:
        return None, None, True
    return fallback, "top_owners", True


def _derive_traffic(
    record: dict[str, Any], thresholds: dict[str, Any], severity: str
) -> ScopeDerivation:
    if str(record.get("source") or "") != "traffic":
        return _ineligible(
            "unsupported_rule",
            "The finding is not a traffic finding.",
            severity=severity,
        )
    traffic = record.get("traffic")
    if not isinstance(traffic, dict):
        traffic = {}
    rate = _number(traffic.get("udp_datagrams_per_second"))
    baseline = _number(traffic.get("baseline_rate"))
    errors = _number(traffic.get("udp_errors_per_second"))
    owners = _parse_traffic_owners(traffic)
    if not owners:
        return _ineligible(
            "no_process_attribution",
            "The UDP traffic cannot be attributed to one process.",
            severity=severity,
        )
    ranked = _aggregate_owners(owners)
    top = ranked[0]
    top_name = top["process_name"]
    top_count = top["count"]
    top_pids = list(top["pids"])
    second = ranked[1] if len(ranked) > 1 else None
    if second is not None and second["count"] >= top_count:
        return _ineligible(
            "ambiguous_udp_owner",
            f"{top_name} ({top_count}) and {second['process_name']} "
            f"({second['count']}) share the UDP sockets; the owner is ambiguous.",
            severity=severity,
        )
    denominator, denominator_source, approximate = _traffic_denominator(
        traffic, owners
    )
    if denominator is None or denominator <= 0:
        return _ineligible(
            "no_process_attribution",
            "The UDP owner share cannot be computed.",
            severity=severity,
        )
    share = min(1.0, top_count / denominator)
    if share < MIN_SHARE:
        prefix = "Based on the sampled owners, " if approximate else ""
        pid_note = (
            f", aggregated across {len(top_pids)} PIDs"
            if len(top_pids) > 1 else ""
        )
        return _ineligible(
            "owner_share_below_min",
            f"{prefix}{top_name} owns only {share:.0%} of UDP sockets"
            f"{pid_note}.",
            severity=severity,
        )
    if rate is None or rate <= 0:
        return _ineligible(
            "rate_unavailable",
            "The UDP rate is unavailable; the mute cannot be bounded.",
            severity=severity,
        )

    absolute_floor = _number(thresholds.get("udp_datagrams_absolute_floor"))
    if absolute_floor is None or absolute_floor <= 0:
        absolute_floor = DEFAULT_ABSOLUTE_FLOOR
    if rate >= absolute_floor:
        return _ineligible(
            "absolute_flood_floor",
            f"The rate is at or above the {absolute_floor:.0f}/s absolute flood floor.",
            severity=severity,
        )
    floor = _number(thresholds.get("udp_datagrams_per_second_floor"))
    if floor is None or floor <= 0:
        floor = DEFAULT_UDP_FLOOR
    rate_max = min(int(absolute_floor) - 1, max(math.ceil(rate * 1.5), int(floor * 2)))
    rate_max = max(1, rate_max)

    scope: dict[str, Any] = {
        "kind": "traffic_udp",
        "rule_ids": [TRAFFIC_RULE],
        "severity_at_mute": severity,
        "process_names": [top_name],
        "pids_at_mute": top_pids,
        "min_share": MIN_SHARE,
        "rate_min": None,
        "rate_max": rate_max,
        "baseline_rate_at_mute": baseline,
        "absolute_ceiling": int(absolute_floor),
        "remote_ip": None,
        "foreign_port": None,
        "local_port": None,
        "protocols": ["UDP"],
    }
    source = {
        "rule_id": TRAFFIC_RULE,
        "rule_ids": [TRAFFIC_RULE],
        "severity": severity,
        "timestamp": record.get("timestamp"),
        "snapshot": record.get("snapshot"),
        "process_names": [top_name],
        "pids": top_pids,
        "udp_rate": rate,
        "baseline_rate": baseline,
        "udp_errors_per_second": errors,
        "udp_socket_count": _int_or_none(
            traffic.get("udp_socket_count"), minimum=1
        ),
        "denominator": denominator,
        "denominator_source": denominator_source,
        "numerator": top_count,
        "share": round(share, 4),
        "top_owners": ranked,
        "ambiguity_candidate": second,
    }
    warnings: list[str] = []
    if approximate:
        warnings.append(
            "The UDP socket count was not recorded; the owner share is approximate."
        )
    if errors is not None and errors > 0:
        warnings.append(
            "UDP receive errors are non-zero now; the agent will reopen this finding."
        )
    guards = (
        f"Severity above {severity} reopens this finding.",
        f"UDP rate at or above {rate_max}/s reopens it "
        f"(the agent also enforces its {int(absolute_floor)}/s absolute flood floor).",
        "Any UDP receive errors, or an unavailable error counter, reopen it.",
        "The allowed process must own at least 50% of UDP sockets.",
        "Process identity must verify; inconclusive identity reopens it.",
        "Co-firing NET-T01/T02/T03/T04/T08/T09/T11/T12/T13/T14 reopens it.",
        "A large baseline shift reopens it.",
    )
    return ScopeDerivation(
        eligible=True,
        code=None,
        reason=None,
        scope=scope,
        source=source,
        severity=severity,
        guards=guards,
        warnings=tuple(warnings),
    )


def _derive_row(
    record: dict[str, Any], rule_ids: list[str], severity: str
) -> ScopeDerivation:
    group = record.get("group")
    process = record.get("process")
    group = group if isinstance(group, dict) else {}
    process = process if isinstance(process, dict) else {}
    name = str(group.get("process_name") or process.get("name") or "").strip().lower()
    if not name or name == "unknown" or not _PROCESS_NAME_RE.fullmatch(name):
        return _ineligible(
            "process_required",
            "A verified process name is required.",
            severity=severity,
        )
    pid = _int_or_none(group.get("pid"), minimum=1)
    try:
        foreign_port = _int_or_none(group.get("foreign_port"), minimum=1, maximum=65535)
    except TypeError, ValueError:
        foreign_port = None
    remote = str(group.get("remote_ip") or "").strip()
    remote_ip = None
    if remote:
        try:
            remote_ip = str(ipaddress.ip_address(remote))
        except ValueError:
            remote_ip = None

    protocols: set[str] = set()
    local_ports: set[int] = set()
    for entry in group.get("entries") or ():
        if not isinstance(entry, dict):
            continue
        proto = str(entry.get("protocol") or "").strip().upper()
        if proto in {"TCP", "UDP"}:
            protocols.add(proto)
        port = _int_or_none(entry.get("local_port"), minimum=1, maximum=65535)
        if port is not None:
            local_ports.add(port)
    if not protocols:
        return _ineligible(
            "no_protocol_evidence",
            "The connection protocols are unavailable.",
            severity=severity,
        )

    need_remote = any(ROW_SCOPE_SPECS[rule]["remote_ip"] for rule in rule_ids)
    need_port = any(ROW_SCOPE_SPECS[rule]["foreign_port"] for rule in rule_ids)
    if need_remote and remote_ip is None:
        return _ineligible(
            "no_endpoint",
            "This rule needs a specific remote IP, which is unavailable.",
            severity=severity,
        )
    if need_port and foreign_port is None:
        return _ineligible(
            "no_endpoint",
            "This rule needs a remote port, which is unavailable.",
            severity=severity,
        )
    if not need_remote and not need_port:
        return _ineligible(
            "no_endpoint",
            "This rule has no stable endpoint to scope.",
            severity=severity,
        )

    scope: dict[str, Any] = {
        "kind": "row_endpoint",
        "rule_ids": rule_ids,
        "severity_at_mute": severity,
        "process_names": [name],
        "pids_at_mute": [pid] if pid else [],
        "remote_ip": remote_ip if need_remote else None,
        "foreign_port": foreign_port if need_port else None,
        "local_port": None,
        "protocols": sorted(protocols),
        "min_share": None,
        "rate_min": None,
        "rate_max": None,
        "baseline_rate_at_mute": None,
        "absolute_ceiling": None,
    }
    source = {
        "rule_id": rule_ids[0],
        "rule_ids": rule_ids,
        "severity": severity,
        "timestamp": record.get("timestamp"),
        "snapshot": record.get("snapshot"),
        "process_names": [name],
        "pids": [pid] if pid else [],
        "remote_ip": remote_ip,
        "foreign_port": foreign_port,
        "local_ports": sorted(local_ports),
    }
    guards = (
        "Severity above the muted level reopens this finding.",
        "An additional rule on the same connection reopens it.",
        "Process identity must verify; inconclusive identity reopens it.",
    )
    return ScopeDerivation(
        eligible=True,
        code=None,
        reason=None,
        scope=scope,
        source=source,
        severity=severity,
        guards=guards,
    )


# ---------------------------------------------------------------------------
# Entry creation
# ---------------------------------------------------------------------------


def _default_guards(scope: dict[str, Any]) -> dict[str, Any]:
    return {
        "reopen_on_severity_increase": True,
        "reopen_on_rate_above_band": scope.get("kind") == "traffic_udp",
        "reopen_on_udp_errors": scope.get("kind") == "traffic_udp",
        "reopen_on_process_share_below_min": scope.get("kind") == "traffic_udp",
        "reopen_on_identity_failure": True,
        "reopen_on_baseline_drift": scope.get("kind") == "traffic_udp",
        "max_baseline_drift_factor": BASELINE_DRIFT_FACTOR,
        "reopen_on_cofire_rules": sorted(COFIRE_GUARD_RULES),
    }


def build_entry(
    derivation: ScopeDerivation,
    *,
    ttl_days: int = DEFAULT_TTL_DAYS,
    reason: str = "",
    now: datetime | None = None,
) -> dict[str, Any]:
    if not derivation.eligible or derivation.scope is None:
        raise ValueError(derivation.reason or "finding is not eligible")
    if isinstance(ttl_days, bool) or ttl_days not in TTL_OPTIONS:
        raise ValueError("ttl_days must be 7, 30 or 90")
    moment = (now or _utcnow()).astimezone(UTC)
    entry = {
        "id": str(uuid.uuid4()),
        "created_at": _iso(moment),
        "expires_at": _iso(moment + timedelta(days=ttl_days)),
        "ttl_days": ttl_days,
        "created_by": "dashboard",
        "enabled": True,
        "reason": str(reason or "").strip()[:MAX_REASON_CHARS],
        "fingerprint": fingerprint_scope(derivation.scope),
        "source": derivation.source,
        "scope": derivation.scope,
        "guards": _default_guards(derivation.scope),
        "disabled_at": None,
        "disabled_by": None,
    }
    normalized, error = validate_entry(entry)
    if error or normalized is None:
        raise ValueError(f"constructed entry is invalid: {error}")
    return normalized


# ---------------------------------------------------------------------------
# Atomic write
# ---------------------------------------------------------------------------


def write_allowlist_atomic(path: Path | str, payload: dict[str, Any]) -> bool:
    target = Path(path)
    try:
        rendered = json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
        encoded = rendered.encode("utf-8")
    except TypeError, ValueError:
        return False
    if len(encoded) > MAX_FILE_BYTES:
        return False
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(
            prefix=target.name + ".", suffix=".tmp", dir=str(target.parent)
        )
    except OSError:
        return False
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        last_error: OSError | None = None
        for attempt in range(3):
            try:
                os.replace(tmp_path, target)
                return True
            except OSError as exc:
                last_error = exc
                time.sleep(0.05 * (attempt + 1))
        if last_error is not None:
            raise last_error
        return False
    except OSError:
        with contextlib.suppress(OSError):
            tmp_path.unlink(missing_ok=True)
        return False


# ---------------------------------------------------------------------------
# Matching and guards
# ---------------------------------------------------------------------------


def _scope_matches(observation: Observation, scope: dict[str, Any]) -> bool:
    if scope.get("kind") != observation.kind:
        return False
    names = set(scope.get("process_names") or ())
    if observation.process_name.lower() not in names:
        return False
    if observation.kind == "traffic_udp":
        return "NET-T10" in observation.rule_ids and "UDP" in observation.protocols
    if not set(observation.rule_ids) & set(scope.get("rule_ids") or ()):
        return False
    if (
        scope.get("remote_ip") is not None
        and observation.remote_ip != scope["remote_ip"]
    ):
        return False
    if (
        scope.get("foreign_port") is not None
        and observation.foreign_port != scope["foreign_port"]
    ):
        return False
    if (
        scope.get("local_port") is not None
        and scope["local_port"] not in observation.local_ports
    ):
        return False
    protocols = set(scope.get("protocols") or ())
    return not protocols or set(observation.protocols) <= protocols


def _identity_failure(observation: Observation, scope: dict[str, Any]) -> str | None:
    names = set(scope.get("process_names") or ())
    present = [
        (name, verified)
        for name, verified in observation.identity_by_name
        if name in names
    ]
    if not present:
        return "identity_unverified"
    if any(verified is not True for _name, verified in present):
        return "identity_unverified"
    return None


def _guard_failure(
    observation: Observation,
    scope: dict[str, Any],
    absolute_floor: float,
    *,
    require_identity: bool = True,
    check_cofire: bool = True,
) -> str | None:
    current = SEVERITY_ORDER.get(observation.severity)
    muted_at = SEVERITY_ORDER.get(str(scope.get("severity_at_mute") or ""))
    if current is None or muted_at is None:
        return "severity_unknown"
    if current > muted_at or observation.severity == "CRITICAL":
        return "severity_increase"

    if observation.kind == "traffic_udp":
        if observation.rate is None:
            return "rate_unavailable"
        effective_max = min(
            float(scope.get("rate_max") or 0), max(1.0, float(absolute_floor) - 1.0)
        )
        if observation.rate >= effective_max:
            return "rate_above_band"
        if observation.udp_errors is None:
            return "udp_errors_unavailable"
        if observation.udp_errors > 0:
            return "udp_errors"
        if check_cofire:
            for rule in sorted(observation.cofire_rules):
                if rule in COFIRE_GUARD_RULES:
                    return f"cofire:{rule}"
        denominator = observation.udp_socket_count
        if denominator is None or denominator <= 0:
            denominator = sum(count for _name, count in observation.top_owner_counts)
        if denominator <= 0:
            return "share_unavailable"
        allowed = sum(
            count
            for name, count in observation.top_owner_counts
            if name in set(scope.get("process_names") or ())
        )
        minimum = float(scope.get("min_share") or MIN_SHARE)
        if allowed / denominator < minimum:
            return "process_share_below_min"
        if require_identity:
            identity = _identity_failure(observation, scope)
            if identity is not None:
                return identity
        baseline = observation.baseline_rate
        baseline_at_mute = scope.get("baseline_rate_at_mute")
        if baseline is not None and baseline_at_mute is not None:
            threshold = max(
                BASELINE_DRIFT_FACTOR * float(baseline_at_mute), BASELINE_DRIFT_FLOOR
            )
            if baseline > threshold:
                return "baseline_drift"
        return None

    extra = set(observation.rule_ids) - set(scope.get("rule_ids") or ())
    if extra:
        for rule in sorted(extra):
            if rule in COFIRE_GUARD_RULES:
                return f"cofire:{rule}"
        return "rule_set_changed"
    if require_identity:
        return _identity_failure(observation, scope)
    return None


def _disposition(
    entry: dict[str, Any], *, muted: bool, guard: str | None
) -> dict[str, Any]:
    return {
        "muted": muted,
        "allowlist_id": entry.get("id"),
        "reason": entry.get("reason") or "",
        "expires_at": entry.get("expires_at"),
        "matched_scope": dict(entry.get("scope") or {}),
        "guard_blocked": guard,
    }


def match_observation(
    observation: Observation | None,
    snapshot: AllowlistSnapshot | None,
    *,
    absolute_floor: float = DEFAULT_ABSOLUTE_FLOOR,
    now: datetime | None = None,
    require_identity: bool = True,
    check_cofire: bool = True,
) -> dict[str, Any] | None:
    """Return a disposition for the first matching entry, or ``None``."""
    if observation is None:
        return None
    entries = sorted(
        active_entries(snapshot, now),
        key=lambda entry: str(entry.get("created_at") or ""),
        reverse=True,
    )
    blocked: dict[str, Any] | None = None
    for entry in entries:
        scope = entry.get("scope") or {}
        if not _scope_matches(observation, scope):
            continue
        guard = _guard_failure(
            observation,
            scope,
            absolute_floor,
            require_identity=require_identity,
            check_cofire=check_cofire,
        )
        if guard is None:
            return _disposition(entry, muted=True, guard=None)
        if blocked is None:
            blocked = _disposition(entry, muted=False, guard=guard)
    return blocked


def _observation_from_record(record: object) -> Observation | None:
    """Build a display-time observation from a persisted finding record."""
    if not isinstance(record, dict):
        return None
    rule_ids = tuple(_record_rule_ids(record))
    severity = _record_severity(record)
    if not rule_ids or severity not in SEVERITY_ORDER:
        return None
    if rule_ids == (TRAFFIC_RULE,):
        if str(record.get("source") or "") != "traffic":
            return None
        traffic = record.get("traffic")
        if not isinstance(traffic, dict):
            return None
        owners = _parse_traffic_owners(traffic)
        if not owners:
            return None
        ranked = _aggregate_owners(owners)
        top = ranked[0]
        return Observation(
            kind="traffic_udp",
            rule_ids=(TRAFFIC_RULE,),
            severity=severity,
            process_name=top["process_name"],
            pid=top["pids"][0] if top["pids"] else None,
            rate=_number(traffic.get("udp_datagrams_per_second")),
            baseline_rate=_number(traffic.get("baseline_rate")),
            udp_errors=_number(traffic.get("udp_errors_per_second")),
            udp_socket_count=_int_or_none(
                traffic.get("udp_socket_count"), minimum=1
            ),
            top_owner_counts=tuple(
                (name, count) for name, _pid, count in owners[:3]
            ),
            protocols=("UDP",),
        )
    if not set(rule_ids) <= set(ROW_SCOPE_SPECS):
        return None
    group = record.get("group")
    process = record.get("process")
    group = group if isinstance(group, dict) else {}
    process = process if isinstance(process, dict) else {}
    name = str(
        group.get("process_name") or process.get("name") or ""
    ).strip().lower()
    if not name or name == "unknown":
        return None
    protocols: set[str] = set()
    local_ports: set[int] = set()
    for entry in group.get("entries") or ():
        if not isinstance(entry, dict):
            continue
        proto = str(entry.get("protocol") or "").strip().upper()
        if proto in {"TCP", "UDP"}:
            protocols.add(proto)
        port = _int_or_none(entry.get("local_port"), minimum=1, maximum=65535)
        if port is not None:
            local_ports.add(port)
    if not protocols:
        return None
    remote = str(group.get("remote_ip") or "").strip()
    remote_ip = None
    if remote:
        try:
            remote_ip = str(ipaddress.ip_address(remote))
        except ValueError:
            remote_ip = None
    return Observation(
        kind="row_endpoint",
        rule_ids=rule_ids,
        severity=severity,
        process_name=name,
        pid=_int_or_none(group.get("pid"), minimum=1),
        remote_ip=remote_ip,
        foreign_port=_int_or_none(
            group.get("foreign_port"), minimum=1, maximum=65535
        ),
        local_ports=tuple(sorted(local_ports)),
        protocols=tuple(sorted(protocols)),
    )


def match_record_for_display(
    record: object,
    snapshot: AllowlistSnapshot | None,
    *,
    absolute_floor: float = DEFAULT_ABSOLUTE_FLOOR,
    now: datetime | None = None,
) -> str | None:
    """Return the active entry id matching a persisted record for display.

    This is a display-only convenience for records written before the mute
    existed. It applies the scope, severity, rate, error, share and baseline
    guards, but not live identity or co-fire context (unavailable for a
    historical record). The agent remains authoritative for future sightings.
    """
    observation = _observation_from_record(record)
    if observation is None:
        return None
    disposition = match_observation(
        observation,
        snapshot,
        absolute_floor=absolute_floor,
        now=now,
        require_identity=False,
        check_cofire=False,
    )
    if disposition and disposition.get("muted"):
        return disposition.get("allowlist_id")
    return None


def describe_record(record: object) -> dict[str, Any]:
    """Return read-only evidence for the preview, even when ineligible.

    Never raises and never influences eligibility.
    """
    try:
        if not isinstance(record, dict):
            return {"kind": "unknown"}
        rule_ids = _record_rule_ids(record)
        severity = _record_severity(record)
        base = {
            "kind": "unknown",
            "source": record.get("source"),
            "rule_ids": rule_ids,
            "severity": severity,
            "timestamp": record.get("timestamp"),
        }
        if rule_ids == [TRAFFIC_RULE]:
            traffic = record.get("traffic")
            if not isinstance(traffic, dict):
                return {**base, "kind": "traffic_udp"}
            owners = _parse_traffic_owners(traffic)
            ranked = _aggregate_owners(owners)
            denominator, denominator_source, approximate = (
                _traffic_denominator(traffic, owners)
            )
            top_owners = []
            for item in ranked:
                share = None
                if denominator:
                    share = round(min(1.0, item["count"] / denominator), 4)
                top_owners.append({
                    "process_name": item["process_name"],
                    "count": item["count"],
                    "pids": item["pids"],
                    "share": share,
                })
            top = top_owners[0] if top_owners else None
            second = top_owners[1] if len(top_owners) > 1 else None
            top_count = top.get("count") if isinstance(top, dict) else None
            second_count = (
                second.get("count") if isinstance(second, dict) else None
            )
            ambiguous = bool(
                isinstance(top_count, (int, float))
                and isinstance(second_count, (int, float))
                and top_count <= second_count
            )
            return {
                **base,
                "kind": "traffic_udp",
                "process_names": [item["process_name"] for item in ranked],
                "pids": top["pids"] if top else [],
                "udp_rate": _number(traffic.get("udp_datagrams_per_second")),
                "baseline_rate": _number(traffic.get("baseline_rate")),
                "udp_errors_per_second": _number(
                    traffic.get("udp_errors_per_second")
                ),
                "udp_socket_count": _int_or_none(
                    traffic.get("udp_socket_count"), minimum=1
                ),
                "denominator": denominator,
                "denominator_source": denominator_source,
                "approximate": approximate,
                "numerator": top["count"] if top else None,
                "owner_share": top["share"] if top else None,
                "top_owners": top_owners,
                "ambiguity_candidate": second,
                "ambiguous": ambiguous,
            }
        if not set(rule_ids) <= set(ROW_SCOPE_SPECS):
            return base
        group = record.get("group")
        process = record.get("process")
        group = group if isinstance(group, dict) else {}
        process = process if isinstance(process, dict) else {}
        name = str(
            group.get("process_name") or process.get("name") or ""
        ).strip().lower()
        protocols: set[str] = set()
        local_ports: set[int] = set()
        for entry in group.get("entries") or ():
            if not isinstance(entry, dict):
                continue
            proto = str(entry.get("protocol") or "").strip().upper()
            if proto in {"TCP", "UDP"}:
                protocols.add(proto)
            port = _int_or_none(
                entry.get("local_port"), minimum=1, maximum=65535
            )
            if port is not None:
                local_ports.add(port)
        remote = str(group.get("remote_ip") or "").strip()
        remote_ip = None
        if remote:
            try:
                remote_ip = str(ipaddress.ip_address(remote))
            except ValueError:
                remote_ip = None
        return {
            **base,
            "kind": "row_endpoint",
            "process_name": name,
            "pid": _int_or_none(group.get("pid"), minimum=1),
            "remote_ip": remote_ip,
            "foreign_port": _int_or_none(
                group.get("foreign_port"), minimum=1, maximum=65535
            ),
            "protocols": sorted(protocols),
            "local_ports": sorted(local_ports),
        }
    except Exception:
        return {"kind": "unknown"}


def describe_scope(scope: dict[str, Any] | None) -> str:
    """Human-readable summary of the complete match scope."""
    if not isinstance(scope, dict):
        return ""
    names = ", ".join(scope.get("process_names") or ())
    if scope.get("kind") == "traffic_udp":
        share = float(scope.get("min_share") or MIN_SHARE)
        rate = scope.get("rate_max")
        rate_text = (
            f"{float(rate):.0f}/s"
            if isinstance(rate, (int, float)) else "the configured band"
        )
        return (
            f"Every {TRAFFIC_RULE} sighting where "
            f"{names or 'the allowed process'} owns at least {share:.0%} of "
            f"UDP sockets and the rate is below {rate_text}."
        )
    if scope.get("kind") == "row_endpoint":
        rules = ", ".join(scope.get("rule_ids") or ())
        parts: list[str] = []
        if scope.get("remote_ip"):
            parts.append(str(scope["remote_ip"]))
        if scope.get("foreign_port"):
            parts.append(f"port {scope['foreign_port']}")
        target = ", ".join(parts) or "the described endpoint"
        protocols = ", ".join(scope.get("protocols") or ())
        return (
            f"Every {rules or 'matching rule'} connection from "
            f"{names or 'the allowed process'} to {target} over "
            f"{protocols or 'the described protocol'}."
        )
    return ""
