"""Active network-health probes for the attack-vs-ISP question (H8).

The module measures the default gateway and a small set of external anchors,
then classifies the *symptom*:

- ``LOCAL_LINK``       gateway is degraded/unreachable
- ``UPSTREAM_ISP``     gateway is fine but every external anchor is degraded
- ``DESTINATION_PATH`` only some external anchors are degraded
- ``RESPONSIVE``       measured paths respond within thresholds
- ``UNKNOWN``          not enough evidence (or probes are blocked)

This is a bounded mitigation, not proof. Packets dropped upstream of the NIC
are invisible to every local measurement, and ISP congestion cannot be
separated from an upstream DDoS from host-side data alone. The report, the
dashboard, and ``CAVEAT`` all say so explicitly.

Standard library only; every public call is failure-tolerant and returns
JSON-safe data. ICMP echo and gateway discovery use documented Windows APIs
and work unelevated. IPv6 targets use the TCP fallback.
"""

from __future__ import annotations

import contextlib
import ctypes
import ipaddress
import json
import math
import os
import socket
import struct
import tempfile
import threading
import time
from copy import deepcopy
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from soca import paths

SCHEMA_VERSION = 1
RESULT_FILE = "soc_network_health.json"
DEFAULT_RESULT_PATH = paths.DEFAULT_NETWORK_HEALTH_FILE
CAVEAT = (
    "Active probes classify path symptoms only. They cannot prove an upstream "
    "DDoS and cannot see packets dropped before the NIC or inside the ISP."
)
VERDICTS = (
    "RESPONSIVE",
    "LOCAL_LINK",
    "UPSTREAM_ISP",
    "DESTINATION_PATH",
    "UNKNOWN",
)

DEFAULT_OPTIONS: dict[str, Any] = {
    "enabled": True,
    "interval_seconds": 60,
    "timeout_ms": 1000,
    "probes_per_target": 4,
    "degraded_loss_pct": 20.0,
    "degraded_jitter_ms": 80.0,
    "degraded_rtt_ms": 500.0,
    "gateway": "auto",
    "gateway_tcp_port": None,
    "targets": [
        {"host": "1.1.1.1", "port": 443, "label": "Cloudflare"},
        {"host": "8.8.8.8", "port": 443, "label": "Google"},
    ],
    "file_max_age_seconds": 180,
}

_ON_WINDOWS = os.name == "nt"
_ICMP_PAYLOAD = b"SOCA-network-health"

_IP_SUCCESS = 0
_IP_REQ_TIMED_OUT = 11010
_IP_DEST_NET_UNREACHABLE = 11002
_IP_DEST_HOST_UNREACHABLE = 11003
_IP_DEST_PROT_UNREACHABLE = 11004
_IP_DEST_PORT_UNREACHABLE = 11005
_IP_TTL_EXPIRED_TRANSIT = 11013
_IP_GENERAL_FAILURE = 11050

_ICMP_ERRORS = {
    _IP_REQ_TIMED_OUT: "timeout",
    _IP_DEST_NET_UNREACHABLE: "destination network unreachable",
    _IP_DEST_HOST_UNREACHABLE: "destination host unreachable",
    _IP_DEST_PROT_UNREACHABLE: "destination protocol unreachable",
    _IP_DEST_PORT_UNREACHABLE: "destination port unreachable",
    _IP_TTL_EXPIRED_TRANSIT: "ttl expired",
    _IP_GENERAL_FAILURE: "general failure",
}

if _ON_WINDOWS:
    _iphlpapi = ctypes.WinDLL("iphlpapi", use_last_error=True)
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
else:  # pragma: no cover - exercised by the non-Windows fallback tests
    _iphlpapi = None
    _kernel32 = None


class _IpOptionInformation(ctypes.Structure):
    _fields_ = [
        ("Ttl", ctypes.c_ubyte),
        ("Tos", ctypes.c_ubyte),
        ("Flags", ctypes.c_ubyte),
        ("OptionsSize", ctypes.c_ubyte),
        ("OptionsData", ctypes.c_void_p),
    ]


class _IcmpEchoReply(ctypes.Structure):
    _fields_ = [
        ("Address", ctypes.c_uint32),
        ("Status", ctypes.c_uint32),
        ("RoundTripTime", ctypes.c_uint32),
        ("DataSize", ctypes.c_ushort),
        ("Reserved", ctypes.c_ushort),
        ("Data", ctypes.c_void_p),
        ("Options", _IpOptionInformation),
    ]


if _ON_WINDOWS:
    _iphlpapi.IcmpCreateFile.restype = ctypes.c_void_p
    _iphlpapi.IcmpSendEcho.argtypes = [
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_ushort,
        ctypes.POINTER(_IpOptionInformation),
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
    ]
    _iphlpapi.IcmpSendEcho.restype = ctypes.c_uint32
    _iphlpapi.IcmpCloseHandle.argtypes = [ctypes.c_void_p]
    _iphlpapi.IcmpCloseHandle.restype = ctypes.c_int
    _iphlpapi.GetIpForwardTable.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.c_int,
    ]
    _iphlpapi.GetIpForwardTable.restype = ctypes.c_uint32


@dataclass
class ProbeAttempt:
    probe: str                  # "icmp" | "tcp"
    ok: bool
    rtt_ms: float | None
    error: str | None = None
    refused: bool = False       # TCP RST still proves path reachability


@dataclass
class ProbeSummary:
    host: str
    port: int | None
    label: str
    sent: int
    received: int
    loss_pct: float
    rtt_ms_min: float | None
    rtt_ms_avg: float | None
    rtt_ms_max: float | None
    jitter_ms: float | None
    probe: str                  # "icmp" | "tcp" | "none"
    reachable: bool
    healthy: bool
    error: str | None = None


@dataclass
class NetworkAssessment:
    verdict: str
    reason: str
    confidence: str             # "high" | "medium" | "low" | "none"
    summary: str
    caveat: str
    gateway: ProbeSummary | None
    gateway_status: str
    targets: list[ProbeSummary]
    targets_up: int
    targets_healthy: int
    targets_total: int
    local_link_ok: bool | None
    external_ok: bool | None


def default_options() -> dict[str, Any]:
    """A fresh copy of the built-in network-health options."""
    return deepcopy(DEFAULT_OPTIONS)


def _now_iso() -> str:
    # Match checkstat's report timestamps (local timezone, not UTC).
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _finite(value: Any) -> float | None:
    try:
        number = float(value)
    except (OverflowError, TypeError, ValueError):
        return None
    return number if math.isfinite(number) else None


def _clip(value: Any, limit: int) -> str:
    text = str(value or "").replace("\r", " ").replace("\n", " ").strip()
    return text[:limit]


def _icmp_error(status: int) -> str:
    return _ICMP_ERRORS.get(int(status), f"icmp status {int(status)}")


def probe_icmp(
    host: str,
    timeout_ms: int,
    payload: bytes = _ICMP_PAYLOAD,
) -> ProbeAttempt:
    """One IPv4 ICMP echo via the documented ``IcmpSendEcho`` API."""
    if not _ON_WINDOWS or _iphlpapi is None:
        return ProbeAttempt("icmp", False, None, "ICMP echo requires Windows")
    try:
        address = ipaddress.IPv4Address(str(host))
    except ValueError:
        return ProbeAttempt("icmp", False, None, "ICMP requires an IPv4 literal")
    handle = _iphlpapi.IcmpCreateFile()
    if not handle:
        return ProbeAttempt("icmp", False, None, "IcmpCreateFile failed")
    try:
        packed = struct.pack("<I", int(address))
        address_value = struct.unpack("<I", packed)[0]
        data = ctypes.c_char_p(payload)
        reply_size = ctypes.sizeof(_IcmpEchoReply) + len(payload) + 64
        reply = ctypes.create_string_buffer(reply_size)
        started = time.perf_counter()
        replies = _iphlpapi.IcmpSendEcho(
            handle,
            address_value,
            data,
            len(payload),
            None,
            reply,
            reply_size,
            max(1, int(timeout_ms)),
        )
        elapsed = (time.perf_counter() - started) * 1000.0
        if not replies:
            error_code = ctypes.get_last_error()
            return ProbeAttempt(
                "icmp", False, None, _icmp_error(error_code)
                if error_code in _ICMP_ERRORS
                else f"icmp failure ({error_code or 'no reply'})",
            )
        parsed = _IcmpEchoReply.from_buffer(reply)
        if parsed.Status != _IP_SUCCESS:
            return ProbeAttempt(
                "icmp", False, None, _icmp_error(parsed.Status)
            )
        rtt = float(parsed.RoundTripTime)
        if rtt <= 0:
            rtt = elapsed
        return ProbeAttempt("icmp", True, round(max(0.01, rtt), 3))
    finally:
        _iphlpapi.IcmpCloseHandle(handle)


def probe_tcp_fallback(
    host: str,
    port: int | None,
    timeout_ms: int,
) -> ProbeAttempt:
    """One TCP-connect attempt; a refused connection is still a reachable path."""
    if port is None:
        return ProbeAttempt("tcp", False, None, "no TCP fallback port")
    started = time.perf_counter()
    try:
        with socket.create_connection(
            (str(host), int(port)), timeout=max(0.05, timeout_ms / 1000.0)
        ):
            pass
        elapsed = (time.perf_counter() - started) * 1000.0
        return ProbeAttempt("tcp", True, round(max(0.01, elapsed), 3))
    except ConnectionRefusedError:
        elapsed = (time.perf_counter() - started) * 1000.0
        return ProbeAttempt(
            "tcp", True, round(max(0.01, elapsed), 3), refused=True
        )
    except (OSError, ValueError) as exc:
        return ProbeAttempt(
            "tcp", False, None, _clip(type(exc).__name__, 80)
        )


def _aggregate(
    attempts: list[ProbeAttempt],
    host: str,
    port: int | None,
    label: str,
    options: dict[str, Any],
) -> ProbeSummary:
    sent = len(attempts)
    received = sum(1 for attempt in attempts if attempt.ok)
    rtts = [
        float(attempt.rtt_ms)
        for attempt in attempts
        if attempt.ok and attempt.rtt_ms is not None
    ]
    loss_pct = (
        round((sent - received) / sent * 100.0, 1) if sent else 100.0
    )
    rtt_min = round(min(rtts), 1) if rtts else None
    rtt_max = round(max(rtts), 1) if rtts else None
    rtt_avg = round(sum(rtts) / len(rtts), 1) if rtts else None
    jitter = None
    if len(rtts) >= 2:
        diffs = [abs(rtts[i] - rtts[i - 1]) for i in range(1, len(rtts))]
        jitter = round(sum(diffs) / len(diffs), 1)
    probe_names = list(dict.fromkeys(attempt.probe for attempt in attempts))
    probe = "+".join(probe_names) if probe_names else "none"
    healthy = bool(
        received > 0
        and loss_pct <= float(options.get("degraded_loss_pct", 20.0))
        and (
            rtt_avg is None
            or rtt_avg <= float(options.get("degraded_rtt_ms", 500.0))
        )
        and (
            jitter is None
            or jitter <= float(options.get("degraded_jitter_ms", 80.0))
        )
    )
    error = None
    if received == 0:
        errors = [
            _clip(attempt.error, 80)
            for attempt in attempts
            if attempt.error
        ]
        error = errors[0] if errors else "no reply"
    return ProbeSummary(
        host=str(host),
        port=port,
        label=_clip(label or host, 64),
        sent=sent,
        received=received,
        loss_pct=loss_pct,
        rtt_ms_min=rtt_min,
        rtt_ms_avg=rtt_avg,
        rtt_ms_max=rtt_max,
        jitter_ms=jitter,
        probe=probe,
        reachable=received > 0,
        healthy=healthy,
        error=error,
    )


def _parse_forward_table(data: bytes) -> str | None:
    """Pick the lowest-metric IPv4 default route from a MIB_IPFORWARDTABLE."""
    if len(data) < 4:
        return None
    count = struct.unpack_from("<I", data, 0)[0]
    row_size = 14 * 4
    selected: tuple[int, str] | None = None
    for index in range(int(count)):
        offset = 4 + index * row_size
        if offset + row_size > len(data):
            break
        (
            dest,
            mask,
            _policy,
            next_hop,
            _if_index,
            _route_type,
            _proto,
            _age,
            _next_hop_as,
            metric1,
            _metric2,
            _metric3,
            _metric4,
            _metric5,
        ) = struct.unpack_from("<14I", data, offset)
        if dest != 0 or mask != 0 or next_hop == 0:
            continue
        gateway = socket.inet_ntoa(struct.pack("<I", next_hop))
        if selected is None or metric1 < selected[0]:
            selected = (metric1, gateway)
    return selected[1] if selected else None


def default_gateway_v4() -> dict[str, Any]:
    """Return ``{"ip": str|None, "error": str|None}`` for the IPv4 default route."""
    if not _ON_WINDOWS or _iphlpapi is None:
        return {"ip": None, "error": "gateway discovery requires Windows"}
    size = ctypes.c_uint32(0)
    first = _iphlpapi.GetIpForwardTable(None, ctypes.byref(size), False)
    if first not in (0, 122):  # 122 == ERROR_INSUFFICIENT_BUFFER
        return {"ip": None, "error": f"GetIpForwardTable failed ({first})"}
    if size.value == 0:
        return {"ip": None, "error": "empty IPv4 forward table"}
    buffer = ctypes.create_string_buffer(size.value)
    status = _iphlpapi.GetIpForwardTable(
        buffer, ctypes.byref(size), False
    )
    if status != 0:
        return {"ip": None, "error": f"GetIpForwardTable failed ({status})"}
    gateway = _parse_forward_table(bytes(buffer.raw[: size.value]))
    if gateway is None:
        return {"ip": None, "error": "no IPv4 default route"}
    return {"ip": gateway, "error": None}


def _deadline_reached(deadline: float | None) -> bool:
    return deadline is not None and time.monotonic() >= deadline


def _host_is_ipv4(host: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(str(host)), ipaddress.IPv4Address)
    except ValueError:
        return False


def probe_target(
    target: dict[str, Any],
    options: dict[str, Any],
    *,
    deadline: float | None = None,
) -> ProbeSummary:
    host = str(target.get("host") or "").strip()
    port_raw = target.get("port", 443)
    port = int(port_raw) if port_raw is not None else None
    label = str(target.get("label") or host)
    count = max(1, int(options.get("probes_per_target", 4)))
    timeout_ms = max(50, int(options.get("timeout_ms", 1000)))
    attempts: list[ProbeAttempt] = []
    if _host_is_ipv4(host):
        for _ in range(count):
            if _deadline_reached(deadline):
                break
            attempts.append(probe_icmp(host, timeout_ms))
        if attempts and not any(attempt.ok for attempt in attempts):
            # ICMP is blocked/filtered rather than the path being down. A
            # TCP connect to the configured port is the language-independent
            # fallback and also covers hosts that rate-limit echo requests.
            attempts = []
            for _ in range(min(2, count)):
                if _deadline_reached(deadline):
                    break
                attempts.append(probe_tcp_fallback(host, port, timeout_ms))
    else:
        # IPv6 (and any non-literal host) uses TCP only in this pass.
        for _ in range(min(2, count)):
            if _deadline_reached(deadline):
                break
            attempts.append(probe_tcp_fallback(host, port, timeout_ms))
    return _aggregate(attempts, host, port, label, options)


def probe_gateway(
    options: dict[str, Any],
    *,
    deadline: float | None = None,
) -> ProbeSummary | None:
    configured = str(options.get("gateway") or "auto").strip()
    gateway_ip: str | None
    discovery_error: str | None = None
    if configured.lower() == "auto":
        result = default_gateway_v4()
        gateway_ip = result.get("ip")
        discovery_error = result.get("error")
    else:
        gateway_ip = configured
    if not gateway_ip:
        return ProbeSummary(
            host="",
            port=None,
            label="gateway",
            sent=0,
            received=0,
            loss_pct=100.0,
            rtt_ms_min=None,
            rtt_ms_avg=None,
            rtt_ms_max=None,
            jitter_ms=None,
            probe="none",
            reachable=False,
            healthy=False,
            error=_clip(discovery_error or "gateway unresolved", 80),
        )
    count = max(1, int(options.get("probes_per_target", 4)))
    timeout_ms = max(50, int(options.get("timeout_ms", 1000)))
    attempts: list[ProbeAttempt] = []
    for _ in range(count):
        if _deadline_reached(deadline):
            break
        attempts.append(probe_icmp(gateway_ip, timeout_ms))
    if attempts and not any(attempt.ok for attempt in attempts):
        tcp_port = options.get("gateway_tcp_port")
        if tcp_port is not None:
            attempts = []
            for _ in range(min(2, count)):
                if _deadline_reached(deadline):
                    break
                attempts.append(
                    probe_tcp_fallback(gateway_ip, int(tcp_port), timeout_ms)
                )
    return _aggregate(attempts, gateway_ip, None, "gateway", options)


def _gateway_status(gateway: ProbeSummary | None, targets: list[ProbeSummary]) -> str:
    if gateway is None or not gateway.host:
        return "unresolved"
    if gateway.reachable:
        return "healthy" if gateway.healthy else "degraded"
    if any(target.reachable for target in targets):
        return "filtered"
    return "unreachable"


def _confidence(verdict: str, gateway_status: str, targets: list[ProbeSummary]) -> str:
    if verdict == "RESPONSIVE":
        return "high" if gateway_status == "healthy" else "medium"
    if verdict == "UPSTREAM_ISP":
        if gateway_status == "healthy" and not any(
            target.reachable for target in targets
        ):
            return "high"
        return "medium" if gateway_status == "healthy" else "low"
    if verdict == "LOCAL_LINK":
        return "medium"
    if verdict == "DESTINATION_PATH":
        return "medium" if len(targets) > 1 else "low"
    return "low"


def _summary(
    verdict: str,
    gateway_status: str,
    targets: list[ProbeSummary],
) -> str:
    up = sum(1 for target in targets if target.reachable)
    healthy = sum(1 for target in targets if target.healthy)
    total = len(targets)
    if verdict == "RESPONSIVE":
        if gateway_status == "degraded":
            return (
                "External anchors respond within thresholds, but the gateway "
                "probe itself is degraded; gateway ICMP may be filtered. "
                "External path looks responsive."
            )
        if gateway_status == "filtered":
            return (
                "External anchors respond within thresholds, but the gateway "
                "did not answer; gateway ICMP may be filtered."
            )
        if gateway_status == "unresolved":
            return (
                "External anchors respond within thresholds; the default "
                "gateway could not be measured."
            )
        return "Gateway and external anchors respond within thresholds."
    if verdict == "LOCAL_LINK":
        return (
            "The local link/Wi-Fi/router is the likely bottleneck: the "
            "gateway is unreachable or degraded and no external anchor "
            "established a healthy path. Probe filtering can mimic this."
        )
    if verdict == "UPSTREAM_ISP":
        counts = (
            f"({healthy}/{total} healthy, {up}/{total} reachable)"
        )
        if gateway_status == "healthy":
            return (
                f"Gateway is healthy but external anchors are degraded "
                f"{counts}; this is consistent with upstream/ISP congestion "
                "or a pre-NIC flood, not proof of an upstream DDoS."
            )
        if gateway_status == "degraded":
            return (
                f"Both the gateway and external anchors are degraded "
                f"{counts}; this is consistent with a local link problem "
                "that also affects upstream paths, or with upstream/ISP "
                "congestion. It is not proof of an upstream DDoS."
            )
        if gateway_status == "filtered":
            return (
                f"Gateway ICMP is filtered and external anchors are degraded "
                f"{counts}; this is consistent with upstream/ISP congestion "
                "or a pre-NIC flood, not proof of an upstream DDoS."
            )
        return (
            f"The default gateway could not be measured and external anchors "
            f"are degraded {counts}; this is consistent with upstream/ISP "
            "congestion or a pre-NIC flood, not proof of an upstream DDoS."
        )
    if verdict == "DESTINATION_PATH":
        if total == 1:
            return (
                "The single external anchor is degraded; with one anchor this "
                "cannot distinguish a destination/peering problem from an "
                "upstream path issue."
            )
        return (
            f"Only some external anchors are degraded ({healthy}/{total} "
            f"healthy, {up}/{total} reachable); this points to a destination "
            "or peering path rather than one upstream flood."
        )
    if gateway_status == "unresolved":
        return (
            "The default gateway could not be measured and no external "
            "anchor produced usable evidence."
        )
    return (
        "Not enough usable probe evidence to classify the path; do not infer "
        "an upstream attack from host counters alone."
    )


def assess_network_health(
    gateway: ProbeSummary | None,
    targets: list[ProbeSummary],
    options: dict[str, Any],
) -> NetworkAssessment:
    """Pure verdict matrix; no I/O."""
    gateway_status = _gateway_status(gateway, targets)
    targets_up = sum(1 for target in targets if target.reachable)
    targets_healthy = sum(1 for target in targets if target.healthy)
    targets_total = len(targets)
    local_link_ok: bool | None = None
    if gateway_status == "healthy":
        local_link_ok = True
    elif gateway_status in ("degraded", "unreachable"):
        local_link_ok = False
    external_ok: bool | None = None
    if targets_total:
        if targets_healthy == targets_total:
            external_ok = True
        elif targets_healthy == 0:
            external_ok = False

    def result(verdict: str, reason: str) -> NetworkAssessment:
        return NetworkAssessment(
            verdict=verdict,
            reason=reason,
            confidence=_confidence(verdict, gateway_status, targets),
            summary=_summary(verdict, gateway_status, targets),
            caveat=CAVEAT,
            gateway=gateway,
            gateway_status=gateway_status,
            targets=targets,
            targets_up=targets_up,
            targets_healthy=targets_healthy,
            targets_total=targets_total,
            local_link_ok=local_link_ok,
            external_ok=external_ok,
        )

    if not targets_total:
        return result("UNKNOWN", "no_external_targets")

    all_failed = targets_up == 0
    all_healthy = targets_total > 0 and targets_healthy == targets_total
    mixed = not all_failed and not all_healthy

    if gateway_status == "unreachable":
        return result("LOCAL_LINK", "gateway_unreachable_external_failed")
    if gateway_status == "degraded" and all_failed:
        return result("LOCAL_LINK", "gateway_degraded_external_failed")
    if gateway_status == "unresolved" and all_failed:
        return result("UNKNOWN", "no_gateway_external_all_failed")

    if all_healthy:
        return result("RESPONSIVE", "external_all_healthy")
    if targets_total == 1 and not targets[0].healthy:
        return result("DESTINATION_PATH", "single_external_degraded")
    if all_failed:
        # A healthy gateway with every external anchor failing is the
        # strongest upstream signal available from the host.
        return result("UPSTREAM_ISP", "external_all_failed")
    if not any(target.healthy for target in targets):
        return result("UPSTREAM_ISP", "external_all_degraded")
    if mixed:
        return result("DESTINATION_PATH", "external_mixed")
    return result("UPSTREAM_ISP", "external_all_degraded")


def probe_once(
    options: dict[str, Any],
    *,
    source: str = "checkstat",
    max_total_seconds: float | None = None,
) -> dict[str, Any]:
    """Run one full probe cycle and return a JSON-safe result."""
    if not options.get("enabled", True):
        return disabled_result(options, "disabled")
    started = time.perf_counter()
    deadline = (
        time.monotonic() + max(1.0, float(max_total_seconds))
        if max_total_seconds is not None
        else None
    )
    gateway = probe_gateway(options, deadline=deadline)
    targets: list[ProbeSummary] = []
    for target in options.get("targets") or []:
        if not isinstance(target, dict):
            continue
        if _deadline_reached(deadline):
            break
        targets.append(probe_target(target, options, deadline=deadline))
    assessment = assess_network_health(gateway, targets, options)
    elapsed_ms = round((time.perf_counter() - started) * 1000.0, 1)
    payload = asdict(assessment)
    payload.update(
        {
            "schema_version": SCHEMA_VERSION,
            "enabled": True,
            "source": source,
            "generated_at": time.time(),
            "generated_iso": _now_iso(),
            "duration_ms": elapsed_ms,
            "thresholds": {
                "degraded_loss_pct": float(
                    options.get("degraded_loss_pct", 20.0)
                ),
                "degraded_jitter_ms": float(
                    options.get("degraded_jitter_ms", 80.0)
                ),
                "degraded_rtt_ms": float(
                    options.get("degraded_rtt_ms", 500.0)
                ),
            },
        }
    )
    return payload


def disabled_result(options: dict[str, Any], reason: str) -> dict[str, Any]:
    """A renderable result for disabled, replay, or pre-first-sample states."""
    enabled = reason not in ("disabled", "replay")
    if reason == "replay":
        summary = "Not run in replay; active probes are live-only."
    elif reason == "pending":
        summary = "Probe pending; no network-health sample yet."
    else:
        summary = (
            "Network probes are disabled; link/ISP health is not measured."
        )
    return {
        "schema_version": SCHEMA_VERSION,
        "enabled": enabled,
        "source": reason,
        "generated_at": time.time(),
        "generated_iso": _now_iso(),
        "duration_ms": 0.0,
        "verdict": "UNKNOWN",
        "reason": reason,
        "confidence": "none",
        "summary": summary,
        "caveat": CAVEAT,
        "gateway": None,
        "gateway_status": "not_probed",
        "targets": [],
        "targets_up": 0,
        "targets_healthy": 0,
        "targets_total": 0,
        "local_link_ok": None,
        "external_ok": None,
        "thresholds": {
            "degraded_loss_pct": float(options.get("degraded_loss_pct", 20.0)),
            "degraded_jitter_ms": float(
                options.get("degraded_jitter_ms", 80.0)
            ),
            "degraded_rtt_ms": float(options.get("degraded_rtt_ms", 500.0)),
        },
    }


def estimated_budget_seconds(options: dict[str, Any]) -> float:
    """Conservative worst-case probe wall-clock for scheduling/validation."""
    targets = len(options.get("targets") or [])
    count = max(1, int(options.get("probes_per_target", 4)))
    timeout = max(0.05, float(options.get("timeout_ms", 1000)) / 1000.0)
    gateway_attempts = count + (
        2 if options.get("gateway_tcp_port") is not None else 0
    )
    target_attempts = count + 2  # ICMP then TCP fallback
    return round(
        (gateway_attempts + targets * target_attempts) * timeout + 2.0, 1
    )


def write_result_atomic(path: str | os.PathLike[str], payload: dict[str, Any]) -> bool:
    """Write the latest result atomically; tolerate transient sharing errors."""
    target = Path(path)
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
    except OSError:
        return False
    data = json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")
    for attempt in range(3):
        tmp_name = None
        try:
            fd, tmp_name = tempfile.mkstemp(
                prefix=f".{target.name}.", suffix=".tmp", dir=str(target.parent)
            )
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
            os.replace(tmp_name, target)
            return True
        except OSError:
            if tmp_name:
                with contextlib.suppress(OSError):
                    os.unlink(tmp_name)
            if attempt < 2:
                time.sleep(0.05)
    return False


def read_result(
    path: str | os.PathLike[str],
    max_bytes: int = 64 * 1024,
) -> dict[str, Any] | None:
    """Read and shape-check a shared result file; never raises."""
    try:
        source = Path(path)
        if source.stat().st_size > max_bytes:
            return None
        raw = source.read_bytes()
    except OSError:
        return None
    if len(raw) > max_bytes:
        return None
    try:
        data = json.loads(raw.decode("utf-8", errors="replace"))
    except (ValueError, UnicodeError):
        return None
    if not isinstance(data, dict):
        return None
    if data.get("verdict") not in VERDICTS:
        return None
    if _finite(data.get("generated_at")) is None:
        return None
    if not isinstance(data.get("caveat"), str):
        return None
    if "targets" in data and not isinstance(data["targets"], list):
        return None
    if "gateway" in data and data["gateway"] is not None and not isinstance(
        data["gateway"], dict
    ):
        return None
    return data


class NetworkHealthMonitor(threading.Thread):
    """Background probe owner; caches the latest result and writes the file."""

    def __init__(
        self,
        options: dict[str, Any],
        logger: Any = None,
        result_path: str | os.PathLike[str] | None = None,
    ):
        super().__init__(daemon=True, name="soc-network-health")
        self.options = dict(options)
        self.logger = logger
        self.result_path = Path(
            result_path or self.options.get("result_path") or DEFAULT_RESULT_PATH
        )
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._sample_ready = threading.Event()
        self._latest: dict[str, Any] | None = None

    def latest(self) -> dict[str, Any] | None:
        with self._lock:
            return deepcopy(self._latest)

    def wait_for_sample(self, timeout: float) -> bool:
        self._sample_ready.wait(max(0.0, float(timeout)))
        return self.latest() is not None

    def stop(self) -> None:
        self._stop_event.set()
        if self.is_alive():
            self.join(timeout=3.0)

    def run(self) -> None:
        interval = max(15.0, float(self.options.get("interval_seconds", 60)))
        while not self._stop_event.is_set():
            started = time.monotonic()
            try:
                result = probe_once(self.options, source="checkstat")
                with self._lock:
                    self._latest = result
                self._sample_ready.set()
                write_result_atomic(self.result_path, result)
            except Exception as exc:  # a probe must never kill the monitor
                if self.logger is not None:
                    self.logger.debug(
                        "Network health probe failed: "
                        f"{type(exc).__name__}: {exc}"
                    )
            elapsed = time.monotonic() - started
            self._stop_event.wait(max(1.0, interval - elapsed))
