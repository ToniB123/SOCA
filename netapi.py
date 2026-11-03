"""Direct Windows network-data access over ctypes (unelevated).

Replaces the netstat subprocesses of checkstat.py's traffic sampler with
iphlpapi calls on the same data: connection tables (states, PIDs),
per-protocol cumulative counters, and interface byte counters. Every call is
read-only and needs no elevation; netstat -ano/-e/-s output parsing (and any
elevated process details) remain checkstat's business.

The API surface is deliberately narrow:

    entries()            -> connection rows shaped like checkstat.Connection
    interface_counters() -> {"bytes_recv", ..., "errors_sent"} or None
    protocol_stats()     -> {"active_opens", ..., "ip_discarded"} or None

`entries()` returns plain dicts with checkstat's field names so checkstat can
build `Connection`s directly. On any OS error or shape mismatch the functions
raise NetApiError; checkstat's sampler catches the failure, falls back to the
netstat subprocess path, and retries the direct API periodically.
"""

from __future__ import annotations

import ctypes
import ipaddress
import struct

_IPHLPAPI = ctypes.WinDLL("iphlpapi.dll", use_last_error=True)

AF_INET = 2
AF_INET6 = 23

TCP_TABLE_OWNER_PID_ALL = 5
UDP_TABLE_OWNER_PID = 1
ERROR_INSUFFICIENT_BUFFER = 122

# MIB_TCP_STATE values. netstat's text prints state 2 as "LISTENING" and
# checkstat's rule engine matches that spelling, so do the same here.
MIB_TCP_STATES = {
    1: "CLOSED", 2: "LISTENING", 3: "SYN_SENT", 4: "SYN_RECEIVED",
    5: "ESTABLISHED", 6: "FIN_WAIT_1", 7: "FIN_WAIT_2", 8: "CLOSE_WAIT",
    9: "CLOSING", 10: "LAST_ACK", 11: "TIME_WAIT", 12: "DELETE",
}


class NetApiError(RuntimeError):
    """An iphlpapi call did not behave; callers fall back to netstat."""


def _addr4(value: int) -> str:
    """Dotted quad of the 4 memory bytes of the stored in_addr (net order)."""
    return ".".join(str(b) for b in struct.pack("<I", value))


def _port(value: int) -> int:
    """TCP table port field (network byte order, low 16 bits) -> host port."""
    v = value & 0xFFFF
    return ((v & 0xFF) << 8) | ((v >> 8) & 0xFF)


class _Tcp4Row(ctypes.Structure):
    _fields_ = [(n, ctypes.c_uint32) for n in (
        "state", "local_addr", "local_port", "remote_addr", "remote_port",
        "pid")]


class _Tcp6Row(ctypes.Structure):
    """MIB_TCP6ROW_OWNER_PID: address-first, per the documented layout.

    ucLocalAddr[16], dwLocalScopeId, dwLocalPort, ucRemoteAddr[16],
    dwRemoteScopeId, dwRemotePort, dwState, dwOwningPid. The old state-first
    layout still sized to 56 bytes with pid at offset 52, which is why only
    value-level assertions could catch the shifted address/port/state fields.
    Scope IDs are interface indexes in host order; _port() swaps the
    network-order port held in each port DWORD's low 16 bits.
    """
    _fields_ = [
        ("local_addr", ctypes.c_ubyte * 16),   # offset 0
        ("local_scope", ctypes.c_uint32),      # offset 16
        ("local_port", ctypes.c_uint32),       # offset 20
        ("remote_addr", ctypes.c_ubyte * 16),  # offset 24
        ("remote_scope", ctypes.c_uint32),     # offset 40
        ("remote_port", ctypes.c_uint32),      # offset 44
        ("state", ctypes.c_uint32),            # offset 48, DWORD not UCHAR
        ("pid", ctypes.c_uint32),              # offset 52
    ]


class _Udp4Row(ctypes.Structure):
    _fields_ = [("local_addr", ctypes.c_uint32),
                ("local_port", ctypes.c_uint32),
                ("pid", ctypes.c_uint32)]


class _Udp6Row(ctypes.Structure):
    _fields_ = [("local_addr", ctypes.c_ubyte * 16),
                ("local_scope", ctypes.c_uint32),
                ("local_port", ctypes.c_uint32),
                ("pid", ctypes.c_uint32)]


class _TcpStats(ctypes.Structure):
    _fields_ = [(n, ctypes.c_uint32) for n in (
        "rto_algorithm", "rto_min", "rto_max", "max_conn",
        "active_opens", "passive_opens", "attempt_fails", "estab_resets",
        "curr_estab", "in_segs", "out_segs", "retrans_segs", "in_errs",
        "out_rsts", "num_conn")]


class _UdpStats(ctypes.Structure):
    _fields_ = [(n, ctypes.c_uint32) for n in (
        "in_datagrams", "no_ports", "in_errors", "out_datagrams", "num_addrs")]


class _IpStats(ctypes.Structure):
    _fields_ = [(n, ctypes.c_uint32) for n in (
        "forwarding", "default_ttl", "in_receives", "in_hdr_errors",
        "in_addr_errors", "forw_datagrams", "in_unknown_protos",
        "in_discards", "in_delivers", "out_requests", "routing_discards",
        "out_discards", "out_no_routes", "reasm_timeout", "reasm_reqds",
        "reasm_oks", "reasm_fails", "frag_oks", "frag_fails",
        "frag_creates", "num_if", "num_addr", "num_routes")]


class _IcmpStats(ctypes.Structure):
    """MIBICMPSTATS: 13 DWORDs of ICMP counters for one direction."""
    _fields_ = [(name, ctypes.c_uint32) for name in (
        "msgs", "errors", "dest_unreachs", "time_excds", "parm_probs",
        "src_quenchs", "redirects", "echos", "echo_reps", "timestamps",
        "timestamp_reps", "addr_masks", "addr_mask_reps")]


class _IcmpInfo(ctypes.Structure):
    """MIBICMPINFO: IPv4 in/out MIBICMPSTATS (104 bytes, MIB_ICMP)."""
    _fields_ = [("in_stats", _IcmpStats), ("out_stats", _IcmpStats)]


class _IcmpStatsEx(ctypes.Structure):
    """MIBICMPSTATS_EX: totals plus per-type counts for one direction."""
    _fields_ = [
        ("msgs", ctypes.c_uint32),
        ("errors", ctypes.c_uint32),
        ("type_counts", ctypes.c_uint32 * 256),
    ]


class _IcmpEx(ctypes.Structure):
    """MIB_ICMP_EX: IPv6 in/out MIBICMPSTATS_EX (2064 bytes)."""
    _fields_ = [("in_stats", _IcmpStatsEx), ("out_stats", _IcmpStatsEx)]


TCP6_ROW_SIZE = ctypes.sizeof(_Tcp6Row)   # 56; dwOwningPid at offset 52
UDP6_ROW_SIZE = ctypes.sizeof(_Udp6Row)
ICMP_INFO_SIZE = ctypes.sizeof(_IcmpInfo)  # 104 = 2 * 13 DWORDs
ICMP_EX_SIZE = ctypes.sizeof(_IcmpEx)      # 2064 = 2 * (2 + 256) DWORDs


def _query_bytes(fn, family: int, table_class: int) -> bytes:
    """Grow-loop query of a variable-length iphlpapi table."""
    size = ctypes.c_uint32(0)
    for _ in range(5):
        if not size.value:
            rc = fn(None, ctypes.byref(size), False, family, table_class, 0)
            if rc != ERROR_INSUFFICIENT_BUFFER or not size.value:
                raise NetApiError(f"iphlpapi size probe rc={rc} size={size.value}")
        buf = (ctypes.c_ubyte * size.value)()
        rc = fn(buf, ctypes.byref(size), False, family, table_class, 0)
        if rc == 0:
            return bytes(buf)
        if rc == ERROR_INSUFFICIENT_BUFFER:
            continue  # table grew between the two calls
        raise NetApiError(f"iphlpapi table query rc={rc}")
    raise NetApiError("iphlpapi table query did not stabilize")


def _v6_text(addr_bytes: bytes, scope: int) -> str:
    text = str(ipaddress.IPv6Address(bytes(addr_bytes)))
    if scope:
        text += f"%{scope}"
    return f"[{text}]"


def _tcp_rows(family: int) -> list[dict]:
    buf = _query_bytes(_IPHLPAPI.GetExtendedTcpTable, family,
                       TCP_TABLE_OWNER_PID_ALL)
    count = struct.unpack_from("<I", buf, 0)[0]
    rows: list[dict] = []
    if family == AF_INET:
        for i in range(count):
            row = _Tcp4Row.from_buffer_copy(buf, 4 + i * ctypes.sizeof(_Tcp4Row))
            rows.append({
                "protocol": "TCP",
                "local": f"{_addr4(row.local_addr)}:{_port(row.local_port)}",
                "remote": f"{_addr4(row.remote_addr)}:{_port(row.remote_port)}",
                "state": MIB_TCP_STATES.get(row.state, "UNKNOWN"),
                "pid": int(row.pid),
            })
    else:
        for i in range(count):
            row = _Tcp6Row.from_buffer_copy(buf, 4 + i * TCP6_ROW_SIZE)
            rows.append({
                # Windows 11 netstat/parse_netstat_line label v6 rows "TCP"
                "protocol": "TCP",
                "local": _v6_text(row.local_addr, row.local_scope)
                         + ":" + str(_port(row.local_port)),
                "remote": _v6_text(row.remote_addr, row.remote_scope)
                          + ":" + str(_port(row.remote_port)),
                "state": MIB_TCP_STATES.get(row.state, "UNKNOWN"),
                "pid": int(row.pid),
            })
    return rows


def _udp_rows(family: int) -> list[dict]:
    """UDP rows for one address family.

    E14a: MIB_UDPROW_OWNER_PID carries only the local endpoint and PID, so
    every API row reports ``remote="*:*"``. Windows exposes connected UDP
    peers only through the netstat text table (and undocumented NSI calls);
    the scan lane parses that text, so NET-009 keeps working there, but the
    API traffic sample cannot attribute a connected UDP peer.
    """
    buf = _query_bytes(_IPHLPAPI.GetExtendedUdpTable, family,
                       UDP_TABLE_OWNER_PID)
    count = struct.unpack_from("<I", buf, 0)[0]
    rows: list[dict] = []
    if family == AF_INET:
        for i in range(count):
            row = _Udp4Row.from_buffer_copy(buf, 4 + i * ctypes.sizeof(_Udp4Row))
            rows.append({
                "protocol": "UDP",
                "local": f"{_addr4(row.local_addr)}:{_port(row.local_port)}",
                "remote": "*:*",
                "state": "UDP",
                "pid": int(row.pid),
            })
    else:
        for i in range(count):
            row = _Udp6Row.from_buffer_copy(buf, 4 + i * UDP6_ROW_SIZE)
            rows.append({
                "protocol": "UDP",
                "local": _v6_text(row.local_addr, row.local_scope)
                         + ":" + str(_port(row.local_port)),
                "remote": "*:*",
                "state": "UDP",
                "pid": int(row.pid),
            })
    return rows


# -- interface counters: MIB_IF_ROW2 (GetIfTable2, per MSDN layout) -----------
# Documented netioapi.h layout: two 514-byte WCHAR strings, no pointer
# buffer members, direct ULONG64 counter fields after the link speeds.
# MSVC natural alignment (ctypes default) reproduces it.

IF_MAX_STRING_SIZE = 256
IF_MAX_PHYS_ADDRESS_LENGTH = 32


class _OperFlags(ctypes.Structure):
    _fields_ = [(n, ctypes.c_ubyte * 1) for n in ("bytes",)]  # 8 bitfields = 1B


class _IfRow2(ctypes.Structure):
    _fields_ = [
        ("luid", ctypes.c_uint64),
        ("index", ctypes.c_uint32),
        ("guid", ctypes.c_ubyte * 16),
        ("alias", ctypes.c_wchar * (IF_MAX_STRING_SIZE + 1)),
        ("description", ctypes.c_wchar * (IF_MAX_STRING_SIZE + 1)),
        ("physical_address_length", ctypes.c_uint32),
        ("physical_address", ctypes.c_ubyte * IF_MAX_PHYS_ADDRESS_LENGTH),
        ("permanent_physical_address", ctypes.c_ubyte * IF_MAX_PHYS_ADDRESS_LENGTH),
        ("mtu", ctypes.c_uint32),
        ("type", ctypes.c_uint32),
        ("tunnel_type", ctypes.c_uint32),
        ("media_type", ctypes.c_uint32),
        ("physical_medium_type", ctypes.c_uint32),
        ("access_type", ctypes.c_uint32),
        ("direction_type", ctypes.c_uint32),
        ("flags", _OperFlags),
        ("oper_status", ctypes.c_uint32),
        ("admin_status", ctypes.c_uint32),
        ("media_connect_state", ctypes.c_uint32),
        ("network_guid", ctypes.c_ubyte * 16),
        ("connection_type", ctypes.c_uint32),
        ("transmit_link_speed", ctypes.c_uint64),
        ("receive_link_speed", ctypes.c_uint64),
        ("in_octets", ctypes.c_uint64),
        ("in_ucast_pkts", ctypes.c_uint64),
        ("in_nucast_pkts", ctypes.c_uint64),
        ("in_discards", ctypes.c_uint64),
        ("in_errors", ctypes.c_uint64),
        ("in_unknown_protos", ctypes.c_uint64),
        ("in_ucast_octets", ctypes.c_uint64),
        ("in_multicast_octets", ctypes.c_uint64),
        ("in_broadcast_octets", ctypes.c_uint64),
        ("out_octets", ctypes.c_uint64),
        ("out_ucast_pkts", ctypes.c_uint64),
        ("out_nucast_pkts", ctypes.c_uint64),
        ("out_discards", ctypes.c_uint64),
        ("out_errors", ctypes.c_uint64),
        ("out_ucast_octets", ctypes.c_uint64),
        ("out_multicast_octets", ctypes.c_uint64),
        ("out_broadcast_octets", ctypes.c_uint64),
        ("out_qlen", ctypes.c_uint64),
    ]


IF_ROW2_SIZE = ctypes.sizeof(_IfRow2)          # computed: 1352 on x64
MIB_IF_TABLE2_HEADER = 8                       # ULONG NumEntries + align pad


def _iface_counters() -> dict[str, int]:
    ptr = ctypes.c_void_p()
    rc = _IPHLPAPI.GetIfTable2(ctypes.byref(ptr))
    if rc != 0 or not ptr.value:
        raise NetApiError(f"GetIfTable2 rc={rc}")
    try:
        num = struct.unpack_from("<I", ctypes.string_at(ptr.value, 4), 0)[0]
        if not 0 < num < 4096:
            raise NetApiError(f"GetIfTable2 absurd interface count {num}")
        needed = MIB_IF_TABLE2_HEADER + num * IF_ROW2_SIZE
        raw = ctypes.string_at(ptr.value, needed)
        totals = dict.fromkeys(
            ("bytes_recv", "bytes_sent", "packets_recv", "packets_sent",
             "discards_recv", "discards_sent", "errors_recv", "errors_sent"), 0)
        hardware_rows = 0
        for i in range(num):
            row = _IfRow2.from_buffer_copy(raw,
                                           MIB_IF_TABLE2_HEADER + i * IF_ROW2_SIZE)
            # The WFP filter stack mirrors every hardware interface's
            # counters (six copies of the same packet on Wi-Fi here), so a
            # plain sum multiplies real traffic. InterfaceAndOperStatusFlags
            # .HardwareInterface is bit 0 of the flags byte.
            if not (row.flags.bytes[0] & 1):
                continue
            hardware_rows += 1
            totals["bytes_recv"] += row.in_octets
            totals["bytes_sent"] += row.out_octets
            totals["packets_recv"] += row.in_ucast_pkts
            totals["packets_sent"] += row.out_ucast_pkts
            totals["discards_recv"] += row.in_discards
            totals["discards_sent"] += row.out_discards
            totals["errors_recv"] += row.in_errors
            totals["errors_sent"] += row.out_errors
        if not hardware_rows:
            raise NetApiError("GetIfTable2 found no hardware interfaces")
        return totals
    finally:
        _IPHLPAPI.FreeMibTable(ptr)


def _protocol_stats_via_api() -> dict[str, int]:
    tcp = _TcpStats()
    udp = _UdpStats()
    udp6 = _UdpStats()
    ip = _IpStats()
    ip6 = _IpStats()
    icmp = _IcmpInfo()
    if _IPHLPAPI.GetTcpStatisticsEx(ctypes.byref(tcp), AF_INET) != 0:
        raise NetApiError("GetTcpStatisticsEx(v4)")
    tcp6 = _TcpStats()
    tcp6_ok = _IPHLPAPI.GetTcpStatisticsEx(ctypes.byref(tcp6), AF_INET6) == 0
    if _IPHLPAPI.GetUdpStatisticsEx(ctypes.byref(udp), AF_INET) != 0:
        raise NetApiError("GetUdpStatisticsEx(v4)")
    udp6_ok = _IPHLPAPI.GetUdpStatisticsEx(ctypes.byref(udp6), AF_INET6) == 0
    ip_ok = _IPHLPAPI.GetIpStatisticsEx(ctypes.byref(ip), AF_INET) == 0
    ip6_ok = _IPHLPAPI.GetIpStatisticsEx(ctypes.byref(ip6), AF_INET6) == 0
    icmp_ok = _IPHLPAPI.GetIcmpStatistics(ctypes.byref(icmp)) == 0
    # GetIcmpStatistics returns the IPv4 MIB_ICMP only. ICMPv6 needs the
    # separate Ex call; when it is absent or fails, v6 contributes nothing.
    icmp6 = _IcmpEx()
    icmp6_ok = False
    try:
        icmp6_ok = (
            _IPHLPAPI.GetIcmpStatisticsEx(ctypes.byref(icmp6), AF_INET6) == 0
        )
    except (AttributeError, OSError):
        icmp6_ok = False

    def add(key: str, value: int, ok: bool = True) -> None:
        if ok and value:
            totals[key] = totals.get(key, 0) + int(value)

    # every key exists even when zero: parse_protocol_stats does, and
    # metrics building/rate logic relies on missing meaning absent-source
    totals: dict[str, int] = dict.fromkeys(
        ("retransmits", "failed_connects", "active_opens", "passive_opens",
         "udp_received", "udp_no_ports", "udp_errors", "icmp_messages",
         "ip_received", "ip_discarded"), 0)
    add("retransmits", tcp.retrans_segs)
    add("failed_connects", tcp.attempt_fails)
    add("active_opens", tcp.active_opens)
    add("passive_opens", tcp.passive_opens)
    if tcp6_ok:
        add("retransmits", tcp6.retrans_segs)
        add("failed_connects", tcp6.attempt_fails)
        add("active_opens", tcp6.active_opens)
        add("passive_opens", tcp6.passive_opens)
    add("udp_received", udp.in_datagrams)
    add("udp_no_ports", udp.no_ports)
    add("udp_errors", udp.in_errors)
    if udp6_ok:
        add("udp_received", udp6.in_datagrams)
        add("udp_no_ports", udp6.no_ports)
        add("udp_errors", udp6.in_errors)
    # Inbound only: the flood rule measures traffic arriving at this host,
    # and counting our own outbound echo traffic would double-count it.
    add("icmp_messages", icmp.in_stats.msgs, icmp_ok)
    if icmp6_ok:
        add("icmp_messages", icmp6.in_stats.msgs)
    add("ip_received", ip.in_receives, ip_ok)
    add("ip_discarded", ip.in_discards, ip_ok)
    if ip6_ok:
        add("ip_received", ip6.in_receives)
        add("ip_discarded", ip6.in_discards)
    if not totals:
        raise NetApiError("protocol counters all zero/absent")
    return totals


def entries() -> list[dict]:
    """All TCP + UDP rows for both address families."""
    rows: list[dict] = []
    for family in (AF_INET, AF_INET6):
        rows.extend(_tcp_rows(family))
        rows.extend(_udp_rows(family))
    return rows


def interface_counters() -> dict[str, int] | None:
    try:
        return _iface_counters()
    except NetApiError:
        return None


def protocol_stats() -> dict[str, int] | None:
    try:
        return _protocol_stats_via_api()
    except NetApiError:
        return None
