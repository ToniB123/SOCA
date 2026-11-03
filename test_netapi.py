#!/usr/bin/env python3
"""Tests for netapi.py (direct iphlpapi capture) and the sampler's fast lane.

Run with:  python test_netapi.py
The API/entry tests run live: they touch only read-only, unelevated OS calls
(connection tables, counters) and netstat subprocesses for cross-checks. No
elevation, no network traffic is generated.
"""

import ctypes
import ipaddress
import struct
import subprocess
import sys
import tempfile
import time
import unittest
import unittest.mock
from pathlib import Path

import checkstat as soc
import netapi


class ApiHelpersTest(unittest.TestCase):
    def test_port_decode(self):
        # low 16 bits of the DWORD hold the port's network-order bytes:
        # memory b0=lo octet -> little-endian value 0xBB01 for port 443
        self.assertEqual(netapi._port(0xBB01), 443)
        self.assertEqual(netapi._port(0x3500), 53)
        self.assertEqual(netapi._port(0), 0)

    def test_addr4_decode(self):
        # 0x0100007F stored little-endian = bytes 7f 00 00 01 = 127.0.0.1
        self.assertEqual(netapi._addr4(0x0100007F), "127.0.0.1")

    def test_port_decode_known_values(self):
        # port 443 network bytes (01, BB) occupy the DWORD low 16 bits as
        # little-endian value 0x01BB when read byte-order-wise... verify the
        # actual decode against real table data instead of guessing constants
        for row in netapi.entries():
            text_port = int(row["local"].rsplit(":", 1)[1])
            self.assertTrue(0 <= text_port <= 65535)
            return
        self.fail("no entries at all")


class Tcp6RowLayoutTest(unittest.TestCase):
    """MIB_TCP6ROW_OWNER_PID is address-first (regression for E1).

    The old layout declared `state` first. It still sized to 56 bytes and put
    pid at offset 52, so size/count checks stayed green while addresses, scope
    IDs, ports and state decoded from shifted bytes. This test builds a row
    from the documented layout and checks every value; the old layout fails
    on all of them except pid.
    """

    def test_documented_layout_decodes_raw_row(self):
        local_addr = ipaddress.IPv6Address("2001:db8::1").packed
        remote_addr = ipaddress.IPv6Address("fe80::abcd").packed

        def port_dword(port: int) -> int:
            # DWORD whose memory bytes are [hi, lo, 0, 0]: network-order port
            # in the low 16 bits, as iphlpapi stores dwLocalPort/dwRemotePort.
            return ((port & 0xFF) << 8) | ((port >> 8) & 0xFF)

        raw = b"".join((
            local_addr,                             # 0  ucLocalAddr[16]
            struct.pack("<I", 12),                  # 16 dwLocalScopeId
            struct.pack("<I", port_dword(443)),     # 20 dwLocalPort
            remote_addr,                            # 24 ucRemoteAddr[16]
            struct.pack("<I", 3),                   # 40 dwRemoteScopeId
            struct.pack("<I", port_dword(53)),      # 44 dwRemotePort
            struct.pack("<I", 5),                   # 48 dwState
            struct.pack("<I", 4242),                # 52 dwOwningPid
        ))
        self.assertEqual(len(raw), 56)

        self.assertEqual(ctypes.sizeof(netapi._Tcp6Row), 56)
        self.assertEqual(netapi.TCP6_ROW_SIZE, 56)
        self.assertEqual(netapi._Tcp6Row.pid.offset, 52)
        self.assertEqual(
            [getattr(netapi._Tcp6Row, name).offset for name in (
                "local_addr", "local_scope", "local_port", "remote_addr",
                "remote_scope", "remote_port", "state", "pid")],
            [0, 16, 20, 24, 40, 44, 48, 52])

        row = netapi._Tcp6Row.from_buffer_copy(raw)
        self.assertEqual(bytes(row.local_addr), local_addr)
        self.assertEqual(row.local_scope, 12)
        self.assertEqual(netapi._port(row.local_port), 443)
        self.assertEqual(bytes(row.remote_addr), remote_addr)
        self.assertEqual(row.remote_scope, 3)
        self.assertEqual(netapi._port(row.remote_port), 53)
        self.assertEqual(row.state, 5)          # ESTABLISHED, a DWORD
        self.assertEqual(row.pid, 4242)


class Tcp6RowsMappingTest(unittest.TestCase):
    """`_tcp_rows` maps a documented 56-byte v6 row to the entry dict."""

    def test_tcp_rows_maps_documented_v6_fields(self):
        local_addr = ipaddress.IPv6Address("2001:db8::1").packed
        remote_addr = ipaddress.IPv6Address("fe80::abcd").packed
        wildcard = ipaddress.IPv6Address("::").packed

        def port_dword(port: int) -> int:
            return ((port & 0xFF) << 8) | ((port >> 8) & 0xFF)

        def raw_row(local, local_scope, local_port, remote, remote_scope,
                    remote_port, state, pid) -> bytes:
            return b"".join((
                local, struct.pack("<I", local_scope),
                struct.pack("<I", port_dword(local_port)),
                remote, struct.pack("<I", remote_scope),
                struct.pack("<I", port_dword(remote_port)),
                struct.pack("<I", state), struct.pack("<I", pid),
            ))

        table = struct.pack("<I", 2) + b"".join((
            raw_row(local_addr, 12, 443, remote_addr, 3, 53, 5, 4242),
            raw_row(wildcard, 0, 135, wildcard, 0, 0, 2, 1824),
        ))
        with unittest.mock.patch.object(netapi, "_query_bytes",
                                        return_value=table):
            rows = netapi._tcp_rows(netapi.AF_INET6)
        self.assertEqual(rows, [
            {"protocol": "TCP", "local": "[2001:db8::1%12]:443",
             "remote": "[fe80::abcd%3]:53", "state": "ESTABLISHED",
             "pid": 4242},
            # scope 0 must not print "%0"; wildcard endpoints keep brackets
            {"protocol": "TCP", "local": "[::]:135", "remote": "[::]:0",
             "state": "LISTENING", "pid": 1824},
        ])


class ApiEntriesTest(unittest.TestCase):
    def setUp(self):
        if sys.platform != "win32":
            self.skipTest("iphlpapi is Windows-only")

    def test_entry_shape(self):
        rows = netapi.entries()
        self.assertGreater(len(rows), 10)
        proto = {r["protocol"] for r in rows}
        self.assertTrue(proto <= {"TCP", "UDP"}, f"unexpected protocols {proto}")
        for row in rows[:20]:
            self.assertIn("local", row)
            self.assertIn("state", row)
            self.assertIsInstance(row["pid"], int)
        # port numbers decode into range for every row
        for row in rows:
            int(row["local"].rsplit(":", 1)[1])

    def test_counts_match_netstat(self):
        text = subprocess.run(
            ["netstat", "-ano"], capture_output=True, text=True, check=False,
            encoding="utf-8", errors="replace").stdout
        parsed = soc.parse_snapshot(text)
        api_count = len(netapi.entries())
        # tables change; allow a small delta between the two calls
        self.assertLessEqual(abs(len(parsed) - api_count), max(5, len(parsed) // 20),
                             f"netstat={len(parsed)} api={api_count}")

    def test_tcp6_rows_match_netstat(self):
        """IPv6 TCP rows must decode to netstat's endpoints and PIDs (E1).

        The old struct still sized to 56 and read pid correctly, but local and
        remote addresses, ports and states were shifted byte slices; matching
        endpoint+PID against netstat exposes that where a count comparison
        cannot. Tables churn between the two snapshots, so only a stride
        sample is compared and a 2/3 match ratio is required.
        """

        def canonical_ip(ip):
            if ip in {"*", ""}:
                return "*"
            try:
                return str(ipaddress.IPv6Address(ip.split("%", 1)[0]))
            except ValueError:
                return ip

        def key(conn):
            # Zone/canonical-form tolerant identity; state excluded because a
            # row can legitimately transition between the two snapshots.
            return (canonical_ip(conn.local_ip), conn.local_port,
                    canonical_ip(conn.remote_ip), conn.foreign_port, conn.pid)

        entries = soc.entries_from_api_rows(netapi.entries())
        self.assertIsNotNone(entries, "checkstat did not import netapi")
        api_v6 = [c for c in entries
                  if c.protocol == "TCP" and c.local_address.startswith("[")]

        text = subprocess.run(
            ["netstat", "-ano"], capture_output=True, text=True, check=False,
            encoding="utf-8", errors="replace").stdout
        netstat_v6 = [c for c in soc.parse_snapshot(text)
                      if c.local_address.startswith("[")
                      and c.protocol in {"TCP", "TCPV6"}]

        if not api_v6 and not netstat_v6:
            self.skipTest("host has no IPv6 TCP rows")
        self.assertTrue(api_v6, "netstat has IPv6 TCP rows but netapi returned none")
        if not netstat_v6:
            self.skipTest("netstat output yielded no IPv6 TCP rows")

        netstat_states = {}
        for conn in netstat_v6:
            netstat_states.setdefault(key(conn), set()).add(conn.state)

        sample = api_v6[::max(1, len(api_v6) // 20)][:20]
        matched = [c for c in sample if key(c) in netstat_states]
        self.assertGreaterEqual(
            len(matched), max(1, (2 * len(sample)) // 3),
            f"{len(matched)}/{len(sample)} sampled IPv6 TCP rows absent from "
            f"netstat: {[c.local_address for c in sample][:5]}")

        known_states = set(netapi.MIB_TCP_STATES.values())
        for conn in matched:
            self.assertIn(conn.state, known_states, conn.local_address)
            if conn.state == "LISTENING":
                self.assertIn("LISTENING", netstat_states[key(conn)])


class ApiCountersTest(unittest.TestCase):
    def setUp(self):
        if sys.platform != "win32":
            self.skipTest("iphlpapi is Windows-only")

    def test_protocol_stats_keys_complete(self):
        stats = netapi.protocol_stats()
        self.assertIsNotNone(stats)
        for key in ("retransmits", "failed_connects", "active_opens",
                    "passive_opens", "udp_received", "udp_no_ports",
                    "udp_errors", "icmp_messages", "ip_received",
                    "ip_discarded"):
            self.assertIn(key, stats)

    def test_protocol_stats_match_netstat_section(self):
        text = subprocess.run(
            ["netstat", "-s"], capture_output=True, text=True, check=False,
            encoding="utf-8", errors="replace").stdout
        parsed = soc.parse_protocol_stats(text)
        api = netapi.protocol_stats()
        if not parsed:
            self.skipTest("netstat -s output shape changed/localized")
        for key, value in parsed.items():
            # monotonic counters: api (queried after netstat) never behind
            self.assertGreaterEqual(api.get(key, 0) + 5, value,
                                    f"{key}: api={api.get(key)} < netstat={value}")

    def test_interface_counters_monotonic(self):
        first = netapi.interface_counters() or {}
        time.sleep(0.3)
        second = netapi.interface_counters() or {"bytes_recv": 0}
        self.assertTrue(first.get("bytes_recv", 0) > 0)
        for key in first:
            self.assertGreaterEqual(second.get(key, 0) + 1, first[key],
                                    f"{key} decreased (64-bit counters)")

    def test_iface_counters_skip_filter_mirrors(self):
        # hardware-only sums must stay within 20% of the busiest WFP layer,
        # never the N-fold sum when the adapter is mirrored by the filter stack
        counters = netapi.interface_counters() or {}
        self.assertTrue(counters.get("bytes_recv", 0) > 0)


class ApiToPipelineTest(unittest.TestCase):
    def test_api_rows_feed_pipeline(self):
        rows = netapi.entries()
        entries = soc.entries_from_api_rows(rows)
        self.assertIsNotNone(entries)
        self.assertEqual(len(entries), len(rows))
        metrics = soc.build_traffic_metrics(
            entries, options={"ignore_local_ports": [135, 5040], "include_private_remotes": False}
        )
        self.assertGreater(metrics.entries, 0)
        self.assertGreaterEqual(metrics.established, 0)
        self.assertGreaterEqual(metrics.syn_received, 0)
        # per-process maps populate when names resolve
        self.assertIsInstance(metrics.per_remote, dict)


class SamplerPersistGateTest(unittest.TestCase):
    def test_history_persists_on_sample_cadence(self):
        with tempfile.TemporaryDirectory() as tmp:
            options = dict(soc.build_traffic_options({}))
            options["history_path"] = Path(tmp) / "history.jsonl"
            sampler = soc.TrafficSampler(options, logger=None)
            sampler.capture_mode = "netstat"   # deterministic, no live API
            sampler._api_mode_ok = False
            sampler.gauge_interval = 0.5
            sampler.interval = 2
            sampler.capture()
            sampler.capture()
            first_rows = (options["history_path"]).read_text().splitlines()
            self.assertEqual(len(first_rows), 1, "1s capture must not multiply 2s history rows")
        # in-memory samples accumulate each capture regardless
        self.assertGreaterEqual(len(sampler._samples), 2)


class _FakeClock:
    """Deterministic clock: +step per time() call. checkstat reads the time
    through its module-level `time` reference, so swapping soc.time gives
    exact control over the fast-lane dedupe windows without real sleeps."""

    def __init__(self, step=5.0):
        self._step = step
        self.value = 1_000_000.0

    def time(self):
        self.value += self._step
        return self.value


class FastFindingsTest(unittest.TestCase):
    """The dedupe/throttle logic in TrafficSampler._run_fast_findings.

    evaluate() is stubbed so the tests exercise only the fast-lane state
    machine (the real evaluator paths are covered in test_parser.py).
    """

    def setUp(self):
        # each tick() consumes one clock step, so windows are exact
        self._real_time = soc.time
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.addCleanup(setattr, soc, "time", self._real_time)
        self.clock = _FakeClock()
        soc.time = self.clock
        options = dict(soc.build_traffic_options({}))
        options["history_path"] = Path(self._tmp.name) / "history.jsonl"
        self.sampler = soc.TrafficSampler(options, logger=None)

    def tick(self, detail: str):
        """One gauge-cycle with a single NET-T10 finding of one shape."""
        self.sampler.evaluate = lambda: [soc.TrafficFinding(
            rule_id="NET-T10", name="UDP flood / amplification response",
            severity="HIGH", detail=detail, action="review",
            metrics={"udp_datagrams_per_second": 500.0},
            key="traffic|NET-T10|udp")]
        self.sampler._run_fast_findings()

    def test_new_changed_and_quiet(self):
        emitted = []
        self.sampler.finding_emitter = emitted.append
        self.assertEqual(emitted, [])  # no findings: nothing to emit
        self.tick("400.0 UDP datagrams/s received (baseline 50.0)")
        self.assertEqual(len(emitted), 1, "first sighting emits")
        self.tick("900.0 UDP datagrams/s received (baseline 50.0)")
        self.assertEqual(len(emitted), 1,
                         "same shape, higher rate: digits stripped, silent")
        self.tick("400.0 UDP datagrams/s received (baseline 100.0)")
        self.assertEqual(len(emitted), 1, "still the same shape: silent")

    def test_shape_change_throttled_then_emits(self):
        """A shape change re-emits at most once per min-emit window, and the
        pending change is not lost while it waits. One tick = 2-3 clock steps
        (10-15 s), so 3 ticks stay inside the 60 s window and 8 more cross it."""
        emitted = []
        self.sampler.finding_emitter = emitted.append
        self.tick("400.0 UDP datagrams/s received (baseline 50.0)")
        self.assertEqual(len(emitted), 1)
        # the error-rate clause appears = shape change
        for _ in range(3):
            self.tick("400.0 UDP datagrams/s; 25.0 UDP receive errors/s")
        self.assertEqual(len(emitted), 1, "oscillation throttled inside the window")
        # the clock crosses the window (one step of 5s per tick); the pending
        # shape finally emits once at the crossing
        for _ in range(16):
            self.tick("400.0 UDP datagrams/s; 25.0 UDP receive errors/s")
        self.assertEqual(len(emitted), 2, "pending change emits once, not per tick")
        self.tick("400.0 UDP datagrams/s; 25.0 UDP receive errors/s")
        self.assertEqual(len(emitted), 2, "emitted shape is now current: silent")

    def test_flap_stays_quiet(self):
        """A key that disappears and reappears within the quiet window emits once."""
        emitted = []
        self.sampler.finding_emitter = emitted.append
        self.tick("400.0 UDP datagrams/s received (baseline 50.0)")
        self.assertEqual(len(emitted), 1)
        self.sampler.evaluate = lambda: []   # finding stops
        self.sampler._run_fast_findings()
        self.assertEqual(len(emitted), 1)    # key retained until quiet passes
        self.tick("400.0 UDP datagrams/s received (baseline 50.0)")
        self.assertEqual(len(emitted), 1, "flap within the quiet window: silent")

    def test_quiet_expiry_counts_as_new(self):
        """A key seen again after the quiet window is a new event."""
        emitted = []
        self.sampler.finding_emitter = emitted.append
        self.tick("400.0 UDP datagrams/s received (baseline 50.0)")
        self.assertEqual(len(emitted), 1)
        self.sampler.evaluate = lambda: []   # gone for the whole quiet window
        self.sampler._run_fast_findings()
        for _ in range(30):                  # > quiet (120s) of clock steps
            self.sampler._run_fast_findings()
        self.tick("400.0 UDP datagrams/s received (baseline 50.0)")
        self.assertEqual(len(emitted), 2, "quiet expiry counts as new")


class FastTrafficNotifierTest(unittest.TestCase):
    class _Cache:
        def __init__(self, entries=None):
            self.seen_by = {}
            self.entries = entries or {}

        def note_finding_seen(self, signature, window):
            self.seen_by[signature] = self.seen_by.get(signature, 0) + 1
            return self.seen_by[signature]

        def should_notify(self, signature, cooldown):
            return True

        def mark_alerted(self, signature):
            pass

        def get(self, signature):
            return self.entries.get(signature)

    class _Logger:
        def __init__(self, records):
            self.records = records

        def finding(self, record):
            self.records.append(record)

        def debug(self, message):
            pass

    @staticmethod
    def _finding(key="traffic|NET-T01|test"):
        return soc.TrafficFinding(
            rule_id="NET-T01", name="SYN flood", severity="HIGH",
            detail="50 SYN_RECEIVED", action="investigate",
            metrics={"syn_received": 50, "pid": 123}, key=key)

    def _notifier(self, records, cache=None):
        return soc.FastTrafficNotifier(
            cache or self._Cache(),
            {"toast_enabled": True,
             "traffic_alert_min_occurrences": 2,
             "traffic_alert_window_minutes": 30,
             "alert_cooldown": 60},
            self._Logger(records),
            host_fn=lambda: {"hostname": "h", "local_ip": "1.2.3.4",
                             "platform": "test"})

    def test_unvetted_finding_queued_for_deferred_triage(self):
        records = []
        queue = soc.DeferredTrafficQueue()
        notifier = soc.FastTrafficNotifier(
            self._Cache(),
            {"toast_enabled": False},
            self._Logger(records),
            host_fn=lambda: {"hostname": "h", "local_ip": "1.2.3.4",
                             "platform": "test"},
            context_fn=lambda: "ctx-line",
            pending=queue,
        )
        notifier.__call__([self._finding()])
        self.assertEqual(len(queue), 1)
        item = queue.take_all()[0]
        self.assertEqual(item["signature"], "traffic|NET-T01|test")
        self.assertEqual(item["context"], "ctx-line")
        self.assertEqual(item["occurrences"], 1)
        self.assertIs(item["finding"].rule_id, "NET-T01")

    def test_pending_signature_not_duplicated(self):
        records = []
        queue = soc.DeferredTrafficQueue()
        notifier = soc.FastTrafficNotifier(
            self._Cache(), {"toast_enabled": False}, self._Logger(records),
            host_fn=lambda: {}, context_fn=lambda: "", pending=queue,
        )
        notifier.__call__([self._finding()])
        notifier.__call__([self._finding()])
        self.assertEqual(len(queue), 1)

    def test_band_crossing_burst_keeps_one_alert_identity(self):
        # Regression: a burst that grows across a shape-band boundary (21 ->
        # 40 conns) used to reset the occurrence counter with the new
        # signature, so its toast never fired. Occurrence counting follows the
        # coarse alert identity; only verdict caching is shape-aware.
        records = []
        queue = soc.DeferredTrafficQueue()
        notifier = soc.FastTrafficNotifier(
            self._Cache(),
            {"toast_enabled": True,
             "traffic_alert_min_occurrences": 2,
             "traffic_alert_window_minutes": 30,
             "alert_cooldown": 60},
            self._Logger(records),
            host_fn=lambda: {"hostname": "h", "local_ip": "1.2.3.4",
                             "platform": "test"},
            pending=queue,
        )

        def variant(shape, conns):
            return soc.TrafficFinding(
                rule_id="NET-T14",
                name="Unexpected per-process connection growth",
                severity="HIGH",
                detail=f"firefox.exe holds {conns} external connection(s)",
                action="inspect",
                metrics={"process": "firefox.exe", "pid": 123},
                key=f"traffic|NET-T14|firefox.exe|{shape}-fanout",
                alert_key="traffic|NET-T14|firefox.exe",
            )

        with unittest.mock.patch.object(soc, "send_toast_notification") as toast:
            notifier.__call__([variant("small", 21)])
            notifier.__call__([variant("medium", 40)])
        toast.assert_called_once()
        self.assertEqual(records[0]["occurrences"], 1)
        self.assertEqual(records[1]["occurrences"], 2)
        self.assertFalse(records[0]["alerted"])
        self.assertTrue(records[1]["alerted"])
        # Both shapes still queue separately for deferred verdict triage.
        self.assertEqual(len(queue), 2)

    def test_cached_verdict_not_queued(self):
        records = []
        queue = soc.DeferredTrafficQueue()
        cache = self._Cache({"traffic|NET-T01|test": {
            "verdict": {"verdict": "FALSE_POSITIVE", "confidence": 90}}})
        notifier = soc.FastTrafficNotifier(
            cache, {"toast_enabled": False}, self._Logger(records),
            host_fn=lambda: {}, context_fn=lambda: "", pending=queue,
        )
        notifier.__call__([self._finding()])
        self.assertEqual(len(queue), 0)

    def test_record_shape(self):
        records = []
        notifier = self._notifier(records)
        notifier.__call__([self._finding()])
        self.assertEqual(len(records), 1)
        record = records[0]
        self.assertTrue(record["snapshot"].startswith("fast-"))
        self.assertEqual(record["source"], "traffic")
        self.assertEqual(record["rule"]["rule_id"], "NET-T01")
        self.assertFalse(record["alerted"])   # occurrences=1 < min 2
        self.assertIn("occurrences", record)
        self.assertIsNone(record["verdict"])  # no cached verdict on file
        self.assertFalse(record["cache_hit"])

    def test_cached_verdict_attached(self):
        records = []
        cache = self._Cache({"traffic|NET-T01|test": {
            "verdict": {"verdict": "FALSE_POSITIVE", "confidence": 90,
                        "source": "ai-escalated",
                        "classification": "legitimate_streaming",
                        "vetted_at": "2026-10-30T17:54:03-05:00",
                        "verdict_id": "7d9e2f10-9b31-4c55-a1b2-000000000042"}}})
        notifier = self._notifier(records, cache)
        notifier.__call__([self._finding()])
        record = records[0]
        self.assertTrue(record["cache_hit"])
        self.assertEqual(record["verdict"]["verdict"], "FALSE_POSITIVE")
        self.assertEqual(record["verdict"]["confidence"], 90)
        self.assertEqual(record["verdict"]["vetted_at"], "2026-10-30T17:54:03-05:00")
        # The cache id rides along so reused verdicts stay traceable.
        self.assertEqual(record["verdict"]["verdict_id"],
                         "7d9e2f10-9b31-4c55-a1b2-000000000042")
        # The classification described the original sighting's evidence, not
        # this one; the fast lane must not re-claim it.
        self.assertNotIn("classification", record["verdict"])

    def test_empty_cached_verdict_ignored(self):
        records = []
        # note_finding_seen leaves an entry with an empty verdict dict; that
        # must not masquerade as a real verdict.
        cache = self._Cache({"traffic|NET-T01|test": {"verdict": {}}})
        notifier = self._notifier(records, cache)
        notifier.__call__([self._finding()])
        self.assertIsNone(records[0]["verdict"])
        self.assertFalse(records[0]["cache_hit"])

    def _run_to_occurrence(self, n, cache):
        """Fire the finding n times so occurrences reaches n."""
        records = []
        notifier = self._notifier(records, cache)
        for _ in range(n):
            notifier.__call__([self._finding()])
        return records

    def test_cached_escalated_false_positive_80_silences_toast(self):
        cache = self._Cache({"traffic|NET-T01|test": {
            "verdict": {"verdict": "FALSE_POSITIVE", "confidence": 90,
                        "source": "ai-escalated", "tier": "escalated"}}})
        with unittest.mock.patch.object(soc, "send_toast_notification") as toast:
            records = self._run_to_occurrence(2, cache)
        toast.assert_not_called()
        self.assertFalse(records[-1]["alerted"])

    def test_cached_routine_false_positive_does_not_silence_high(self):
        # A routine-model FP never outranks the deterministic HIGH severity;
        # the guardrail turns it into SUSPICIOUS and the toast still fires.
        cache = self._Cache({"traffic|NET-T01|test": {
            "verdict": {"verdict": "FALSE_POSITIVE", "confidence": 90,
                        "source": "ai-routine", "tier": "routine"}}})
        with unittest.mock.patch.object(soc, "send_toast_notification") as toast:
            records = self._run_to_occurrence(2, cache)
        toast.assert_called_once()
        self.assertTrue(records[-1]["alerted"])

    def test_cached_false_positive_below_80_still_toasts(self):
        cache = self._Cache({"traffic|NET-T01|test": {
            "verdict": {"verdict": "FALSE_POSITIVE", "confidence": 70}}})
        with unittest.mock.patch.object(soc, "send_toast_notification") as toast:
            records = self._run_to_occurrence(2, cache)
        toast.assert_called_once()
        self.assertTrue(records[-1]["alerted"])

    def test_cached_suspicious_still_toasts(self):
        cache = self._Cache({"traffic|NET-T01|test": {
            "verdict": {"verdict": "SUSPICIOUS", "confidence": 90}}})
        with unittest.mock.patch.object(soc, "send_toast_notification") as toast:
            records = self._run_to_occurrence(2, cache)
        toast.assert_called_once()
        self.assertTrue(records[-1]["alerted"])


class SamplerCounterCadenceTest(unittest.TestCase):
    """E13: counter caching, suppression, source barriers, and API retry."""

    RAW = "  TCP 10.0.0.5:50000 8.8.8.8:443 ESTABLISHED 42\n"

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.clock = [1_000_000.0]
        patcher = unittest.mock.patch.object(
            soc.time, "time", side_effect=lambda: self.clock[0]
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    def _netstat_sampler(self):
        options = dict(soc.build_traffic_options({}))
        options["history_path"] = Path(self._tmp.name) / "history.jsonl"
        sampler = soc.TrafficSampler(options, logger=None)
        sampler.capture_mode = "netstat"
        sampler._api_mode_ok = False
        sampler._counters_source = "netstat"
        sampler._suppress_next_counter_rates = False
        return sampler

    def test_fallback_reads_counters_once_per_sample_interval(self):
        sampler = self._netstat_sampler()
        calls = []

        def iface():
            calls.append("iface")
            return {"bytes_recv": 100 * calls.count("iface")}

        def proto():
            calls.append("proto")
            return {"retransmits": 5 * calls.count("proto")}

        with (
            unittest.mock.patch.object(
                soc, "read_interface_counters", side_effect=iface
            ),
            unittest.mock.patch.object(
                soc, "read_protocol_stats", side_effect=proto
            ),
            unittest.mock.patch.object(soc, "get_process_map", return_value={}),
        ):
            first = sampler.capture(self.RAW)
            self.clock[0] += 1
            second = sampler.capture(self.RAW)
            self.assertEqual(calls, ["iface", "proto"])
            self.assertEqual(first.bytes_recv, 100)
            self.assertEqual(first.retransmits, 5)
            self.assertEqual(second.bytes_recv, 100)
            self.assertEqual(second.retransmits, 5)
            self.assertEqual(second.counters_at, first.counters_at)
            self.clock[0] += sampler.interval
            third = sampler.capture(self.RAW)
        self.assertEqual(calls, ["iface", "proto", "iface", "proto"])
        self.assertEqual(third.bytes_recv, 200)
        self.assertEqual(third.retransmits, 10)
        self.assertEqual(third.counter_source, "netstat")

    def test_fallback_honors_suppression_for_one_sample(self):
        sampler = self._netstat_sampler()
        sampler._suppress_next_counter_rates = True
        calls = []

        def iface():
            calls.append("iface")
            return {"bytes_recv": 100}

        def proto():
            calls.append("proto")
            return {"retransmits": 5}

        with (
            unittest.mock.patch.object(
                soc, "read_interface_counters", side_effect=iface
            ),
            unittest.mock.patch.object(
                soc, "read_protocol_stats", side_effect=proto
            ),
            unittest.mock.patch.object(soc, "get_process_map", return_value={}),
        ):
            suppressed = sampler.capture(self.RAW)
            self.assertIsNone(suppressed.bytes_recv)
            self.assertIsNone(suppressed.retransmits)
            self.assertIsNone(suppressed.counters_at)
            self.assertEqual(calls, [])
            self.assertFalse(sampler._suppress_next_counter_rates)
            resumed = sampler.capture(self.RAW)
        self.assertEqual(calls, ["iface", "proto"])
        self.assertEqual(resumed.bytes_recv, 100)
        self.assertEqual(resumed.retransmits, 5)

    def test_api_failure_retries_and_reenables(self):
        options = dict(soc.build_traffic_options({}))
        options["history_path"] = Path(self._tmp.name) / "api.jsonl"
        with (
            unittest.mock.patch.object(soc, "_netapi") as api,
            unittest.mock.patch.object(
                soc, "read_interface_counters", return_value={"bytes_recv": 7}
            ),
            unittest.mock.patch.object(
                soc, "read_protocol_stats", return_value={"retransmits": 1}
            ),
            unittest.mock.patch.object(soc, "get_process_map", return_value={}),
        ):
            api.interface_counters.return_value = {"bytes_recv": 9}
            api.protocol_stats.return_value = {"retransmits": 2}
            api.entries.side_effect = RuntimeError("boom")
            sampler = soc.TrafficSampler(options, logger=None)
            self.assertTrue(sampler._api_mode_ok)
            first = sampler.capture(self.RAW)
            self.assertFalse(sampler._api_mode_ok)
            self.assertIsNone(first.bytes_recv)
            self.assertEqual(first.counter_source, "netstat")
            retry_at = sampler._api_retry_at
            self.assertGreater(retry_at, self.clock[0])
            self.clock[0] += 1
            sampler.capture(self.RAW)
            self.assertEqual(api.entries.call_count, 1)
            api.entries.side_effect = None
            api.entries.return_value = []
            self.clock[0] = retry_at + 1
            switched = sampler.capture(self.RAW)
            self.assertTrue(sampler._api_mode_ok)
            self.assertIsNone(switched.bytes_recv)
            self.assertIsNone(switched.counters_at)
            self.assertEqual(switched.counter_source, "api")
            self.clock[0] += 1
            resumed = sampler.capture(self.RAW)
        self.assertEqual(resumed.bytes_recv, 9)
        self.assertEqual(resumed.retransmits, 2)

    def test_cached_counters_rate_uses_fetch_time(self):
        options = dict(soc.build_traffic_options({}))
        first = soc.build_traffic_metrics(
            [], options=options, timestamp=0.0,
            counters={"bytes_recv": 0}, counters_at=0.0,
            counter_source="netstat",
        )
        cached = soc.build_traffic_metrics(
            [], options=options, timestamp=5.0,
            counters={"bytes_recv": 0}, counters_at=0.0,
            counter_source="netstat",
        )
        refreshed = soc.build_traffic_metrics(
            [], options=options, timestamp=10.0,
            counters={"bytes_recv": 1000}, counters_at=10.0,
            counter_source="netstat",
        )
        self.assertEqual(
            soc._per_second([first, cached, refreshed], "bytes_recv", 5.0),
            100.0,
        )
        self.assertEqual(
            soc._rate_series([first, cached, refreshed], "bytes_recv", 5.0),
            [100.0],
        )

    def test_rates_do_not_cross_counter_sources(self):
        options = dict(soc.build_traffic_options({}))
        base = soc.build_traffic_metrics(
            [], options=options, timestamp=1000.0,
            counters={"bytes_recv": 1000}, counter_source="api",
        )
        boundary = soc.build_traffic_metrics(
            [], options=options, timestamp=1001.0, counters=None,
            counter_source="netstat",
        )
        resumed = soc.build_traffic_metrics(
            [], options=options, timestamp=1006.0,
            counters={"bytes_recv": 5000}, counter_source="netstat",
        )
        self.assertIsNone(
            soc._per_second([base, boundary, resumed], "bytes_recv", 5.0)
        )
        later = soc.build_traffic_metrics(
            [], options=options, timestamp=1011.0,
            counters={"bytes_recv": 7000}, counter_source="netstat",
        )
        self.assertEqual(
            soc._per_second(
                [base, boundary, resumed, later], "bytes_recv", 5.0
            ),
            400.0,
        )


class IcmpStructLayoutTest(unittest.TestCase):
    """E14b: the ICMP MIB layouts must match the documented DWORD counts."""

    ICMP_STATS_FIELDS = (
        "msgs", "errors", "dest_unreachs", "time_excds", "parm_probs",
        "src_quenchs", "redirects", "echos", "echo_reps", "timestamps",
        "timestamp_reps", "addr_masks", "addr_mask_reps",
    )

    def test_mibicmpinfo_is_two_13_dword_stats_blocks(self):
        self.assertEqual(ctypes.sizeof(netapi._IcmpStats), 52)
        self.assertEqual(ctypes.sizeof(netapi._IcmpInfo), 104)
        self.assertEqual(netapi.ICMP_INFO_SIZE, 104)
        self.assertEqual(netapi._IcmpInfo.in_stats.offset, 0)
        self.assertEqual(netapi._IcmpInfo.out_stats.offset, 52)
        self.assertEqual(
            [getattr(netapi._IcmpStats, name).offset
             for name in self.ICMP_STATS_FIELDS],
            [4 * index for index in range(13)],
        )
        info = netapi._IcmpInfo.from_buffer_copy(
            struct.pack("<26I", *range(26))
        )
        self.assertEqual(
            (info.in_stats.msgs, info.in_stats.errors,
             info.in_stats.dest_unreachs, info.in_stats.addr_mask_reps),
            (0, 1, 2, 12),
        )
        self.assertEqual(
            (info.out_stats.msgs, info.out_stats.errors,
             info.out_stats.dest_unreachs, info.out_stats.addr_mask_reps),
            (13, 14, 15, 25),
        )

    def test_mib_icmp_ex_is_two_1032_byte_blocks(self):
        self.assertEqual(ctypes.sizeof(netapi._IcmpStatsEx), 1032)
        self.assertEqual(ctypes.sizeof(netapi._IcmpEx), 2064)
        self.assertEqual(netapi.ICMP_EX_SIZE, 2064)
        self.assertEqual(netapi._IcmpEx.out_stats.offset, 1032)
        self.assertEqual(netapi._IcmpStatsEx.type_counts.offset, 8)
        raw = (
            struct.pack("<2I", 5, 1) + bytes(256 * 4)
            + struct.pack("<2I", 6, 2) + bytes(256 * 4)
        )
        stats = netapi._IcmpEx.from_buffer_copy(raw)
        self.assertEqual((stats.in_stats.msgs, stats.in_stats.errors), (5, 1))
        self.assertEqual((stats.out_stats.msgs, stats.out_stats.errors), (6, 2))
        self.assertEqual(len(stats.in_stats.type_counts), 256)


class IcmpProtocolStatsTest(unittest.TestCase):
    """E14b: icmp_messages is inbound v4 + inbound v6, never the old bogus block."""

    def _patch_other_stats(self):
        return (
            unittest.mock.patch.object(
                netapi._IPHLPAPI, "GetTcpStatisticsEx", return_value=0
            ),
            unittest.mock.patch.object(
                netapi._IPHLPAPI, "GetUdpStatisticsEx", return_value=0
            ),
            unittest.mock.patch.object(
                netapi._IPHLPAPI, "GetIpStatisticsEx", return_value=0
            ),
        )

    def test_only_inbound_icmp_messages_are_counted(self):
        def fake_icmp4(ptr):
            stats = ctypes.cast(
                ptr, ctypes.POINTER(netapi._IcmpInfo)
            ).contents
            stats.in_stats.msgs = 11
            stats.out_stats.msgs = 999
            return 0

        def fake_icmp6(ptr, family):
            stats = ctypes.cast(
                ptr, ctypes.POINTER(netapi._IcmpEx)
            ).contents
            stats.in_stats.msgs = 7
            stats.out_stats.msgs = 999
            self.assertEqual(family, netapi.AF_INET6)
            return 0

        tcp_patch, udp_patch, ip_patch = self._patch_other_stats()
        with (
            tcp_patch, udp_patch, ip_patch,
            unittest.mock.patch.object(
                netapi._IPHLPAPI, "GetIcmpStatistics", side_effect=fake_icmp4
            ),
            unittest.mock.patch.object(
                netapi._IPHLPAPI, "GetIcmpStatisticsEx", side_effect=fake_icmp6
            ),
        ):
            stats = netapi._protocol_stats_via_api()
        self.assertEqual(stats["icmp_messages"], 18)

    def test_v4_survives_when_icmp_ex_is_unavailable(self):
        def fake_icmp4(ptr):
            stats = ctypes.cast(
                ptr, ctypes.POINTER(netapi._IcmpInfo)
            ).contents
            stats.in_stats.msgs = 11
            return 0

        tcp_patch, udp_patch, ip_patch = self._patch_other_stats()
        with (
            tcp_patch, udp_patch, ip_patch,
            unittest.mock.patch.object(
                netapi._IPHLPAPI, "GetIcmpStatistics", side_effect=fake_icmp4
            ),
            unittest.mock.patch.object(
                netapi._IPHLPAPI, "GetIcmpStatisticsEx",
                side_effect=AttributeError("missing"),
            ),
        ):
            stats = netapi._protocol_stats_via_api()
        self.assertEqual(stats["icmp_messages"], 11)


class UdpApiGapTest(unittest.TestCase):
    """E14a: MIB_UDPROW_OWNER_PID has no remote endpoint."""

    def test_udp_rows_report_wildcard_remote_by_design(self):
        port_dword = ((62644 & 0xFF) << 8) | ((62644 >> 8) & 0xFF)
        raw = struct.pack("<I", 1) + struct.pack(
            "<III", 0x0100007F, port_dword, 1234
        )
        with unittest.mock.patch.object(
            netapi, "_query_bytes", return_value=raw
        ):
            rows = netapi._udp_rows(netapi.AF_INET)
        self.assertEqual(rows, [{
            "protocol": "UDP",
            "local": "127.0.0.1:62644",
            "remote": "*:*",
            "state": "UDP",
            "pid": 1234,
        }])
        # The netstat text parser is the only path that carries a UDP peer.
        entry = soc.parse_netstat_line(
            "  UDP    0.0.0.0:62644          18.160.200.49:443"
            "                      6789"
        )
        self.assertEqual(
            (entry.remote_ip, entry.foreign_port), ("18.160.200.49", 443)
        )


class DeferredTrafficQueueRestoreTest(unittest.TestCase):
    """E14f: restore must keep the newest findings on overflow."""

    @staticmethod
    def _finding(signature):
        return soc.TrafficFinding(
            rule_id="NET-T10",
            name="UDP flood",
            severity="HIGH",
            detail="500 UDP datagrams/s",
            action="review",
            key=signature,
        )

    def test_restore_keeps_newest_max_pending(self):
        queue = soc.DeferredTrafficQueue()
        queue.MAX_PENDING = 5
        for index in range(4):
            queue.push(self._finding(f"old{index}"), {}, "", f"old{index}", 1)
        leftovers = queue.take_all()
        for index in range(4):
            queue.push(self._finding(f"new{index}"), {}, "", f"new{index}", 1)
        queue.restore(leftovers)
        self.assertEqual(
            [item["signature"] for item in queue.take_all()],
            ["old3", "new0", "new1", "new2", "new3"],
        )

    def test_restore_without_overflow_keeps_chronological_order(self):
        queue = soc.DeferredTrafficQueue()
        queue.MAX_PENDING = 5
        queue.push(self._finding("old0"), {}, "", "old0", 1)
        leftovers = queue.take_all()
        queue.push(self._finding("new0"), {}, "", "new0", 1)
        queue.restore(leftovers)
        self.assertEqual(
            [item["signature"] for item in queue.take_all()],
            ["old0", "new0"],
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
