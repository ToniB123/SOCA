#!/usr/bin/env python3
"""Offline tests for network_health.py.

Run with:  uv run python -m unittest tests.test_network_health -v
No live probes are made: IcmpSendEcho/TCP/gateway discovery are patched.
"""

import ipaddress
import json
import math
import struct
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from soca.core import network_health as nh


def _summary(
    *,
    host="8.8.8.8",
    label="target",
    reachable=True,
    healthy=True,
    sent=4,
    received=4,
    loss=0.0,
    rtt=20.0,
    jitter=1.0,
    probe="icmp",
    error=None,
):
    return nh.ProbeSummary(
        host=host,
        port=443,
        label=label,
        sent=sent,
        received=received,
        loss_pct=loss,
        rtt_ms_min=rtt,
        rtt_ms_avg=rtt,
        rtt_ms_max=rtt,
        jitter_ms=jitter,
        probe=probe,
        reachable=reachable,
        healthy=healthy,
        error=error,
    )


def _assessment(gateway, targets):
    return nh.assess_network_health(gateway, targets, nh.default_options())


def _raw_ipv4(value):
    """Network-order IPv4 bytes as the little-endian DWORD Windows stores."""
    return struct.unpack("<I", ipaddress.IPv4Address(value).packed)[0]


def _forward_table(rows):
    """Build a MIB_IPFORWARDTABLE blob; rows are 14-value tuples."""
    body = b"".join(struct.pack("<14I", *row) for row in rows)
    return struct.pack("<I", len(rows)) + body


class AssessmentMatrixTests(unittest.TestCase):
    def test_responsive_when_gateway_and_targets_healthy(self):
        assessment = _assessment(
            _summary(host="10.0.0.1"), [_summary(), _summary(host="1.1.1.1")]
        )
        self.assertEqual(assessment.verdict, "RESPONSIVE")
        self.assertEqual(assessment.gateway_status, "healthy")
        self.assertEqual(assessment.confidence, "high")
        self.assertTrue(assessment.external_ok)

    def test_local_link_when_gateway_unreachable_and_external_failed(self):
        gateway = _summary(
            host="10.0.0.1", reachable=False, healthy=False,
            sent=4, received=0, loss=100.0, rtt=None, jitter=None,
            error="timeout",
        )
        targets = [
            _summary(reachable=False, healthy=False, received=0, loss=100.0),
            _summary(reachable=False, healthy=False, received=0, loss=100.0),
        ]
        assessment = _assessment(gateway, targets)
        self.assertEqual(assessment.verdict, "LOCAL_LINK")
        self.assertEqual(assessment.gateway_status, "unreachable")
        self.assertFalse(assessment.local_link_ok)

    def test_local_link_when_gateway_degraded_and_external_failed(self):
        gateway = _summary(healthy=False, loss=40.0)
        targets = [
            _summary(reachable=False, healthy=False, received=0, loss=100.0),
        ]
        assessment = _assessment(gateway, targets)
        self.assertEqual(assessment.verdict, "LOCAL_LINK")
        self.assertEqual(assessment.gateway_status, "degraded")

    def test_filtered_gateway_with_external_success_is_not_local_link(self):
        gateway = _summary(
            host="10.0.0.1", reachable=False, healthy=False,
            received=0, loss=100.0, error="timeout",
        )
        assessment = _assessment(gateway, [_summary()])
        self.assertEqual(assessment.verdict, "RESPONSIVE")
        self.assertEqual(assessment.gateway_status, "filtered")
        self.assertIn("filtered", assessment.summary)

    def test_upstream_when_gateway_healthy_and_all_targets_failed(self):
        targets = [
            _summary(reachable=False, healthy=False, received=0, loss=100.0),
            _summary(reachable=False, healthy=False, received=0, loss=100.0),
        ]
        assessment = _assessment(_summary(host="10.0.0.1"), targets)
        self.assertEqual(assessment.verdict, "UPSTREAM_ISP")
        self.assertEqual(assessment.confidence, "high")
        self.assertIn("not proof of an upstream DDoS", assessment.summary)
        self.assertIn("consistent with upstream/ISP", assessment.summary)

    def test_upstream_when_gateway_healthy_and_targets_reachable_degraded(self):
        targets = [
            _summary(healthy=False, loss=40.0, rtt=600.0),
            _summary(healthy=False, loss=40.0, rtt=600.0),
        ]
        assessment = _assessment(_summary(host="10.0.0.1"), targets)
        self.assertEqual(assessment.verdict, "UPSTREAM_ISP")
        self.assertEqual(assessment.confidence, "medium")

    def test_destination_path_when_targets_are_mixed(self):
        targets = [_summary(host="1.1.1.1"), _summary(healthy=False, loss=40.0)]
        assessment = _assessment(_summary(host="10.0.0.1"), targets)
        self.assertEqual(assessment.verdict, "DESTINATION_PATH")
        self.assertIn("destination or peering", assessment.summary)

    def test_unknown_when_no_gateway_and_all_targets_failed(self):
        targets = [
            _summary(reachable=False, healthy=False, received=0, loss=100.0),
        ]
        assessment = _assessment(None, targets)
        self.assertEqual(assessment.verdict, "UNKNOWN")
        self.assertEqual(assessment.gateway_status, "unresolved")
        self.assertEqual(assessment.confidence, "low")

    def test_unresolved_gateway_probe_is_unknown_when_external_fails(self):
        gateway = nh.ProbeSummary(
            host="", port=None, label="gateway", sent=0, received=0,
            loss_pct=100.0, rtt_ms_min=None, rtt_ms_avg=None,
            rtt_ms_max=None, jitter_ms=None, probe="none",
            reachable=False, healthy=False, error="no IPv4 default route",
        )
        target = _summary(reachable=False, healthy=False, received=0, loss=100.0)
        assessment = _assessment(gateway, [target])
        self.assertEqual(assessment.verdict, "UNKNOWN")
        self.assertEqual(assessment.gateway_status, "unresolved")

    def test_unknown_when_no_targets_configured(self):
        assessment = _assessment(_summary(host="10.0.0.1"), [])
        self.assertEqual(assessment.verdict, "UNKNOWN")
        self.assertEqual(assessment.reason, "no_external_targets")

    def test_single_degraded_target_is_destination_path(self):
        assessment = _assessment(
            _summary(host="10.0.0.1"),
            [_summary(healthy=False, loss=40.0)],
        )
        self.assertEqual(assessment.verdict, "DESTINATION_PATH")
        self.assertEqual(assessment.reason, "single_external_degraded")

    def test_threshold_boundaries_are_inclusive(self):
        options = nh.default_options()
        summary = nh._aggregate(
            [
                nh.ProbeAttempt("icmp", True, float(options["degraded_rtt_ms"]))
                for _ in range(4)
            ],
            "1.1.1.1",
            443,
            "boundary",
            options,
        )
        self.assertTrue(summary.healthy)
        self.assertEqual(
            summary.loss_pct, 0.0
        )

    def test_caveat_and_summaries_never_claim_confirmation(self):
        for verdict in ("LOCAL_LINK", "UPSTREAM_ISP"):
            if verdict == "LOCAL_LINK":
                failed = _summary(
                    reachable=False, healthy=False, received=0, loss=100.0
                )
                assessment = _assessment(
                    _summary(
                        reachable=False, healthy=False, received=0,
                        loss=100.0,
                    ),
                    [failed],
                )
            else:
                assessment = _assessment(
                    _summary(host="10.0.0.1"),
                    [
                        _summary(host="1.1.1.1", healthy=False, loss=40.0),
                        _summary(host="8.8.8.8", healthy=False, loss=40.0),
                    ],
                )
            self.assertEqual(assessment.verdict, verdict)
            self.assertNotIn("DDoS detected", assessment.summary)
            self.assertNotIn("attack confirmed", assessment.summary)
            self.assertNotIn("proven", assessment.summary)


class ProbeAggregationTests(unittest.TestCase):
    def test_aggregate_counts_loss_rtt_and_jitter(self):
        summary = nh._aggregate(
            [
                nh.ProbeAttempt("icmp", True, 10.0),
                nh.ProbeAttempt("icmp", True, 20.0),
                nh.ProbeAttempt("icmp", False, None, "timeout"),
            ],
            "8.8.8.8",
            443,
            "test",
            nh.default_options(),
        )
        self.assertEqual(summary.sent, 3)
        self.assertEqual(summary.received, 2)
        self.assertAlmostEqual(summary.loss_pct, 33.3)
        self.assertEqual(summary.rtt_ms_min, 10.0)
        self.assertEqual(summary.rtt_ms_avg, 15.0)
        self.assertEqual(summary.rtt_ms_max, 20.0)
        self.assertEqual(summary.jitter_ms, 10.0)
        self.assertFalse(summary.healthy)
        self.assertEqual(summary.probe, "icmp")

    def test_jitter_needs_two_successes(self):
        summary = nh._aggregate(
            [nh.ProbeAttempt("icmp", True, 10.0)],
            "8.8.8.8",
            443,
            "test",
            nh.default_options(),
        )
        self.assertIsNone(summary.jitter_ms)

    def test_tcp_refused_counts_as_reachable(self):
        with mock.patch.object(
            nh.socket, "create_connection", side_effect=ConnectionRefusedError()
        ):
            attempt = nh.probe_tcp_fallback("1.1.1.1", 443, 100)
        self.assertTrue(attempt.ok)
        self.assertTrue(attempt.refused)

    def test_tcp_timeout_is_failure(self):
        with mock.patch.object(
            nh.socket, "create_connection", side_effect=TimeoutError("timeout")
        ):
            attempt = nh.probe_tcp_fallback("1.1.1.1", 443, 100)
        self.assertFalse(attempt.ok)

    def test_probe_target_falls_back_to_tcp_after_icmp_failures(self):
        options = dict(nh.default_options())
        options["probes_per_target"] = 2
        with (mock.patch.object(
                  nh, "probe_icmp",
                  return_value=nh.ProbeAttempt("icmp", False, None, "timeout")),
              mock.patch.object(
                  nh, "probe_tcp_fallback",
                  return_value=nh.ProbeAttempt("tcp", True, 12.0))):
            summary = nh.probe_target(
                {"host": "1.1.1.1", "port": 443, "label": "cf"}, options
            )
        self.assertEqual(summary.probe, "tcp")
        self.assertTrue(summary.reachable)
        self.assertEqual(summary.sent, 2)

    def test_ipv6_target_uses_tcp_only(self):
        options = dict(nh.default_options())
        options["probes_per_target"] = 2
        with (mock.patch.object(nh, "probe_icmp") as icmp,
              mock.patch.object(
                  nh, "probe_tcp_fallback",
                  return_value=nh.ProbeAttempt("tcp", True, 12.0))):
            summary = nh.probe_target(
                {"host": "2001:db8::1", "port": 443, "label": "v6"}, options
            )
        icmp.assert_not_called()
        self.assertEqual(summary.probe, "tcp")
        self.assertTrue(summary.reachable)

    def test_deadline_stops_attempts(self):
        options = dict(nh.default_options())
        summary = nh.probe_target(
            {"host": "1.1.1.1", "port": 443, "label": "cf"},
            options,
            deadline=time.monotonic() - 1,
        )
        self.assertEqual(summary.sent, 0)
        self.assertFalse(summary.reachable)

    def test_aggregation_is_json_safe(self):
        summary = nh._aggregate(
            [
                nh.ProbeAttempt("tcp", True, 1.23456789),
                nh.ProbeAttempt("tcp", True, 2.3456789),
            ],
            "1.1.1.1",
            443,
            "cf",
            nh.default_options(),
        )
        payload = json.dumps(summary.__dict__)
        self.assertIn("jitter_ms", payload)
        for value in (
            summary.rtt_ms_min, summary.rtt_ms_avg, summary.rtt_ms_max,
            summary.jitter_ms,
        ):
            self.assertTrue(value is None or math.isfinite(value))


class GatewayDiscoveryTests(unittest.TestCase):
    def test_parser_picks_lowest_metric_default_route(self):
        low = _raw_ipv4("10.0.0.1")
        high = _raw_ipv4("10.0.0.2")
        data = _forward_table([
            (0, 0, 0, high, 1, 3, 3, 0, 0, 30, 0, 0, 0, 0),
            (0, 0, 0, low, 1, 3, 3, 0, 0, 10, 0, 0, 0, 0),
        ])
        self.assertEqual(nh._parse_forward_table(data), "10.0.0.1")

    def test_parser_ignores_non_default_routes(self):
        next_hop = _raw_ipv4("10.0.0.1")
        data = _forward_table([
            (0x0A000000, 0xFFFFFF00, 0, next_hop, 1, 3, 3, 0, 0, 1, 0, 0, 0, 0),
        ])
        self.assertIsNone(nh._parse_forward_table(data))

    def test_default_gateway_reports_error_off_windows(self):
        with mock.patch.object(nh, "_ON_WINDOWS", False), \
                mock.patch.object(nh, "_iphlpapi", None):
            result = nh.default_gateway_v4()
        self.assertIsNone(result["ip"])
        self.assertIn("Windows", result["error"])

    def test_configured_gateway_skips_discovery(self):
        options = dict(nh.default_options())
        options["gateway"] = "10.0.0.1"
        options["probes_per_target"] = 1
        with (mock.patch.object(nh, "default_gateway_v4") as discovery,
              mock.patch.object(
                  nh, "probe_icmp",
                  return_value=nh.ProbeAttempt("icmp", True, 2.0))):
            summary = nh.probe_gateway(options)
        discovery.assert_not_called()
        self.assertIsNotNone(summary)
        self.assertEqual(summary.host, "10.0.0.1")

    def test_unresolved_gateway_summary(self):
        with mock.patch.object(
            nh, "default_gateway_v4",
            return_value={"ip": None, "error": "no IPv4 default route"},
        ):
            summary = nh.probe_gateway(nh.default_options())
        self.assertIsNotNone(summary)
        self.assertFalse(summary.reachable)
        self.assertIn("no IPv4 default route", summary.error)


class ResultFileTests(unittest.TestCase):
    def test_write_and_read_round_trip(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / nh.RESULT_FILE
            result = nh.disabled_result(nh.default_options(), "pending")
            self.assertTrue(nh.write_result_atomic(path, result))
            loaded = nh.read_result(path)
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded["verdict"], "UNKNOWN")
        self.assertEqual(loaded["source"], "pending")

    def test_read_rejects_oversized_and_malformed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / nh.RESULT_FILE
            path.write_bytes(b"x" * 100)
            self.assertIsNone(nh.read_result(path, max_bytes=10))
            path.write_text("not json", encoding="utf-8")
            self.assertIsNone(nh.read_result(path))
            path.write_text(json.dumps({"verdict": "BOGUS",
                                       "generated_at": time.time(),
                                       "caveat": "x"}),
                            encoding="utf-8")
            self.assertIsNone(nh.read_result(path))

    def test_write_retries_a_sharing_violation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / nh.RESULT_FILE
            real_replace = nh.os.replace
            calls = {"n": 0}

            def flaky_replace(src, dst):
                calls["n"] += 1
                if calls["n"] == 1:
                    raise PermissionError("sharing violation")
                return real_replace(src, dst)

            with mock.patch.object(nh.os, "replace", side_effect=flaky_replace):
                ok = nh.write_result_atomic(
                    path, nh.disabled_result(nh.default_options(), "pending")
                )
        self.assertTrue(ok)
        self.assertEqual(calls["n"], 2)


class MonitorLifecycleTests(unittest.TestCase):
    def test_monitor_writes_result_and_can_be_stopped(self):
        sample = nh.disabled_result(nh.default_options(), "pending")
        sample["verdict"] = "RESPONSIVE"
        sample["source"] = "checkstat"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / nh.RESULT_FILE
            options = dict(nh.default_options())
            options["interval_seconds"] = 15
            monitor = nh.NetworkHealthMonitor(options, result_path=path)
            with mock.patch.object(nh, "probe_once", return_value=sample):
                monitor.start()
                self.assertTrue(monitor.wait_for_sample(3.0))
                monitor.stop()
            self.assertFalse(monitor.is_alive())
            loaded = nh.read_result(path)
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded["verdict"], "RESPONSIVE")

    def test_monitor_retains_last_result_after_exception(self):
        sample = nh.disabled_result(nh.default_options(), "pending")
        options = dict(nh.default_options())
        monitor = nh.NetworkHealthMonitor(options, result_path=Path("unused"))
        monitor._latest = sample

        def fail(*args, **kwargs):
            monitor._stop_event.set()
            raise RuntimeError("probe exploded")

        with mock.patch.object(nh, "probe_once", side_effect=fail):
            monitor.run()
        self.assertEqual(monitor.latest()["verdict"], "UNKNOWN")

    def test_wait_for_sample_times_out(self):
        monitor = nh.NetworkHealthMonitor(
            nh.default_options(), result_path=Path("unused")
        )
        self.assertFalse(monitor.wait_for_sample(0.01))

    def test_budget_is_bounded(self):
        options = nh.default_options()
        budget = nh.estimated_budget_seconds(options)
        self.assertGreater(budget, 0)
        self.assertLess(budget, options["interval_seconds"])


class DisabledResultTests(unittest.TestCase):
    def test_disabled_replay_and_pending_shapes(self):
        options = nh.default_options()
        disabled = nh.disabled_result(options, "disabled")
        replay = nh.disabled_result(options, "replay")
        pending = nh.disabled_result(options, "pending")
        self.assertFalse(disabled["enabled"])
        self.assertEqual(disabled["gateway_status"], "not_probed")
        self.assertFalse(replay["enabled"])
        self.assertIn("replay", replay["summary"].lower())
        self.assertTrue(pending["enabled"])
        self.assertIn("pending", pending["summary"].lower())
        for result in (disabled, replay, pending):
            self.assertEqual(result["verdict"], "UNKNOWN")
            self.assertEqual(result["caveat"], nh.CAVEAT)

    def test_probe_once_respects_disabled(self):
        options = nh.default_options()
        options["enabled"] = False
        with mock.patch.object(nh, "probe_gateway") as gateway:
            result = nh.probe_once(options)
        gateway.assert_not_called()
        self.assertEqual(result["source"], "disabled")
        self.assertFalse(result["enabled"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
