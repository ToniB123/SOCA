"""Integration tests for allow-list enforcement in checkstat.py.

Run with:  python -m unittest test_allowlist_integration.py
"""

import json
import tempfile
import unittest
from pathlib import Path

import checkstat as soc
import user_allowlist as u


def _options():
    return soc.build_traffic_options(
        {
            "traffic_detection": {
                "enabled": True,
                "sample_interval_seconds": 10,
                "window_seconds": 300,
                "min_baseline_samples": 4,
                "min_rate_seconds": 5,
                "thresholds": {
                    "udp_datagrams_per_second_floor": 500,
                    "udp_datagrams_baseline_multiplier": 3,
                    "udp_datagrams_absolute_floor": 25000,
                },
            },
        }
    )


def _udp_entry(pid=1234, port=50000):
    return soc.Connection(
        protocol="UDP",
        local_address=f"192.0.2.10:{port}",
        local_ip="192.0.2.10",
        local_port=port,
        foreign_address="",
        remote_ip="",
        foreign_port=0,
        state="",
        pid=pid,
    )


def _samples(options):
    entries = [_udp_entry() for _ in range(5)]
    stats = [0, 500, 1000, 1500, 2000, 2500, 8500]
    return [
        soc.build_traffic_metrics(
            entries,
            options=options,
            timestamp=index * 10.0,
            protocol_stats={"udp_received": value, "udp_errors": 0},
        )
        for index, value in enumerate(stats)
    ]


def _traffic_record():
    return {
        "timestamp": "2026-11-02T20:14:57-05:00",
        "snapshot": "fast-2026-11-02T20:14:57-05:00",
        "source": "traffic",
        "rule": {
            "rule_id": "NET-T10",
            "rule_ids": ["NET-T10"],
            "severity": "HIGH",
            "rule_name": "UDP flood",
        },
        "traffic": {
            "udp_datagrams_per_second": 600.0,
            "baseline_rate": 50.0,
            "udp_errors_per_second": 0.0,
            "udp_socket_count": 5,
            "udp_top_pids": [
                {"pid": 1234, "count": 5, "process_name": "firefox.exe"},
            ],
        },
    }


def _snapshot(record):
    derivation = u.derive_scope_from_record(record)
    assert derivation.eligible, derivation.reason
    entry = u.build_entry(derivation)
    return u.AllowlistSnapshot(entries=(entry,), revision="test", status="ok")


def _valid_details():
    return {
        1234: {
            "name": "firefox.exe",
            "path": "C:/Program Files/Mozilla Firefox/firefox.exe",
            "signature": "Valid",
        }
    }


class TrafficIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.options = _options()
        self.samples = _samples(self.options)

    def test_mute_applies_and_keeps_severity(self):
        findings = soc.evaluate_traffic(
            self.samples,
            self.options,
            process_names={1234: "firefox.exe"},
            process_details=_valid_details(),
            allowlist=_snapshot(_traffic_record()),
        )
        finding = next(item for item in findings if item.rule_id == "NET-T10")
        self.assertEqual(finding.severity, "HIGH")
        self.assertFalse(finding.informational)
        self.assertIsNotNone(finding.disposition)
        assert finding.disposition is not None
        self.assertTrue(finding.disposition["muted"])
        self.assertEqual(finding.metrics["udp_socket_count"], 5)
        self.assertTrue(finding.fast_key.endswith("owner:firefox.exe"))
        # A muted, non-informational finding still poisons the baseline sample.
        self.assertTrue(self.samples[-1].triggered)

    def test_identity_failure_blocks_mute(self):
        findings = soc.evaluate_traffic(
            self.samples,
            self.options,
            process_names={1234: "firefox.exe"},
            process_details={},
            allowlist=_snapshot(_traffic_record()),
        )
        finding = next(item for item in findings if item.rule_id == "NET-T10")
        assert finding.disposition is not None
        self.assertFalse(finding.disposition["muted"])
        self.assertEqual(finding.disposition["guard_blocked"], "identity_unverified")

    def test_no_allowlist_leaves_no_disposition(self):
        findings = soc.evaluate_traffic(
            self.samples,
            self.options,
            process_names={1234: "firefox.exe"},
            process_details=_valid_details(),
        )
        finding = next(item for item in findings if item.rule_id == "NET-T10")
        self.assertIsNone(finding.disposition)
        self.assertEqual(finding.fast_key, "")


class RowIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.group = soc.AnomalyGroup(
            rule_id="NET-002",
            rule_name="Connection flood from single remote",
            severity="HIGH",
            description="many connections",
            reason="count above threshold",
            remote_ip="203.0.113.10",
            foreign_port=50000,
            pid=4321,
            process_name="chrome.exe",
            rule_ids=["NET-002"],
            entries=[
                soc.Connection(
                    protocol="TCP",
                    local_address="192.0.2.10:53000",
                    local_ip="192.0.2.10",
                    local_port=53000,
                    foreign_address="203.0.113.10:50000",
                    remote_ip="203.0.113.10",
                    foreign_port=50000,
                    state="ESTABLISHED",
                    pid=4321,
                    process_name="chrome.exe",
                    remote_scope="global",
                )
            ],
        )
        record = {
            "timestamp": "2026-11-02T20:14:57-05:00",
            "snapshot": "live-2026-11-02T20:14:57-05:00",
            "rule": {
                "rule_id": "NET-002",
                "rule_ids": ["NET-002"],
                "severity": "HIGH",
                "rule_name": self.group.rule_name,
            },
            "group": {
                "remote_ip": "203.0.113.10",
                "foreign_port": 50000,
                "pid": 4321,
                "process_name": "chrome.exe",
                "local_ports": [53000],
                "entries": [{"protocol": "TCP", "local_port": 53000}],
            },
            "process": {"name": "chrome.exe"},
        }
        self.snapshot = _snapshot(record)
        self.details = {
            "name": "chrome.exe",
            "path": "C:/Program Files/Google/Chrome/chrome.exe",
            "signature": "Valid",
        }

    def test_row_mute_applies(self):
        disposition = soc.annotate_row_disposition(
            self.group, process_info=self.details, allowlist=self.snapshot
        )
        assert disposition is not None
        self.assertTrue(disposition["muted"])

    def test_row_identity_failure_blocks_mute(self):
        disposition = soc.annotate_row_disposition(
            self.group,
            process_info={
                "name": "chrome.exe",
                "path": "C:/Temp/chrome.exe",
                "signature": "NotSigned",
            },
            allowlist=self.snapshot,
        )
        assert disposition is not None
        self.assertFalse(disposition["muted"])
        self.assertEqual(disposition["guard_blocked"], "identity_unverified")

    def test_row_endpoint_mismatch_returns_none(self):
        self.group.foreign_port = 50001
        disposition = soc.annotate_row_disposition(
            self.group, process_info=self.details, allowlist=self.snapshot
        )
        self.assertIsNone(disposition)


class RecordSchemaTests(unittest.TestCase):
    def test_disposition_is_written_with_schema_v1(self):
        with tempfile.TemporaryDirectory() as temp:
            findings = Path(temp) / "soc_findings.jsonl"
            logger = soc.SocLogger(Path(temp) / "human.log", findings)
            logger.finding(
                {
                    "timestamp": "2026-11-02T20:14:57-05:00",
                    "rule": {"rule_id": "NET-T10", "severity": "HIGH"},
                    "disposition": {"muted": True, "allowlist_id": "abc"},
                }
            )
            record = json.loads(findings.read_text(encoding="utf-8").strip())
        self.assertEqual(record["schema_version"], 1)
        self.assertTrue(record["disposition"]["muted"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
