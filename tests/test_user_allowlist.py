"""Offline tests for the scoped user allow-list.

Run with:  uv run python -m unittest tests.test_user_allowlist -v
"""

import json
import os
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path
from typing import Any
from unittest import mock

import user_allowlist as u

# ---------------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------------


def traffic_record(
    *,
    rate=600.0,
    baseline=50.0,
    errors=0.0,
    sockets=6,
    owners=None,
    severity="HIGH",
    rule="NET-T10",
    source="traffic",
):
    return {
        "timestamp": "2026-11-02T20:14:57-05:00",
        "snapshot": "fast-2026-11-02T20:14:57-05:00",
        "source": source,
        "rule": {
            "rule_id": rule,
            "rule_ids": [rule],
            "severity": severity,
            "rule_name": "UDP flood",
            "description": "UDP flood",
        },
        "traffic": {
            "udp_datagrams_per_second": rate,
            "baseline_rate": baseline,
            "udp_errors_per_second": errors,
            "udp_socket_count": sockets,
            "udp_top_pids": owners
            if owners is not None
            else [
                {"pid": 1234, "count": 5, "process_name": "firefox.exe"},
            ],
        },
    }


def row_record(
    *,
    rule="NET-002",
    severity="HIGH",
    remote="203.0.113.10",
    port=50000,
    protocol="TCP",
    process="chrome.exe",
):
    return {
        "timestamp": "2026-11-02T20:14:57-05:00",
        "snapshot": "live-2026-11-02T20:14:57-05:00",
        "rule": {
            "rule_id": rule,
            "rule_ids": [rule],
            "severity": severity,
            "rule_name": "row rule",
            "description": "row rule",
        },
        "group": {
            "remote_ip": remote,
            "foreign_port": port,
            "pid": 4321,
            "process_name": process,
            "local_ports": [53000],
            "entries": [{"protocol": protocol, "local_port": 53000}],
        },
        "process": {
            "name": process,
            "path": "C:/Program Files/Chrome/chrome.exe",
            "signature": "Valid",
        },
    }


def entry_for(record, *, ttl_days=30, reason="test"):
    derivation = u.derive_scope_from_record(record)
    assert derivation.eligible, derivation.reason
    return u.build_entry(derivation, ttl_days=ttl_days, reason=reason)


def snapshot(entries):
    return u.AllowlistSnapshot(entries=tuple(entries), revision="test", status="ok")


def traffic_observation(**overrides: Any):
    values: dict[str, Any] = {
        "kind": "traffic_udp",
        "rule_ids": ("NET-T10",),
        "severity": "HIGH",
        "process_name": "firefox.exe",
        "pid": 1234,
        "rate": 600.0,
        "baseline_rate": 50.0,
        "udp_errors": 0.0,
        "udp_socket_count": 6,
        "top_owner_counts": (("firefox.exe", 5),),
        "identity_by_name": (("firefox.exe", True),),
        "protocols": ("UDP",),
    }
    values.update(overrides)
    return u.Observation(**values)


def row_observation(**overrides: Any):
    values: dict[str, Any] = {
        "kind": "row_endpoint",
        "rule_ids": ("NET-002",),
        "severity": "HIGH",
        "process_name": "chrome.exe",
        "pid": 4321,
        "remote_ip": "203.0.113.10",
        "foreign_port": 50000,
        "local_ports": (53000,),
        "protocols": ("TCP",),
        "identity_by_name": (("chrome.exe", True),),
    }
    values.update(overrides)
    return u.Observation(**values)


# ---------------------------------------------------------------------------
# Loading and schema
# ---------------------------------------------------------------------------


class LoaderTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "soc_user_allowlist.json"

    def write(self, payload):
        self.path.write_text(json.dumps(payload), encoding="utf-8")

    def test_missing_file_is_empty(self):
        snap = u.load_snapshot(self.path, force=True)
        self.assertEqual(snap.status, "missing")
        self.assertEqual(snap.entries, ())

    def test_valid_round_trip(self):
        entry = entry_for(traffic_record())
        self.write({"schema_version": 1, "entries": [entry]})
        snap = u.load_snapshot(self.path, force=True)
        self.assertEqual(snap.status, "ok")
        self.assertEqual(len(snap.entries), 1)
        self.assertEqual(snap.invalid_entries, 0)
        self.assertEqual(len(u.active_entries(snap)), 1)

    def test_invalid_json_disables_all(self):
        self.path.write_text("{not json", encoding="utf-8")
        snap = u.load_snapshot(self.path, force=True)
        self.assertEqual(snap.status, "unreadable")
        self.assertEqual(snap.entries, ())

    def test_unsupported_schema_version(self):
        self.write({"schema_version": 2, "entries": []})
        snap = u.load_snapshot(self.path, force=True)
        self.assertEqual(snap.status, "unsupported_version")
        self.assertEqual(snap.entries, ())

    def test_oversized_file(self):
        self.path.write_bytes(b"x" * (u.MAX_FILE_BYTES + 1))
        snap = u.load_snapshot(self.path, force=True)
        self.assertEqual(snap.status, "oversized")
        self.assertEqual(snap.entries, ())

    def test_one_bad_entry_among_valid(self):
        good = entry_for(traffic_record())
        bad = dict(good)
        bad["id"] = "not-a-uuid"
        self.write({"schema_version": 1, "entries": [bad, good]})
        snap = u.load_snapshot(self.path, force=True)
        self.assertEqual(len(snap.entries), 1)
        self.assertEqual(snap.invalid_entries, 1)

    def test_disabled_entry_is_retained_but_inactive(self):
        entry = entry_for(traffic_record())
        entry["enabled"] = False
        self.write({"schema_version": 1, "entries": [entry]})
        snap = u.load_snapshot(self.path, force=True)
        self.assertEqual(len(snap.entries), 1)
        self.assertEqual(u.active_entries(snap), ())

    def test_corruption_does_not_reuse_last_good(self):
        entry = entry_for(traffic_record())
        self.write({"schema_version": 1, "entries": [entry]})
        self.assertEqual(len(u.load_snapshot(self.path, force=True).entries), 1)
        self.path.write_text("{broken", encoding="utf-8")
        snap = u.load_snapshot(self.path, force=True)
        self.assertEqual(snap.entries, ())

    def test_mtime_cache_sees_edits(self):
        first = entry_for(traffic_record())
        self.write({"schema_version": 1, "entries": [first]})
        self.assertEqual(len(u.load_snapshot(self.path).entries), 1)
        second = entry_for(traffic_record(rate=900.0))
        self.write({"schema_version": 1, "entries": [second]})
        stat = self.path.stat()
        os.utime(
            self.path,
            ns=(stat.st_mtime_ns + 1_000_000_000, stat.st_mtime_ns + 1_000_000_000),
        )
        snap = u.load_snapshot(self.path)
        self.assertEqual(snap.entries[0]["id"], second["id"])


class ValidationTests(unittest.TestCase):
    def test_valid_traffic_entry(self):
        entry = entry_for(traffic_record())
        normalized, error = u.validate_entry(entry)
        self.assertIsNone(error)
        assert normalized is not None
        self.assertEqual(normalized["scope"]["kind"], "traffic_udp")

    def test_valid_row_entry(self):
        entry = entry_for(row_record())
        normalized, error = u.validate_entry(entry)
        self.assertIsNone(error)
        assert normalized is not None
        self.assertEqual(normalized["scope"]["kind"], "row_endpoint")

    def test_critical_severity_rejected(self):
        entry = entry_for(traffic_record())
        entry["scope"] = dict(entry["scope"], severity_at_mute="CRITICAL")
        self.assertIsNotNone(u.validate_entry(entry)[1])

    def test_rule_only_row_scope_rejected(self):
        entry = entry_for(row_record())
        scope = dict(entry["scope"], remote_ip=None, foreign_port=None)
        entry["scope"] = scope
        self.assertIsNotNone(u.validate_entry(entry)[1])

    def test_missing_process_names_rejected(self):
        entry = entry_for(traffic_record())
        entry["scope"] = dict(entry["scope"], process_names=[])
        self.assertIsNotNone(u.validate_entry(entry)[1])

    def test_absurd_rate_max_rejected(self):
        entry = entry_for(traffic_record())
        entry["scope"] = dict(entry["scope"], rate_max=u.MAX_RATE)
        self.assertIsNotNone(u.validate_entry(entry)[1])

    def test_ttl_mismatch_rejected(self):
        entry = entry_for(traffic_record(), ttl_days=30)
        entry["expires_at"] = entry["created_at"]  # same instant
        self.assertIsNotNone(u.validate_entry(entry)[1])

    def test_future_created_rejected(self):
        entry = entry_for(traffic_record())
        future = u._utcnow() + timedelta(hours=1)
        entry["created_at"] = u._iso(future)
        entry["expires_at"] = u._iso(future + timedelta(days=30))
        self.assertIsNotNone(u.validate_entry(entry)[1])

    def test_bad_uuid_rejected(self):
        entry = entry_for(traffic_record())
        entry["id"] = "1234"
        self.assertIsNotNone(u.validate_entry(entry)[1])

    def test_reason_control_chars_rejected(self):
        entry = entry_for(traffic_record())
        entry["reason"] = "bad\x00reason"
        self.assertIsNotNone(u.validate_entry(entry)[1])

    def test_row_remote_ip_not_allowed_for_port_rule(self):
        entry = entry_for(row_record(rule="NET-001", process="chrome.exe"))
        entry["scope"] = dict(entry["scope"], remote_ip="203.0.113.10")
        self.assertIsNotNone(u.validate_entry(entry)[1])


# ---------------------------------------------------------------------------
# Scope derivation
# ---------------------------------------------------------------------------


class DerivationTests(unittest.TestCase):
    def test_traffic_happy_path(self):
        derivation = u.derive_scope_from_record(traffic_record())
        self.assertTrue(derivation.eligible)
        scope = derivation.scope
        assert scope is not None
        self.assertEqual(scope["rule_ids"], ["NET-T10"])
        self.assertEqual(scope["process_names"], ["firefox.exe"])
        self.assertEqual(scope["pids_at_mute"], [1234])
        self.assertEqual(scope["rate_max"], 1000)
        self.assertEqual(scope["min_share"], 0.5)
        self.assertTrue(derivation.guards)

    def test_traffic_absolute_floor_ineligible(self):
        derivation = u.derive_scope_from_record(traffic_record(rate=25000.0))
        self.assertFalse(derivation.eligible)
        self.assertEqual(derivation.code, "absolute_flood_floor")

    def test_traffic_missing_owner_ineligible(self):
        derivation = u.derive_scope_from_record(traffic_record(owners=[]))
        self.assertFalse(derivation.eligible)
        self.assertEqual(derivation.code, "no_process_attribution")

    def test_traffic_unknown_owner_ineligible(self):
        owners = [{"pid": 1, "count": 5, "process_name": "Unknown"}]
        derivation = u.derive_scope_from_record(traffic_record(owners=owners))
        self.assertEqual(derivation.code, "no_process_attribution")

    def test_traffic_ambiguous_owner_ineligible(self):
        owners = [
            {"pid": 1, "count": 5, "process_name": "firefox.exe"},
            {"pid": 2, "count": 5, "process_name": "svchost.exe"},
        ]
        derivation = u.derive_scope_from_record(traffic_record(owners=owners))
        self.assertEqual(derivation.code, "ambiguous_udp_owner")

    def test_traffic_share_below_min_ineligible(self):
        owners = [{"pid": 1, "count": 2, "process_name": "firefox.exe"}]
        derivation = u.derive_scope_from_record(
            traffic_record(owners=owners, sockets=10)
        )
        self.assertEqual(derivation.code, "owner_share_below_min")

    def test_critical_ineligible(self):
        derivation = u.derive_scope_from_record(traffic_record(severity="CRITICAL"))
        self.assertEqual(derivation.code, "critical_not_mutable")

    def test_unsupported_rule_ineligible(self):
        derivation = u.derive_scope_from_record(traffic_record(rule="NET-003"))
        self.assertEqual(derivation.code, "unsupported_rule")

    def test_row_net002_keeps_remote_ip(self):
        derivation = u.derive_scope_from_record(row_record(rule="NET-002"))
        self.assertTrue(derivation.eligible)
        assert derivation.scope is not None
        self.assertEqual(derivation.scope["remote_ip"], "203.0.113.10")
        self.assertEqual(derivation.scope["foreign_port"], 50000)

    def test_row_net001_drops_remote_ip(self):
        derivation = u.derive_scope_from_record(row_record(rule="NET-001"))
        self.assertTrue(derivation.eligible)
        assert derivation.scope is not None
        self.assertIsNone(derivation.scope["remote_ip"])
        self.assertEqual(derivation.scope["foreign_port"], 50000)

    def test_row_net009_keeps_remote_ip(self):
        derivation = u.derive_scope_from_record(
            row_record(rule="NET-009", protocol="UDP")
        )
        self.assertTrue(derivation.eligible)
        assert derivation.scope is not None
        self.assertEqual(derivation.scope["remote_ip"], "203.0.113.10")

    def test_row_missing_process_ineligible(self):
        record = row_record(process="Unknown")
        record["process"]["name"] = ""
        derivation = u.derive_scope_from_record(record)
        self.assertEqual(derivation.code, "process_required")

    def test_row_missing_endpoint_ineligible(self):
        record = row_record()
        record["group"]["foreign_port"] = None
        derivation = u.derive_scope_from_record(record)
        self.assertEqual(derivation.code, "no_endpoint")


# ---------------------------------------------------------------------------
# Matching and guards
# ---------------------------------------------------------------------------


class MatchingTests(unittest.TestCase):
    def setUp(self):
        self.entry = entry_for(traffic_record())
        self.snap = snapshot([self.entry])

    def test_mute_applies(self):
        disposition = u.match_observation(traffic_observation(), self.snap)
        self.assertTrue(disposition["muted"])
        self.assertEqual(disposition["allowlist_id"], self.entry["id"])
        self.assertIsNone(disposition["guard_blocked"])

    def test_severity_increase_reopens(self):
        disposition = u.match_observation(
            traffic_observation(severity="CRITICAL"), self.snap
        )
        self.assertFalse(disposition["muted"])
        self.assertEqual(disposition["guard_blocked"], "severity_increase")

    def test_rate_above_band_reopens(self):
        disposition = u.match_observation(traffic_observation(rate=5000.0), self.snap)
        self.assertEqual(disposition["guard_blocked"], "rate_above_band")

    def test_agent_absolute_floor_clamps(self):
        entry = dict(self.entry)
        entry["scope"] = dict(entry["scope"], rate_max=40000.0)
        snap = snapshot([entry])
        disposition = u.match_observation(traffic_observation(rate=30000.0), snap)
        self.assertEqual(disposition["guard_blocked"], "rate_above_band")

    def test_udp_errors_reopen(self):
        disposition = u.match_observation(
            traffic_observation(udp_errors=3.0), self.snap
        )
        self.assertEqual(disposition["guard_blocked"], "udp_errors")

    def test_missing_udp_errors_fail_closed(self):
        disposition = u.match_observation(
            traffic_observation(udp_errors=None), self.snap
        )
        self.assertEqual(disposition["guard_blocked"], "udp_errors_unavailable")

    def test_cofire_reopens(self):
        disposition = u.match_observation(
            traffic_observation(cofire_rules=("NET-T12",)), self.snap
        )
        self.assertEqual(disposition["guard_blocked"], "cofire:NET-T12")

    def test_share_below_min_reopens(self):
        disposition = u.match_observation(
            traffic_observation(
                udp_socket_count=20, top_owner_counts=(("firefox.exe", 5),)
            ),
            self.snap,
        )
        self.assertEqual(disposition["guard_blocked"], "process_share_below_min")

    def test_identity_unverified_reopens(self):
        for identity in (None, False):
            disposition = u.match_observation(
                traffic_observation(identity_by_name=(("firefox.exe", identity),)),
                self.snap,
            )
            self.assertEqual(disposition["guard_blocked"], "identity_unverified")

    def test_baseline_drift_reopens(self):
        disposition = u.match_observation(
            traffic_observation(baseline_rate=6000.0), self.snap
        )
        self.assertEqual(disposition["guard_blocked"], "baseline_drift")

    def test_hand_edited_guards_do_not_weaken(self):
        entry = dict(self.entry)
        entry["guards"] = dict(entry["guards"], reopen_on_udp_errors=False)
        disposition = u.match_observation(
            traffic_observation(udp_errors=5.0), snapshot([entry])
        )
        self.assertEqual(disposition["guard_blocked"], "udp_errors")

    def test_scope_mismatch_returns_none(self):
        disposition = u.match_observation(
            traffic_observation(process_name="svchost.exe"), self.snap
        )
        self.assertIsNone(disposition)

    def test_expired_entry_does_not_mute(self):
        expiry = u._parse_iso(self.entry["expires_at"]) + timedelta(seconds=1)
        disposition = u.match_observation(traffic_observation(), self.snap, now=expiry)
        self.assertIsNone(disposition)

    def test_disabled_entry_does_not_mute(self):
        entry = dict(self.entry, enabled=False)
        self.assertIsNone(u.match_observation(traffic_observation(), snapshot([entry])))

    def test_row_mute_applies(self):
        entry = entry_for(row_record(rule="NET-002"))
        disposition = u.match_observation(row_observation(), snapshot([entry]))
        self.assertTrue(disposition["muted"])

    def test_row_endpoint_mismatch_returns_none(self):
        entry = entry_for(row_record(rule="NET-002"))
        disposition = u.match_observation(
            row_observation(foreign_port=50001), snapshot([entry])
        )
        self.assertIsNone(disposition)

    def test_row_extra_rule_reopens(self):
        entry = entry_for(row_record(rule="NET-002"))
        disposition = u.match_observation(
            row_observation(cofire_rules=(), rule_ids=("NET-002", "NET-009")),
            snapshot([entry]),
        )
        self.assertIn(
            disposition["guard_blocked"], {"rule_set_changed", "cofire:NET-009"}
        )

    def test_row_severity_increase_reopens(self):
        entry = entry_for(row_record(rule="NET-002"))
        disposition = u.match_observation(
            row_observation(severity="CRITICAL"), snapshot([entry])
        )
        self.assertEqual(disposition["guard_blocked"], "severity_increase")

    def test_row_identity_failure_reopens(self):
        entry = entry_for(row_record(rule="NET-002"))
        disposition = u.match_observation(
            row_observation(identity_by_name=(("chrome.exe", False),)),
            snapshot([entry]),
        )
        self.assertEqual(disposition["guard_blocked"], "identity_unverified")


# ---------------------------------------------------------------------------
# Display matching for historical records
# ---------------------------------------------------------------------------


class MatchRecordForDisplayTests(unittest.TestCase):
    def test_traffic_record_matches(self):
        entry = entry_for(traffic_record())
        self.assertEqual(
            u.match_record_for_display(traffic_record(), snapshot([entry])),
            entry["id"],
        )

    def test_rate_above_band_does_not_match(self):
        entry = entry_for(traffic_record())
        self.assertIsNone(
            u.match_record_for_display(
                traffic_record(rate=5000.0), snapshot([entry])
            )
        )

    def test_severity_increase_does_not_match(self):
        entry = entry_for(traffic_record())
        self.assertIsNone(
            u.match_record_for_display(
                traffic_record(severity="CRITICAL"), snapshot([entry])
            )
        )

    def test_row_record_matches(self):
        entry = entry_for(row_record())
        self.assertEqual(
            u.match_record_for_display(row_record(), snapshot([entry])),
            entry["id"],
        )

    def test_no_entry_does_not_match(self):
        self.assertIsNone(
            u.match_record_for_display(traffic_record(), snapshot([]))
        )


# ---------------------------------------------------------------------------
# Owner aggregation, diagnostics, and display parity
# ---------------------------------------------------------------------------

MULTI_PID_OWNERS = [
    {"pid": 1, "count": 8, "process_name": "svchost.exe"},
    {"pid": 2, "count": 8, "process_name": "svchost.exe"},
    {"pid": 3, "count": 4, "process_name": "firefox.exe"},
]


class AggregationTests(unittest.TestCase):
    def test_multi_pid_share_is_aggregated(self):
        derivation = u.derive_scope_from_record(
            traffic_record(owners=MULTI_PID_OWNERS, sockets=20)
        )
        self.assertTrue(derivation.eligible)
        scope = derivation.scope
        assert scope is not None
        self.assertEqual(scope["process_names"], ["svchost.exe"])
        self.assertEqual(scope["pids_at_mute"], [1, 2])
        source = derivation.source
        self.assertEqual(source["numerator"], 16)
        self.assertEqual(source["denominator"], 20)
        self.assertEqual(source["denominator_source"], "udp_socket_count")
        self.assertAlmostEqual(source["share"], 0.8)

    def test_aggregate_top_can_differ_from_single_pid(self):
        owners = [
            {"pid": 1, "count": 13, "process_name": "firefox.exe"},
            {"pid": 2, "count": 8, "process_name": "svchost.exe"},
            {"pid": 3, "count": 8, "process_name": "svchost.exe"},
        ]
        derivation = u.derive_scope_from_record(
            traffic_record(owners=owners, sockets=30)
        )
        self.assertTrue(derivation.eligible)
        assert derivation.scope is not None
        self.assertEqual(derivation.scope["process_names"], ["svchost.exe"])

    def test_ambiguity_uses_aggregated_counts(self):
        owners = [
            {"pid": 1, "count": 5, "process_name": "firefox.exe"},
            {"pid": 2, "count": 5, "process_name": "firefox.exe"},
            {"pid": 3, "count": 10, "process_name": "svchost.exe"},
        ]
        derivation = u.derive_scope_from_record(traffic_record(owners=owners))
        self.assertEqual(derivation.code, "ambiguous_udp_owner")

    def test_aggregate_breaks_single_pid_tie(self):
        owners = [
            {"pid": 1, "count": 10, "process_name": "firefox.exe"},
            {"pid": 2, "count": 6, "process_name": "svchost.exe"},
            {"pid": 3, "count": 6, "process_name": "svchost.exe"},
        ]
        derivation = u.derive_scope_from_record(
            traffic_record(owners=owners, sockets=22)
        )
        self.assertTrue(derivation.eligible)
        assert derivation.scope is not None
        self.assertEqual(derivation.scope["process_names"], ["svchost.exe"])

    def test_missing_socket_count_falls_back(self):
        derivation = u.derive_scope_from_record(
            traffic_record(owners=MULTI_PID_OWNERS, sockets=None)
        )
        self.assertTrue(derivation.eligible)
        self.assertEqual(
            derivation.source["denominator_source"], "top_owners"
        )
        self.assertAlmostEqual(derivation.source["share"], 0.8)
        self.assertTrue(derivation.warnings)

    def test_reason_is_aggregate_aware(self):
        derivation = u.derive_scope_from_record(
            traffic_record(owners=MULTI_PID_OWNERS, sockets=40)
        )
        self.assertFalse(derivation.eligible)
        assert derivation.reason is not None
        self.assertIn("svchost.exe", derivation.reason)
        self.assertIn("40%", derivation.reason)
        self.assertIn("2 PIDs", derivation.reason)

    def test_multi_pid_share_guard(self):
        entry = entry_for(
            traffic_record(owners=MULTI_PID_OWNERS, sockets=20)
        )
        observation = traffic_observation(
            process_name="svchost.exe",
            top_owner_counts=(("svchost.exe", 8), ("svchost.exe", 8)),
            udp_socket_count=20,
            identity_by_name=(("svchost.exe", True),),
        )
        disposition = u.match_observation(observation, snapshot([entry]))
        assert disposition is not None
        self.assertTrue(disposition["muted"])


class DescribeRecordTests(unittest.TestCase):
    def test_traffic_diagnostics(self):
        diagnostics = u.describe_record(
            traffic_record(owners=MULTI_PID_OWNERS, sockets=20)
        )
        self.assertEqual(diagnostics["kind"], "traffic_udp")
        self.assertEqual(diagnostics["numerator"], 16)
        self.assertEqual(diagnostics["denominator"], 20)
        self.assertAlmostEqual(diagnostics["owner_share"], 0.8)
        self.assertEqual(diagnostics["process_names"][0], "svchost.exe")
        self.assertEqual(diagnostics["pids"], [1, 2])

    def test_ineligible_still_has_diagnostics(self):
        diagnostics = u.describe_record(
            traffic_record(owners=MULTI_PID_OWNERS, sockets=40)
        )
        self.assertEqual(diagnostics["kind"], "traffic_udp")
        self.assertAlmostEqual(diagnostics["owner_share"], 0.4)
        self.assertTrue(diagnostics["top_owners"])

    def test_row_diagnostics(self):
        diagnostics = u.describe_record(row_record())
        self.assertEqual(diagnostics["kind"], "row_endpoint")
        self.assertEqual(diagnostics["process_name"], "chrome.exe")
        self.assertEqual(diagnostics["remote_ip"], "203.0.113.10")
        self.assertEqual(diagnostics["protocols"], ["TCP"])

    def test_malformed_record(self):
        self.assertEqual(u.describe_record("nope")["kind"], "unknown")


class DisplayAggregationTests(unittest.TestCase):
    def test_multi_pid_record_matches_aggregated_scope(self):
        record = traffic_record(owners=MULTI_PID_OWNERS, sockets=20)
        entry = entry_for(record)
        self.assertEqual(
            u.match_record_for_display(record, snapshot([entry])),
            entry["id"],
        )

    def test_observation_uses_aggregate_top(self):
        owners = [
            {"pid": 1, "count": 13, "process_name": "firefox.exe"},
            {"pid": 2, "count": 8, "process_name": "svchost.exe"},
            {"pid": 3, "count": 8, "process_name": "svchost.exe"},
        ]
        observation = u._observation_from_record(
            traffic_record(owners=owners, sockets=30)
        )
        assert observation is not None
        self.assertEqual(observation.process_name, "svchost.exe")

    def test_absolute_floor_is_honored(self):
        record = traffic_record()
        entry = entry_for(record)
        self.assertIsNone(
            u.match_record_for_display(
                record, snapshot([entry]), absolute_floor=600.0
            )
        )

    def test_non_traffic_source_does_not_match(self):
        record = traffic_record(source="row")
        entry = entry_for(traffic_record())
        self.assertIsNone(
            u.match_record_for_display(record, snapshot([entry]))
        )


class ScopeSummaryTests(unittest.TestCase):
    def test_traffic_scope_summary(self):
        entry = entry_for(traffic_record())
        summary = u.describe_scope(entry["scope"])
        self.assertIn("Every NET-T10", summary)
        self.assertIn("firefox.exe", summary)
        self.assertIn("50%", summary)
        self.assertIn("1000/s", summary)

    def test_row_scope_summary(self):
        entry = entry_for(row_record())
        summary = u.describe_scope(entry["scope"])
        self.assertIn("Every NET-002", summary)
        self.assertIn("chrome.exe", summary)
        self.assertIn("50000", summary)
        self.assertIn("TCP", summary)

    def test_invalid_scope(self):
        self.assertEqual(u.describe_scope(None), "")


# ---------------------------------------------------------------------------
# Atomic write
# ---------------------------------------------------------------------------


class AtomicWriteTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "soc_user_allowlist.json"

    def test_success(self):
        payload = {"schema_version": 1, "entries": []}
        self.assertTrue(u.write_allowlist_atomic(self.path, payload))
        self.assertEqual(json.loads(self.path.read_text(encoding="utf-8")), payload)

    def test_failure_leaves_target_unchanged(self):
        self.path.write_text("original", encoding="utf-8")
        with mock.patch.object(u.os, "replace", side_effect=OSError("busy")):
            self.assertFalse(
                u.write_allowlist_atomic(
                    self.path, {"schema_version": 1, "entries": []}
                )
            )
        self.assertEqual(self.path.read_text(encoding="utf-8"), "original")
        leftovers = [p for p in self.path.parent.iterdir() if p.name.endswith(".tmp")]
        self.assertEqual(leftovers, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
