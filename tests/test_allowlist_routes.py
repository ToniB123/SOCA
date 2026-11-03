"""Route tests for the dashboard allow-list API.

Run with:  uv run python -m unittest tests.test_allowlist_routes -v
"""

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import soc_ui as ui

TOKEN = "unit-test-token-0123456789abcdef"
TIMESTAMP = "2026-11-02T20:14:57-05:00"


class _FakeRunner:
    def snapshot(self):
        return {"state": "STOPPED"}

    def stop(self, block=False, timeout=10.0):
        return self.snapshot()


class _FakeConsole:
    def since(self, index, limit=1500):
        return {"lines": [], "next": max(index, 0), "gap": False}


class _FakeTrafficTailer:
    def poll(self):
        return False

    def key_range(self):
        return None, None

    def snapshot(self):
        return []

    def rows_since(self, since):
        return [], None


class _FakeStatus:
    def get(self):
        return {}


class _ChatTailer:
    def __init__(self, records):
        self.records = records

    def poll(self):
        return False

    def snapshot(self):
        return list(self.records)

    def latest_seq(self):
        return max((r.get("_seq", 0) for r in self.records), default=0)

    def records_after(self, after):
        return [], False

    def __len__(self):
        return len(self.records)

    def skipped(self):
        return 0


def traffic_record(*, seq=1, rate=600.0, severity="HIGH", owners=None,
                   sockets=6):
    return {
        "_seq": seq,
        "timestamp": TIMESTAMP,
        "snapshot": "fast-2026-11-02T20:14:57-05:00",
        "source": "traffic",
        "rule": {
            "rule_id": "NET-T10",
            "rule_ids": ["NET-T10"],
            "severity": severity,
            "rule_name": "UDP flood",
        },
        "traffic": {
            "udp_datagrams_per_second": rate,
            "baseline_rate": 50.0,
            "udp_errors_per_second": 0.0,
            "udp_socket_count": sockets,
            "udp_top_pids": owners if owners is not None else [
                {"pid": 1234, "count": 5, "process_name": "firefox.exe"},
            ],
        },
    }


def defaults():
    return {
        "traffic": {
            "thresholds": {
                "udp_datagrams_per_second_floor": 500,
                "udp_datagrams_absolute_floor": 25000,
            }
        }
    }


class AllowlistRouteTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "soc_user_allowlist.json"
        self.records = [traffic_record()]
        self.app = self.make_app(self.records)
        self.client = self.app.test_client()

    def make_app(self, records, defaults_override=None):
        get_defaults = (
            (lambda: defaults_override)
            if defaults_override is not None else defaults
        )
        app = ui.create_app(
            _FakeRunner(),  # ty: ignore[invalid-argument-type]
            _FakeConsole(),  # ty: ignore[invalid-argument-type]
            _FakeTrafficTailer(),  # ty: ignore[invalid-argument-type]
            _ChatTailer(records),  # ty: ignore[invalid-argument-type]
            _FakeStatus(),  # ty: ignore[invalid-argument-type]
            get_defaults=get_defaults,
            auth_token=TOKEN,
            allowlist_path=self.path,
        )
        app.config["TESTING"] = True
        return app

    def headers(self, extra=None):
        headers = {"X-Auth-Token": TOKEN}
        if extra:
            headers.update(extra)
        return headers

    def get(self, path, **kwargs):
        return self.client.get(path, headers=self.headers(), **kwargs)

    def post(self, payload, **kwargs):
        return self.client.post(
            "/api/allowlist", json=payload, headers=self.headers(), **kwargs
        )

    def delete(self, entry_id, hard=False):
        suffix = "?hard=1" if hard else ""
        return self.client.delete(
            f"/api/allowlist/{entry_id}{suffix}", headers=self.headers()
        )

    def clear_all(self):
        return self.client.delete("/api/allowlist", headers=self.headers())

    def create_body(self, **overrides):
        body = {
            "seq": 1,
            "timestamp": TIMESTAMP,
            "ttl_days": 30,
            "reason": "YouTube/Twitch QUIC",
        }
        body.update(overrides)
        return body

    # -- auth and listing -------------------------------------------------

    def test_requires_auth(self):
        response = self.client.get("/api/allowlist")
        self.assertEqual(response.status_code, 401)

    def test_empty_list(self):
        response = self.get("/api/allowlist")
        self.assertEqual(response.status_code, 200)
        body = response.get_json()
        self.assertEqual(body["status"], "missing")
        self.assertEqual(body["entries"], [])
        self.assertEqual(body["active_count"], 0)

    def test_security_headers(self):
        response = self.get("/api/allowlist")
        self.assertIn("Content-Security-Policy", response.headers)
        self.assertEqual(response.headers.get("Cache-Control"), "no-store")

    # -- preview ----------------------------------------------------------

    def test_preview_happy_path(self):
        response = self.get(
            "/api/allowlist/preview", query_string={"seq": 1, "timestamp": TIMESTAMP}
        )
        self.assertEqual(response.status_code, 200)
        body = response.get_json()
        self.assertTrue(body["eligible"])
        self.assertEqual(body["rule_id"], "NET-T10")
        self.assertEqual(body["kind"], "traffic_udp")
        self.assertEqual(body["scope"]["rate_max"], 1000)
        self.assertEqual(body["default_ttl_days"], 30)
        self.assertEqual(body["ttl_options"], [7, 30, 90])
        self.assertTrue(body["guards"])
        self.assertIn("Every NET-T10", body["scope_summary"])
        self.assertIsNone(body["existing_entry_id"])
        self.assertIsNone(body["existing_entry"])

    def test_preview_unknown_seq(self):
        response = self.get(
            "/api/allowlist/preview", query_string={"seq": 99, "timestamp": TIMESTAMP}
        )
        self.assertEqual(response.status_code, 404)

    def test_preview_timestamp_mismatch(self):
        response = self.get(
            "/api/allowlist/preview", query_string={"seq": 1, "timestamp": "1999-01-01"}
        )
        self.assertEqual(response.status_code, 409)

    def test_preview_critical_ineligible(self):
        self.app = self.make_app([traffic_record(severity="CRITICAL")])
        self.client = self.app.test_client()
        response = self.get(
            "/api/allowlist/preview", query_string={"seq": 1, "timestamp": TIMESTAMP}
        )
        body = response.get_json()
        self.assertFalse(body["eligible"])
        self.assertEqual(body["code"], "critical_not_mutable")

    def test_preview_absolute_floor_ineligible(self):
        self.app = self.make_app([traffic_record(rate=25000.0)])
        self.client = self.app.test_client()
        response = self.get(
            "/api/allowlist/preview", query_string={"seq": 1, "timestamp": TIMESTAMP}
        )
        body = response.get_json()
        self.assertEqual(body["code"], "absolute_flood_floor")

    # -- create -----------------------------------------------------------

    def test_create_and_list(self):
        response = self.post(self.create_body())
        self.assertEqual(response.status_code, 201)
        entry = response.get_json()["entry"]
        self.assertTrue(entry["enabled"])
        self.assertTrue(self.path.exists())

        listed = self.get("/api/allowlist").get_json()
        self.assertEqual(listed["status"], "ok")
        self.assertEqual(listed["active_count"], 1)
        self.assertTrue(listed["entries"][0]["active"])
        self.assertEqual(listed["entries"][0]["id"], entry["id"])

    def test_create_rejects_unknown_fields(self):
        response = self.post(self.create_body(scope={"rule_ids": ["NET-T10"]}))
        self.assertEqual(response.status_code, 400)

    def test_create_rejects_bad_ttl(self):
        for ttl in (1, 365, "30", True):
            response = self.post(self.create_body(ttl_days=ttl))
            self.assertEqual(response.status_code, 400)

    def test_create_unknown_seq(self):
        response = self.post(self.create_body(seq=99))
        self.assertEqual(response.status_code, 404)

    def test_create_timestamp_mismatch(self):
        response = self.post(self.create_body(timestamp="1999-01-01"))
        self.assertEqual(response.status_code, 409)

    def test_create_critical_conflict(self):
        self.app = self.make_app([traffic_record(severity="CRITICAL")])
        self.client = self.app.test_client()
        response = self.post(self.create_body())
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.get_json()["code"], "critical_not_mutable")

    def test_create_duplicate(self):
        self.assertEqual(self.post(self.create_body()).status_code, 201)
        response = self.post(self.create_body())
        self.assertEqual(response.status_code, 409)
        body = response.get_json()
        self.assertEqual(body["code"], "duplicate_entry")
        self.assertTrue(body["existing_id"])

    def test_create_refuses_corrupt_file(self):
        self.path.write_text("{broken", encoding="utf-8")
        response = self.post(self.create_body())
        self.assertEqual(response.status_code, 503)
        self.assertEqual(self.path.read_text(encoding="utf-8"), "{broken")

    def test_create_oversized_body(self):
        response = self.client.post(
            "/api/allowlist",
            data="x" * (ui.MAX_CONTENT_LENGTH + 1),
            headers=self.headers({"Content-Type": "application/json"}),
        )
        self.assertEqual(response.status_code, 413)

    def test_create_concurrent_write_is_429(self):
        slot = self.app.extensions["allowlist_slot"]
        slot.acquire()
        try:
            response = self.post(self.create_body())
        finally:
            slot.release()
        self.assertEqual(response.status_code, 429)

    # -- delete -----------------------------------------------------------

    def test_delete_disables_and_is_idempotent(self):
        entry = self.post(self.create_body()).get_json()["entry"]
        response = self.delete(entry["id"])
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.get_json()["entry"]["enabled"])
        listed = self.get("/api/allowlist").get_json()
        self.assertEqual(listed["active_count"], 0)
        self.assertFalse(listed["entries"][0]["active"])

        again = self.delete(entry["id"])
        self.assertEqual(again.status_code, 200)

    def test_delete_bad_id(self):
        self.assertEqual(self.delete("not-a-uuid").status_code, 400)

    def test_delete_unknown_id(self):
        import uuid

        self.assertEqual(self.delete(str(uuid.uuid4())).status_code, 404)

    def test_findings_route_marks_historical_match(self):
        entry = self.post(self.create_body()).get_json()["entry"]
        record = self.get("/api/findings").get_json()["records"][0]
        self.assertTrue(record.get("display_muted"))
        self.assertEqual(record.get("display_allowlist_id"), entry["id"])

        self.delete(entry["id"])
        record = self.get("/api/findings").get_json()["records"][0]
        self.assertNotIn("display_muted", record)

    def test_findings_route_keeps_agent_reopened_record(self):
        self.post(self.create_body())
        record = dict(
            self.records[0],
            disposition={"muted": False, "guard_blocked": "identity_unverified"},
        )
        self.app = self.make_app([record])
        self.client = self.app.test_client()
        fetched = self.get("/api/findings").get_json()["records"][0]
        self.assertNotIn("display_muted", fetched)
        self.assertEqual(
            fetched["disposition"]["guard_blocked"], "identity_unverified"
        )

    # -- diagnostics ------------------------------------------------------

    def test_preview_includes_diagnostics(self):
        body = self.get(
            "/api/allowlist/preview",
            query_string={"seq": 1, "timestamp": TIMESTAMP},
        ).get_json()
        diagnostics = body["diagnostics"]
        self.assertEqual(diagnostics["kind"], "traffic_udp")
        self.assertEqual(diagnostics["numerator"], 5)
        self.assertEqual(diagnostics["denominator"], 6)
        self.assertAlmostEqual(diagnostics["owner_share"], 0.8333, places=3)

    def test_preview_existing_entry_details(self):
        entry = self.post(self.create_body()).get_json()["entry"]
        body = self.get(
            "/api/allowlist/preview",
            query_string={"seq": 1, "timestamp": TIMESTAMP},
        ).get_json()
        self.assertEqual(body["existing_entry_id"], entry["id"])
        existing = body["existing_entry"]
        self.assertEqual(existing["reason"], "YouTube/Twitch QUIC")
        self.assertEqual(
            existing["scope"]["process_names"], ["firefox.exe"]
        )
        self.assertTrue(existing["expires_at"])
        self.assertIn("Every NET-T10", existing["scope_summary"])
        self.assertIn("1000/s", existing["scope_summary"])

    def test_preview_ineligible_includes_diagnostics(self):
        owners = [{"pid": 7, "count": 2, "process_name": "firefox.exe"}]
        self.app = self.make_app([
            traffic_record(owners=owners, sockets=10)
        ])
        self.client = self.app.test_client()
        body = self.get(
            "/api/allowlist/preview",
            query_string={"seq": 1, "timestamp": TIMESTAMP},
        ).get_json()
        self.assertFalse(body["eligible"])
        self.assertEqual(body["code"], "owner_share_below_min")
        self.assertEqual(body["diagnostics"]["kind"], "traffic_udp")
        self.assertAlmostEqual(
            body["diagnostics"]["owner_share"], 0.2
        )
        self.assertTrue(body["diagnostics"]["top_owners"])

    # -- hard delete ------------------------------------------------------

    def test_hard_delete_removes_entry(self):
        entry = self.post(self.create_body()).get_json()["entry"]
        response = self.delete(entry["id"], hard=True)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.get_json()["deleted"])
        document = json.loads(self.path.read_text(encoding="utf-8"))
        self.assertEqual(document["entries"], [])
        listed = self.get("/api/allowlist").get_json()
        self.assertEqual(listed["active_count"], 0)
        self.assertEqual(listed["entries"], [])
        record = self.get("/api/findings").get_json()["records"][0]
        self.assertNotIn("display_muted", record)

    def test_hard_delete_disabled_entry(self):
        entry = self.post(self.create_body()).get_json()["entry"]
        self.assertEqual(self.delete(entry["id"]).status_code, 200)
        response = self.delete(entry["id"], hard=True)
        self.assertEqual(response.status_code, 200)
        document = json.loads(self.path.read_text(encoding="utf-8"))
        self.assertEqual(document["entries"], [])

    def test_hard_delete_bad_id(self):
        self.assertEqual(self.delete("not-a-uuid", hard=True).status_code, 400)

    def test_hard_delete_unknown_id(self):
        import uuid

        self.assertEqual(
            self.delete(str(uuid.uuid4()), hard=True).status_code, 404
        )

    def test_hard_delete_missing_file(self):
        import uuid

        self.assertEqual(
            self.delete(str(uuid.uuid4()), hard=True).status_code, 404
        )

    def test_hard_delete_lock_busy(self):
        entry = self.post(self.create_body()).get_json()["entry"]
        slot = self.app.extensions["allowlist_slot"]
        slot.acquire()
        try:
            response = self.delete(entry["id"], hard=True)
        finally:
            slot.release()
        self.assertEqual(response.status_code, 429)

    def test_hard_delete_corrupt_file_does_not_rewrite(self):
        entry = self.post(self.create_body()).get_json()["entry"]
        self.path.write_text("{broken", encoding="utf-8")
        response = self.delete(entry["id"], hard=True)
        self.assertEqual(response.status_code, 503)
        self.assertEqual(self.path.read_text(encoding="utf-8"), "{broken")

    # -- clear all --------------------------------------------------------

    def test_clear_all_removes_active_and_disabled(self):
        first = self.post(self.create_body()).get_json()["entry"]
        self.delete(first["id"])
        second = self.post(self.create_body()).get_json()["entry"]
        self.assertNotEqual(first["id"], second["id"])
        response = self.clear_all()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["cleared"], 2)
        document = json.loads(self.path.read_text(encoding="utf-8"))
        self.assertEqual(document["entries"], [])
        listed = self.get("/api/allowlist").get_json()
        self.assertEqual(listed["status"], "ok")
        self.assertEqual(listed["active_count"], 0)
        self.assertEqual(listed["entries"], [])
        record = self.get("/api/findings").get_json()["records"][0]
        self.assertNotIn("display_muted", record)

    def test_clear_all_missing_file(self):
        response = self.clear_all()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["cleared"], 0)
        document = json.loads(self.path.read_text(encoding="utf-8"))
        self.assertEqual(document["entries"], [])

    def test_clear_all_repairs_corrupt_file(self):
        self.path.write_text("{broken", encoding="utf-8")
        response = self.clear_all()
        self.assertEqual(response.status_code, 200)
        document = json.loads(self.path.read_text(encoding="utf-8"))
        self.assertEqual(document["schema_version"], 1)
        self.assertEqual(document["entries"], [])

    def test_clear_all_repairs_oversized_file(self):
        self.path.write_bytes(b"x" * (ui.user_allowlist.MAX_FILE_BYTES + 1))
        response = self.clear_all()
        self.assertEqual(response.status_code, 200)
        document = json.loads(self.path.read_text(encoding="utf-8"))
        self.assertEqual(document["entries"], [])

    def test_clear_all_lock_busy(self):
        slot = self.app.extensions["allowlist_slot"]
        slot.acquire()
        try:
            response = self.clear_all()
        finally:
            slot.release()
        self.assertEqual(response.status_code, 429)

    def test_clear_all_write_failure(self):
        self.path.write_text(
            json.dumps({"schema_version": 1, "entries": []}),
            encoding="utf-8",
        )
        with mock.patch.object(
            ui.user_allowlist, "write_allowlist_atomic", return_value=False
        ):
            response = self.clear_all()
        self.assertEqual(response.status_code, 503)
        document = json.loads(self.path.read_text(encoding="utf-8"))
        self.assertEqual(document["entries"], [])

    def test_clear_all_requires_auth(self):
        response = self.client.delete("/api/allowlist")
        self.assertEqual(response.status_code, 401)

    def test_display_floor_matches_preview(self):
        entry = self.post(self.create_body()).get_json()["entry"]
        self.assertTrue(entry["enabled"])
        low_floor = {
            "traffic": {
                "thresholds": {
                    "udp_datagrams_per_second_floor": 500,
                    "udp_datagrams_absolute_floor": 600,
                }
            }
        }
        self.app = self.make_app(self.records, defaults_override=low_floor)
        self.client = self.app.test_client()
        preview = self.get(
            "/api/allowlist/preview",
            query_string={"seq": 1, "timestamp": TIMESTAMP},
        ).get_json()
        self.assertEqual(preview["code"], "absolute_flood_floor")
        record = self.get("/api/findings").get_json()["records"][0]
        self.assertNotIn("display_muted", record)


if __name__ == "__main__":
    unittest.main(verbosity=2)
