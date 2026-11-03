"""Route tests for the dashboard allow-list API.

Run with:  python -m unittest test_allowlist_routes.py
"""

import tempfile
import unittest
from pathlib import Path

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


def traffic_record(*, seq=1, rate=600.0, severity="HIGH"):
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
            "udp_socket_count": 6,
            "udp_top_pids": [
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

    def make_app(self, records):
        app = ui.create_app(
            _FakeRunner(),  # ty: ignore[invalid-argument-type]
            _FakeConsole(),  # ty: ignore[invalid-argument-type]
            _FakeTrafficTailer(),  # ty: ignore[invalid-argument-type]
            _ChatTailer(records),  # ty: ignore[invalid-argument-type]
            _FakeStatus(),  # ty: ignore[invalid-argument-type]
            get_defaults=defaults,
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

    def delete(self, entry_id):
        return self.client.delete(f"/api/allowlist/{entry_id}", headers=self.headers())

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
        self.assertIsNone(body["existing_entry_id"])

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


if __name__ == "__main__":
    unittest.main(verbosity=2)
