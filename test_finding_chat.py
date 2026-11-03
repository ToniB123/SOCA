"""Offline tests for the read-only finding chat (finding_chat.py + route).

Run with:  python -m unittest test_finding_chat.py
"""

import json
import unittest
import urllib.error
from email.message import Message
from unittest import mock

import finding_chat
import soc_ui as ui

TOKEN = "unit-test-token-0123456789abcdef"


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


class _FakeResponse:
    def __init__(self, body: bytes) -> None:
        self._body = body

    def read(self, size: int = -1) -> bytes:
        if size is None or size < 0:
            return self._body
        return self._body[:size]

    def __enter__(self):
        return self

    def __exit__(self, *_exc) -> bool:
        return False


class _FakeRunner:
    def snapshot(self) -> dict:
        return {"state": "STOPPED"}

    def stop(self, block: bool = False, timeout: float = 10.0) -> dict:
        return self.snapshot()


class _FakeConsole:
    def since(self, index: int, limit: int = 1500) -> dict:
        return {"lines": [], "next": max(index, 0), "gap": False}


class _FakeTrafficTailer:
    def poll(self) -> bool:
        return False

    def key_range(self):
        return None, None

    def snapshot(self):
        return []

    def rows_since(self, since):
        return [], None


class _FakeStatus:
    def __init__(self, models=None):
        self.models = list(models or [])

    def get(self) -> dict:
        return {"ollama": {"models": [{"name": name} for name in self.models]}}


class _ChatTailer:
    def __init__(self, records):
        self.records = records

    def poll(self) -> bool:
        return False

    def snapshot(self):
        return list(self.records)

    def latest_seq(self) -> int:
        return max((r.get("_seq", 0) for r in self.records), default=0)

    def records_after(self, after):
        return [], False

    def __len__(self) -> int:
        return len(self.records)

    def skipped(self) -> int:
        return 0


def _verdict(**overrides) -> dict:
    verdict = {
        "verdict": "SUSPICIOUS",
        "confidence": 72,
        "reasoning": "Tier-2 reasoning cites the unusual remote port.",
        "false_positive_factors": ["Browser update check"],
        "risk_factors": ["Unsigned process", "Known-risk port"],
        "recommended_action": "Inspect the process path before blocking.",
        "source": "ai-escalated",
        "tier": "escalated",
        "classification": "scan_or_probe",
        "vetted_at": "2026-01-01T00:00:10-00:00",
        "verdict_id": "11111111-2222-3333-4444-555555555555",
        "routine_opinion": {
            "verdict": "FALSE_POSITIVE",
            "confidence": 55,
            "reasoning": "Tier-1 thought it looked like a browser update.",
            "source": "ai",
        },
    }
    verdict.update(overrides)
    return verdict


def _record(
    seq: int = 1, timestamp: str = "2026-01-01T00:00:00-00:00", **overrides
) -> dict:
    record = {
        "_seq": seq,
        "timestamp": timestamp,
        "snapshot": "live-1",
        "host": {"hostname": "box", "local_ip": "192.0.2.10"},
        "models": {"routine": "llama3.1:8b", "escalation": "qwen3.8:27b"},
        "rule": {
            "rule_id": "NET-T14",
            "rule_name": "Connection spike",
            "severity": "HIGH",
            "description": "Many connections.",
        },
        "traffic": {"process": "firefox.exe", "current_connections": 25},
        "detail": "25 connections from firefox.exe",
        "verdict": _verdict(),
        "cache_hit": False,
    }
    record.update(overrides)
    return record


def _defaults(
    url: str = "http://127.0.0.1:11434/api/generate",
    model: str = "qwen3.8:27b",
    **overrides,
) -> dict:
    agent = {
        "ollama_url": url,
        "escalation_model": model,
        "escalation_timeout_seconds": 90,
        "num_ctx": 4096,
        "keep_alive": "30m",
    }
    yaml_only = {
        "escalation_num_ctx": 8192,
        "escalation_keep_alive": "10m",
        "escalation_think": True,
    }
    agent.update(overrides.get("agent", {}))
    yaml_only.update(overrides.get("yaml_only", {}))
    return {"agent": agent, "yaml_only": yaml_only, "traffic": {}}


def _app(records, defaults=None, allow_remote: bool = False, models=None):
    app = ui.create_app(
        _FakeRunner(),  # ty: ignore[invalid-argument-type]
        _FakeConsole(),  # ty: ignore[invalid-argument-type]
        _FakeTrafficTailer(),  # ty: ignore[invalid-argument-type]
        _ChatTailer(records),  # ty: ignore[invalid-argument-type]
        _FakeStatus(models),  # ty: ignore[invalid-argument-type]
        get_defaults=lambda: defaults or _defaults(),
        auth_token=TOKEN,
        allow_remote_ollama=allow_remote,
    )
    app.config["TESTING"] = True
    return app


class _RouteCase(unittest.TestCase):
    def setUp(self):
        self.records = [_record()]
        self.app = _app(self.records)
        self.client = self.app.test_client()

    def post(self, payload, **kwargs):
        headers = {"X-Auth-Token": TOKEN}
        headers.update(kwargs.pop("headers", {}))
        return self.client.post(
            "/api/findings/chat", json=payload, headers=headers, **kwargs
        )


# ---------------------------------------------------------------------------
# Context construction
# ---------------------------------------------------------------------------


class BuildFindingContextTests(unittest.TestCase):
    def test_contains_both_tiers(self):
        context = finding_chat.build_finding_context(_record())
        self.assertIn("Tier-1 thought it looked like a browser update.", context)
        self.assertIn("Tier-2 reasoning cites the unusual remote port.", context)

    def test_fences_and_escapes_markup(self):
        record = _record(detail="<script>alert(1)</script>")
        context = finding_chat.build_finding_context(record)
        self.assertTrue(context.startswith("<untrusted_finding>\n"))
        self.assertTrue(context.endswith("\n</untrusted_finding>"))
        self.assertNotIn("<script>", context)
        self.assertIn("\\u003cscript", context)

    def test_truncates_to_budget(self):
        record = _record(detail="x" * 5000, intel={"whois": {"remarks": ["y"] * 40}})
        context = finding_chat.build_finding_context(record, max_chars=300)
        self.assertLessEqual(len(context), 300)
        self.assertIn("[truncated]", context)
        self.assertTrue(context.endswith("</untrusted_finding>"))

    def test_tolerates_missing_and_non_dict_verdict(self):
        for verdict in (None, "nope", [], 3):
            context = finding_chat.build_finding_context(
                {"verdict": verdict, "rule": {"rule_id": "X"}}
            )
            self.assertIn('"tier2_final_verdict": {}', context)

    def test_triage_precedes_bulky_evidence(self):
        record = _record(intel={"whois": {"remarks": ["z"] * 40}})
        context = finding_chat.build_finding_context(record)
        self.assertLess(context.index('"triage"'), context.index('"intel"'))

    def test_non_dict_record(self):
        context = finding_chat.build_finding_context("nope")
        self.assertIn("<untrusted_finding>", context)


# ---------------------------------------------------------------------------
# Payload validation
# ---------------------------------------------------------------------------


class ValidateChatPayloadTests(unittest.TestCase):
    def valid(self, **overrides):
        payload = {
            "seq": 1,
            "timestamp": "2026-01-01T00:00:00-00:00",
            "question": "Why was this flagged?",
            "history": [],
        }
        payload.update(overrides)
        return payload

    def assert_bad(self, payload):
        with self.assertRaises(finding_chat.FindingChatError) as ctx:
            finding_chat.validate_chat_payload(payload)
        self.assertEqual(ctx.exception.status, 400)

    def test_normalizes_valid_payload(self):
        out = finding_chat.validate_chat_payload(
            self.valid(
                question="  why?  ", history=[{"role": "user", "content": " hi "}]
            )
        )
        self.assertEqual(out["question"], "why?")
        self.assertEqual(out["history"], [{"role": "user", "content": "hi"}])
        self.assertEqual(out["model"], "")

    def test_accepts_model_override(self):
        out = finding_chat.validate_chat_payload(
            self.valid(model=" llama3.1:8b ")
        )
        self.assertEqual(out["model"], "llama3.1:8b")

    def test_rejects_bad_model(self):
        for model in (5, "bad model", "x" * 129, "-leading-dash"):
            self.assert_bad(self.valid(model=model))

    def test_rejects_non_object(self):
        self.assert_bad([])
        self.assert_bad("x")

    def test_rejects_unknown_keys(self):
        self.assert_bad(self.valid(record={"evil": True}))

    def test_rejects_bad_seq(self):
        for seq in (True, 0, -1, "1", None):
            self.assert_bad(self.valid(seq=seq))

    def test_rejects_bad_timestamp(self):
        for ts in (None, "", "   ", "x" * 65, 5):
            self.assert_bad(self.valid(timestamp=ts))

    def test_rejects_bad_question(self):
        for question in (None, "", "   ", 5, "x" * 1501, "bad\x00char"):
            self.assert_bad(self.valid(question=question))

    def test_rejects_bad_history(self):
        cases = [
            "nope",
            [{"role": "system", "content": "x"}],
            [{"role": "user"}],
            [{"role": "user", "content": "x", "extra": 1}],
            [{"role": "user", "content": ""}],
            [{"role": "user", "content": 5}],
            [{"role": "user", "content": "x" * 2001}],
            [{"role": "user", "content": "x"} for _ in range(9)],
            [{"role": "user", "content": "x" * 1000} for _ in range(5)],
        ]
        for history in cases:
            self.assert_bad(self.valid(history=history))


# ---------------------------------------------------------------------------
# Ollama transport
# ---------------------------------------------------------------------------


class ChatCompletionTests(unittest.TestCase):
    def run_with(self, raw: bytes):
        captured = {}

        def fake_open(request, timeout):
            captured["request"] = request
            captured["timeout"] = timeout
            return _FakeResponse(raw)

        with mock.patch.object(finding_chat, "_open_request", fake_open):
            answer = finding_chat.chat_completion(
                "http://127.0.0.1:11434",
                "qwen3.8:27b",
                [{"role": "user", "content": "hi"}],
                timeout=42,
                num_ctx=8192,
                keep_alive="5m",
            )
        return answer, captured

    def test_happy_path_and_payload(self):
        body = json.dumps({"message": {"content": "  Because  "}}).encode()
        answer, captured = self.run_with(body)
        self.assertEqual(answer, "Because")
        self.assertEqual(captured["timeout"], 42)
        payload = json.loads(captured["request"].data)
        self.assertEqual(payload["model"], "qwen3.8:27b")
        self.assertFalse(payload["stream"])
        self.assertEqual(payload["keep_alive"], "5m")
        self.assertEqual(payload["options"]["num_ctx"], 8192)
        self.assertNotIn("think", payload)
        self.assertEqual(
            captured["request"].full_url, "http://127.0.0.1:11434/api/chat"
        )

    def test_think_flag_is_forwarded(self):
        body = json.dumps({"message": {"content": "ok"}}).encode()
        captured = {}

        def fake_open(request, timeout):
            captured["request"] = request
            return _FakeResponse(body)

        with mock.patch.object(finding_chat, "_open_request", fake_open):
            finding_chat.chat_completion(
                "http://127.0.0.1:11434",
                "m",
                [{"role": "user", "content": "hi"}],
                timeout=5,
                think=True,
            )
        self.assertTrue(json.loads(captured["request"].data)["think"])

    def test_oversized_response_is_502(self):
        raw = b"x" * (finding_chat.MAX_RESPONSE_BYTES + 2)
        with self.assertRaises(finding_chat.FindingChatError) as ctx:
            self.run_with(raw)
        self.assertEqual(ctx.exception.status, 502)

    def test_invalid_json_is_502(self):
        with self.assertRaises(finding_chat.FindingChatError) as ctx:
            self.run_with(b"not json")
        self.assertEqual(ctx.exception.status, 502)

    def test_missing_content_is_502(self):
        for body in (b"{}", b'{"message": {}}', b'{"message": {"content": ""}}'):
            with self.assertRaises(finding_chat.FindingChatError) as ctx:
                self.run_with(body)
            self.assertEqual(ctx.exception.status, 502)

    def test_thinking_only_reply_falls_back(self):
        body = json.dumps(
            {"message": {"content": "  ", "thinking": "  reasoned answer  "}}
        ).encode()
        answer, _captured = self.run_with(body)
        self.assertEqual(answer, "reasoned answer")

    def test_empty_content_and_thinking_is_502(self):
        body = json.dumps({"message": {"content": "", "thinking": "   "}}).encode()
        with self.assertRaises(finding_chat.FindingChatError) as ctx:
            self.run_with(body)
        self.assertEqual(ctx.exception.status, 502)

    def test_timeout_is_504(self):
        def fake_open(_request, _timeout):
            raise TimeoutError()

        with (
            mock.patch.object(finding_chat, "_open_request", fake_open),
            self.assertRaises(finding_chat.FindingChatError) as ctx,
        ):
            finding_chat.chat_completion("http://127.0.0.1:11434", "m", [], timeout=5)
        self.assertEqual(ctx.exception.status, 504)

    def test_unreachable_is_503(self):
        def fake_open(_request, _timeout):
            raise urllib.error.URLError("refused")

        with (
            mock.patch.object(finding_chat, "_open_request", fake_open),
            self.assertRaises(finding_chat.FindingChatError) as ctx,
        ):
            finding_chat.chat_completion("http://127.0.0.1:11434", "m", [], timeout=5)
        self.assertEqual(ctx.exception.status, 503)

    def test_http_error_is_502(self):
        def fake_open(request, _timeout):
            raise urllib.error.HTTPError(request.full_url, 500, "boom", Message(), None)

        with (
            mock.patch.object(finding_chat, "_open_request", fake_open),
            self.assertRaises(finding_chat.FindingChatError) as ctx,
        ):
            finding_chat.chat_completion("http://127.0.0.1:11434", "m", [], timeout=5)
        self.assertEqual(ctx.exception.status, 502)

    def test_redirects_are_refused(self):
        handler = finding_chat._NoRedirect()
        self.assertIsNone(
            handler.redirect_request(
                None, None, 302, "Found", {}, "http://evil.example/"
            )
        )


# ---------------------------------------------------------------------------
# Settings resolution
# ---------------------------------------------------------------------------


class ResolveChatSettingsTests(unittest.TestCase):
    def resolve(self, defaults, allow_remote=False):
        return ui._resolve_finding_chat_settings(defaults, allow_remote)

    def test_uses_escalation_settings(self):
        settings, err = self.resolve(_defaults())
        self.assertIsNone(err)
        self.assertEqual(settings["base_url"], "http://127.0.0.1:11434")
        self.assertEqual(settings["model"], "qwen3.8:27b")
        self.assertEqual(settings["timeout"], 90.0)
        self.assertEqual(settings["num_ctx"], 8192)
        self.assertEqual(settings["keep_alive"], "10m")
        self.assertTrue(settings["think"])

    def test_clamps_timeout_and_num_ctx(self):
        settings, _ = self.resolve(
            _defaults(
                agent={"escalation_timeout_seconds": 10000, "num_ctx": 1},
                yaml_only={"escalation_num_ctx": 1},
            )
        )
        self.assertEqual(settings["timeout"], ui.CHAT_TIMEOUT_MAX_SECONDS)
        self.assertEqual(settings["num_ctx"], ui.CHAT_NUM_CTX_MIN)

        settings, _ = self.resolve(
            _defaults(
                agent={"escalation_timeout_seconds": 0.1},
                yaml_only={"escalation_num_ctx": 999999},
            )
        )
        self.assertEqual(settings["timeout"], ui.CHAT_TIMEOUT_MIN_SECONDS)
        self.assertEqual(settings["num_ctx"], ui.CHAT_NUM_CTX_MAX)

    def test_invalid_model_is_rejected(self):
        settings, err = self.resolve(_defaults(model="bad model!"))
        self.assertIsNone(settings)
        self.assertIn("escalation model", err)

    def test_remote_url_requires_opt_in(self):
        settings, err = self.resolve(
            _defaults(url="http://10.0.0.5:11434/api/generate")
        )
        self.assertIsNone(settings)
        self.assertIn("endpoint", err)

        settings, err = self.resolve(
            _defaults(url="http://10.0.0.5:11434/api/generate"), allow_remote=True
        )
        self.assertIsNone(err)
        self.assertEqual(settings["base_url"], "http://10.0.0.5:11434")

    def test_invalid_keep_alive_falls_back(self):
        settings, _ = self.resolve(
            _defaults(yaml_only={"escalation_keep_alive": "forever"})
        )
        self.assertEqual(settings["keep_alive"], "30m")

    def test_missing_sections_use_defaults(self):
        settings, err = self.resolve({})
        self.assertIsNone(err)
        self.assertEqual(settings["model"], ui._D["escalation_model"])


# ---------------------------------------------------------------------------
# Route
# ---------------------------------------------------------------------------


class FindingChatRouteTests(_RouteCase):
    def payload(self, **overrides):
        payload = {
            "seq": 1,
            "timestamp": "2026-01-01T00:00:00-00:00",
            "question": "Why was this flagged?",
            "history": [],
        }
        payload.update(overrides)
        return payload

    def test_requires_auth(self):
        response = self.client.post("/api/findings/chat", json=self.payload())
        self.assertEqual(response.status_code, 401)

    def test_invalid_json_is_400(self):
        response = self.client.post(
            "/api/findings/chat",
            data="not json",
            headers={"X-Auth-Token": TOKEN, "Content-Type": "application/json"},
        )
        self.assertEqual(response.status_code, 400)

    def test_unknown_key_is_400(self):
        response = self.post(self.payload(record={"evil": True}))
        self.assertEqual(response.status_code, 400)

    def test_unknown_seq_is_404(self):
        response = self.post(self.payload(seq=99))
        self.assertEqual(response.status_code, 404)

    def test_timestamp_mismatch_is_409(self):
        response = self.post(self.payload(timestamp="1999-01-01T00:00:00Z"))
        self.assertEqual(response.status_code, 409)

    def test_happy_path_uses_server_record_and_escalation_model(self):
        with mock.patch.object(
            finding_chat,
            "chat_completion",
            return_value="It was flagged for the connection spike.",
        ) as call:
            response = self.post(self.payload())
        self.assertEqual(response.status_code, 200)
        body = response.get_json()
        self.assertEqual(body["answer"], "It was flagged for the connection spike.")
        self.assertEqual(body["model"], "qwen3.8:27b")
        args, _kwargs = call.call_args
        self.assertEqual(args[1], "qwen3.8:27b")
        rendered = json.dumps(args[2])
        self.assertIn("Tier-1 thought it looked like a browser update.", rendered)
        self.assertIn("Tier-2 reasoning cites the unusual remote port.", rendered)
        self.assertIn("NET-T14", rendered)

    def test_model_override_is_used(self):
        with mock.patch.object(
            finding_chat, "chat_completion", return_value="ok"
        ) as call:
            response = self.post(self.payload(model="llama3.1:8b"))
        self.assertEqual(response.status_code, 200)
        args, _kwargs = call.call_args
        self.assertEqual(args[1], "llama3.1:8b")
        self.assertEqual(response.get_json()["model"], "llama3.1:8b")

    def test_model_not_installed_is_400(self):
        self.app = _app(self.records, models=["llama3.1:8b"])
        self.client = self.app.test_client()
        with mock.patch.object(finding_chat, "chat_completion") as call:
            response = self.post(self.payload(model="qwen3.8:27b"))
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()["code"], "model_not_installed")
        call.assert_not_called()

    def test_config_route_lists_models(self):
        self.app = _app(
            self.records, models=["llama3.1:8b", "qwen3.8:27b"]
        )
        self.client = self.app.test_client()
        response = self.client.get(
            "/api/findings/chat/config", headers={"X-Auth-Token": TOKEN}
        )
        self.assertEqual(response.status_code, 200)
        body = response.get_json()
        self.assertEqual(body["default_model"], "qwen3.8:27b")
        self.assertEqual(body["routine_model"], "llama3.1:8b")
        self.assertIn("llama3.1:8b", body["models"])
        self.assertIn("qwen3.8:27b", body["models"])
        self.assertTrue(body["installed"])

    def test_config_falls_back_when_default_not_installed(self):
        self.app = _app(self.records, models=["llama3.1:8b"])
        self.client = self.app.test_client()
        response = self.client.get(
            "/api/findings/chat/config", headers={"X-Auth-Token": TOKEN}
        )
        body = response.get_json()
        self.assertEqual(body["default_model"], "llama3.1:8b")
        self.assertEqual(body["routine_model"], "llama3.1:8b")
        self.assertEqual(body["models"], ["llama3.1:8b"])

    def test_remote_endpoint_without_opt_in_is_503(self):
        self.app = _app(
            self.records, defaults=_defaults(url="http://10.0.0.5:11434/api/generate")
        )
        self.client = self.app.test_client()
        with mock.patch.object(finding_chat, "chat_completion") as call:
            response = self.post(self.payload())
        self.assertEqual(response.status_code, 503)
        call.assert_not_called()
        text = response.get_data(as_text=True)
        self.assertNotIn("10.0.0.5", text)
        self.assertNotIn("SOCA", text)

    def test_remote_endpoint_with_opt_in_is_ok(self):
        self.app = _app(
            self.records,
            defaults=_defaults(url="http://10.0.0.5:11434/api/generate"),
            allow_remote=True,
        )
        self.client = self.app.test_client()
        with mock.patch.object(finding_chat, "chat_completion", return_value="ok"):
            response = self.post(self.payload())
        self.assertEqual(response.status_code, 200)

    def test_upstream_error_maps_to_status(self):
        with mock.patch.object(
            finding_chat,
            "chat_completion",
            side_effect=finding_chat.FindingChatError("timed out", 504),
        ):
            response = self.post(self.payload())
        self.assertEqual(response.status_code, 504)
        self.assertEqual(response.get_json()["error"], "timed out")

    def test_oversized_body_is_413(self):
        response = self.client.post(
            "/api/findings/chat",
            data="x" * (ui.MAX_CONTENT_LENGTH + 1),
            headers={"X-Auth-Token": TOKEN, "Content-Type": "application/json"},
        )
        self.assertEqual(response.status_code, 413)

    def test_security_headers_on_chat_route(self):
        with mock.patch.object(finding_chat, "chat_completion", return_value="ok"):
            response = self.post(self.payload())
        self.assertIn("Content-Security-Policy", response.headers)
        self.assertEqual(response.headers.get("Cache-Control"), "no-store")


if __name__ == "__main__":
    unittest.main(verbosity=2)
