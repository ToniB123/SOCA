#!/usr/bin/env python3
"""Regression tests for the soc_ui.py dashboard backend.

Run with:  uv run python -m unittest tests.test_ui_runner -v
These tests are offline: no agent process is spawned and no network call is
made. Temp files live in system temp directories; the path-containment tests
may create a temporary directory junction with cmd.exe, and the replay test
creates a uniquely named placeholder file under the project tree.
"""

import contextlib
import http.client
import io
import json
import os
import signal
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

import checkstat as soc
import install_security
import soc_ui as ui

REPO_ROOT = Path(__file__).resolve().parents[1]
RULES_FILE = REPO_ROOT / "config" / "netstat_baseline_rules.example.yaml"


def _write_lines(path: Path, *lines: str) -> None:
    with path.open("ab") as fh:
        for line in lines:
            fh.write(line.encode("utf-8") + b"\n")


def _row(ts: int, **extra) -> dict:
    row = {"timestamp": ts, "iso": f"2026-01-01T00:00:{ts:02d}-00:00",
           "established": 1, "syn_received": 0}
    row.update(extra)
    return row


class ArgvRoundTripTests(unittest.TestCase):
    """build_argv output must parse back through checkstat.parse_args."""

    @staticmethod
    def _parse(argv: list[str]):
        # argv = [python, checkstat.py, ...flags]
        return soc.parse_args(argv[2:])

    def test_minimal_payload(self):
        flags, mode, errors = ui.validate_payload({"interval": 30})
        self.assertEqual(errors, [])
        self.assertEqual(mode, "continuous")
        argv = ui.build_argv(flags, mode)
        self.assertEqual(argv[:2], [sys.executable, str(ui.CHECKSTAT_PATH)])
        args = self._parse(argv)
        self.assertEqual(args.interval, 30)
        self.assertFalse(args.no_ai)

    def test_full_payload(self):
        flags, mode, errors = ui.validate_payload({
            "interval": 90, "model": "llama3.1:8b",
            "escalation_model": "qwen3.8:27b", "max_ai_checks": 5,
            "max_escalations": 1, "ai_timeout": 45.5, "escalation_timeout": 90,
            "num_ctx": 2048, "keep_alive": "15m", "cache_hours": 2.5,
            "no_escalation": True, "no_whois": True,
            "include_private_remotes": True, "verbose": True,
            "rules_path": "config/netstat_baseline_rules.example.yaml",
            "ollama_url": "http://127.0.0.1:11434/api/generate",
        })
        self.assertEqual(errors, [])
        self.assertEqual(mode, "continuous")
        args = self._parse(ui.build_argv(flags, mode))
        self.assertEqual(args.interval, 90)
        self.assertEqual(args.model, "llama3.1:8b")
        self.assertEqual(args.escalation_model, "qwen3.8:27b")
        self.assertEqual(args.max_ai_checks, 5)
        self.assertEqual(args.max_escalations, 1)
        self.assertEqual(args.ai_timeout, 45.5)
        self.assertEqual(args.escalation_timeout, 90)
        self.assertEqual(args.num_ctx, 2048)
        self.assertEqual(args.keep_alive, "15m")
        self.assertEqual(args.cache_hours, 2.5)
        self.assertTrue(args.no_escalation)
        self.assertTrue(args.no_whois)
        self.assertTrue(args.include_private_remotes)
        self.assertTrue(args.verbose)
        self.assertTrue(args.rules.is_absolute())

    def test_replay_mode_omits_interval(self):
        # resolve_agent_path requires the file to exist inside the project
        # tree; a unique mkstemp name keeps parallel runs from colliding.
        fd, name = tempfile.mkstemp(
            prefix="test_replay_", suffix=".log", dir=str(ui.SCRIPT_DIR))
        os.close(fd)
        placeholder = Path(name)
        self.addCleanup(placeholder.unlink, missing_ok=True)
        flags, mode, errors = ui.validate_payload(
            {"replay_path": placeholder.name, "interval": 120})
        self.assertEqual(errors, [])
        self.assertEqual(mode, "replay")
        self.assertNotIn("interval", flags)
        argv = ui.build_argv(flags, mode)
        args = self._parse(argv)
        self.assertEqual(args.file, Path(flags["replay_path"]))
        self.assertIsNone(args.interval)

    def test_think_quirk(self):
        flags, _, errors = ui.validate_payload({"think": True})
        self.assertEqual(errors, [])
        self.assertIn("--think", ui.build_argv(flags, "continuous"))
        flags, _, errors = ui.validate_payload({"think": False})
        self.assertEqual(errors, [], "think=False is valid but must be omitted")
        self.assertNotIn("think", flags)
        self.assertNotIn("--think", ui.build_argv(flags, "continuous"))

    def test_force_is_meta_only(self):
        flags, _, errors = ui.validate_payload({"force": True, "interval": 30})
        self.assertEqual(errors, [])
        self.assertNotIn("force", flags)
        args = self._parse(ui.build_argv(flags, "continuous"))
        self.assertEqual(args.interval, 30)

    def test_child_command_override(self):
        argv = ui.build_argv({}, "continuous",
                             "python -c 'import time; time.sleep(999)'")
        self.assertEqual(argv, ["python", "-c", "import time; time.sleep(999)"])

    def test_child_command_env_var_ignored(self):
        import os
        os.environ["SOC_UI_CHILD_COMMAND"] = "cmd.exe /c calc.exe"
        try:
            argv = ui.build_argv({}, "continuous")
            explicit = ui.build_argv({}, "continuous", "python -c pass")
        finally:
            os.environ.pop("SOC_UI_CHILD_COMMAND", None)
        self.assertEqual(argv, [sys.executable, str(ui.CHECKSTAT_PATH)])
        self.assertEqual(explicit, ["python", "-c", "pass"])

    def test_runner_child_command_defaults_to_none(self):
        self.assertIsNone(ui.AgentRunner(ui.ConsoleLog()).child_command)


class InstallSecurityTests(unittest.TestCase):
    """U3/U2 operational hardening: install warnings and principal checks."""

    def test_install_warnings_report_broad_write_acl(self):
        with (mock.patch.object(
                  install_security, "is_elevated", return_value=False),
              mock.patch.object(
                  install_security, "broad_write_sids",
                  return_value=["Authenticated Users", "Everyone"])):
            warnings = install_security.install_warnings(Path("C:/SOCAgent"))
        self.assertEqual(len(warnings), 1)
        self.assertIn("C:\\SOCAgent", warnings[0].replace("/", "\\"))
        self.assertIn("Authenticated Users", warnings[0])
        self.assertIn("Everyone", warnings[0])
        self.assertIn("never run elevated", warnings[0])

    def test_install_warnings_report_elevation(self):
        with (mock.patch.object(
                  install_security, "is_elevated", return_value=True),
              mock.patch.object(
                  install_security, "broad_write_sids", return_value=[])):
            warnings = install_security.install_warnings(Path("C:/SOCAgent"))
        self.assertEqual(len(warnings), 1)
        self.assertIn("elevated", warnings[0])

    def test_install_warnings_are_quiet_for_a_restricted_install(self):
        with (mock.patch.object(
                  install_security, "is_elevated", return_value=False),
              mock.patch.object(
                  install_security, "broad_write_sids", return_value=[])):
            self.assertEqual(
                install_security.install_warnings(Path("C:/SOCAgent")), [])

    def test_install_warning_probe_failure_does_not_block_startup(self):
        with mock.patch.object(
                install_security, "is_elevated",
                side_effect=OSError("probe failed")):
            self.assertEqual(
                install_security.install_warnings(Path("C:/SOCAgent")), [])

    def test_write_mask_detection(self):
        self.assertTrue(install_security._mask_grants_write(0x120116))
        self.assertTrue(install_security._mask_grants_write(0x40000000))
        self.assertTrue(install_security._mask_grants_write(0x00010000))
        self.assertFalse(install_security._mask_grants_write(0x00120089))

    def test_interpreter_match_is_path_based(self):
        self.assertTrue(
            install_security.image_matches_current_interpreter(
                sys.executable))
        self.assertFalse(
            install_security.image_matches_current_interpreter(
                str(Path(sys.executable).with_name("other-python.exe"))))
        self.assertFalse(
            install_security.image_matches_current_interpreter(None))

    @unittest.skipUnless(ui.ON_WINDOWS, "Windows process probes are live")
    def test_live_principal_probes_agree_for_this_process(self):
        pid = os.getpid()
        self.assertIsNotNone(install_security.process_image_path(pid))
        self.assertEqual(
            install_security.process_owner_sid(pid),
            install_security.current_user_sid())
        self.assertEqual(
            install_security.process_session_id(pid),
            install_security.current_session_id())

    def _principal(self, **overrides):
        values = {
            "image": sys.executable,
            "owner": "S-1-5-21-test",
            "user": "S-1-5-21-test",
            "session": 7,
            "current": 7,
        }
        values.update(overrides)
        with (mock.patch.object(
                  install_security, "process_image_path",
                  return_value=values["image"]),
              mock.patch.object(
                  install_security, "process_owner_sid",
                  return_value=values["owner"]),
              mock.patch.object(
                  install_security, "current_user_sid",
                  return_value=values["user"]),
              mock.patch.object(
                  install_security, "process_session_id",
                  return_value=values["session"]),
              mock.patch.object(
                  install_security, "current_session_id",
                  return_value=values["current"])):
            return ui._process_principal_matches(4242)

    def test_principal_requires_every_probe(self):
        self.assertTrue(self._principal())
        self.assertFalse(self._principal(image="C:/other/python.exe"))
        self.assertFalse(self._principal(owner=None))
        self.assertFalse(self._principal(owner="S-1-5-21-other"))
        self.assertFalse(self._principal(user=None))
        self.assertFalse(self._principal(session=None))
        self.assertFalse(self._principal(session=8))
        self.assertFalse(self._principal(current=None))

    def test_principal_probe_exception_fails_closed(self):
        with mock.patch.object(
                install_security, "process_image_path",
                side_effect=OSError("access denied")):
            self.assertFalse(ui._process_principal_matches(4242))


class AdoptionTests(unittest.TestCase):
    """try_adopt_orphan must only adopt a verified checkstat.py process."""

    PID = 424242
    STARTED_AT = 1_700_000_000.0

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.state_file = Path(self._tmp.name) / "soc_ui_agent_state.json"
        self.console = ui.ConsoleLog()
        self.runner = ui.AgentRunner(self.console)
        self._real_exists = ui.process_exists
        self._real_creation = ui.process_creation_time
        self._real_probe = ui.external_checkstat_processes
        self._real_principal = ui._process_principal_matches
        self.addCleanup(self._restore_mocks)

    def _restore_mocks(self):
        # stop the orphan watcher before restoring the real process helpers
        with self.runner._lock:
            self.runner.state = ui.STATE_STOPPED
        ui.process_exists = self._real_exists
        ui.process_creation_time = self._real_creation
        ui.external_checkstat_processes = self._real_probe
        ui._process_principal_matches = self._real_principal

    def _install_process_mocks(self, *, exists=True, creation="match",
                               checkstat=True, probe_checked=True,
                               principal=True):
        ui.process_exists = lambda pid: exists
        ui._process_principal_matches = lambda pid: principal
        creation_value = self.STARTED_AT if creation == "match" else creation
        ui.process_creation_time = lambda pid: creation_value
        absolute_cmdline = f'"{sys.executable}" "{ui.CHECKSTAT_PATH}"'
        processes = (
            [{"pid": self.PID, "cmdline": absolute_cmdline}]
            if checkstat else
            [{"pid": self.PID + 1, "cmdline": absolute_cmdline}]
        )
        ui.external_checkstat_processes = lambda *a, **k: {
            "checked": probe_checked, "processes": processes}

    def _write_state(self, **overrides):
        data = {
            "pid": self.PID,
            "argv": [sys.executable, str(ui.CHECKSTAT_PATH)],
            "started_at": self.STARTED_AT,
            "mode": "continuous",
        }
        data.update(overrides)
        self.state_file.write_text(json.dumps(data), encoding="utf-8")

    def _adopt(self):
        return ui.try_adopt_orphan(self.runner, self.console, self.state_file)

    def _assert_rejected(self):
        self.assertFalse(self.state_file.exists())
        self.assertEqual(self.runner.state, ui.STATE_STOPPED)
        self.assertIsNone(self.runner.pid)

    def test_adopts_verified_orphan(self):
        self._write_state()
        self._install_process_mocks()
        self.assertTrue(self._adopt())
        snapshot = self.runner.snapshot()
        self.assertEqual(snapshot["state"], ui.STATE_RUNNING)
        self.assertEqual(snapshot["pid"], self.PID)
        self.assertFalse(snapshot["attached"])

    def test_rejects_missing_process(self):
        self._write_state()
        self._install_process_mocks(exists=False)
        self.assertFalse(self._adopt())
        self._assert_rejected()

    def test_rejects_unknown_creation_time(self):
        self._write_state()
        self._install_process_mocks(creation=None)
        self.assertFalse(self._adopt())
        self._assert_rejected()

    def test_rejects_creation_time_mismatch(self):
        self._write_state()
        self._install_process_mocks(creation=self.STARTED_AT + 6)
        self.assertFalse(self._adopt())
        self._assert_rejected()

    def test_rejects_non_checkstat_process(self):
        self._write_state()
        self._install_process_mocks(checkstat=False)
        self.assertFalse(self._adopt())
        self._assert_rejected()

    def test_rejects_decoy_without_absolute_agent_path(self):
        # A process whose command line merely contains the basename must not
        # qualify; the absolute CHECKSTAT_PATH is required.
        self._write_state()
        self._install_process_mocks()
        ui.external_checkstat_processes = lambda *a, **k: {
            "checked": True,
            "processes": [{"pid": self.PID, "cmdline": "python checkstat.py"}],
        }
        self.assertFalse(self._adopt())
        self._assert_rejected()

    def test_rejects_wrong_interpreter_user_or_session(self):
        self._write_state()
        self._install_process_mocks(principal=False)
        self.assertFalse(self._adopt())
        self._assert_rejected()

    def test_rejects_inconclusive_probe(self):
        self._write_state()
        self._install_process_mocks(probe_checked=False)
        self.assertFalse(self._adopt())
        self._assert_rejected()

    def test_rejects_unusable_started_at(self):
        for bad_started_at in (float("nan"), float("inf"), float("-inf"),
                               10**400):
            with self.subTest(started_at=bad_started_at):
                self._write_state(started_at=bad_started_at)
                self._install_process_mocks()
                self.assertFalse(self._adopt())
                self._assert_rejected()

    def test_rejects_invalid_pid(self):
        for bad_pid in (True, False, "424242", 424242.0, 0, -1, 2**32,
                        None):
            with self.subTest(pid=bad_pid):
                self._write_state(pid=bad_pid)
                ui.process_exists = lambda pid: self.fail(
                    "process_exists must not be called for an invalid pid")
                ui.process_creation_time = lambda pid: self.STARTED_AT
                ui.external_checkstat_processes = lambda *a, **k: {
                    "checked": True, "processes": []}
                self.assertFalse(self._adopt())
                self._assert_rejected()

    def test_stop_refuses_when_identity_changes(self):
        self._write_state()
        self._install_process_mocks()
        self.assertTrue(self._adopt())
        # the PID was recycled after adoption: creation time no longer matches
        ui.process_creation_time = lambda pid: self.STARTED_AT + 60
        with mock.patch.object(ui.subprocess, "run") as run:
            self.runner.stop(block=True, timeout=5)
        run.assert_not_called()
        self.assertEqual(self.runner.state, ui.STATE_STOPPED)
        self.assertEqual(self.runner.exit_kind, "refused_identity_mismatch")
        self.assertFalse(self.state_file.exists())

    def test_verified_orphan_stop_uses_taskkill_and_clears_state(self):
        self._write_state()
        self._install_process_mocks()
        self.assertTrue(self._adopt())
        with mock.patch.object(ui.subprocess, "run") as run:
            run.return_value.returncode = 0
            self.runner.stop(block=True, timeout=5)
        run.assert_called_once()
        args = run.call_args[0][0]
        self.assertEqual(args[0], ui.TASKKILL_EXE)
        self.assertIn("/T", args)
        self.assertIn("/F", args)
        self.assertFalse(self.state_file.exists())
        self.assertEqual(self.runner.state, ui.STATE_STOPPED)

    def test_watcher_marks_orphan_exited(self):
        self._write_state()
        alive = {"value": True}
        ui.process_exists = lambda pid: alive["value"]
        ui.process_creation_time = lambda pid: self.STARTED_AT
        ui._process_principal_matches = lambda pid: True
        ui.external_checkstat_processes = lambda *a, **k: {
            "checked": True,
            "processes": [{
                "pid": self.PID,
                "cmdline": f'"{sys.executable}" "{ui.CHECKSTAT_PATH}"',
            }]}
        with mock.patch.object(ui, "ORPHAN_POLL_SECONDS", 0.01):
            self.assertTrue(self._adopt())
            alive["value"] = False
            deadline = time.time() + 2.0
            while self.state_file.exists() and time.time() < deadline:
                time.sleep(0.01)
        self.assertFalse(self.state_file.exists())
        self.assertEqual(self.runner.state, ui.STATE_STOPPED)
        self.assertEqual(self.runner.exit_kind, "orphan_exited")


class StatusCacheDefaultsTests(unittest.TestCase):
    def test_initial_payload_has_renderable_shape(self):
        class _Tailer:
            def key_range(self):
                return None, None

            def __len__(self):
                return 0

            def skipped(self):
                return 0

        cache = ui.StatusCache(lambda: {}, _Tailer())
        data = cache.get()
        self.assertFalse(data["ready"])
        self.assertEqual(data["ollama"]["models"], [])
        self.assertEqual(data["traffic"]["rows"], 0)
        self.assertIn("entries", data["verdict_cache"])
        self.assertFalse(data["network"]["available"])
        self.assertEqual(data["network"]["verdict"], "UNKNOWN")
        self.assertEqual(data["network"]["caveat"], ui.network_health.CAVEAT)


class NetworkStatusCacheTests(unittest.TestCase):
    """H8: the dashboard projects the agent file and never probes itself."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / ui.network_health.RESULT_FILE
        self.cache = ui.StatusCache(
            lambda: {
                "network_health": {
                    "enabled": True,
                    "interval_seconds": 60,
                    "file_max_age_seconds": 180,
                }
            },
            _FakeTailer(),
            network_path=self.path,
        )

    @staticmethod
    def _sample(*, generated_at=None, verdict="RESPONSIVE", **overrides):
        sample = {
            "schema_version": 1,
            "enabled": True,
            "source": "checkstat",
            "generated_at": time.time() if generated_at is None else generated_at,
            "generated_iso": "2026-11-01T10:00:00+00:00",
            "verdict": verdict,
            "reason": "external_all_healthy",
            "confidence": "high",
            "summary": "Gateway and external anchors respond.",
            "caveat": ui.network_health.CAVEAT,
            "gateway": {
                "host": "10.0.0.1", "label": "gateway", "port": None,
                "reachable": True, "healthy": True, "loss_pct": 0.0,
                "rtt_ms_avg": 2.0, "jitter_ms": 0.5, "probe": "icmp",
                "error": None,
            },
            "gateway_status": "healthy",
            "targets": [
                {"host": "1.1.1.1", "label": "Cloudflare", "port": 443,
                 "reachable": True, "healthy": True, "loss_pct": 0.0,
                 "rtt_ms_avg": 18.0, "jitter_ms": 1.0, "probe": "icmp",
                 "error": None},
            ],
            "targets_up": 1,
            "targets_healthy": 1,
            "targets_total": 1,
        }
        sample.update(overrides)
        return sample

    def _write(self, sample):
        self.path.write_text(json.dumps(sample), encoding="utf-8")

    def _status(self):
        defaults = self.cache._get_defaults()
        return self.cache._network_status(defaults)

    def test_fresh_agent_file_is_projected_without_probing(self):
        self._write(self._sample())
        status = self._status()
        self.assertTrue(status["available"])
        self.assertFalse(status["stale"])
        self.assertEqual(status["verdict"], "RESPONSIVE")
        self.assertEqual(status["targets"][0]["label"], "Cloudflare")
        self.assertEqual(status["gateway"]["host"], "10.0.0.1")
        self.assertEqual(status["source"], "checkstat")

    def test_missing_file_is_unknown_and_offline(self):
        status = self._status()
        self.assertFalse(status["available"])
        self.assertEqual(status["verdict"], "UNKNOWN")
        self.assertIn("no agent sample", status["error"])

    def test_stale_file_is_marked_stale(self):
        self._write(self._sample(generated_at=time.time() - 1000))
        status = self._status()
        self.assertTrue(status["available"])
        self.assertTrue(status["stale"])
        self.assertGreater(status["age_seconds"], 900)

    def test_malformed_and_oversized_files_are_rejected(self):
        self.path.write_text("not json", encoding="utf-8")
        self.assertFalse(self._status()["available"])
        self.path.write_bytes(b"x" * (ui.NETWORK_HEALTH_MAX_BYTES + 1))
        self.assertFalse(self._status()["available"])

    def test_disabled_config_ignores_the_file(self):
        self._write(self._sample())
        cache = ui.StatusCache(
            lambda: {"network_health": {"enabled": False}},
            _FakeTailer(),
            network_path=self.path,
        )
        status = cache._network_status(cache._get_defaults())
        self.assertFalse(status["enabled"])
        self.assertFalse(status["available"])

    def test_read_exception_does_not_escape(self):
        with mock.patch.object(
            ui.network_health, "read_result", side_effect=OSError("boom")
        ):
            status = self._status()
        self.assertFalse(status["available"])
        self.assertIn("network status read failed", status["error"])


class ApiStatusRouteTests(unittest.TestCase):
    TOKEN = "unit-test-token-0123456789abcdef"

    def setUp(self):
        class _Status:
            def get(self):
                return {
                    "ready": True,
                    "network": {
                        "available": True,
                        "enabled": True,
                        "stale": False,
                        "verdict": "UPSTREAM_ISP",
                        "summary": "upstream path degraded",
                        "targets_up": 0,
                        "targets_total": 2,
                    },
                }

        app = ui.create_app(
            _FakeRunner(), _FakeConsole(), _FakeTailer(), _FakeTailer(),
            _Status(), get_defaults=_fake_defaults,
            auth_token=self.TOKEN)
        app.config["TESTING"] = True
        self.client = app.test_client()

    def test_status_includes_network_payload_and_requires_auth(self):
        resp = self.client.get(
            "/api/status", headers={"X-Auth-Token": self.TOKEN}
        )
        self.assertEqual(resp.status_code, 200)
        body = resp.get_json()
        self.assertEqual(body["network"]["verdict"], "UPSTREAM_ISP")
        self.assertIn("sample_age", body)
        unauth = self.client.get("/api/status")
        self.assertEqual(unauth.status_code, 401)


class SystemToolsTests(unittest.TestCase):
    def test_system_tools_are_absolute_on_windows(self):
        if not ui.ON_WINDOWS:
            self.assertEqual(
                (ui.POWERSHELL_EXE, ui.TASKKILL_EXE),
                ("powershell.exe", "taskkill.exe"))
            return
        self.assertTrue(Path(ui.POWERSHELL_EXE).is_absolute())
        self.assertTrue(Path(ui.TASKKILL_EXE).is_absolute())
        self.assertEqual(Path(ui.POWERSHELL_EXE).name.lower(),
                         "powershell.exe")
        self.assertEqual(Path(ui.TASKKILL_EXE).name.lower(), "taskkill.exe")


class ValidationTests(unittest.TestCase):
    def test_unknown_key_named_in_error(self):
        _, _, errors = ui.validate_payload({"bogus_flag": 1, "interval": 30})
        self.assertEqual(len(errors), 1)
        self.assertEqual(errors[0]["key"], "bogus_flag")
        self.assertIn("bogus_flag", errors[0]["msg"])

    def test_interval_rules(self):
        for bad in (10, "30", 30.5, True):
            _, _, errors = ui.validate_payload({"interval": bad})
            self.assertTrue(errors, f"interval={bad!r} must be rejected")
        _, _, errors = ui.validate_payload({"interval": 15})
        self.assertEqual(errors, [])
        _, _, errors = ui.validate_payload({"interval": 600})
        self.assertEqual(errors, [])

    def test_strict_booleans(self):
        for bad in (1, "true", None):
            _, _, errors = ui.validate_payload({"no_ai": bad})
            self.assertTrue(errors, f"no_ai={bad!r} must be rejected")
        _, _, errors = ui.validate_payload({"no_ai": False})
        self.assertEqual(errors, [])

    def test_keep_alive_regex(self):
        for good in ("30m", "90", "1.5h", "45s", "500ms", "0"):
            _, _, errors = ui.validate_payload({"keep_alive": good})
            self.assertEqual(errors, [])
        for bad in ("30x", "-1m", "30 m"):
            _, _, errors = ui.validate_payload({"keep_alive": bad})
            self.assertTrue(errors, f"keep_alive={bad!r} must be rejected")
        # empty string means "use the YAML default" -> valid, flag omitted
        flags, _, errors = ui.validate_payload({"keep_alive": ""})
        self.assertEqual(errors, [])
        self.assertNotIn("keep_alive", flags)

    def test_numeric_ranges(self):
        rejections = [
            {"escalation_timeout": 0}, {"escalation_timeout": 3601},
            {"ai_timeout": -1}, {"num_ctx": 511}, {"num_ctx": 132000},
            {"max_ai_checks": -1}, {"max_escalations": 65},
            {"cache_hours": -1},
        ]
        for payload in rejections:
            _, _, errors = ui.validate_payload(payload)
            self.assertTrue(errors, f"{payload} must be rejected")
        accepts = [
            {"escalation_timeout": 180, "ai_timeout": 120, "num_ctx": 4096,
             "max_ai_checks": 0, "max_escalations": 64, "cache_hours": 0},
        ]
        for payload in accepts:
            _, _, errors = ui.validate_payload(payload)
            self.assertEqual(errors, [], f"{payload} must be accepted")

    def test_ollama_url(self):
        _, _, errors = ui.validate_payload(
            {"ollama_url": "not-a-url"})
        self.assertTrue(errors)
        _, _, errors = ui.validate_payload(
            {"ollama_url": "http://127.0.0.1:11434/api/generate"})
        self.assertEqual(errors, [])

    def test_empty_model_uses_defaults(self):
        flags, _, errors = ui.validate_payload({"model": "   "})
        self.assertEqual(errors, [])
        self.assertNotIn("model", flags)

    def test_path_rules(self):
        with tempfile.TemporaryDirectory() as tmp:
            original = ui.SCRIPT_DIR
            ui.SCRIPT_DIR = Path(tmp)
            try:
                inside = Path(tmp) / "snap.log"
                _write_lines(inside, "seed")
                _, err = ui.resolve_agent_path(str(inside))
                self.assertIsNone(err)
                rel, err = ui.resolve_agent_path("snap.log")
                self.assertIsNone(err)
                self.assertEqual(Path(rel), inside)
                _, err = ui.resolve_agent_path("missing.log")
                self.assertIsNotNone(err)
                _, err = ui.resolve_agent_path(str(Path(tmp).parent / "elsewhere.txt"))
                self.assertIsNotNone(err)
                _, err = ui.resolve_agent_path("")
                self.assertIsNotNone(err)
            finally:
                ui.SCRIPT_DIR = original


class TailerTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.path = Path(self._tmp.name) / "rows.jsonl"

    def tearDown(self):
        self._tmp.cleanup()

    def _tailer(self, **kw):
        return ui.FileTailer(self.path, 10, **kw)

    def test_absent_file_tolerated(self):
        tailer = self._tailer()
        self.assertFalse(tailer.poll())
        self.assertEqual(tailer.snapshot(), [])

    def test_incremental_reads(self):
        tailer = self._tailer()
        _write_lines(self.path, json.dumps(_row(1)), json.dumps(_row(2)))
        self.assertFalse(tailer.poll())
        self.assertEqual(len(tailer.snapshot()), 2)
        _write_lines(self.path, json.dumps(_row(3)))
        self.assertFalse(tailer.poll())
        rows = tailer.snapshot()
        self.assertEqual([r["timestamp"] for r in rows], [1, 2, 3])

    def test_torn_line_heals(self):
        tailer = self._tailer()
        with self.path.open("ab") as fh:
            fh.write(json.dumps(_row(1)).encode() + b"\n")
            fh.write(b'{"timestamp": 2, "estab')  # no newline: torn
        self.assertFalse(tailer.poll())
        self.assertEqual([r["timestamp"] for r in tailer.snapshot()], [1])
        with self.path.open("ab") as fh:
            fh.write(b'lished": 5}\n')
        self.assertFalse(tailer.poll())
        self.assertEqual([r["timestamp"] for r in tailer.snapshot()], [1, 2])

    def test_malformed_lines_skipped_and_counted(self):
        tailer = self._tailer()
        _write_lines(self.path, json.dumps(_row(1)), "not json at all",
                     json.dumps(_row(2)))
        self.assertFalse(tailer.poll())
        self.assertEqual([r["timestamp"] for r in tailer.snapshot()], [1, 2])
        self.assertEqual(tailer.skipped(), 1)

    def test_rotation_resets_offset(self):
        tailer = self._tailer()
        _write_lines(self.path, json.dumps(_row(1)), json.dumps(_row(2)))
        tailer.poll()
        # simulate rotation: file replaced with smaller fresh content
        self.path.write_bytes(json.dumps(_row(9)).encode() + b"\n")
        self.assertTrue(tailer.poll())
        self.assertEqual([r["timestamp"] for r in tailer.snapshot()], [9])

    def test_traffic_dedupe_on_timestamp(self):
        tailer = self._tailer(key_field="timestamp")
        _write_lines(self.path, json.dumps(_row(1)), json.dumps(_row(1)),
                     json.dumps(_row(2)))
        tailer.poll()
        self.assertEqual(len(tailer.snapshot()), 2)

    def test_findings_attach_seq(self):
        tailer = self._tailer(attach_seq=True)
        _write_lines(self.path, json.dumps({"rule": "NET-001"}),
                     json.dumps({"rule": "NET-T02"}))
        tailer.poll()
        seqs = [r["_seq"] for r in tailer.snapshot()]
        self.assertEqual(seqs, [1, 2])

    def test_rows_since_boundary(self):
        tailer = self._tailer(key_field="timestamp")
        _write_lines(self.path, json.dumps(_row(1)), json.dumps(_row(2)),
                     json.dumps(_row(3)))
        tailer.poll()
        rows, prev = tailer.rows_since(2)
        self.assertEqual([r["timestamp"] for r in rows], [3])
        self.assertEqual(prev["timestamp"], 2)
        rows, prev = tailer.rows_since(0)
        self.assertEqual([r["timestamp"] for r in rows], [1, 2, 3])
        self.assertIsNone(prev)

    def test_cap_evicts_oldest(self):
        tailer = ui.FileTailer(self.path, 2)
        _write_lines(self.path, *[json.dumps(_row(i)) for i in range(1, 5)])
        tailer.poll()
        self.assertEqual([r["timestamp"] for r in tailer.snapshot()], [3, 4])

    def test_rows_missing_process_maps(self):
        tailer = self._tailer(key_field="timestamp")
        row = _row(1)  # no per_process_names key at all
        _write_lines(self.path, json.dumps(row))
        tailer.poll()
        self.assertEqual(tailer.snapshot()[0].get("per_process_names", {}), {})


class ConsoleLogTests(unittest.TestCase):
    def test_since_cursor(self):
        log = ui.ConsoleLog()
        log.append("out", "one")
        log.append("err", "two")
        log.append("out", "three")
        first = log.since(0)
        self.assertEqual([e["line"] for e in first["lines"]],
                         ["one", "two", "three"])
        self.assertTrue(all(e["s"] == "err" for e in first["lines"] if e["line"] == "two"))
        next_index = first["next"]
        log.append("out", "four")
        again = log.since(next_index)
        self.assertEqual([e["line"] for e in again["lines"]], ["four"])
        self.assertEqual(again["gap"], False)
        stable = log.since(again["next"])
        self.assertEqual(stable["lines"], [])

    def test_gap_detected_after_eviction(self):
        log = ui.ConsoleLog(cap=2)
        for word in ("a", "b", "c", "d"):
            log.append("out", word)
        # buffer holds c(i=3) and d(i=4); oldest=3
        # client cursor=1 (has "a"): it needs b(2) too, but b was evicted
        result = log.since(1)
        self.assertTrue(result["gap"])
        self.assertEqual([e["line"] for e in result["lines"]], ["c", "d"])
        # client cursor=3 (already has "b"): exactly the buffered lines remain
        result = log.since(3)
        self.assertFalse(result["gap"])
        self.assertEqual([e["line"] for e in result["lines"]], ["c", "d"])

    def test_long_line_truncated(self):
        log = ui.ConsoleLog()
        log.append("out", "x" * (ui.CONSOLE_LINE_MAX + 100))
        line = log.since(0)["lines"][0]["line"]
        self.assertLessEqual(len(line), ui.CONSOLE_LINE_MAX + 20)
        self.assertTrue(line.endswith("…[truncated]"))


class DefaultsTests(unittest.TestCase):
    def test_real_yaml_defaults(self):
        data = ui.load_yaml_defaults(RULES_FILE, force=True)
        self.assertEqual(data["agent"]["model"], "llama3.1:8b")
        self.assertEqual(data["agent"]["scan_interval_seconds"], 300)
        self.assertEqual(data["agent"]["max_ai_checks_per_run"], 8)
        self.assertEqual(data["traffic"]["sample_interval_seconds"], 3)
        self.assertIn("escalation_severities", data["yaml_only"])
        self.assertEqual(data["yaml_only"]["alert_cooldown_minutes"], 60)

    def test_ollama_base_derivation(self):
        self.assertEqual(ui._ollama_base("http://localhost:11434/api/generate"),
                         "http://localhost:11434")
        self.assertEqual(ui._ollama_base("http://localhost:11434/api/tags"),
                         "http://localhost:11434")
        self.assertEqual(ui._ollama_base("http://localhost:11434"),
                         "http://localhost:11434")


class InputValidationHardeningTests(unittest.TestCase):
    """U5: rule paths must yield real detection; numeric caps and force are strict."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self._orig_script_dir = ui.SCRIPT_DIR
        ui.SCRIPT_DIR = self.tmp

    def tearDown(self):
        ui.SCRIPT_DIR = self._orig_script_dir
        self._tmp.cleanup()

    def _write(self, name: str, text: str) -> Path:
        path = self.tmp / name
        path.write_text(text, encoding="utf-8")
        return path

    def test_interval_upper_bound(self):
        _, _, errors = ui.validate_payload({"interval": 86401})
        self.assertTrue(errors, "interval=86401 must be rejected")
        _, _, errors = ui.validate_payload({"interval": 86400})
        self.assertEqual(errors, [], "interval=86400 must be accepted")

    def test_other_numeric_upper_bounds(self):
        for bad in ({"max_ai_checks": 1001}, {"cache_hours": 8760.1}):
            _, _, errors = ui.validate_payload(bad)
            self.assertTrue(errors, f"{bad} must be rejected")
        for good in ({"max_ai_checks": 1000}, {"cache_hours": 8760}):
            _, _, errors = ui.validate_payload(good)
            self.assertEqual(errors, [], f"{good} must be accepted")

    def test_rules_path_rejects_json_cache(self):
        # JSON is valid YAML, so the old resolver accepted this mapping file
        # even though it contains no anomaly rules.
        self._write("soc_verdict_cache.json", '{"verdicts": {}}')
        flags, _, errors = ui.validate_payload(
            {"rules_path": "soc_verdict_cache.json"})
        self.assertTrue(errors)
        self.assertEqual(errors[0]["key"], "rules_path")
        self.assertNotIn("rules_path", flags)

    def test_rules_path_requires_anomaly_rules_mapping(self):
        self._write("no_rules.yaml", "agent:\n  model: llama3.1:8b\n")
        flags, _, errors = ui.validate_payload({"rules_path": "no_rules.yaml"})
        self.assertTrue(errors)
        self.assertIn("anomaly_rules", errors[0]["msg"])
        self.assertNotIn("rules_path", flags)

    def test_rules_path_rejects_all_disabled_rules(self):
        self._write(
            "disabled.yaml",
            "anomaly_rules:\n"
            "  high_severity:\n"
            "    - rule_id: NET-001\n"
            "      enabled: false\n"
            "  medium_severity:\n"
            "    - rule_id: NET-002\n"
            "      enabled: false\n")
        flags, _, errors = ui.validate_payload({"rules_path": "disabled.yaml"})
        self.assertTrue(errors)
        self.assertIn("enabled", errors[0]["msg"])
        self.assertNotIn("rules_path", flags)

    def test_rules_path_accepts_valid_yaml(self):
        self._write(
            "rules.yaml",
            "anomaly_rules:\n"
            "  high_severity:\n"
            "    - rule_id: NET-001\n"
            "      enabled: true\n")
        flags, _, errors = ui.validate_payload({"rules_path": "rules.yaml"})
        self.assertEqual(errors, [])
        self.assertEqual(Path(flags["rules_path"]).name, "rules.yaml")
        # checkstat defaults a missing "enabled" to true; accept that too.
        self._write(
            "rules_default_enabled.yaml",
            "anomaly_rules:\n"
            "  medium_severity:\n"
            "    - rule_id: NET-002\n")
        _, _, errors = ui.validate_payload(
            {"rules_path": "rules_default_enabled.yaml"})
        self.assertEqual(errors, [])

    def test_replay_path_requires_log_or_txt(self):
        self._write("snapshot.exe", "MZ")
        flags, mode, errors = ui.validate_payload({"replay_path": "snapshot.exe"})
        self.assertTrue(errors)
        self.assertEqual(errors[0]["key"], "replay_path")
        self.assertNotIn("replay_path", flags)
        self._write("snapshot.log", "")
        flags, mode, errors = ui.validate_payload({"replay_path": "snapshot.log"})
        self.assertEqual(errors, [])
        self.assertEqual(mode, "replay")
        self.assertIn("replay_path", flags)

    def test_force_requires_json_boolean(self):
        for bad in ("false", "true", 0, 1, None):
            _, _, errors = ui.validate_payload({"force": bad})
            self.assertTrue(errors, f"force={bad!r} must be rejected")
            self.assertEqual(errors[0]["key"], "force")
        for good in (True, False):
            flags, _, errors = ui.validate_payload({"force": good})
            self.assertEqual(errors, [], f"force={good!r} must be accepted")
            self.assertNotIn("force", flags)


class _FakeRunner:
    """AgentRunner stand-in; no child process is ever spawned."""

    def __init__(self):
        self.stop_calls = 0

    def snapshot(self) -> dict:
        return {
            "state": "STOPPED", "mode": "continuous", "pid": None,
            "argv_display": None, "started_at": None, "uptime_seconds": None,
            "exit_code": None, "exit_kind": None, "attached": True,
            "stop_requested": False,
        }

    def stop(self, block: bool = False, timeout: float = 10.0) -> dict:
        self.stop_calls += 1
        return self.snapshot()


class _FakeConsole:
    def since(self, index: int, limit: int = 1500) -> dict:
        return {"lines": [], "next": max(index, 0), "gap": False}


class _FakeTailer:
    def poll(self) -> bool:
        return False

    def key_range(self):
        return None, None

    def snapshot(self):
        return []

    def rows_since(self, since):
        return [], None

    def records_after(self, after):
        return [], False

    def latest_seq(self) -> int:
        return 0

    def __len__(self) -> int:
        return 0

    def skipped(self) -> int:
        return 0


class _FakeStatus:
    def get(self) -> dict:
        return {}


def _fake_defaults(**kwargs) -> dict:
    return {"agent": {}, "yaml_only": {}, "enrichment": {},
            "traffic": {"sample_interval_seconds": 3}}


class ApiAuthTests(unittest.TestCase):
    TOKEN = "unit-test-token-0123456789abcdef"

    def setUp(self):
        self.runner = _FakeRunner()
        self.app = ui.create_app(
            self.runner, _FakeConsole(), _FakeTailer(), _FakeTailer(),
            _FakeStatus(), get_defaults=_fake_defaults,
            auth_token=self.TOKEN)
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

    def _headers(self, **extra):
        headers = {"X-Auth-Token": self.TOKEN}
        headers.update(extra)
        return headers

    def test_state_without_token_is_401(self):
        resp = self.client.get("/api/state")
        self.assertEqual(resp.status_code, 401)
        self.assertIn("error", resp.get_json())

    def test_state_with_wrong_token_is_401(self):
        resp = self.client.get("/api/state",
                               headers={"X-Auth-Token": self.TOKEN + "x"})
        self.assertEqual(resp.status_code, 401)

    def test_state_with_correct_token_is_200(self):
        resp = self.client.get("/api/state", headers=self._headers())
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["state"], "STOPPED")

    def test_non_loopback_host_is_421(self):
        resp = self.client.get("/api/state",
                               headers=self._headers(Host="evil.example"))
        self.assertEqual(resp.status_code, 421)
        self.assertIn("Host", resp.get_json()["error"])

    def test_cross_origin_is_403(self):
        resp = self.client.get(
            "/api/state", headers=self._headers(Origin="http://evil.example"))
        self.assertEqual(resp.status_code, 403)

    def test_loopback_hosts_and_same_origin_are_accepted(self):
        for host in ("localhost", "127.0.0.1:8765", "[::1]:8765"):
            with self.subTest(host=host):
                resp = self.client.get(
                    "/api/state",
                    headers=self._headers(Host=host, Origin=f"http://{host}"))
                self.assertEqual(resp.status_code, 200)

    def test_stop_without_token_is_401_and_does_not_stop(self):
        resp = self.client.post("/api/stop")
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(self.runner.stop_calls, 0)

    def test_index_and_static_stay_unauthenticated(self):
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        resp = self.client.get("/static/app.js")
        self.assertEqual(resp.status_code, 200)

    def test_token_generated_when_omitted(self):
        app = ui.create_app(_FakeRunner(), _FakeConsole(), _FakeTailer(),
                            _FakeTailer(), _FakeStatus(),
                            get_defaults=_fake_defaults)
        token = app.config["auth_token"]
        self.assertIsInstance(token, str)
        self.assertGreaterEqual(len(token), 32)


class OllamaUrlValidationTests(unittest.TestCase):
    """U6: only validated loopback Ollama endpoints by default."""

    def test_loopback_urls_are_accepted(self):
        for url in (
                "http://127.0.0.1:11434/api/generate",
                "http://localhost:11434",
                "http://[::1]:11434/api/tags",
                "https://localhost:443/proxy"):
            with self.subTest(url=url):
                flags, _, errors = ui.validate_payload({"ollama_url": url})
                self.assertEqual(errors, [])
                self.assertEqual(flags["ollama_url"], url)

    def test_non_loopback_requires_explicit_opt_in(self):
        for url in (
                "http://169.254.169.254/latest/meta-data",
                "http://192.168.1.50:11434/api/generate",
                "https://ollama.example.com",
                "http://localhost.evil.example:11434/"):
            with self.subTest(url=url):
                flags, _, errors = ui.validate_payload({"ollama_url": url})
                self.assertTrue(errors)
                self.assertEqual(errors[0]["key"], "ollama_url")
                self.assertNotIn("ollama_url", flags)
                flags, _, errors = ui.validate_payload(
                    {"ollama_url": url}, allow_remote_ollama=True)
                self.assertEqual(errors, [])
                self.assertEqual(flags["ollama_url"], url)

    def test_malformed_urls_are_rejected_even_with_opt_in(self):
        bad = (
            "ftp://127.0.0.1:11434/",
            "file:///C:/Windows/win.ini",
            "//127.0.0.1:11434/",
            "http:///api/tags",
            "http://127.0.0.1:0/",
            "http://127.0.0.1:70000/",
            "http://127.0.0.1:/api/tags",
            "http://[::1]:/api/tags",
            "http://127.0.0.1:notaport/",
            "http://user:pass@127.0.0.1:11434/",
            "http://127.0.0.1:11434/?x=1",
            "http://127.0.0.1:11434/#fragment",
            "http://::1:11434/",
            "http://127.0.0.1:11434/a b",
            "http://127.0.0.1:11434/" + "a" * ui.OLLAMA_URL_MAX_LENGTH,
        )
        for url in bad:
            for allow_remote in (False, True):
                with self.subTest(url=url, allow_remote=allow_remote):
                    flags, _, errors = ui.validate_payload(
                        {"ollama_url": url},
                        allow_remote_ollama=allow_remote)
                    self.assertTrue(errors, url)
                    self.assertNotIn("ollama_url", flags)


class _TagsResponse:
    def __init__(self, body=b"{}", oversized=False):
        self._body = body
        self._oversized = oversized
        self.read_amount = None

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False

    def read(self, amt=None):
        self.read_amount = amt
        if self._oversized:
            return b"x" * (amt if amt is not None else 1)
        return self._body if amt is None else self._body[:amt]


class OllamaStatusCacheHardeningTests(unittest.TestCase):
    """U6: the status probe must not relay SSRF or consume unbounded JSON."""

    def test_remote_url_is_rejected_without_network(self):
        cache = ui.StatusCache(lambda: {}, _FakeTailer())
        with mock.patch.object(ui.urllib.request, "urlopen") as urlopen:
            result = cache._check_ollama(
                "http://169.254.169.254/latest/meta-data")
        urlopen.assert_not_called()
        self.assertFalse(result["reachable"])
        self.assertEqual(result["base"], "")
        self.assertIn("rejected", result["error"].lower())

    def test_tags_read_is_capped(self):
        cache = ui.StatusCache(lambda: {}, _FakeTailer())
        response = _TagsResponse(oversized=True)
        opener = mock.Mock()
        opener.open.return_value = response
        with mock.patch.object(
                ui.urllib.request, "build_opener", return_value=opener):
            result = cache._check_ollama(
                "http://127.0.0.1:11434/api/generate")
        self.assertEqual(response.read_amount,
                         ui.OLLAMA_RESPONSE_MAX_BYTES + 1)
        self.assertFalse(result["reachable"])
        self.assertIn("size", result["error"].lower())

    def test_non_object_json_is_rejected(self):
        cache = ui.StatusCache(lambda: {}, _FakeTailer())
        response = _TagsResponse(body=b'["not", "an", "object"]')
        opener = mock.Mock()
        opener.open.return_value = response
        with mock.patch.object(
                ui.urllib.request, "build_opener", return_value=opener):
            result = cache._check_ollama("http://127.0.0.1:11434")
        self.assertFalse(result["reachable"])
        self.assertIn("object", result["error"].lower())

    def test_empty_query_or_fragment_is_rejected(self):
        for url in ("http://127.0.0.1:11434/api/generate?",
                    "http://127.0.0.1:11434/api/generate#"):
            with self.subTest(url=url):
                _, _, errors = ui.validate_payload({"ollama_url": url})
                self.assertTrue(errors)

    def test_refresh_survives_a_bad_probe(self):
        defaults = {
            "agent": {"ollama_url": "http://127.0.0.1:11434/api/generate"},
            "traffic": {},
        }
        cache = ui.StatusCache(lambda: defaults, _FakeTailer())
        with mock.patch.object(
                cache, "_check_ollama",
                side_effect=http.client.BadStatusLine("bad")):
            cache._refresh()
        self.assertIn("status refresh failed", cache.get()["error"])

    def test_remote_url_is_probed_with_explicit_opt_in(self):
        cache = ui.StatusCache(lambda: {}, _FakeTailer(),
                               allow_remote_ollama=True)
        body = json.dumps(
            {"models": [{"name": "llama3.1:8b", "size": 2048}]}).encode()
        response = _TagsResponse(body=body)
        opener = mock.Mock()
        opener.open.return_value = response
        with mock.patch.object(
                ui.urllib.request, "build_opener",
                return_value=opener) as build:
            result = cache._check_ollama(
                "http://ollama.example.com:11434/api/generate")
        build.assert_called_once_with(ui._NoRedirect)
        opener.open.assert_called_once_with(
            "http://ollama.example.com:11434/api/tags",
            timeout=ui.OLLAMA_TIMEOUT)
        self.assertTrue(result["reachable"])
        self.assertEqual(result["base"], "http://ollama.example.com:11434")
        self.assertEqual(result["models"][0]["name"], "llama3.1:8b")
        self.assertEqual(result["models"][0]["size_human"], "2.0 KB")


class ModelNameValidationTests(unittest.TestCase):
    """U9: model names are argv tokens, not arbitrary console text."""

    def test_valid_model_tokens_are_accepted(self):
        for name in ("llama3.1:8b", "qwen3.8:27b",
                     "library/llama3:latest", "model_1.2-3", "a" * 128):
            for key in ("model", "escalation_model"):
                with self.subTest(key=key, name=name):
                    flags, _, errors = ui.validate_payload({key: name})
                    self.assertEqual(errors, [])
                    self.assertEqual(flags[key], name)

    def test_forged_or_malformed_model_names_are_rejected(self):
        for name in ("bad\n[warn] forged", "bad\rname", "bad name",
                     "bad;remove", "bad\x1b[31m", "bad\x85name",
                     "a" * 129, "-h", "--", "--verbose", "--model"):
            for key in ("model", "escalation_model"):
                with self.subTest(key=key, name=name):
                    flags, _, errors = ui.validate_payload({key: name})
                    self.assertTrue(errors)
                    self.assertEqual(errors[0]["key"], key)
                    self.assertNotIn(key, flags)


class ConsoleSanitizationTests(unittest.TestCase):
    """U9: child/model output cannot forge a console line or emit controls."""

    def test_control_characters_and_ansi_are_stripped(self):
        log = ui.ConsoleLog()
        log.append(
            "out",
            "model\x1b[31mRED\x1b[0m\r[warn] forged\nnext\x9b2J")
        lines = log.since(0)["lines"]
        self.assertEqual(len(lines), 1)
        line = lines[0]["line"]
        for forbidden in ("\x1b", "\x9b", "\r", "\n", "\x07"):
            self.assertNotIn(forbidden, line)
        self.assertEqual(line, "modelRED[warn] forgednext")

    def test_plain_lines_and_trailing_newlines_are_unchanged(self):
        log = ui.ConsoleLog()
        log.append("out", "plain line\r\n")
        self.assertEqual(log.since(0)["lines"][0]["line"], "plain line")


class SecurityHeaderTests(unittest.TestCase):
    """U10: every response carries the dashboard security headers."""

    TOKEN = "unit-test-token-0123456789abcdef"
    CSP = ("default-src 'self'; script-src 'self'; "
           "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
           "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'")

    def setUp(self):
        self.app = ui.create_app(
            _FakeRunner(), _FakeConsole(), _FakeTailer(), _FakeTailer(),
            _FakeStatus(), get_defaults=_fake_defaults,
            auth_token=self.TOKEN)
        self.client = self.app.test_client()

    def test_headers_on_index_static_and_api(self):
        cases = (("/", {}), ("/static/app.js", {}),
                 ("/api/state", {"X-Auth-Token": self.TOKEN}))
        for path, headers in cases:
            with self.subTest(path=path):
                resp = self.client.get(path, headers=headers)
                self.assertEqual(resp.status_code, 200)
                self.assertEqual(resp.headers["Content-Security-Policy"],
                                 self.CSP)
                self.assertEqual(resp.headers["X-Frame-Options"], "DENY")
                self.assertEqual(
                    resp.headers["X-Content-Type-Options"], "nosniff")
                self.assertEqual(resp.headers["Referrer-Policy"],
                                 "no-referrer")

    def test_headers_are_present_on_auth_rejections(self):
        resp = self.client.get("/api/state")
        self.assertEqual(resp.status_code, 401)
        self.assertIn("Content-Security-Policy", resp.headers)
        self.assertEqual(resp.headers["X-Frame-Options"], "DENY")


class _StartFakeRunner:
    """Stateful runner stub; never spawns a process."""

    def __init__(self, fail_with=None,
                 argv_display="C:\\secret\\checkstat.py --token x"):
        self.started = False
        self.start_calls = []
        self.fail_with = fail_with
        self.child_command = None
        self._argv_display = argv_display

    def snapshot(self):
        return {
            "state": "RUNNING" if self.started else "STOPPED",
            "mode": "continuous",
            "pid": 4242 if self.started else None,
            "argv_display": self._argv_display if self.started else None,
            "started_at": 1.0 if self.started else None,
            "uptime_seconds": 0.0 if self.started else None,
            "exit_code": None, "exit_kind": None, "attached": True,
            "stop_requested": False,
        }

    def start(self, argv, mode):
        self.start_calls.append(list(argv))
        if self.fail_with is not None:
            return False, self.fail_with
        self.started = True
        return True, 4242

    def stop(self, block=False, timeout=10.0):
        self.started = False
        return self.snapshot()


class StartApiHardeningTests(unittest.TestCase):
    TOKEN = "unit-test-token-0123456789abcdef"

    def _client(self, runner, console=None, allow_remote=False,
                get_defaults=_fake_defaults):
        app = ui.create_app(
            runner, console or _FakeConsole(), _FakeTailer(), _FakeTailer(),
            _FakeStatus(), get_defaults=get_defaults,
            auth_token=self.TOKEN, allow_remote_ollama=allow_remote)
        app.config["TESTING"] = True
        return app.test_client()

    def _post(self, client, payload):
        return client.post("/api/start", json=payload,
                           headers={"X-Auth-Token": self.TOKEN})

    def test_remote_ollama_rejected_without_opt_in(self):
        runner = _StartFakeRunner()
        client = self._client(runner)
        resp = self._post(
            client, {"ollama_url": "http://169.254.169.254/latest/meta-data"})
        self.assertEqual(resp.status_code, 400)
        fields = resp.get_json()["fields"]
        self.assertEqual(fields[0]["key"], "ollama_url")
        self.assertEqual(runner.start_calls, [])

    def test_remote_ollama_allowed_with_flag_and_no_argv_display(self):
        runner = _StartFakeRunner()
        client = self._client(runner, allow_remote=True)
        url = "http://ollama.internal.example:11434/api/generate"
        resp = self._post(client, {"interval": 30, "force": True,
                                   "ollama_url": url})
        self.assertEqual(resp.status_code, 200, resp.get_json())
        body = resp.get_json()
        self.assertEqual(body["state"], "RUNNING")
        self.assertEqual(body["pid"], 4242)
        self.assertNotIn("argv_display", body)
        self.assertEqual(len(runner.start_calls), 1)
        self.assertIn("--ollama-url", runner.start_calls[0])
        self.assertIn(url, runner.start_calls[0])

    def test_412_external_is_pids_only(self):
        runner = _StartFakeRunner()
        client = self._client(runner)
        probe = {"checked": True, "processes": [
            {"pid": 111, "cmdline": "C:\\secret\\checkstat.py --token abc"},
            {"pid": 222, "cmdline": "C:\\secret\\other.py"}]}
        with mock.patch.object(ui, "external_checkstat_processes",
                               return_value=probe):
            resp = self._post(client, {"interval": 30})
        self.assertEqual(resp.status_code, 412)
        body = resp.get_json()
        dumped = json.dumps(body)
        self.assertNotIn("cmdline", dumped)
        self.assertNotIn("secret", dumped)
        self.assertEqual(body["external"], [{"pid": 111}, {"pid": 222}])
        self.assertEqual(runner.start_calls, [])

    def test_start_failure_is_generic_and_logged(self):
        console = ui.ConsoleLog()
        runner = ui.AgentRunner(console)
        client = self._client(runner, console=console)
        with mock.patch.object(
                ui.subprocess, "Popen",
                side_effect=OSError("C:\\secret\\checkstat.py is broken")):
            resp = self._post(client, {"interval": 30, "force": True})
        self.assertEqual(resp.status_code, 503)
        dumped = json.dumps(resp.get_json())
        self.assertNotIn("secret", dumped)
        self.assertNotIn("broken", dumped)
        lines = [e["line"] for e in console.since(0)["lines"]]
        self.assertTrue(any("secret" in line for line in lines),
                        f"failure detail missing from console: {lines}")


class ConfigDefaultsHardeningTests(unittest.TestCase):
    TOKEN = "unit-test-token-0123456789abcdef"

    def test_defaults_failure_is_generic_and_logged(self):
        console = ui.ConsoleLog()

        def bad_defaults(force=False):
            raise ui.DefaultsError(
                "YAML parse error at C:\\secret\\rules.yaml")

        app = ui.create_app(
            _FakeRunner(), console, _FakeTailer(), _FakeTailer(),
            _FakeStatus(), get_defaults=bad_defaults,
            auth_token=self.TOKEN)
        client = app.test_client()
        resp = client.get("/api/config-defaults",
                          headers={"X-Auth-Token": self.TOKEN})
        self.assertEqual(resp.status_code, 500)
        body = resp.get_json()
        dumped = json.dumps(body)
        self.assertNotIn("secret", dumped)
        self.assertNotIn("YAML", dumped)
        self.assertEqual(body["error"], "configuration defaults unavailable")
        lines = [e["line"] for e in console.since(0)["lines"]]
        self.assertTrue(any("secret" in line for line in lines),
                        f"failure detail missing from console: {lines}")


class ExternalPidProjectionTests(unittest.TestCase):
    """U11: probe command lines never cross the HTTP boundary."""

    def test_projection_keeps_only_integer_pids(self):
        rows = [
            {"pid": 7, "cmdline": "C:\\secret\\checkstat.py --x"},
            {"pid": "8", "cmdline": "y"},
            {"cmdline": "z"},
            "not-a-dict",
            {"pid": True, "cmdline": "bool-is-not-a-pid"},
        ]
        self.assertEqual(ui.external_process_pids(rows), [{"pid": 7}])


class ConsoleResponseLimitTests(unittest.TestCase):
    """U7: console responses are bounded in lines and bytes."""

    def test_since_caps_total_line_bytes(self):
        log = ui.ConsoleLog()
        line = "x" * ui.CONSOLE_LINE_MAX
        for _ in range(100):
            log.append("out", line)
        payload = log.since(0)
        cost = sum(len(e["line"].encode("utf-8")) + 64
                   for e in payload["lines"])
        self.assertLessEqual(cost, ui.CONSOLE_RESPONSE_MAX_BYTES)
        self.assertGreater(len(payload["lines"]), 0)
        self.assertLess(len(payload["lines"]), 100)
        self.assertTrue(payload["gap"])

    def test_since_caps_line_count_and_keeps_newest(self):
        log = ui.ConsoleLog(cap=1000)
        for i in range(700):
            log.append("out", f"line {i}")
        payload = log.since(0)
        self.assertEqual(len(payload["lines"]),
                         ui.CONSOLE_API_DEFAULT_LINES)
        self.assertEqual(payload["lines"][-1]["line"], "line 699")
        self.assertEqual(payload["next"], payload["lines"][-1]["i"] + 1)
        self.assertTrue(payload["gap"])

    def test_since_bounds_json_escaped_size(self):
        # Non-ASCII text expands to \uXXXX escapes in the JSON payload; the
        # cap must be measured after escaping, not on the raw UTF-8 length.
        log = ui.ConsoleLog()
        for _ in range(50):
            log.append("out", "\u4e00" * ui.CONSOLE_LINE_MAX)
        payload = log.since(0)
        encoded = len(json.dumps(payload["lines"]))
        self.assertLessEqual(encoded, ui.CONSOLE_RESPONSE_MAX_BYTES)
        self.assertGreater(len(payload["lines"]), 0)


class TailerPendingCapTests(unittest.TestCase):
    """U7: a torn line larger than the cap must not grow memory without bound."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.path = Path(self._tmp.name) / "rows.jsonl"

    def test_oversized_torn_line_is_dropped_not_buffered(self):
        tailer = ui.FileTailer(self.path, 10)
        with self.path.open("ab") as fh:
            fh.write(b"x" * (ui.FILE_TAILER_PENDING_MAX + 1))
        self.assertFalse(tailer.poll())
        self.assertEqual(tailer.snapshot(), [])
        self.assertLessEqual(len(tailer._pending),
                             ui.FILE_TAILER_PENDING_MAX)
        self.assertGreaterEqual(tailer.skipped(), 1)

    def test_oversized_line_does_not_block_following_records(self):
        tailer = ui.FileTailer(self.path, 10)
        with self.path.open("ab") as fh:
            fh.write(b"x" * (ui.FILE_TAILER_PENDING_MAX + 1))
        tailer.poll()
        with self.path.open("ab") as fh:
            fh.write(b"\n" + json.dumps(_row(1)).encode() + b"\n")
        self.assertFalse(tailer.poll())
        self.assertEqual([r["timestamp"] for r in tailer.snapshot()], [1])

    def test_pending_at_cap_is_kept_for_healing(self):
        tailer = ui.FileTailer(self.path, 10)
        with self.path.open("ab") as fh:
            fh.write(b"x" * ui.FILE_TAILER_PENDING_MAX)
        tailer.poll()
        self.assertEqual(len(tailer._pending), ui.FILE_TAILER_PENDING_MAX)
        self.assertEqual(tailer.skipped(), 0)

    def test_oversized_complete_line_is_skipped(self):
        tailer = ui.FileTailer(self.path, 10)
        with self.path.open("ab") as fh:
            fh.write(b'{"x": "' + b"x" * (ui.FILE_TAILER_LINE_MAX + 1) + b'"}\n')
        self.assertFalse(tailer.poll())
        self.assertEqual(tailer.snapshot(), [])
        self.assertGreaterEqual(tailer.skipped(), 1)


class ExternalProbeSerializationTests(unittest.TestCase):
    """U7: parallel /api/start probes must not spawn parallel PowerShell runs."""

    def test_parallel_probes_never_run_concurrently(self):
        state = {"active": 0, "peak": 0}
        guard = threading.Lock()

        def fake_run(*args, **kwargs):
            with guard:
                state["active"] += 1
                state["peak"] = max(state["peak"], state["active"])
            time.sleep(0.05)
            with guard:
                state["active"] -= 1
            return mock.Mock(stdout="", returncode=0)

        with mock.patch.object(ui, "ON_WINDOWS", True), \
                mock.patch.object(ui.subprocess, "run", side_effect=fake_run):
            threads = [threading.Thread(target=ui.external_checkstat_processes)
                       for _ in range(5)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(10)
                self.assertFalse(thread.is_alive())
        self.assertEqual(state["peak"], 1)


class PathContainmentTests(unittest.TestCase):
    """U8: resolve_agent_path canonicalizes before the containment check."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self._outside_tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._outside_tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.outside = Path(self._outside_tmp.name)
        self._orig_script_dir = ui.SCRIPT_DIR
        ui.SCRIPT_DIR = self.root
        self._links = []
        self.addCleanup(self._restore)
        self.addCleanup(self._remove_links)

    def _restore(self):
        ui.SCRIPT_DIR = self._orig_script_dir

    def _remove_links(self):
        for link in self._links:
            with contextlib.suppress(OSError):
                if link.is_symlink() or not link.is_dir():
                    link.unlink()
                else:
                    os.rmdir(link)

    def _directory_link(self, name: str, target: Path) -> Path:
        link = self.root / name
        try:
            os.symlink(target, link, target_is_directory=True)
        except (OSError, NotImplementedError):
            if os.name != "nt":
                self.skipTest("directory symlinks are unavailable")
            result = ui.subprocess.run(
                [ui._system32_tool("cmd.exe"), "/c", "mklink", "/J",
                 str(link), str(target)],
                capture_output=True, check=False)
            if result.returncode != 0 or not link.is_dir():
                self.skipTest("directory symlinks/junctions are unavailable")
        self._links.append(link)
        return link

    def test_rejects_symlink_or_junction_escape(self):
        (self.outside / "secret.log").write_text("secret", encoding="utf-8")
        link = self._directory_link("escape", self.outside)
        resolved, err = ui.resolve_agent_path(str(link / "secret.log"))
        self.assertIsNone(resolved)
        self.assertIn("outside", err)

    def test_rejects_relative_dotdot_escape(self):
        target = self.outside / "secret.log"
        target.write_text("secret", encoding="utf-8")
        resolved, err = ui.resolve_agent_path(
            os.path.relpath(target, self.root))
        self.assertIsNone(resolved)
        self.assertIn("outside", err)

    def test_accepts_regular_file_inside_project(self):
        target = self.root / "snap.log"
        target.write_text("", encoding="utf-8")
        resolved, err = ui.resolve_agent_path("snap.log")
        self.assertIsNone(err)
        self.assertEqual(resolved, target.resolve())

    def test_rejects_empty_missing_and_directory(self):
        (self.root / "subdir").mkdir()
        for raw in ("", "   ", "missing.log", "subdir"):
            with self.subTest(raw=raw):
                resolved, err = ui.resolve_agent_path(raw)
                self.assertIsNone(resolved)
                self.assertIsNotNone(err)


class StateFileWriteTests(unittest.TestCase):
    """U8: the state file is published via mkstemp + os.replace."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dir = Path(self._tmp.name)
        self.target = self.dir / "soc_ui_agent_state.json"

    def test_writes_json_atomically_without_predictable_tmp(self):
        seen = {}
        real_replace = os.replace

        def fake_replace(src, dst):
            seen["src"] = Path(src)
            seen["dst"] = Path(dst)
            self.assertTrue(seen["src"].is_file())
            return real_replace(src, dst)

        with mock.patch.object(ui.os, "replace", side_effect=fake_replace):
            ui._write_state_file(1234, ["python", "checkstat.py"], 1.5,
                                 "continuous", path=self.target)
        self.assertEqual(seen["src"].parent, self.dir)
        self.assertNotEqual(seen["src"],
                            self.dir / "soc_ui_agent_state.json.tmp")
        self.assertFalse(seen["src"].exists())
        data = json.loads(self.target.read_text(encoding="utf-8"))
        self.assertEqual(data["pid"], 1234)
        self.assertEqual(data["mode"], "continuous")

    def test_unlink_state_if_pid_keeps_another_owner(self):
        self.target.write_text(json.dumps({"pid": 2}), encoding="utf-8")
        ui._unlink_state_if_pid(self.target, 1)
        self.assertTrue(self.target.exists())
        ui._unlink_state_if_pid(self.target, 2)
        self.assertFalse(self.target.exists())

    def test_failed_replace_cleans_up_temp_file(self):
        with (mock.patch.object(ui.os, "replace", side_effect=OSError("boom")),
              self.assertRaises(OSError)):
            ui._write_state_file(1, [], 1.0, "continuous",
                                 path=self.target)
        self.assertFalse(self.target.exists())
        self.assertEqual(list(self.dir.iterdir()), [])

    def test_replace_does_not_write_through_a_target_symlink(self):
        outside = tempfile.TemporaryDirectory()
        self.addCleanup(outside.cleanup)
        outside_file = Path(outside.name) / "outside.json"
        outside_file.write_text("original", encoding="utf-8")
        try:
            self.target.symlink_to(outside_file)
        except (OSError, NotImplementedError):
            self.skipTest("file symlinks are unavailable")
        ui._write_state_file(7, [], 2.0, "continuous", path=self.target)
        self.assertFalse(self.target.is_symlink())
        self.assertEqual(outside_file.read_text(encoding="utf-8"),
                         "original")
        data = json.loads(self.target.read_text(encoding="utf-8"))
        self.assertEqual(data["pid"], 7)


class _FakeProc:
    """Minimal Popen stand-in; never spawns a child."""

    def __init__(self, pid: int = 4242):
        self.pid = pid
        self.stdout = io.BytesIO()
        self.stderr = io.BytesIO()
        self.signals = []
        self.returncode = None
        self.killed = False
        self.exited = threading.Event()
        self.waiting = threading.Event()

    def send_signal(self, sig):
        self.signals.append(sig)
        self.returncode = 0
        self.exited.set()

    def wait(self, timeout=None):
        self.waiting.set()
        if not self.exited.wait(timeout):
            raise ui.subprocess.TimeoutExpired(cmd="fake", timeout=timeout)
        return self.returncode

    def kill(self):
        self.killed = True
        self.returncode = -9
        self.exited.set()

    def poll(self):
        return self.returncode


class _UnkillableProc:
    """Popen stand-in whose signal/wait/kill all fail."""

    pid = 999

    def send_signal(self, sig):
        raise OSError("no console")

    def wait(self, timeout=None):
        raise ui.subprocess.TimeoutExpired(cmd="fake", timeout=timeout)

    def kill(self):
        raise OSError("already gone")

    def poll(self):
        return None


class StartStopRaceTests(unittest.TestCase):
    """U12: a stop racing a start is honored and STOPPING is never sticky."""

    def test_popen_runtime_error_leaves_stopped(self):
        runner = ui.AgentRunner(ui.ConsoleLog())
        with mock.patch.object(
                ui.subprocess, "Popen", side_effect=RuntimeError("boom")):
            ok, _ = runner.start(["fake"], "continuous")
        self.assertFalse(ok)
        self.assertEqual(runner.state, ui.STATE_STOPPED)

    @unittest.skipUnless(ui.ON_WINDOWS, "CTRL_BREAK_EVENT is Windows-only")
    def test_stop_during_start_waits_then_stops_the_child(self):
        entered = threading.Event()
        release = threading.Event()
        created = []

        class _SlowPopen(_FakeProc):
            def __init__(self, *args, **kwargs):
                super().__init__(pid=5150)
                created.append(self)
                entered.set()
                release.wait(5)

        runner = ui.AgentRunner(ui.ConsoleLog())
        start_result = {}
        stop_done = threading.Event()
        stop_thread = None

        def call_stop():
            runner.stop(block=True, timeout=5)
            stop_done.set()

        start_thread = threading.Thread(
            target=lambda: start_result.setdefault(
                "value", runner.start(["fake"], "continuous")))
        with (tempfile.TemporaryDirectory() as state_dir,
              mock.patch.object(
                  ui, "STATE_FILE", Path(state_dir) / "state.json"),
              mock.patch.object(ui.subprocess, "Popen", _SlowPopen)):
            start_thread.start()
            try:
                self.assertTrue(entered.wait(2.0),
                                "start() never reached Popen")
                self.assertEqual(runner.state, ui.STATE_STARTING)
                stop_thread = threading.Thread(target=call_stop)
                stop_thread.start()
                self.assertFalse(
                    stop_done.wait(0.15),
                    "stop() must block while start() holds the lock")
            finally:
                release.set()
            start_thread.join(5)
            stop_thread.join(5)
        self.assertFalse(start_thread.is_alive())
        self.assertFalse(stop_thread.is_alive())
        self.assertTrue(start_result["value"][0])
        self.assertEqual(created[0].signals, [signal.CTRL_BREAK_EVENT])
        self.assertEqual(runner.state, ui.STATE_STOPPED)

    def test_failed_stop_sequence_still_transitions_to_stopped(self):
        runner = ui.AgentRunner(ui.ConsoleLog())
        runner.proc = _UnkillableProc()
        runner.pid = 999
        runner.state = ui.STATE_STOPPING
        runner._stop_requested = True
        with mock.patch.object(ui.subprocess, "run") as run:
            run.return_value.returncode = 1
            runner._stop_sequence()
        self.assertEqual(runner.state, ui.STATE_STOPPED)
        self.assertIsNotNone(runner.stopped_at)
        self.assertEqual(runner.exit_kind, "stop_failed")

    def test_taskkill_spawn_failure_still_transitions_to_stopped(self):
        runner = ui.AgentRunner(ui.ConsoleLog())
        runner.proc = _UnkillableProc()
        runner.pid = 999
        runner.state = ui.STATE_STOPPING
        runner._stop_requested = True
        with mock.patch.object(ui.subprocess, "run",
                               side_effect=OSError("no taskkill")):
            runner._stop_sequence()
        self.assertEqual(runner.state, ui.STATE_STOPPED)
        self.assertEqual(runner.exit_kind, "stop_failed")

    def test_orphan_stop_finally_transitions_on_kill_failure(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        state_file = Path(tmp.name) / "state.json"
        state_file.write_text("{}", encoding="utf-8")
        runner = ui.AgentRunner(ui.ConsoleLog())
        runner.pid = 9001
        runner.started_at = 1.0
        runner.state = ui.STATE_STOPPING
        runner._state_file = state_file
        with mock.patch.object(ui, "process_exists", return_value=True), \
                mock.patch.object(runner, "_orphan_identity_matches",
                                  return_value=True), \
                mock.patch.object(ui.subprocess, "run",
                                  side_effect=OSError("no taskkill")), \
                mock.patch.object(ui, "terminate_pid", return_value=False):
            runner._stop_orphan_inline(1.0)
        self.assertEqual(runner.state, ui.STATE_STOPPED)
        self.assertIsNotNone(runner.stopped_at)
        self.assertEqual(runner.exit_kind, "stop_failed")
        self.assertFalse(state_file.exists())

    def test_orphan_identity_probe_exception_still_transitions(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        state_file = Path(tmp.name) / "state.json"
        state_file.write_text("{}", encoding="utf-8")
        runner = ui.AgentRunner(ui.ConsoleLog())
        runner.pid = 9002
        runner.started_at = 1.0
        runner.state = ui.STATE_STOPPING
        runner._state_file = state_file
        with (mock.patch.object(ui, "process_exists", return_value=True),
              mock.patch.object(runner, "_orphan_identity_matches",
                                side_effect=OSError("probe died")),
              self.assertRaises(OSError)):
            runner._stop_orphan_inline(1.0)
        self.assertEqual(runner.state, ui.STATE_STOPPED)
        self.assertFalse(state_file.exists())

    def test_stale_watch_exit_cannot_clobber_a_new_run(self):
        runner = ui.AgentRunner(ui.ConsoleLog())
        old = _FakeProc(pid=111)
        runner.proc = old
        runner.pid = 111
        runner.state = ui.STATE_RUNNING
        watcher = threading.Thread(target=runner._watch_exit)
        watcher.start()
        self.assertTrue(old.waiting.wait(2.0))
        new = _FakeProc(pid=222)
        with runner._lock:
            runner.proc = new
            runner.pid = 222
            runner.state = ui.STATE_RUNNING
        old.returncode = 0
        old.exited.set()
        watcher.join(2)
        self.assertFalse(watcher.is_alive())
        self.assertEqual(runner.state, ui.STATE_RUNNING)
        self.assertIs(runner.proc, new)
        self.assertIsNone(runner.exit_code)


class ApiLifecycleTests(unittest.TestCase):
    """H9: /api/* start/stop lifecycle, state visibility, and concurrency.

    These exercise the real AgentRunner through Flask rather than the runner
    stub: every child process is a _FakeProc, and STATE_FILE points into a
    temporary directory.
    """

    TOKEN = "unit-test-token-0123456789abcdef"

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.state_file = Path(self.tmp.name) / "state.json"
        state_patch = mock.patch.object(ui, "STATE_FILE", self.state_file)
        state_patch.start()
        self.addCleanup(state_patch.stop)
        self.console = ui.ConsoleLog()
        self.runner = ui.AgentRunner(self.console)
        self.procs: list[_FakeProc] = []

        def factory(argv, **kwargs):
            proc = _FakeProc(pid=6000 + len(self.procs))
            proc.argv = list(argv)
            self.procs.append(proc)
            return proc

        popen_patch = mock.patch.object(
            ui.subprocess, "Popen", side_effect=factory)
        popen_patch.start()
        self.addCleanup(popen_patch.stop)
        self.app = ui.create_app(
            self.runner, self.console, _FakeTailer(), _FakeTailer(),
            _FakeStatus(), get_defaults=_fake_defaults,
            auth_token=self.TOKEN)
        self.app.config["TESTING"] = True

    def tearDown(self):
        # Release every fake child, then drain the runner so watcher threads
        # cannot outlive the test.
        for proc in self.procs:
            if proc.returncode is None:
                proc.returncode = -1
                proc.exited.set()
        with contextlib.suppress(Exception):
            self.runner.stop(block=True, timeout=2)
        if self.runner.state == ui.STATE_STOPPING:
            self.runner._finalize_stop(self.runner.proc)

    def _client(self):
        return self.app.test_client()

    def _headers(self):
        return {"X-Auth-Token": self.TOKEN}

    def _start(self, client=None, **extra):
        payload = {"interval": 30, "force": True}
        payload.update(extra)
        return (client or self._client()).post(
            "/api/start", json=payload, headers=self._headers())

    def _stop(self, client=None):
        return (client or self._client()).post(
            "/api/stop", headers=self._headers())

    def _state(self, client=None):
        return (client or self._client()).get(
            "/api/state", headers=self._headers())

    def _wait_until(self, predicate, timeout=2.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                return True
            time.sleep(0.01)
        return predicate()

    def _wait_state(self, state, timeout=2.0):
        return self._wait_until(
            lambda: self.runner.snapshot()["state"] == state, timeout)

    def test_start_stop_round_trip_clears_state_file(self):
        client = self._client()
        resp = self._start(client)
        self.assertEqual(resp.status_code, 200, resp.get_json())
        self.assertEqual(resp.get_json()["state"], ui.STATE_RUNNING)
        self.assertEqual(resp.get_json()["pid"], 6000)
        self.assertTrue(self.state_file.exists())

        resp = self._stop(client)
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(self._wait_state(ui.STATE_STOPPED))
        self.assertTrue(self._wait_until(lambda: not self.state_file.exists()))
        if ui.ON_WINDOWS:
            self.assertEqual(
                self.procs[0].signals, [signal.CTRL_BREAK_EVENT])

    def test_stop_when_stopped_is_idempotent(self):
        resp = self._stop()
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["state"], ui.STATE_STOPPED)
        self.assertEqual(self.procs, [])

    def test_restart_after_stop_spawns_a_new_child(self):
        client = self._client()
        self.assertEqual(self._start(client).status_code, 200)
        self.assertEqual(self._stop(client).status_code, 200)
        self.assertTrue(self._wait_state(ui.STATE_STOPPED))

        resp = self._start(client)
        self.assertEqual(resp.status_code, 200, resp.get_json())
        self.assertEqual(resp.get_json()["pid"], 6001)
        self.assertEqual(len(self.procs), 2)
        self.assertEqual(self.runner.snapshot()["state"], ui.STATE_RUNNING)

    def test_concurrent_starts_spawn_one_child_and_conflict(self):
        barrier = threading.Barrier(2)
        statuses: list[int] = []

        def call():
            client = self._client()
            barrier.wait(5)
            statuses.append(self._start(client).status_code)

        threads = [threading.Thread(target=call) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(5)

        self.assertEqual(sorted(statuses), [200, 409], statuses)
        self.assertEqual(len(self.procs), 1)
        self.assertEqual(self.runner.snapshot()["state"], ui.STATE_RUNNING)

    def test_concurrent_stops_send_one_signal_and_finish_stopped(self):
        self.assertEqual(self._start().status_code, 200)
        barrier = threading.Barrier(2)
        statuses: list[int] = []

        def call():
            client = self._client()
            barrier.wait(5)
            statuses.append(self._stop(client).status_code)

        threads = [threading.Thread(target=call) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(5)

        self.assertEqual(statuses, [200, 200])
        self.assertTrue(self._wait_state(ui.STATE_STOPPED))
        if ui.ON_WINDOWS:
            signals = sum(
                proc.signals.count(signal.CTRL_BREAK_EVENT)
                for proc in self.procs)
            self.assertEqual(signals, 1)

    def test_start_while_stopping_returns_409_without_spawning(self):
        self.runner.state = ui.STATE_STOPPING
        resp = self._start()
        self.assertEqual(resp.status_code, 409)
        self.assertEqual(resp.get_json()["state"], ui.STATE_STOPPING)
        self.assertEqual(self.procs, [])

    def test_start_holds_state_until_popen_publishes_the_child(self):
        entered = threading.Event()
        release = threading.Event()

        def slow_factory(argv, **kwargs):
            entered.set()
            release.wait(5)
            proc = _FakeProc(pid=7000)
            proc.argv = list(argv)
            self.procs.append(proc)
            return proc

        result = {}

        def call():
            result["resp"] = self._start(self._client())

        with mock.patch.object(
                ui.subprocess, "Popen", side_effect=slow_factory):
            thread = threading.Thread(target=call)
            thread.start()
            try:
                self.assertTrue(entered.wait(2.0))
                # The runner is visibly STARTING while CreateProcess runs; the
                # /api/state route takes the same lock, so it blocks until the
                # child is published and then reports a coherent RUNNING state.
                self.assertEqual(self.runner.state, ui.STATE_STARTING)
            finally:
                release.set()
            thread.join(5)

        self.assertFalse(thread.is_alive())
        self.assertEqual(result["resp"].status_code, 200)
        payload = self._state().get_json()
        self.assertEqual(payload["state"], ui.STATE_RUNNING)
        self.assertEqual(payload["pid"], 7000)

    def test_clean_exit_is_observed_without_a_stop_request(self):
        self.assertEqual(self._start().status_code, 200)
        proc = self.procs[0]
        proc.returncode = 0
        proc.exited.set()

        self.assertTrue(self._wait_state(ui.STATE_STOPPED))
        payload = self._state().get_json()
        self.assertEqual(payload["exit_code"], 0)
        self.assertEqual(payload["exit_kind"], "clean")
        self.assertFalse(payload["stop_requested"])
        self.assertTrue(self._wait_until(lambda: not self.state_file.exists()))

    def test_crashed_exit_is_reported_as_crashed(self):
        self.assertEqual(self._start().status_code, 200)
        proc = self.procs[0]
        proc.returncode = 3
        proc.exited.set()

        self.assertTrue(self._wait_state(ui.STATE_STOPPED))
        payload = self._state().get_json()
        self.assertEqual(payload["exit_code"], 3)
        self.assertEqual(payload["exit_kind"], "crashed")

    def test_adopted_stop_route_terminates_and_clears_state(self):
        self.state_file.write_text(
            json.dumps({"pid": 8000}), encoding="utf-8")
        with (mock.patch.object(ui, "process_exists", return_value=True),
              mock.patch.object(
                  self.runner, "_orphan_identity_matches", return_value=True),
              mock.patch.object(ui.subprocess, "run") as run):
            run.return_value.returncode = 0
            self.runner.adopt(
                8000, ["python", str(ui.CHECKSTAT_PATH)],
                time.time(), "continuous", state_file=self.state_file)
            resp = self._stop()

            self.assertEqual(resp.status_code, 200)
            self.assertTrue(self._wait_state(ui.STATE_STOPPED))
            self.assertEqual(
                self.runner.snapshot()["exit_kind"], "terminated")
            self.assertTrue(
                self._wait_until(lambda: not self.state_file.exists()))


class ApiLimitTests(unittest.TestCase):
    """U7: request bodies and console responses are hard-limited."""

    TOKEN = "unit-test-token-0123456789abcdef"

    def setUp(self):
        self.console = ui.ConsoleLog()
        self.app = ui.create_app(
            _FakeRunner(), self.console, _FakeTailer(), _FakeTailer(),
            _FakeStatus(), get_defaults=_fake_defaults,
            auth_token=self.TOKEN)
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()
        self.headers = {"X-Auth-Token": self.TOKEN}

    def test_max_content_length_is_configured(self):
        self.assertEqual(self.app.config["MAX_CONTENT_LENGTH"],
                         ui.MAX_CONTENT_LENGTH)
        self.assertEqual(ui.MAX_CONTENT_LENGTH, 64 * 1024)

    def test_oversized_json_body_is_rejected(self):
        body = b"{" + b" " * ui.MAX_CONTENT_LENGTH + b"}"
        resp = self.client.post("/api/start", data=body,
                                content_type="application/json",
                                headers=self.headers)
        self.assertEqual(resp.status_code, 413)
        self.assertEqual(resp.get_json()["error"],
                         "request body too large")

    def test_console_line_limit_is_clamped(self):
        for i in range(ui.CONSOLE_API_MAX_LINES + 200):
            self.console.append("out", f"line {i}")
        resp = self.client.get("/api/console?limit=999999",
                               headers=self.headers)
        payload = resp.get_json()
        self.assertLessEqual(len(payload["lines"]),
                             ui.CONSOLE_API_MAX_LINES)
        self.assertEqual(payload["lines"][-1]["line"],
                         f"line {ui.CONSOLE_API_MAX_LINES + 199}")

    def test_console_default_response_is_byte_bounded(self):
        for _ in range(400):
            self.console.append("out", "y" * ui.CONSOLE_LINE_MAX)
        resp = self.client.get("/api/console", headers=self.headers)
        payload = resp.get_json()
        cost = sum(len(e["line"].encode("utf-8")) + 64
                   for e in payload["lines"])
        self.assertLessEqual(cost, ui.CONSOLE_RESPONSE_MAX_BYTES)
        self.assertGreater(len(payload["lines"]), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
