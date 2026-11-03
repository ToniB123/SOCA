"""Tests for the pre-commit sensitive-data scanner.

Run with:  uv run python -m unittest tests.test_sensitive_scan -v
"""

import getpass
import importlib.util
import re
import sys
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
SCANNER_PATH = REPO_ROOT / "scripts" / "check_sensitive_data.py"
_spec = importlib.util.spec_from_file_location("sensitive_scan", SCANNER_PATH)
assert _spec and _spec.loader
scan = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = scan
_spec.loader.exec_module(scan)


def kinds(path, text):
    return {finding.kind for finding in scan.scan_text(path, text)}


class SensitiveScanTests(unittest.TestCase):
    def test_private_ip_in_source_is_flagged(self):
        self.assertIn("private-ip", kinds("src.py", "host = '10.1.2.3'"))

    def test_private_ip_in_tests_is_allowed(self):
        self.assertNotIn("private-ip", kinds("test_fixture.py", "host = '10.1.2.3'"))

    def test_documentation_ip_is_allowed(self):
        self.assertNotIn("private-ip", kinds("src.py", "host = '192.0.2.10'"))
        self.assertNotIn("private-ip", kinds("src.py", "host = '203.0.113.10'"))

    def test_synthetic_private_ip_is_allowed(self):
        self.assertNotIn("private-ip", kinds("src.py", "host = '10.0.0.5'"))

    def test_token_is_flagged_and_masked(self):
        findings = scan.scan_text("src.py", "token = 'github_pat_" + "A" * 30 + "'")
        self.assertIn("token", {finding.kind for finding in findings})
        self.assertEqual(findings[0].detail, "gith…[redacted]")

    def test_example_email_is_allowed(self):
        self.assertNotIn("email", kinds("src.py", "user@example.com"))

    def test_company_email_is_flagged(self):
        self.assertIn("email", kinds("src.py", "user@corp.local"))

    def test_personal_path_and_name_are_flagged(self):
        with mock.patch.object(
            scan, "USERNAME_RE", re.compile(r"\bcaseuser\b", re.IGNORECASE)
        ):
            found = kinds("src.py", "C:\\Users\\caseuser\\secret.txt")
        self.assertIn("personal-path", found)
        self.assertIn("personal-username", found)

    def test_username_pattern_tracks_runtime_user(self):
        name = getpass.getuser()
        if not name or name.lower() in scan.USERNAME_ALLOW:
            self.skipTest("no operator-specific username")
        self.assertIn("personal-username", kinds("src.py", f"owner={name}"))

    def test_public_path_is_allowed(self):
        self.assertNotIn(
            "personal-path", kinds("src.py", "C:\\Users\\Public\\file.txt")
        )

    def test_local_only_files(self):
        self.assertTrue(scan._is_local_only("netstat_baseline_rules.yaml"))
        self.assertTrue(scan._is_local_only("soc_findings.jsonl"))
        self.assertTrue(scan._is_local_only("CODE_REVIEW.md"))
        self.assertFalse(scan._is_local_only("netstat_baseline_rules.example.yaml"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
