"""Validate the sanitized baseline example used by a clean clone.

Run with:  uv run python -m unittest tests.test_baseline_example -v
"""

import unittest
from pathlib import Path

import yaml

from soca.agent import checkstat as soc
from soca.ui import soc_ui as ui

REPO_ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = REPO_ROOT / "config" / "netstat_baseline_rules.example.yaml"


class BaselineExampleTests(unittest.TestCase):
    def test_example_loads_and_validates(self):
        rules = soc.load_rules(EXAMPLE)
        self.assertIsInstance(rules, dict)
        self.assertTrue(rules["anomaly_rules"])
        self.assertIsNone(ui.validate_rules_document(EXAMPLE))

    def test_example_has_no_host_specific_values(self):
        doc = yaml.safe_load(EXAMPLE.read_text(encoding="utf-8"))
        self.assertEqual(doc["baseline"]["system_pids"], [4])
        self.assertEqual(doc["baseline"]["application_ports"], [11434])
        self.assertEqual(doc["observed_legitimate_pids"], [])
        self.assertEqual(doc["trusted_remote_networks"], [])
        text = EXAMPLE.read_text(encoding="utf-8")
        for marker in (
            "appeared at",
            "observed in this host",
            "from baseline log",
            "from observed data",
        ):
            self.assertNotIn(marker, text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
