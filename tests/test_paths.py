"""Tests for the shared filesystem paths module."""

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from soca import paths


class PathsTests(unittest.TestCase):
    def test_project_layout_defaults(self):
        self.assertEqual(paths.PROJECT_ROOT, paths.PACKAGE_DIR.parent)
        self.assertEqual(paths.PACKAGE_DIR.name, "soca")
        self.assertTrue((paths.PROJECT_ROOT / "pyproject.toml").is_file())
        self.assertTrue(paths.CONFIG_DIR.is_absolute())
        self.assertTrue(paths.DATA_DIR.is_absolute())
        self.assertEqual(paths.STATIC_DIR.name, "static")
        self.assertEqual(
            paths.DEFAULT_RULES_FILE.name, "netstat_baseline_rules.yaml"
        )

    def test_relative_env_override_anchors_at_project_root(self):
        with mock.patch.dict(os.environ, {"SOCA_DATA_DIR": "var/data"}):
            resolved = paths._resolve_dir(
                "SOCA_DATA_DIR", paths.PROJECT_ROOT / "data"
            )
        self.assertEqual(
            resolved, (paths.PROJECT_ROOT / "var" / "data").resolve()
        )

    def test_ensure_data_dir_is_idempotent(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "data"
            with mock.patch.object(paths, "DATA_DIR", target):
                self.assertEqual(paths.ensure_data_dir(), target)
                self.assertTrue(target.is_dir())
                self.assertEqual(paths.ensure_data_dir(), target)


if __name__ == "__main__":
    unittest.main(verbosity=2)
