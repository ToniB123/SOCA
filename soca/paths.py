"""Filesystem locations for the SOCA application.

One source of truth for the package, config, runtime data, and static paths.
Consumers keep module-level aliases so tests can patch them; functions resolve
paths at call time rather than binding them in signature defaults.
"""

from __future__ import annotations

import os
from pathlib import Path

PACKAGE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = PACKAGE_DIR.parent


def _resolve_dir(env_name: str, default: Path) -> Path:
    raw = os.environ.get(env_name, "").strip()
    if raw:
        candidate = Path(raw).expanduser()
        if not candidate.is_absolute():
            candidate = PROJECT_ROOT / candidate
        return candidate.resolve()
    return default.resolve()


CONFIG_DIR = _resolve_dir("SOCA_CONFIG_DIR", PROJECT_ROOT / "config")
DATA_DIR = _resolve_dir("SOCA_DATA_DIR", PROJECT_ROOT / "data")
STATIC_DIR = PACKAGE_DIR / "ui" / "static"

DEFAULT_RULES_FILE = CONFIG_DIR / "netstat_baseline_rules.yaml"
EXAMPLE_RULES_FILE = CONFIG_DIR / "netstat_baseline_rules.example.yaml"

DEFAULT_LOG_FILE = DATA_DIR / "local_soc_agent.log"
DEFAULT_SNAPSHOT_LOG = DATA_DIR / "netstat_snapshot.log"
DEFAULT_FINDINGS_LOG = DATA_DIR / "soc_findings.jsonl"
DEFAULT_TRAFFIC_HISTORY = DATA_DIR / "soc_traffic_history.jsonl"
DEFAULT_VERDICT_CACHE = DATA_DIR / "soc_verdict_cache.json"
DEFAULT_INTEL_CACHE = DATA_DIR / "soc_intel_cache.json"
DEFAULT_ALLOWLIST_FILE = DATA_DIR / "soc_user_allowlist.json"
DEFAULT_STATE_FILE = DATA_DIR / "soc_ui_agent_state.json"
DEFAULT_NETWORK_HEALTH_FILE = DATA_DIR / "soc_network_health.json"


def ensure_data_dir() -> Path:
    """Create the runtime data directory if needed and return it."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    return DATA_DIR
