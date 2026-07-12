"""
Shared configuration for panoptes layers (trust, compliance, dashboard).

Reads ~/.panoptes/config.yaml and deep-merges it over built-in defaults, so a
user config only needs to state what it changes. Unknown keys are preserved —
individual layers own the meaning of their own sections.
"""

import copy
import os
from typing import Any, Dict, Optional

import yaml

DEFAULT_CONFIG_PATH = "~/.panoptes/config.yaml"

# Built-in defaults. Layers read their own section; everything here must be
# safe with no config file present at all.
DEFAULT_CONFIG: Dict[str, Any] = {
    "alerts": {
        "min_severity": "warning",      # info | warning | critical
        "dedup_window_minutes": 10,
        "sinks": [
            {"type": "stderr"},
        ],
    },
    "trust": {
        "learning_min_sessions": 20,
        "learning_min_days": 7,
        "decay_half_life_hours": 24,
        "deductions": {
            "policy_warn": 3,
            "policy_block": 10,
            "tool_error": 1,
            "tool_error_session_cap": 10,
            "novel_pair": 8,
            "drift_metric": 5,
            "sensitive_burst": 6,
        },
        "drift_z_threshold": 3.0,
    },
    "dashboard": {
        "host": "127.0.0.1",
        "port": 8420,
        "token": None,
    },
}


class ConfigError(Exception):
    """Raised when the config file exists but cannot be parsed."""
    pass


def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    """Return a new dict with *override* recursively merged over *base*.

    Dicts merge key-by-key; any other type (including lists) replaces the
    base value wholesale — a user overriding `alerts.sinks` replaces the
    default sink list rather than appending to it.

    The result shares no structure with *base*, so callers can mutate it
    without corrupting DEFAULT_CONFIG.
    """
    merged = {k: copy.deepcopy(v) for k, v in base.items()}
    for key, value in override.items():
        if (
            key in merged
            and isinstance(merged[key], dict)
            and isinstance(value, dict)
        ):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = copy.deepcopy(value)
    return merged


def load_config(path: Optional[str] = None) -> Dict[str, Any]:
    """Load config from *path* (default ~/.panoptes/config.yaml).

    A missing file returns the defaults. An unreadable or non-mapping file
    raises ConfigError — a config the user wrote but that isn't taking effect
    is worse than a hard error.
    """
    path = os.path.expanduser(path or DEFAULT_CONFIG_PATH)
    if not os.path.exists(path):
        return _deep_merge(DEFAULT_CONFIG, {})

    try:
        with open(path, "r", encoding="utf-8") as f:
            loaded = yaml.safe_load(f)
    except yaml.YAMLError as exc:
        raise ConfigError(f"Failed to parse {path}: {exc}") from exc

    if loaded is None:
        return _deep_merge(DEFAULT_CONFIG, {})
    if not isinstance(loaded, dict):
        raise ConfigError(
            f"{path} must contain a YAML mapping, got {type(loaded).__name__}"
        )
    return _deep_merge(DEFAULT_CONFIG, loaded)
