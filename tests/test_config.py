#!/usr/bin/env python3
"""Tests for the shared config loader (panoptes/config.py).

Covers:
  - Defaults returned when no config file exists
  - Deep merge: nested overrides keep sibling defaults
  - Lists and scalars replace wholesale (no list append)
  - Unknown user keys preserved
  - ConfigError on unparseable YAML and non-mapping files
  - Defaults are not mutated by callers
"""

import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from panoptes import ConfigError, load_config
from panoptes.config import DEFAULT_CONFIG


def _write(tmpdir: str, content: str) -> str:
    path = os.path.join(tmpdir, "config.yaml")
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    return path


def test_missing_file_returns_defaults():
    """A nonexistent path yields the built-in defaults."""
    print("--- test_missing_file_returns_defaults ---")

    cfg = load_config("/nonexistent/panoptes/config.yaml")
    assert cfg == DEFAULT_CONFIG
    assert cfg["alerts"]["min_severity"] == "warning"
    assert cfg["dashboard"]["port"] == 8420
    print("  PASSED")


def test_deep_merge_keeps_sibling_defaults():
    """Overriding one nested key keeps the rest of that section intact."""
    print("--- test_deep_merge_keeps_sibling_defaults ---")

    with tempfile.TemporaryDirectory() as tmpdir:
        path = _write(tmpdir, "trust:\n  decay_half_life_hours: 48\n")
        cfg = load_config(path)

        assert cfg["trust"]["decay_half_life_hours"] == 48
        # Siblings untouched
        assert cfg["trust"]["learning_min_sessions"] == 20
        assert cfg["trust"]["deductions"]["policy_block"] == 10
        # Other sections untouched
        assert cfg["alerts"]["min_severity"] == "warning"
    print("  PASSED")


def test_lists_replace_wholesale():
    """A user sink list replaces the default sinks, not appends."""
    print("--- test_lists_replace_wholesale ---")

    with tempfile.TemporaryDirectory() as tmpdir:
        path = _write(tmpdir, (
            "alerts:\n"
            "  sinks:\n"
            "    - type: webhook\n"
            "      url: https://hooks.example.com/x\n"
        ))
        cfg = load_config(path)

        assert cfg["alerts"]["sinks"] == [
            {"type": "webhook", "url": "https://hooks.example.com/x"}
        ]
        # Sibling key from defaults still present
        assert cfg["alerts"]["dedup_window_minutes"] == 10
    print("  PASSED")


def test_unknown_keys_preserved():
    """Sections/keys panoptes doesn't know about survive the merge."""
    print("--- test_unknown_keys_preserved ---")

    with tempfile.TemporaryDirectory() as tmpdir:
        path = _write(tmpdir, "my_custom_section:\n  foo: 1\ntrust:\n  custom_flag: true\n")
        cfg = load_config(path)

        assert cfg["my_custom_section"] == {"foo": 1}
        assert cfg["trust"]["custom_flag"] is True
        assert cfg["trust"]["learning_min_days"] == 7
    print("  PASSED")


def test_empty_file_returns_defaults():
    """An empty (or comments-only) config file behaves like no file."""
    print("--- test_empty_file_returns_defaults ---")

    with tempfile.TemporaryDirectory() as tmpdir:
        path = _write(tmpdir, "# nothing here yet\n")
        cfg = load_config(path)
        assert cfg == DEFAULT_CONFIG
    print("  PASSED")


def test_config_error_on_bad_yaml():
    """Unparseable YAML raises ConfigError instead of silently using defaults."""
    print("--- test_config_error_on_bad_yaml ---")

    with tempfile.TemporaryDirectory() as tmpdir:
        path = _write(tmpdir, "alerts: [unclosed\n  nope: :\n")
        try:
            load_config(path)
            assert False, "Expected ConfigError"
        except ConfigError:
            pass
    print("  PASSED")


def test_config_error_on_non_mapping():
    """A YAML file whose root isn't a mapping raises ConfigError."""
    print("--- test_config_error_on_non_mapping ---")

    with tempfile.TemporaryDirectory() as tmpdir:
        path = _write(tmpdir, "- just\n- a\n- list\n")
        try:
            load_config(path)
            assert False, "Expected ConfigError"
        except ConfigError:
            pass
    print("  PASSED")


def test_defaults_not_mutated():
    """Mutating a loaded config never leaks into DEFAULT_CONFIG."""
    print("--- test_defaults_not_mutated ---")

    cfg = load_config("/nonexistent/panoptes/config.yaml")
    cfg["alerts"]["min_severity"] = "critical"
    cfg["trust"]["deductions"]["policy_block"] = 999

    fresh = load_config("/nonexistent/panoptes/config.yaml")
    assert fresh["alerts"]["min_severity"] == "warning"
    assert fresh["trust"]["deductions"]["policy_block"] == 10
    print("  PASSED")


if __name__ == "__main__":
    test_missing_file_returns_defaults()
    test_deep_merge_keeps_sibling_defaults()
    test_lists_replace_wholesale()
    test_unknown_keys_preserved()
    test_empty_file_returns_defaults()
    test_config_error_on_bad_yaml()
    test_config_error_on_non_mapping()
    test_defaults_not_mutated()
    print("\n=== ALL CONFIG TESTS PASSED ===")
