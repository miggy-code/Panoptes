#!/usr/bin/env python3
"""Comprehensive tests for the panoptes policy engine.

Covers:
  - Policy loading from YAML
  - Basic condition matching (==, !=, contains, in, matches)
  - Boolean logic (AND, OR)
  - Policy violation recording to DB
  - Scope filtering (only applies to specified agents)
  - Disabled policies are skipped
  - Malformed YAML is handled gracefully
  - Missing policies directory is handled gracefully
  - Numeric comparisons (gt, lt, gte, lte)
"""

import json
import os
import tempfile

import pytest

from panoptes.db import AuditDB
import panoptes.policy as policy_module
from panoptes.policy import (
    MAX_POLICY_REASON_LENGTH,
    POLICY_ENGINE_SEMANTICS_VERSION,
    Policy,
    PolicyEngine,
    PolicyResult,
)


def _make_event(**overrides):
    """Build a minimal valid event dict for testing."""
    base = {
        "event_id": "test-evt-001",
        "timestamp": "2026-07-05T10:00:00.000Z",
        "agent": {
            "type": "hermes",
            "session_id": "sess-001",
            "run_id": "run-001",
        },
        "event_type": "tool_call",
        "action": {
            "tool_name": "terminal",
            "parameters": {"command": "ls -la"},
            "target": None,
            "data_accessed": [],
        },
        "outcome": {"status": "success", "summary": "ok"},
        "context": {"turn_number": 1},
        "cost": {"tokens_in": 100, "tokens_out": 50},
    }
    base.update(overrides)
    return base


# ── Policy loading tests ──────────────────────────────────────────────────────


def test_load_policies_from_yaml():
    """Policies are loaded from YAML files in a directory."""

    with tempfile.TemporaryDirectory() as tmpdir:
        # Write a valid policy
        policy_yaml = """
name: "test-policy"
description: "A test policy"
enabled: true
scope:
  agents: ["hermes", "claude_code"]
rule:
  event_type: "tool_call"
  conditions:
    - field: "action.tool_name"
      operator: "=="
      value: "terminal"
  logic: "AND"
action: warn
message: "Watch out for terminal use"
"""
        policy_path = os.path.join(tmpdir, "test-policy.yaml")
        with open(policy_path, "w") as f:
            f.write(policy_yaml)

        engine = PolicyEngine(policies_dir=tmpdir)
        assert len(engine.policies) == 1
        p = engine.policies[0]
        assert p.name == "test-policy"
        assert p.description == "A test policy"
        assert p.enabled is True
        assert p.action == "warn"
        assert p.message == "Watch out for terminal use"
        assert p.scope["agents"] == ["hermes", "claude_code"]


def test_load_multiple_policies():
    """Multiple YAML files are all loaded."""

    with tempfile.TemporaryDirectory() as tmpdir:
        for i in range(3):
            yaml_str = f"""
name: "policy-{i}"
enabled: true
action: warn
rule:
  conditions: []
"""
            path = os.path.join(tmpdir, f"policy-{i}.yaml")
            with open(path, "w") as f:
                f.write(yaml_str)

        engine = PolicyEngine(policies_dir=tmpdir)
        assert len(engine.policies) == 3
        names = {p.name for p in engine.policies}
        assert names == {"policy-0", "policy-1", "policy-2"}


def test_missing_policies_dir():
    """Missing policy storage is explicit and respects failure mode."""

    opened = PolicyEngine(
        policies_dir="/nonexistent/path/to/policies",
        failure_mode="fail_open",
    )
    closed = PolicyEngine(
        policies_dir="/nonexistent/path/to/policies",
        failure_mode="fail_closed",
    )

    opened_result = opened.evaluate(_make_event())
    closed_result = closed.evaluate(_make_event())

    assert opened.policies == []
    assert opened_result.action == "allow"
    assert opened_result.evaluation_errors
    assert closed_result.action == "block"
    assert closed_result.evaluation_errors


def test_malformed_yaml_skipped():
    """A partial candidate never replaces or becomes an active snapshot."""

    with tempfile.TemporaryDirectory() as tmpdir:
        # Write a malformed YAML file
        bad_path = os.path.join(tmpdir, "bad.yaml")
        with open(bad_path, "w") as f:
            f.write("this is not: valid: yaml: [unclosed\n")

        # Write a valid one too
        good_path = os.path.join(tmpdir, "good.yaml")
        with open(good_path, "w") as f:
            f.write("name: good-policy\nenabled: true\naction: warn\nrule:\n  conditions: []\n")

        engine = PolicyEngine(policies_dir=tmpdir, failure_mode="fail_open")
        result = engine.evaluate(_make_event())

        assert engine.policies == []
        assert engine.load_errors
        assert result.action == "allow"
        assert result.evaluation_errors


def test_non_yaml_files_skipped():
    """Non-YAML files in the directory are ignored."""

    with tempfile.TemporaryDirectory() as tmpdir:
        # Write a .txt file
        txt_path = os.path.join(tmpdir, "notes.txt")
        with open(txt_path, "w") as f:
            f.write("not a policy")

        engine = PolicyEngine(policies_dir=tmpdir)
        assert len(engine.policies) == 0


def test_non_dict_yaml_skipped():
    """YAML file that doesn't parse to a dict is skipped."""

    with tempfile.TemporaryDirectory() as tmpdir:
        # Write a YAML file that's a list, not a dict
        list_path = os.path.join(tmpdir, "list.yaml")
        with open(list_path, "w") as f:
            f.write("- item: 1\n- item: 2\n")

        engine = PolicyEngine(policies_dir=tmpdir)
        assert len(engine.policies) == 0


def test_empty_policy_dir_has_no_valid_snapshot():
    with tempfile.TemporaryDirectory() as tmpdir:
        opened = PolicyEngine(tmpdir, failure_mode="fail_open")
        closed = PolicyEngine(tmpdir, failure_mode="fail_closed")

        opened_result = opened.evaluate(_make_event())
        closed_result = closed.evaluate(_make_event())

        assert opened_result.action == "allow"
        assert opened_result.evaluation_errors
        assert closed_result.action == "block"
        assert closed_result.evaluation_errors
        assert opened.policy_snapshot_id is None
        assert closed.policy_snapshot_id is None


def test_invalid_event_respects_failure_mode_before_policy_evaluation():
    with tempfile.TemporaryDirectory() as tmpdir:
        with open(
            os.path.join(tmpdir, "always.yaml"), "w", encoding="utf-8"
        ) as f:
            f.write(
                "name: always\n"
                "action: warn\n"
                "rule:\n"
                "  conditions: []\n"
            )
        invalid = _make_event(action={
            "tool_name": None,
            "parameters": {},
            "data_accessed": [],
        })

        opened = PolicyEngine(tmpdir, failure_mode="fail_open").evaluate(invalid)
        closed = PolicyEngine(tmpdir, failure_mode="fail_closed").evaluate(invalid)

        assert opened.action == "allow"
        assert opened.evaluation_errors
        assert closed.action == "block"
        assert closed.evaluation_errors


def test_unreadable_policy_dir_respects_failure_mode(monkeypatch):
    with tempfile.TemporaryDirectory() as tmpdir:
        original_listdir = os.listdir

        def deny_policy_directory(path):
            if os.fspath(path) == tmpdir:
                raise PermissionError("test denied")
            return original_listdir(path)

        monkeypatch.setattr("panoptes.policy.os.listdir", deny_policy_directory)

        opened = PolicyEngine(tmpdir, failure_mode="fail_open")
        closed = PolicyEngine(tmpdir, failure_mode="fail_closed")

        assert opened.evaluate(_make_event()).action == "allow"
        assert opened.load_errors
        assert closed.evaluate(_make_event()).action == "block"
        assert closed.load_errors


def test_failed_explicit_load_retains_active_snapshot():
    with tempfile.TemporaryDirectory() as tmpdir:
        policy_path = os.path.join(tmpdir, "block.yaml")
        with open(policy_path, "w", encoding="utf-8") as f:
            f.write(
                "name: block-terminal\n"
                "action: block\n"
                "rule:\n"
                "  event_type: tool_call\n"
                "  conditions:\n"
                "    - field: action.tool_name\n"
                "      operator: ==\n"
                "      value: terminal\n"
            )

        engine = PolicyEngine(tmpdir, failure_mode="fail_closed")
        original_snapshot = engine._snapshot
        original_policy = engine.policies[0]
        original_snapshot_id = engine.policy_snapshot_id
        assert engine.evaluate(_make_event()).action == "block"

        with open(policy_path, "w", encoding="utf-8") as f:
            f.write("name: [unterminated\n")
        engine.load_policies()

        assert engine._snapshot is original_snapshot
        assert engine.policies[0] is original_policy
        assert engine.policy_snapshot_id == original_snapshot_id
        assert engine.load_errors

        blocked = engine.evaluate(_make_event())
        safe = engine.evaluate(
            _make_event(
                action={
                    "tool_name": "read_file",
                    "parameters": {},
                    "data_accessed": [],
                }
            )
        )
        assert blocked.action == "block"
        assert blocked.policy_snapshot_id == original_snapshot_id
        assert blocked.evaluation_errors
        assert safe.action == "allow"
        assert safe.evaluation_errors


# ── Condition matching tests ──────────────────────────────────────────────────


@pytest.mark.parametrize(
    "operator,field,expected,matching,nonmatching",
    [
        ("==", "action.tool_name", "terminal", "terminal", "read_file"),
        ("!=", "action.tool_name", "read_file", "terminal", "read_file"),
        ("contains", "outcome.summary", "error", "error: file not found", "ok"),
        ("contains", "action.data_accessed", "prod", ["prod", "config"], ["dev"]),
        ("in", "action.tool_name", ["terminal", "write_file"], "terminal", "read_file"),
        ("matches", "action.tool_name", r"^write_", "write_file", "read_file"),
        ("gt", "cost.tokens_in", 1000, 2000, 1000),
        ("lt", "cost.tokens_in", 1000, 500, 1000),
        ("gte", "cost.tokens_in", 1000, 1000, 500),
        ("lte", "cost.tokens_out", 100, 100, 200),
    ],
)
def test_condition_operators(operator, field, expected, matching, nonmatching):
    policy = Policy({
        "name": "operator-test",
        "action": "warn",
        "rule": {"conditions": [{"field": field, "operator": operator, "value": expected}]},
    })
    section, key = field.split(".")
    for value, expected_match in ((matching, True), (nonmatching, False)):
        event = _make_event()
        event[section][key] = value
        matched, _ = policy.evaluate_conditions(event)
        assert matched is expected_match


@pytest.mark.parametrize(
    "pattern",
    [
        r"(a+)+$",
        r"a|b",
        r"a{1,3}",
        r"a+b+",
        r"a+b",
        "a" * 257,
    ],
)
def test_matches_rejects_unsafe_or_unbounded_regexes(pattern):
    with pytest.raises(ValueError, match="regex|unsupported|quantifier"):
        Policy({
            "name": "unsafe-regex",
            "action": "block",
            "rule": {
                "conditions": [{
                    "field": "action.tool_name",
                    "operator": "matches",
                    "value": pattern,
                }],
            },
        })


def test_matches_allows_escaped_quantifier_literal():
    policy = Policy({
        "name": "escaped-literal",
        "action": "warn",
        "rule": {
            "conditions": [{
                "field": "action.tool_name",
                "operator": "matches",
                "value": r"^write\+file$",
            }],
        },
    })

    matched, _ = policy.evaluate_conditions(
        _make_event(action={
            "tool_name": "write+file",
            "parameters": {},
            "data_accessed": [],
        })
    )
    assert matched


def test_policy_reason_is_redacted_and_bounded():
    secret = "sk-" + ("A" * 40)
    policy = Policy({
        "name": "bounded-reason",
        "action": "warn",
        "rule": {
            "conditions": [{
                "field": "action.parameters.command",
                "operator": "contains",
                "value": "deploy",
            }],
        },
    })
    event = _make_event(action={
        "tool_name": "terminal",
        "parameters": {
            "command": f"deploy api_key={secret} " + ("x" * 10_000),
        },
        "data_accessed": [],
    })

    matched, reason = policy.evaluate_conditions(event)

    assert matched
    assert secret not in reason
    assert "[REDACTED]" in reason
    assert len(reason) <= MAX_POLICY_REASON_LENGTH


def test_policy_reason_uses_key_aware_redaction_for_short_secrets():
    policy = Policy({
        "name": "structured-secret",
        "action": "warn",
        "rule": {
            "conditions": [{
                "field": "action.parameters",
                "operator": "==",
                "value": {"password": "tiny-secret"},
            }],
        },
    })
    matched, reason = policy.evaluate_conditions(_make_event(action={
        "tool_name": "terminal",
        "parameters": {"password": "tiny-secret"},
        "data_accessed": [],
    }))

    assert matched
    assert "tiny-secret" not in reason
    assert "[REDACTED]" in reason


# ── Boolean logic tests ───────────────────────────────────────────────────────


def test_logic_and():
    """AND logic: all conditions must match."""

    raw = {
        "name": "and-test",
        "enabled": True,
        "action": "warn",
        "rule": {
            "conditions": [
                {"field": "action.tool_name", "operator": "==", "value": "terminal"},
                {"field": "action.data_accessed", "operator": "contains", "value": "prod"},
            ],
            "logic": "AND",
        },
    }
    policy = Policy(raw)

    # Both match
    event = _make_event(action={
        "tool_name": "terminal",
        "parameters": {},
        "data_accessed": ["prod"],
    })
    matched, _ = policy.evaluate_conditions(event)
    assert matched, "Both conditions should match"

    # Only one matches
    event2 = _make_event(action={
        "tool_name": "terminal",
        "parameters": {},
        "data_accessed": ["dev"],
    })
    matched2, _ = policy.evaluate_conditions(event2)
    assert not matched2, "Only one condition matches, AND should fail"

    # Neither matches
    event3 = _make_event(action={
        "tool_name": "read_file",
        "parameters": {},
        "data_accessed": ["dev"],
    })
    matched3, _ = policy.evaluate_conditions(event3)
    assert not matched3, "Neither matches"


def test_logic_or():
    """OR logic: any condition can match."""

    raw = {
        "name": "or-test",
        "enabled": True,
        "action": "warn",
        "rule": {
            "conditions": [
                {"field": "action.tool_name", "operator": "==", "value": "terminal"},
                {"field": "action.tool_name", "operator": "==", "value": "browser_navigate"},
            ],
            "logic": "OR",
        },
    }
    policy = Policy(raw)

    event = _make_event(action={"tool_name": "terminal", "parameters": {}, "data_accessed": []})
    matched, _ = policy.evaluate_conditions(event)
    assert matched, "terminal matches first condition"

    event2 = _make_event(action={"tool_name": "browser_navigate", "parameters": {}, "data_accessed": []})
    matched2, _ = policy.evaluate_conditions(event2)
    assert matched2, "browser_navigate matches second condition"

    event3 = _make_event(action={"tool_name": "read_file", "parameters": {}, "data_accessed": []})
    matched3, _ = policy.evaluate_conditions(event3)
    assert not matched3, "read_file matches neither"


# ── Scope filtering tests ─────────────────────────────────────────────────────


def test_scope_agent_filter():
    """Scope with specific agents only applies to those agents."""

    raw = {
        "name": "scope-test",
        "enabled": True,
        "action": "warn",
        "scope": {"agents": ["hermes", "claude_code"]},
        "rule": {"conditions": [], "logic": "AND"},
    }
    policy = Policy(raw)

    # Hermes event should match scope
    event_h = _make_event(agent={"type": "hermes", "session_id": "s1", "run_id": "r1"})
    assert policy.matches_scope(event_h), "hermes should be in scope"

    # Claude Code should match scope
    event_c = _make_event(agent={"type": "claude_code", "session_id": "s2", "run_id": "r2"})
    assert policy.matches_scope(event_c), "claude_code should be in scope"

    # Codex should NOT match scope
    event_x = _make_event(agent={"type": "codex", "session_id": "s3", "run_id": "r3"})
    assert not policy.matches_scope(event_x), "codex should NOT be in scope"


def test_scope_wildcard():
    """Scope with ['*'] applies to all agents."""

    raw = {
        "name": "wildcard-test",
        "enabled": True,
        "action": "warn",
        "scope": {"agents": ["*"]},
        "rule": {"conditions": [], "logic": "AND"},
    }
    policy = Policy(raw)

    event_h = _make_event(agent={"type": "hermes", "session_id": "s1", "run_id": "r1"})
    assert policy.matches_scope(event_h), "hermes should match *"

    event_x = _make_event(agent={"type": "codex", "session_id": "s2", "run_id": "r2"})
    assert policy.matches_scope(event_x), "codex should match *"

    event_u = _make_event(agent={"type": "unknown", "session_id": "s3", "run_id": "r3"})
    assert policy.matches_scope(event_u), "unknown should match *"


def test_scope_rejects_wildcard_mixed_with_named_agents():
    with pytest.raises(ValueError, match="wildcard.*only entry"):
        Policy({
            "name": "ambiguous-scope",
            "action": "block",
            "scope": {"agents": ["*", "hermes"]},
            "rule": {"conditions": []},
        })


def test_scope_session_filter():
    """Scope with session list only applies to those sessions."""

    raw = {
        "name": "session-scope-test",
        "enabled": True,
        "action": "warn",
        "scope": {"agents": ["*"], "sessions": ["sess-a", "sess-b"]},
        "rule": {"conditions": [], "logic": "AND"},
    }
    policy = Policy(raw)

    event_a = _make_event(agent={"type": "hermes", "session_id": "sess-a", "run_id": "r1"})
    assert policy.matches_scope(event_a), "sess-a should match"

    event_c = _make_event(agent={"type": "hermes", "session_id": "sess-c", "run_id": "r2"})
    assert not policy.matches_scope(event_c), "sess-c should NOT match"


# ── Disabled policies ─────────────────────────────────────────────────────────


def test_disabled_policy_skipped():
    """Disabled policies are skipped during evaluation."""

    with tempfile.TemporaryDirectory() as tmpdir:
        # Write a disabled policy
        yaml_str = """
name: "disabled-policy"
enabled: false
action: block
rule:
  conditions: []
  logic: "AND"
"""
        path = os.path.join(tmpdir, "disabled.yaml")
        with open(path, "w") as f:
            f.write(yaml_str)

        engine = PolicyEngine(policies_dir=tmpdir)
        assert len(engine.policies) == 1
        assert engine.policies[0].enabled is False

        event = _make_event()
        result = engine.evaluate(event)
        assert result.action == "allow", "Disabled policy should not block"
        assert len(result.violated_policies) == 0


# ── Snapshot immutability tests ───────────────────────────────────────────────────────


def test_compatibility_policy_list_cannot_mutate_active_snapshot():
    with tempfile.TemporaryDirectory() as tmpdir:
        with open(
            os.path.join(tmpdir, "block.yaml"), "w", encoding="utf-8"
        ) as f:
            f.write(
                "name: immutable\n"
                "action: block\n"
                "rule:\n"
                "  conditions: []\n"
            )

        engine = PolicyEngine(tmpdir)
        assert engine.evaluate(_make_event()).action == "block"

        engine.policies[0].action = "allow"
        engine.policies[0].rule["conditions"] = [
            {"field": "action.tool_name", "operator": "==", "value": "never"}
        ]

        assert engine.evaluate(_make_event()).action == "block"


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_numeric_policy_threshold_must_be_finite(value):
    with pytest.raises(ValueError, match="finite"):
        Policy({
            "name": "finite-threshold",
            "action": "block",
            "rule": {
                "conditions": [{
                    "field": "cost.tokens_in",
                    "operator": "gt",
                    "value": value,
                }],
            },
        })


def test_numeric_policy_threshold_rejects_bool():
    with pytest.raises(ValueError, match="must be numeric"):
        Policy({
            "name": "bool-threshold",
            "action": "block",
            "rule": {
                "conditions": [{
                    "field": "cost.tokens_in",
                    "operator": "gt",
                    "value": True,
                }],
            },
        })


def test_numeric_comparison_handles_huge_integer_without_float_overflow():
    policy = Policy({
        "name": "huge-number",
        "action": "block",
        "rule": {
            "conditions": [{
                "field": "cost.tokens_in",
                "operator": "gt",
                "value": 10,
            }],
        },
    })
    matched, reason = policy.evaluate_conditions(_make_event(cost={
        "tokens_in": 1 << 4095,
        "tokens_out": 0,
    }))

    assert matched
    assert "cost.tokens_in gt" in reason


@pytest.mark.parametrize("actual", [True, False, float("inf"), float("nan")])
def test_numeric_comparison_does_not_coerce_bool_or_nonfinite_actual(actual):
    policy = Policy({
        "name": "strict-number",
        "action": "warn",
        "rule": {
            "conditions": [{
                "field": "action.parameters.value",
                "operator": "gte",
                "value": 1,
            }],
        },
    })
    matched, reason = policy.evaluate_conditions(_make_event(action={
        "tool_name": "terminal",
        "parameters": {"value": actual},
        "data_accessed": [],
    }))

    assert not matched
    assert "not a finite numeric value" in reason


def test_policy_semantics_version_participates_in_snapshot_digest(monkeypatch):
    with tempfile.TemporaryDirectory() as tmpdir:
        with open(
            os.path.join(tmpdir, "policy.yaml"), "w", encoding="utf-8"
        ) as f:
            f.write(
                "name: semantics\n"
                "action: allow\n"
                "rule:\n"
                "  conditions: []\n"
            )

        first = PolicyEngine(tmpdir)
        monkeypatch.setattr(
            policy_module,
            "POLICY_ENGINE_SEMANTICS_VERSION",
            POLICY_ENGINE_SEMANTICS_VERSION + 1,
        )
        second = PolicyEngine(tmpdir)

        assert first.policy_snapshot_id != second.policy_snapshot_id


def test_action_escalation():
    """Block > warn > allow escalation."""

    with tempfile.TemporaryDirectory() as tmpdir:
        # Policy 1: warn
        yaml1 = """
name: "warn-policy"
enabled: true
action: warn
rule:
  conditions:
    - field: "action.tool_name"
      operator: "=="
      value: "terminal"
  logic: "AND"
"""
        path1 = os.path.join(tmpdir, "warn.yaml")
        with open(path1, "w") as f:
            f.write(yaml1)

        # Policy 2: block
        yaml2 = """
name: "block-policy"
enabled: true
action: block
rule:
  conditions:
    - field: "action.tool_name"
      operator: "=="
      value: "terminal"
  logic: "AND"
"""
        path2 = os.path.join(tmpdir, "block.yaml")
        with open(path2, "w") as f:
            f.write(yaml2)

        engine = PolicyEngine(policies_dir=tmpdir)
        event = _make_event()

        result = engine.evaluate(event)
        # Block should win over warn
        assert result.action == "block", f"Expected block, got {result.action}"
        assert len(result.violated_policies) == 2


# ── Policy violation recording tests ──────────────────────────────────────────


def test_record_violation_to_db():
    """Policy violations are recorded as policy_violation events in the DB."""

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test_violations.db")
        db = AuditDB(db_path)

        engine = PolicyEngine.__new__(PolicyEngine)
        engine._policies_dir = "/nonexistent"
        engine._db = db
        engine.policies = []

        event = _make_event(
            agent={"type": "hermes", "session_id": "sess-001", "run_id": "run-001"},
            action={"tool_name": "terminal", "parameters": {}, "data_accessed": ["prod"]},
        )

        engine.record_violation(event, "test-policy", "Test violation message")

        # Query for policy_violation events
        violations = db.query(event_type="policy_violation")
        assert len(violations) == 1, f"Expected 1 violation, got {len(violations)}"
        v = violations[0]
        assert v["event_type"] == "policy_violation"
        assert v["outcome"]["status"] == "blocked"
        assert "test-policy" in v["outcome"]["summary"]
        assert v["context"]["policy_name"] == "test-policy"

        db.close()


def test_check_event_with_db():
    """check_event evaluates and records violations."""

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test_check.db")
        db = AuditDB(db_path)

        # Create policies dir with a blocking policy
        policies_dir = os.path.join(tmpdir, "policies")
        os.makedirs(policies_dir)
        yaml_str = """
name: "block-terminal"
enabled: true
scope:
  agents: ["*"]
rule:
  event_type: "tool_call"
  conditions:
    - field: "action.tool_name"
      operator: "=="
      value: "terminal"
  logic: "AND"
action: block
message: "Terminal blocked"
"""
        path = os.path.join(policies_dir, "block.yaml")
        with open(path, "w") as f:
            f.write(yaml_str)

        engine = PolicyEngine(policies_dir=policies_dir, db=db)

        event = _make_event(
            agent={"type": "hermes", "session_id": "sess-001", "run_id": "run-001"},
            action={"tool_name": "terminal", "parameters": {}, "data_accessed": []},
        )

        result = engine.check_event(event)
        assert result.action == "block"
        assert len(result.violated_policies) == 1
        assert result.violated_policies[0]["action"] == "block"

        # Verify violation was recorded
        violations = db.query(event_type="policy_violation")
        assert len(violations) == 1
        assert violations[0]["context"]["policy_name"] == "block-terminal"
        assert violations[0]["context"]["policy_action"] == "block"
        assert (
            violations[0]["context"]["policy_snapshot_id"]
            == result.policy_snapshot_id
        )
        assert (
            violations[0]["context"]["policy_engine_semantics_version"]
            == POLICY_ENGINE_SEMANTICS_VERSION
        )

        db.close()


def test_check_event_normalizes_source_and_records_recomputable_lineage():
    with tempfile.TemporaryDirectory() as tmpdir:
        policies_dir = os.path.join(tmpdir, "policies")
        os.makedirs(policies_dir)
        with open(
            os.path.join(policies_dir, "prod.yaml"), "w", encoding="utf-8"
        ) as f:
            f.write(
                "name: block-derived-prod\n"
                "action: block\n"
                "rule:\n"
                "  event_type: tool_call\n"
                "  conditions:\n"
                "    - field: action.data_accessed\n"
                "      operator: contains\n"
                "      value: prod\n"
            )

        db = AuditDB(os.path.join(tmpdir, "audit.db"))
        engine = PolicyEngine(policies_dir, db=db)
        secret = "sk-" + ("Z" * 40)
        raw_event = _make_event(
            event_id="source-event-123",
            action={
                "tool_name": "bash",
                "call_id": "provider-call-456",
                "parameters": {
                    "command": (
                        "kubectl apply -f /prod/deployment.yaml "
                        f"--token={secret}"
                    ),
                },
                "target": "/prod/deployment.yaml",
                "data_accessed": ["dev"],
            },
            context={
                "turn_number": 1,
                "capture": {
                    "adapter": "test",
                    "fidelity": "host_reported",
                    "observation_boundary": "unit_test",
                    "identity_assurance": "client_asserted",
                    "provenance": "adapter_asserted",
                    "execution_observed": False,
                    "enforcement_mandatory": False,
                    "authenticated": False,
                },
            },
        )

        result = engine.check_event(raw_event)
        violations = db.query(event_type="policy_violation")

        assert result.action == "block"
        assert len(violations) == 1
        violation = violations[0]
        assert violation["context"]["source_event_id"] == "source-event-123"
        assert violation["context"]["source_event_type"] == "tool_call"
        assert violation["action"]["call_id"] == "provider-call-456"
        assert violation["action"]["declared_data_accessed"] == ["dev"]
        assert {"prod", "infra"}.issubset(
            violation["action"]["derived_data_accessed"]
        )
        assert secret not in json.dumps(violation)
        assert "[REDACTED" in json.dumps(violation["action"]["parameters"])
        assert violation["context"]["capture"]["adapter"] == "policy_engine"
        assert violation["context"]["capture"]["observed_events"] == [
            "policy_violation"
        ]
        assert violation["context"]["source_capture"]["adapter"] == "test"
        db.close()


def test_allow_match_is_visible_but_not_recorded_as_violation():
    with tempfile.TemporaryDirectory() as tmpdir:
        policy_path = os.path.join(tmpdir, "allow.yaml")
        with open(policy_path, "w", encoding="utf-8") as f:
            f.write(
                "name: explicitly-allowed\n"
                "action: allow\n"
                "rule:\n"
                "  conditions: []\n"
            )

        db = AuditDB(os.path.join(tmpdir, "allow-audit.db"))
        engine = PolicyEngine(tmpdir, db=db)
        result = engine.check_event(_make_event())

        assert result.action == "allow"
        assert result.violated_policies == []
        assert len(result.matched_policies) == 1
        assert result.matched_policies[0]["policy_name"] == "explicitly-allowed"
        assert result.matched_policies[0]["action"] == "allow"
        assert result.matched_policies[0]["reason"]
        assert db.query(event_type="policy_violation") == []
        db.close()


def test_warn_match_records_warned_outcome_and_snapshot():
    with tempfile.TemporaryDirectory() as tmpdir:
        policy_path = os.path.join(tmpdir, "warn.yaml")
        with open(policy_path, "w", encoding="utf-8") as f:
            f.write(
                "name: warn-terminal\n"
                "action: warn\n"
                "message: Terminal use observed\n"
                "rule:\n"
                "  conditions: []\n"
            )

        db = AuditDB(os.path.join(tmpdir, "warn-audit.db"))
        engine = PolicyEngine(tmpdir, db=db)
        result = engine.check_event(_make_event())

        assert result.action == "warn"
        assert result.violated_policies[0]["action"] == "warn"
        audit_events = db.query(event_type="policy_violation")
        assert len(audit_events) == 1
        audit_event = audit_events[0]
        assert audit_event["outcome"]["status"] == "warned"
        assert audit_event["context"]["policy_action"] == "warn"
        assert audit_event["context"]["policy_snapshot_id"]
        assert (
            audit_event["context"]["policy_snapshot_id"]
            == result.policy_snapshot_id
        )
        db.close()


# ── Error handling / fail-open tests ──────────────────────────────────────────


def test_evaluate_error_fail_open():
    """Errors during policy evaluation result in allow (fail-open)."""

    with tempfile.TemporaryDirectory() as tmpdir:
        # Policy with a condition that would cause an error if the field
        # path traverses through None — but our implementation handles that
        # gracefully. Let's test with an unknown operator.
        yaml_str = """
name: "weird-policy"
enabled: true
action: block
rule:
  conditions:
    - field: "action.tool_name"
      operator: "UNKNOWN_OP"
      value: "anything"
  logic: "AND"
"""
        path = os.path.join(tmpdir, "weird.yaml")
        with open(path, "w") as f:
            f.write(yaml_str)

        engine = PolicyEngine(policies_dir=tmpdir)
        event = _make_event()

        # Should not raise — should fail-open
        result = engine.evaluate(event)
        assert result.action == "allow", f"Unknown operator should fail-open, got {result.action}"


def test_structurally_invalid_policy_respects_failure_mode():
    """Invalid condition shapes are load errors, never always-match rules."""
    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "invalid-conditions.yaml")
        with open(path, "w", encoding="utf-8") as f:
            f.write(
                "name: invalid-conditions\n"
                "action: block\n"
                "rule:\n"
                "  conditions: not-a-list\n"
            )

        opened = PolicyEngine(tmpdir, failure_mode="fail_open")
        closed = PolicyEngine(tmpdir, failure_mode="fail_closed")

        assert opened.load_errors
        assert opened.evaluate(_make_event()).action == "allow"
        assert closed.evaluate(_make_event()).action == "block"


@pytest.mark.parametrize(
    "policy_yaml",
    [
        (
            "name: typo\n"
            "actions: block\n"
            "rule:\n"
            "  conditions: []\n"
        ),
        (
            "name: typo\n"
            "action: block\n"
            "rule:\n"
            "  condition: []\n"
        ),
        (
            "name: typo\n"
            "action: block\n"
            "scope:\n"
            "  agent: [hermes]\n"
            "rule:\n"
            "  conditions: []\n"
        ),
        (
            "name: typo\n"
            "action: block\n"
            "rule:\n"
            "  event_type: tool_cal\n"
            "  conditions: []\n"
        ),
        (
            "name: typo\n"
            "action: block\n"
            "rule:\n"
            "  conditions:\n"
            "    - field: action.tool_name\n"
            "      operators: '=='\n"
            "      value: terminal\n"
        ),
        (
            "name: duplicate\n"
            "action: block\n"
            "action: allow\n"
            "rule:\n"
            "  conditions: []\n"
        ),
    ],
)
def test_policy_typos_and_duplicate_keys_cannot_silently_weaken_enforcement(
    policy_yaml,
):
    with tempfile.TemporaryDirectory() as tmpdir:
        with open(
            os.path.join(tmpdir, "invalid.yaml"), "w", encoding="utf-8"
        ) as f:
            f.write(policy_yaml)

        opened = PolicyEngine(tmpdir, failure_mode="fail_open")
        closed = PolicyEngine(tmpdir, failure_mode="fail_closed")

        assert opened.load_errors
        assert opened.evaluate(_make_event()).action == "allow"
        assert closed.evaluate(_make_event()).action == "block"


def test_nonexistent_nested_field():
    """A missing nested field below a canonical root simply does not match."""

    raw = {
        "name": "nested-test",
        "enabled": True,
        "action": "warn",
        "rule": {
            "conditions": [
                {"field": "action.parameters.nonexistent.path", "operator": "==", "value": "something"},
            ],
            "logic": "AND",
        },
    }
    policy = Policy(raw)

    event = _make_event()
    matched, _ = policy.evaluate_conditions(event)
    assert not matched, "Nonexistent field should not match"


def test_nonexistent_top_level_policy_field_is_rejected():
    with pytest.raises(ValueError, match="not a canonical enforceable field"):
        Policy({
            "name": "typo",
            "action": "block",
            "rule": {
                "conditions": [{
                    "field": "acton.tool_name",
                    "operator": "==",
                    "value": "terminal",
                }],
            },
        })


def test_nonexistent_fixed_leaf_policy_field_is_rejected():
    with pytest.raises(ValueError, match="not a canonical enforceable field"):
        Policy({
            "name": "leaf-typo",
            "action": "block",
            "rule": {
                "conditions": [{
                    "field": "action.tool_nmae",
                    "operator": "==",
                    "value": "terminal",
                }],
            },
        })


@pytest.mark.parametrize(
    "field_path",
    [
        "action.client_side_tools",
        "action.server_side_tools",
        "action.unknown_tool_types",
        "action.requested_tool_targets",
        "action.execution_scope",
        "action.provider_item_type",
        "action.server_result_type",
        "action.server_result_complete",
        "action.result.error.code",
    ],
)
def test_complete_structured_tool_fields_are_enforceable(field_path):
    policy = Policy({
        "name": "structured-tool-policy",
        "action": "block",
        "rule": {
            "conditions": [{
                "field": field_path,
                "operator": "contains",
                "value": "forbidden",
            }],
        },
    })
    assert policy.name == "structured-tool-policy"


@pytest.mark.parametrize(
    "field_path",
    ["raw_request", "raw_response", "action.server_result_summary"],
)
def test_lossy_raw_payload_fields_cannot_be_enforcement_conditions(field_path):
    with pytest.raises(ValueError, match="lossy presentation field"):
        Policy({
            "name": "lossy-input",
            "action": "block",
            "rule": {
                "conditions": [{
                    "field": field_path,
                    "operator": "contains",
                    "value": "forbidden",
                }],
            },
        })


# ── Event type filter tests ───────────────────────────────────────────────────


def test_rule_event_type_filter():
    """The event_type in the rule filters which events are evaluated."""

    raw = {
        "name": "type-filter",
        "enabled": True,
        "action": "warn",
        "rule": {
            "event_type": "tool_call",
            "conditions": [],
            "logic": "AND",
        },
    }
    policy = Policy(raw)

    event_tc = _make_event(event_type="tool_call")
    matched, _ = policy.evaluate_conditions(event_tc)
    assert matched, "tool_call event should match rule with event_type=tool_call"

    event_mr = _make_event(event_type="model_request")
    matched2, _ = policy.evaluate_conditions(event_mr)
    assert not matched2, "model_request should not match rule with event_type=tool_call"


# ── test_policy method tests ──────────────────────────────────────────────────


def test_test_policy_method():
    """PolicyEngine.test_policy tests a policy file against event JSON."""

    with tempfile.TemporaryDirectory() as tmpdir:
        # Create a policy file
        policy_yaml = """
name: "test-policy"
enabled: true
action: block
rule:
  conditions:
    - field: "action.tool_name"
      operator: "=="
      value: "terminal"
  logic: "AND"
"""
        policy_path = os.path.join(tmpdir, "test.yaml")
        with open(policy_path, "w") as f:
            f.write(policy_yaml)

        engine = PolicyEngine.__new__(PolicyEngine)
        engine._policies_dir = "/nonexistent"
        engine._db = None
        engine.policies = []

        # Matching event
        event_json = json.dumps(_make_event())
        result = engine.test_policy(policy_path, event_json)
        assert result.action == "block"
        assert len(result.violated_policies) == 1

        # Non-matching event
        event_json2 = json.dumps(_make_event(
            action={"tool_name": "read_file", "parameters": {}, "data_accessed": []},
        ))
        result2 = engine.test_policy(policy_path, event_json2)
        assert result2.action == "allow"
        assert len(result2.violated_policies) == 0

        # Invalid JSON
        try:
            engine.test_policy(policy_path, "not valid json")
            assert False, "Should raise ValueError for invalid JSON"
        except ValueError:
            pass

        # Nonexistent policy file
        try:
            engine.test_policy("/nonexistent/policy.yaml", event_json)
            assert False, "Should raise ValueError for missing file"
        except ValueError:
            pass


def test_test_policy_uses_live_single_event_semantics():
    with tempfile.TemporaryDirectory() as tmpdir:
        policy_path = os.path.join(tmpdir, "test.yaml")
        event_json = json.dumps(_make_event())

        with open(policy_path, "w", encoding="utf-8") as f:
            f.write(
                "name: disabled\n"
                "enabled: false\n"
                "action: block\n"
                "rule:\n"
                "  conditions: []\n"
            )
        disabled = PolicyEngine.test_policy(policy_path, event_json)
        assert disabled.action == "allow"
        assert disabled.matched_policies == []

        with open(policy_path, "w", encoding="utf-8") as f:
            f.write(
                "name: other-agent\n"
                "scope:\n"
                "  agents: [codex]\n"
                "action: block\n"
                "rule:\n"
                "  conditions: []\n"
            )
        out_of_scope = PolicyEngine.test_policy(policy_path, event_json)
        assert out_of_scope.action == "allow"
        assert out_of_scope.matched_policies == []

        with open(policy_path, "w", encoding="utf-8") as f:
            f.write(
                "name: derived-prod\n"
                "action: block\n"
                "rule:\n"
                "  conditions:\n"
                "    - field: action.data_accessed\n"
                "      operator: contains\n"
                "      value: prod\n"
            )
        derived = PolicyEngine.test_policy(
            policy_path,
            json.dumps(_make_event(action={
                "tool_name": "bash",
                "parameters": {"command": "kubectl get pods -n prod"},
                "data_accessed": [],
            })),
        )
        assert derived.action == "block"

        invalid = _make_event(action={
            "tool_name": None,
            "parameters": {},
            "data_accessed": [],
        })
        with pytest.raises(ValueError, match="Invalid event"):
            PolicyEngine.test_policy(policy_path, json.dumps(invalid))


@pytest.mark.parametrize(
    "event_json",
    [
        '{"event_type":"tool_call","event_type":"model_request"}',
        '{"cost":{"tokens_in":NaN}}',
        '{"cost":{"estimated_usd":Infinity}}',
    ],
)
def test_test_policy_rejects_ambiguous_or_nonstandard_json(event_json):
    with tempfile.TemporaryDirectory() as tmpdir:
        policy_path = os.path.join(tmpdir, "test.yaml")
        with open(policy_path, "w", encoding="utf-8") as f:
            f.write(
                "name: strict-json\n"
                "action: allow\n"
                "rule:\n"
                "  conditions: []\n"
            )

        with pytest.raises(ValueError, match="Invalid event JSON"):
            PolicyEngine.test_policy(policy_path, event_json)


# ── Default policies test ─────────────────────────────────────────────────────


def test_no_prod_access_policy():
    """The bundled no-prod-access policy works correctly.

    After fix #3, the policy is data-driven: it fires on ANY tool_call whose
    data_accessed contains 'prod', regardless of which specific tool was used.
    """

    import yaml

    # Load the default policy
    default_path = os.path.join(
        os.path.dirname(__file__),
        "..",
        "panoptes",
        "default_policies",
        "no-prod-access.yaml",
    )
    assert os.path.exists(default_path), f"Default policy not found at {default_path}"

    with open(default_path, "r") as f:
        raw = yaml.safe_load(f)

    policy = Policy(raw)
    assert policy.name == "no-prod-access"
    assert policy.action == "block"
    assert policy.enabled is True

    # Terminal call with prod data — should match
    event_prod = _make_event(
        agent={"type": "hermes", "session_id": "s1", "run_id": "r1"},
        action={
            "tool_name": "terminal",
            "parameters": {},
            "data_accessed": ["prod", "db"],
        },
    )
    matched, reason = policy.evaluate_conditions(event_prod)
    assert matched, f"Should block prod access via terminal: {reason}"

    # read_file with prod data — NOW ALSO MATCHES (no tool_name filter in updated policy)
    event_read = _make_event(
        agent={"type": "hermes", "session_id": "s1", "run_id": "r1"},
        action={
            "tool_name": "read_file",
            "parameters": {},
            "data_accessed": ["prod"],
        },
    )
    matched2, reason2 = policy.evaluate_conditions(event_read)
    assert matched2, (
        f"read_file with prod data_accessed should now match (policy is data-driven, "
        f"no tool_name filter): {reason2}"
    )

    # Write tool with prod data — also matches
    event_write = _make_event(
        agent={"type": "hermes", "session_id": "s1", "run_id": "r1"},
        action={
            "tool_name": "Write",
            "parameters": {},
            "data_accessed": ["prod", "infra"],
        },
    )
    matched3, _ = policy.evaluate_conditions(event_write)
    assert matched3, "Write with prod data_accessed should match"

    # Tool call without prod access — should NOT match
    event_safe = _make_event(
        agent={"type": "hermes", "session_id": "s1", "run_id": "r1"},
        action={
            "tool_name": "terminal",
            "parameters": {},
            "data_accessed": ["dev"],
        },
    )
    matched4, _ = policy.evaluate_conditions(event_safe)
    assert not matched4, "terminal without prod should not match"

    # model_request with prod in data_accessed — should NOT match (event_type filter)
    event_mr = _make_event(
        event_type="model_request",
        agent={"type": "hermes", "session_id": "s1", "run_id": "r1"},
        action={
            "tool_name": None,
            "parameters": {},
            "data_accessed": ["prod"],
        },
    )
    matched5, _ = policy.evaluate_conditions(event_mr)
    assert not matched5, "model_request should not match (event_type=tool_call filter)"


def test_no_prod_access_with_derived_data_accessed():
    """no-prod-access policy fires on events with derived data_accessed from normalize_event."""

    import yaml
    from panoptes.schema import normalize_event

    default_path = os.path.join(
        os.path.dirname(__file__),
        "..",
        "panoptes",
        "default_policies",
        "no-prod-access.yaml",
    )
    with open(default_path, "r") as f:
        raw = yaml.safe_load(f)
    policy = Policy(raw)

    # Raw event with no data_accessed — but command contains "prod"
    raw_event = {
        "agent": {"type": "hermes", "session_id": "s1", "run_id": "r1"},
        "event_type": "tool_call",
        "action": {
            "tool_name": "bash",
            "parameters": {"command": "kubectl apply -f /prod/deployment.yaml"},
            "data_accessed": [],
        },
        "outcome": {"status": "success"},
        "context": {},
    }
    # normalize_event derives data_accessed from the command string
    normalized = normalize_event(raw_event)
    assert "prod" in normalized["action"]["data_accessed"], (
        f"Expected 'prod' derived from command, got {normalized['action']['data_accessed']}"
    )
    assert "infra" in normalized["action"]["data_accessed"], (
        f"Expected 'infra' derived from 'kubectl', got {normalized['action']['data_accessed']}"
    )

    # Policy should match the normalized event
    matched, reason = policy.evaluate_conditions(normalized)
    assert matched, (
        f"no-prod-access should fire on derived 'prod' in data_accessed: {reason}"
    )


def test_engine_evaluate_derives_authoritative_tags_before_policy_matching():
    default_dir = os.path.join(
        os.path.dirname(__file__),
        "..",
        "panoptes",
        "default_policies",
    )
    engine = PolicyEngine(default_dir)
    raw_event = _make_event(action={
        "tool_name": "bash",
        "parameters": {
            "command": "kubectl apply -f /prod/deployment.yaml",
        },
        # An adapter-declared safe tag must not suppress classifier output.
        "data_accessed": ["dev"],
    })

    result = engine.evaluate(raw_event)

    assert result.action == "block"
    assert result.violated_policies[0]["policy_name"] == "no-prod-access"


def test_check_event_surfaces_violation_evidence_write_failure():
    class _FailingDB:
        def insert_event(self, event):
            raise OSError("disk full")

    with tempfile.TemporaryDirectory() as directory:
        with open(
            os.path.join(directory, "warn.yaml"),
            "w",
            encoding="utf-8",
        ) as handle:
            handle.write(
                "name: warn-all\n"
                "action: warn\n"
                "rule:\n"
                "  conditions: []\n"
            )

        open_engine = PolicyEngine(
            directory,
            db=_FailingDB(),
            failure_mode="fail_open",
        )
        open_result = open_engine.check_event(_make_event())
        assert open_result.action == "warn"
        assert "could not be persisted" in open_result.evaluation_errors[0]

        closed_engine = PolicyEngine(
            directory,
            db=_FailingDB(),
            failure_mode="fail_closed",
        )
        closed_result = closed_engine.check_event(_make_event())
        assert closed_result.action == "block"
        assert any(
            violation["policy_name"] == "policy_evidence_write_error"
            for violation in closed_result.violated_policies
        )


# ── Run all tests ─────────────────────────────────────────────────────────────


def test_invalid_input_is_denied_while_block_policies_are_active():
    """A caller-shaped validation failure must not fail open past a block."""
    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, "block.yaml"), "w", encoding="utf-8") as f:
            f.write(
                "name: block-terminal\n"
                "action: block\n"
                "rule:\n"
                "  event_type: tool_call\n"
                "  conditions:\n"
                "    - field: action.tool_name\n"
                "      operator: ==\n"
                "      value: terminal\n"
            )
        engine = PolicyEngine(tmpdir, failure_mode="fail_open")
        for bad in (
            _make_event(action={"tool_name": "terminal", "parameters": ["ls"]}),
            _make_event(timestamp="0001-01-01T00:00:00+05:00"),
        ):
            result = engine.evaluate(bad)
            assert result.action == "block"
            assert result.violated_policies[0]["policy_name"] == "invalid_event_input"


def test_invalid_input_without_block_policies_keeps_fail_open():
    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, "warn.yaml"), "w", encoding="utf-8") as f:
            f.write(
                "name: warn-terminal\n"
                "action: warn\n"
                "rule:\n"
                "  event_type: tool_call\n"
                "  conditions:\n"
                "    - field: action.tool_name\n"
                "      operator: ==\n"
                "      value: terminal\n"
            )
        engine = PolicyEngine(tmpdir, failure_mode="fail_open")
        result = engine.evaluate(
            _make_event(action={"tool_name": "terminal", "parameters": ["ls"]})
        )
        assert result.action == "allow"
        assert result.evaluation_errors
