#!/usr/bin/env python3
"""Comprehensive tests for the panoptes policy engine.

Covers:
  - Policy loading from YAML
  - Basic condition matching (==, !=, contains, in, matches)
  - Boolean logic (AND, OR)
  - Rate limiting
  - PolicyResult construction
  - Policy violation recording to DB
  - Scope filtering (only applies to specified agents)
  - Disabled policies are skipped
  - Malformed YAML is handled gracefully
  - Missing policies directory is handled gracefully
  - Numeric comparisons (gt, lt, gte, lte)
"""

import json
import os
import sys
import tempfile

# Ensure local package is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from panoptes.db import AuditDB
from panoptes.policy import Policy, PolicyEngine, PolicyResult


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
    print("--- test_load_policies_from_yaml ---")

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

    print("  PASSED")


def test_load_multiple_policies():
    """Multiple YAML files are all loaded."""
    print("--- test_load_multiple_policies ---")

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

    print("  PASSED")


def test_missing_policies_dir():
    """Missing policies directory is handled gracefully (no policies)."""
    print("--- test_missing_policies_dir ---")

    engine = PolicyEngine(policies_dir="/nonexistent/path/to/policies")
    assert len(engine.policies) == 0

    print("  PASSED")


def test_malformed_yaml_skipped():
    """Malformed YAML files are skipped with a warning."""
    print("--- test_malformed_yaml_skipped ---")

    with tempfile.TemporaryDirectory() as tmpdir:
        # Write a malformed YAML file
        bad_path = os.path.join(tmpdir, "bad.yaml")
        with open(bad_path, "w") as f:
            f.write("this is not: valid: yaml: [unclosed\n")

        # Write a valid one too
        good_path = os.path.join(tmpdir, "good.yaml")
        with open(good_path, "w") as f:
            f.write("name: good-policy\nenabled: true\naction: warn\nrule:\n  conditions: []\n")

        engine = PolicyEngine(policies_dir=tmpdir)
        # Only the valid policy should be loaded
        assert len(engine.policies) == 1
        assert engine.policies[0].name == "good-policy"

    print("  PASSED")


def test_non_yaml_files_skipped():
    """Non-YAML files in the directory are ignored."""
    print("--- test_non_yaml_files_skipped ---")

    with tempfile.TemporaryDirectory() as tmpdir:
        # Write a .txt file
        txt_path = os.path.join(tmpdir, "notes.txt")
        with open(txt_path, "w") as f:
            f.write("not a policy")

        engine = PolicyEngine(policies_dir=tmpdir)
        assert len(engine.policies) == 0

    print("  PASSED")


def test_non_dict_yaml_skipped():
    """YAML file that doesn't parse to a dict is skipped."""
    print("--- test_non_dict_yaml_skipped ---")

    with tempfile.TemporaryDirectory() as tmpdir:
        # Write a YAML file that's a list, not a dict
        list_path = os.path.join(tmpdir, "list.yaml")
        with open(list_path, "w") as f:
            f.write("- item: 1\n- item: 2\n")

        engine = PolicyEngine(policies_dir=tmpdir)
        assert len(engine.policies) == 0

    print("  PASSED")


# ── Condition matching tests ──────────────────────────────────────────────────


def test_operator_equals():
    """== operator: exact match."""
    print("--- test_operator_equals ---")

    raw = {
        "name": "eq-test",
        "enabled": True,
        "action": "warn",
        "rule": {
            "event_type": "tool_call",
            "conditions": [
                {"field": "action.tool_name", "operator": "==", "value": "terminal"},
            ],
            "logic": "AND",
        },
    }
    policy = Policy(raw)

    # Matching event
    event = _make_event(action={"tool_name": "terminal", "parameters": {}, "data_accessed": []})
    matched, _ = policy.evaluate_conditions(event)
    assert matched, "Should match terminal"

    # Non-matching event
    event2 = _make_event(action={"tool_name": "read_file", "parameters": {}, "data_accessed": []})
    matched2, _ = policy.evaluate_conditions(event2)
    assert not matched2, "Should not match read_file"

    print("  PASSED")


def test_operator_not_equals():
    """!= operator: excludes specific values."""
    print("--- test_operator_not_equals ---")

    raw = {
        "name": "neq-test",
        "enabled": True,
        "action": "warn",
        "rule": {
            "conditions": [
                {"field": "action.tool_name", "operator": "!=", "value": "read_file"},
            ],
            "logic": "AND",
        },
    }
    policy = Policy(raw)

    event = _make_event(action={"tool_name": "terminal", "parameters": {}, "data_accessed": []})
    matched, _ = policy.evaluate_conditions(event)
    assert matched, "Should match terminal (not read_file)"

    event2 = _make_event(action={"tool_name": "read_file", "parameters": {}, "data_accessed": []})
    matched2, _ = policy.evaluate_conditions(event2)
    assert not matched2, "Should not match read_file"

    print("  PASSED")


def test_operator_contains_string():
    """contains operator for strings: substring match."""
    print("--- test_operator_contains_string ---")

    raw = {
        "name": "contains-test",
        "enabled": True,
        "action": "warn",
        "rule": {
            "conditions": [
                {"field": "outcome.summary", "operator": "contains", "value": "error"},
            ],
            "logic": "AND",
        },
    }
    policy = Policy(raw)

    event = _make_event(outcome={"status": "error", "summary": "error: file not found"})
    matched, _ = policy.evaluate_conditions(event)
    assert matched, "Should match 'error' in summary"

    event2 = _make_event(outcome={"status": "success", "summary": "everything ok"})
    matched2, _ = policy.evaluate_conditions(event2)
    assert not matched2, "Should not match success summary"

    print("  PASSED")


def test_operator_contains_list():
    """contains operator for lists: checks if value is in the list."""
    print("--- test_operator_contains_list ---")

    raw = {
        "name": "contains-list-test",
        "enabled": True,
        "action": "warn",
        "rule": {
            "conditions": [
                {"field": "action.data_accessed", "operator": "contains", "value": "prod"},
            ],
            "logic": "AND",
        },
    }
    policy = Policy(raw)

    event = _make_event(action={
        "tool_name": "read_file",
        "parameters": {},
        "data_accessed": ["prod", "config"],
    })
    matched, _ = policy.evaluate_conditions(event)
    assert matched, "Should match 'prod' in data_accessed"

    event2 = _make_event(action={
        "tool_name": "read_file",
        "parameters": {},
        "data_accessed": ["dev", "staging"],
    })
    matched2, _ = policy.evaluate_conditions(event2)
    assert not matched2, "Should not match dev/staging only"

    print("  PASSED")


def test_operator_in():
    """in operator: checks if value is in expected list."""
    print("--- test_operator_in ---")

    raw = {
        "name": "in-test",
        "enabled": True,
        "action": "warn",
        "rule": {
            "conditions": [
                {"field": "action.tool_name", "operator": "in",
                 "value": ["terminal", "write_file", "browser_navigate"]},
            ],
            "logic": "AND",
        },
    }
    policy = Policy(raw)

    event = _make_event(action={"tool_name": "terminal", "parameters": {}, "data_accessed": []})
    matched, _ = policy.evaluate_conditions(event)
    assert matched, "terminal should be in the list"

    event2 = _make_event(action={"tool_name": "read_file", "parameters": {}, "data_accessed": []})
    matched2, _ = policy.evaluate_conditions(event2)
    assert not matched2, "read_file should NOT be in the list"

    print("  PASSED")


def test_operator_matches():
    """matches operator: regex pattern."""
    print("--- test_operator_matches ---")

    raw = {
        "name": "regex-test",
        "enabled": True,
        "action": "warn",
        "rule": {
            "conditions": [
                {"field": "action.tool_name", "operator": "matches", "value": r"^write_"},
            ],
            "logic": "AND",
        },
    }
    policy = Policy(raw)

    event = _make_event(action={"tool_name": "write_file", "parameters": {}, "data_accessed": []})
    matched, _ = policy.evaluate_conditions(event)
    assert matched, "write_file should match ^write_"

    event2 = _make_event(action={"tool_name": "read_file", "parameters": {}, "data_accessed": []})
    matched2, _ = policy.evaluate_conditions(event2)
    assert not matched2, "read_file should not match ^write_"

    print("  PASSED")


def test_operator_numeric():
    """Numeric comparison operators: gt, lt, gte, lte."""
    print("--- test_operator_numeric ---")

    # gt
    raw_gt = {
        "name": "gt-test",
        "enabled": True,
        "action": "warn",
        "rule": {
            "conditions": [
                {"field": "cost.tokens_in", "operator": "gt", "value": 1000},
            ],
            "logic": "AND",
        },
    }
    policy_gt = Policy(raw_gt)

    event_high = _make_event(cost={"tokens_in": 2000, "tokens_out": 500})
    matched, _ = policy_gt.evaluate_conditions(event_high)
    assert matched, "2000 > 1000 should match"

    event_low = _make_event(cost={"tokens_in": 500, "tokens_out": 200})
    matched2, _ = policy_gt.evaluate_conditions(event_low)
    assert not matched2, "500 > 1000 should NOT match"

    # lte
    raw_lte = {
        "name": "lte-test",
        "enabled": True,
        "action": "warn",
        "rule": {
            "conditions": [
                {"field": "cost.tokens_out", "operator": "lte", "value": 100},
            ],
            "logic": "AND",
        },
    }
    policy_lte = Policy(raw_lte)

    event_under = _make_event(cost={"tokens_in": 50, "tokens_out": 100})
    matched3, _ = policy_lte.evaluate_conditions(event_under)
    assert matched3, "100 <= 100 should match"

    event_over = _make_event(cost={"tokens_in": 50, "tokens_out": 200})
    matched4, _ = policy_lte.evaluate_conditions(event_over)
    assert not matched4, "200 <= 100 should NOT match"

    print("  PASSED")


# ── Boolean logic tests ───────────────────────────────────────────────────────


def test_logic_and():
    """AND logic: all conditions must match."""
    print("--- test_logic_and ---")

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

    print("  PASSED")


def test_logic_or():
    """OR logic: any condition can match."""
    print("--- test_logic_or ---")

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

    print("  PASSED")


# ── Scope filtering tests ─────────────────────────────────────────────────────


def test_scope_agent_filter():
    """Scope with specific agents only applies to those agents."""
    print("--- test_scope_agent_filter ---")

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

    print("  PASSED")


def test_scope_wildcard():
    """Scope with ['*'] applies to all agents."""
    print("--- test_scope_wildcard ---")

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

    print("  PASSED")


def test_scope_session_filter():
    """Scope with session list only applies to those sessions."""
    print("--- test_scope_session_filter ---")

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

    print("  PASSED")


# ── Disabled policies ─────────────────────────────────────────────────────────


def test_disabled_policy_skipped():
    """Disabled policies are skipped during evaluation."""
    print("--- test_disabled_policy_skipped ---")

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

    print("  PASSED")


# ── Rate limiting tests ───────────────────────────────────────────────────────


def test_rate_limit_basic():
    """Rate limiting tracks counts and triggers after threshold."""
    print("--- test_rate_limit_basic ---")

    raw = {
        "name": "rate-limit-test",
        "enabled": True,
        "action": "warn",
        "rule": {
            "event_type": "tool_call",
            "conditions": [
                {"field": "action.tool_name", "operator": "==", "value": "terminal"},
            ],
            "logic": "AND",
            "rate_limit": {
                "count": 3,
                "window": "session",
            },
        },
    }
    policy = Policy(raw)

    event = _make_event(action={"tool_name": "terminal", "parameters": {}, "data_accessed": []})

    engine = PolicyEngine.__new__(PolicyEngine)
    engine._policies_dir = "/nonexistent"
    engine._db = None
    engine._rate_limits = {}
    engine._rate_lock = threading = __import__("threading")
    engine.policies = [policy]

    import threading as thr
    engine._rate_lock = thr.Lock()

    # First 3 should NOT trigger (count 1, 2, 3 — threshold is 3, exceeded at 4+)
    for i in range(3):
        result = engine.evaluate(event)
        assert result.action == "allow", f"Call {i+1} should be allow (under limit)"

    # 4th call should trigger
    result = engine.evaluate(event)
    assert result.action == "warn", f"4th call should trigger rate limit, got {result.action}"
    assert len(result.violated_policies) == 1

    print("  PASSED")


def test_rate_limit_per_session():
    """Rate limits are tracked per session ID."""
    print("--- test_rate_limit_per_session ---")

    raw = {
        "name": "rate-limit-session",
        "enabled": True,
        "action": "warn",
        "rule": {
            "event_type": "tool_call",
            "conditions": [],
            "logic": "AND",
            "rate_limit": {
                "count": 2,
                "window": "session",
            },
        },
    }

    import threading as thr

    policy = Policy(raw)
    engine = PolicyEngine.__new__(PolicyEngine)
    engine._policies_dir = "/nonexistent"
    engine._db = None
    engine._rate_limits = {}
    engine._rate_lock = thr.Lock()
    engine.policies = [policy]

    # Session A: 3 calls — first 2 ok, 3rd triggers
    for i in range(2):
        result = engine.evaluate(_make_event(agent={"type": "hermes", "session_id": "sess-a", "run_id": "r1"}))
        assert result.action == "allow", f"Session A call {i+1} should be allow"

    result_a = engine.evaluate(_make_event(agent={"type": "hermes", "session_id": "sess-a", "run_id": "r1"}))
    assert result_a.action == "warn", "Session A 3rd call should trigger"

    # Session B: first call should still be allowed (separate counter)
    result_b = engine.evaluate(_make_event(agent={"type": "hermes", "session_id": "sess-b", "run_id": "r2"}))
    assert result_b.action == "allow", "Session B first call should be allow"

    print("  PASSED")


# ── PolicyResult tests ────────────────────────────────────────────────────────


def test_policy_result_construction():
    """PolicyResult dataclass works as expected."""
    print("--- test_policy_result_construction ---")

    r1 = PolicyResult(action="allow")
    assert r1.action == "allow"
    assert r1.violated_policies == []
    assert r1.warnings == []

    r2 = PolicyResult(
        action="block",
        violated_policies=[{"policy_name": "test", "message": "blocked", "reason": "matched"}],
        warnings=["test: blocked"],
    )
    assert r2.action == "block"
    assert len(r2.violated_policies) == 1
    assert r2.violated_policies[0]["policy_name"] == "test"

    print("  PASSED")


def test_action_escalation():
    """Block > warn > allow escalation."""
    print("--- test_action_escalation ---")

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

    print("  PASSED")


# ── Policy violation recording tests ──────────────────────────────────────────


def test_record_violation_to_db():
    """Policy violations are recorded as policy_violation events in the DB."""
    print("--- test_record_violation_to_db ---")

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test_violations.db")
        db = AuditDB(db_path)

        engine = PolicyEngine.__new__(PolicyEngine)
        engine._policies_dir = "/nonexistent"
        engine._db = db
        import threading as thr
        engine._rate_limits = {}
        engine._rate_lock = thr.Lock()
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

    print("  PASSED")


def test_check_event_with_db():
    """check_event evaluates and records violations."""
    print("--- test_check_event_with_db ---")

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

        # Verify violation was recorded
        violations = db.query(event_type="policy_violation")
        assert len(violations) == 1
        assert violations[0]["context"]["policy_name"] == "block-terminal"

        db.close()

    print("  PASSED")


# ── Error handling / fail-open tests ──────────────────────────────────────────


def test_evaluate_error_fail_open():
    """Errors during policy evaluation result in allow (fail-open)."""
    print("--- test_evaluate_error_fail_open ---")

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

    print("  PASSED")


def test_nonexistent_field():
    """Accessing a nonexistent field returns None and condition fails gracefully."""
    print("--- test_nonexistent_field ---")

    raw = {
        "name": "nested-test",
        "enabled": True,
        "action": "warn",
        "rule": {
            "conditions": [
                {"field": "nonexistent.field.path", "operator": "==", "value": "something"},
            ],
            "logic": "AND",
        },
    }
    policy = Policy(raw)

    event = _make_event()
    matched, _ = policy.evaluate_conditions(event)
    assert not matched, "Nonexistent field should not match"

    print("  PASSED")


# ── Event type filter tests ───────────────────────────────────────────────────


def test_rule_event_type_filter():
    """The event_type in the rule filters which events are evaluated."""
    print("--- test_rule_event_type_filter ---")

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

    print("  PASSED")


# ── test_policy method tests ──────────────────────────────────────────────────


def test_test_policy_method():
    """PolicyEngine.test_policy tests a policy file against event JSON."""
    print("--- test_test_policy_method ---")

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
        import threading as thr
        engine._db = None
        engine._rate_limits = {}
        engine._rate_lock = thr.Lock()
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

    print("  PASSED")


# ── Default policies test ─────────────────────────────────────────────────────


def test_no_prod_access_policy():
    """The bundled no-prod-access policy works correctly.

    After fix #3, the policy is data-driven: it fires on ANY tool_call whose
    data_accessed contains 'prod', regardless of which specific tool was used.
    """
    print("--- test_no_prod_access_policy ---")

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

    print("  PASSED")


def test_no_prod_access_with_derived_data_accessed():
    """no-prod-access policy fires on events with derived data_accessed from normalize_event."""
    print("--- test_no_prod_access_with_derived_data_accessed ---")

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

    print("  PASSED")


# ── Run all tests ─────────────────────────────────────────────────────────────


if __name__ == "__main__":
    # Load tests
    test_load_policies_from_yaml()
    test_load_multiple_policies()
    test_missing_policies_dir()
    test_malformed_yaml_skipped()
    test_non_yaml_files_skipped()
    test_non_dict_yaml_skipped()
    test_operator_equals()
    test_operator_not_equals()
    test_operator_contains_string()
    test_operator_contains_list()
    test_operator_in()
    test_operator_matches()
    test_operator_numeric()
    test_logic_and()
    test_logic_or()
    test_scope_agent_filter()
    test_scope_wildcard()
    test_scope_session_filter()
    test_disabled_policy_skipped()
    test_rate_limit_basic()
    test_rate_limit_per_session()
    test_policy_result_construction()
    test_action_escalation()
    test_record_violation_to_db()
    test_check_event_with_db()
    test_evaluate_error_fail_open()
    test_nonexistent_field()
    test_rule_event_type_filter()
    test_test_policy_method()
    test_no_prod_access_policy()
    test_no_prod_access_with_derived_data_accessed()
    print("\n=== ALL POLICY TESTS PASSED ===")
