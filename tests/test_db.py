#!/usr/bin/env python3
"""Comprehensive tests for the panoptes storage layer.

Covers:
  - DB creation, schema versioning
  - Event insertion with normalization and secret redaction
  - Querying by agent_type, event_type, time range, data_accessed
  - Evidence chain reconstruction
  - Session listing and statistics
  - Validation errors
  - Thread safety (basic)
"""

import os
import sys
import tempfile
import threading
import time
import uuid

# Ensure local package is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from panoptes import AuditDB, ValidationError, normalize_event, validate_event
from panoptes.schema import redact_secrets


def test_redact_secrets():
    """Secret redaction removes sensitive data from strings and nested dicts."""
    print("--- test_redact_secrets ---")

    # API key in parameters
    params = {"headers": {"Authorization": "Bearer sk-ant-api03-abcdefghijklmnopqrstuvwxyz"}}
    cleaned = redact_secrets(params)
    assert "[REDACTED]" in str(cleaned), f"Bearer token not redacted: {cleaned}"

    # Password in nested dict
    params2 = {"db": {"password": "supersecret123", "host": "localhost"}}
    cleaned2 = redact_secrets(params2)
    assert "supersecret123" not in str(cleaned2), f"Password not redacted: {cleaned2}"
    assert "[REDACTED]" in str(cleaned2)

    # Private key
    params3 = {"key": "-----BEGIN RSA PRIVATE KEY-----\nabc123\n-----END RSA PRIVATE KEY-----"}
    cleaned3 = redact_secrets(params3)
    assert "PRIVATE KEY" not in str(cleaned3) or "[REDACTED" in str(cleaned3), f"Private key not redacted: {cleaned3}"

    # AWS key
    params4 = {"aws_access_key": "AKIAIOSFODNN7EXAMPLE"}
    cleaned4 = redact_secrets(params4)
    assert "AKIA" not in str(cleaned4), f"AWS key not redacted: {cleaned4}"

    # GitHub token
    params5 = {"token": "ghp_1234567890abcdefghijklmnopqrstuvwxyz1234"}
    cleaned5 = redact_secrets(params5)
    assert "ghp_" not in str(cleaned5), f"GitHub token not redacted: {cleaned5}"

    # Non-sensitive data passes through
    params6 = {"file": "config.yaml", "lines": 200}
    cleaned6 = redact_secrets(params6)
    assert cleaned6 == params6, f"Non-sensitive data altered: {cleaned6}"

    print("  PASSED")


def test_normalize_event():
    """Normalize fills defaults, generates IDs, redacts secrets."""
    print("--- test_normalize_event ---")

    raw = {
        "agent": {"type": "hermes", "session_id": "s1", "run_id": "r1"},
        "event_type": "tool_call",
        "action": {
            "tool_name": "read_file",
            "parameters": {"path": "/etc/passwd", "Authorization": "Bearer secret123"},
            "data_accessed": ["prod_config"],
        },
        "outcome": {"status": "success", "summary": "ok"},
        "context": {"turn_number": 1, "user_message": "read the config"},
    }
    norm = normalize_event(raw)

    assert norm["event_id"], "event_id not generated"
    assert norm["timestamp"], "timestamp not generated"
    assert norm["agent"]["type"] == "hermes"
    assert norm["agent"]["session_id"] == "s1"
    assert norm["user"]["id"] == "local_user"
    assert norm["event_type"] == "tool_call"

    # Secret redacted in normalized action
    params_str = str(norm["action"]["parameters"])
    assert "secret123" not in params_str, f"Secret leak in normalized event: {params_str}"
    assert "[REDACTED]" in params_str, f"Secret not redacted: {params_str}"

    # data_accessed preserved
    assert norm["action"]["data_accessed"] == ["prod_config"]

    # Truncation of user_message
    long_msg = "x" * 600
    raw2 = {
        "agent": {"type": "claude_code", "session_id": "s2", "run_id": "r2"},
        "event_type": "model_request",
        "action": {"tool_name": None, "parameters": {}, "data_accessed": []},
        "outcome": {"status": "success"},
        "context": {"turn_number": 1, "user_message": long_msg},
    }
    norm2 = normalize_event(raw2)
    assert len(norm2["context"]["user_message"]) <= 500
    assert norm2["context"]["user_message"].endswith("...")

    print("  PASSED")


def test_validate_event():
    """Validate catches missing fields and invalid values."""
    print("--- test_validate_event ---")

    # Valid minimal event
    valid = {
        "agent": {"type": "hermes", "session_id": "s1", "run_id": "r1"},
        "event_type": "tool_call",
        "action": {"tool_name": "read_file", "parameters": {}, "data_accessed": []},
        "outcome": {"status": "success"},
        "context": {"turn_number": 1},
    }
    warnings = validate_event(valid)
    assert isinstance(warnings, list)

    # Missing agent
    try:
        validate_event({"event_type": "tool_call", "action": {}, "outcome": {"status": "success"}, "context": {}})
        assert False, "Should have raised ValidationError"
    except ValidationError:
        pass

    # Invalid agent type
    try:
        validate_event({
            "agent": {"type": "skynet", "session_id": "s1", "run_id": "r1"},
            "event_type": "tool_call",
            "action": {},
            "outcome": {"status": "success"},
            "context": {},
        })
        assert False, "Should have raised ValidationError"
    except ValidationError:
        pass

    # Invalid event_type
    try:
        validate_event({
            "agent": {"type": "hermes", "session_id": "s1", "run_id": "r1"},
            "event_type": "mind_control",
            "action": {},
            "outcome": {"status": "success"},
            "context": {},
        })
        assert False, "Should have raised ValidationError"
    except ValidationError:
        pass

    # Invalid outcome status
    try:
        validate_event({
            "agent": {"type": "hermes", "session_id": "s1", "run_id": "r1"},
            "event_type": "tool_call",
            "action": {},
            "outcome": {"status": "catastrophe"},
            "context": {},
        })
        assert False, "Should have raised ValidationError"
    except ValidationError:
        pass

    print("  PASSED")


def test_db_lifecycle():
    """Create DB, insert events from different agents, verify schema version."""
    print("--- test_db_lifecycle ---")

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test_audit.db")
        db = AuditDB(db_path)

        # Schema version should be 1
        stats = db.get_stats()
        assert stats["schema_version"] == 1, f"Expected schema_version=1, got {stats['schema_version']}"
        assert stats["total_events"] == 0

        # Insert events from different agent types
        session_ids = {}
        for agent_type in ("hermes", "claude_code", "codex"):
            sid = uuid.uuid4().hex
            session_ids[agent_type] = sid
            for i in range(3):
                eid = db.insert_event({
                    "agent": {
                        "type": agent_type,
                        "session_id": sid,
                        "run_id": uuid.uuid4().hex,
                    },
                    "event_type": "tool_call" if i % 2 == 0 else "model_response",
                    "action": {
                        "tool_name": "read_file" if i % 2 == 0 else None,
                        "parameters": {"path": f"/tmp/file_{i}.txt"},
                        "data_accessed": ["prod_db"] if i == 0 else [],
                    },
                    "outcome": {"status": "success", "summary": f"step {i}"},
                    "context": {"turn_number": i, "user_message": f"do step {i}"},
                })
                assert eid, "insert_event should return event_id"

        stats2 = db.get_stats()
        assert stats2["total_events"] == 9
        assert stats2["events_by_agent"]["hermes"] == 3
        assert stats2["events_by_agent"]["claude_code"] == 3
        assert stats2["events_by_agent"]["codex"] == 3
        assert stats2["events_by_type"]["tool_call"] == 6
        assert stats2["events_by_type"]["model_response"] == 3

        db.close()
        print("  PASSED")


def test_query_filters():
    """Query supports filtering by agent_type, event_type, time range, data_accessed, pagination."""
    print("--- test_query_filters ---")

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test_query.db")
        db = AuditDB(db_path)

        sid = uuid.uuid4().hex
        base_ts = "2026-07-05T10:00:00.000Z"

        # Insert events with known timestamps
        for i in range(5):
            ts = f"2026-07-05T10:0{i}:00.000Z"
            db.insert_event({
                "event_id": f"evt_{i}",
                "timestamp": ts,
                "agent": {"type": "hermes", "session_id": sid, "run_id": "r1"},
                "event_type": "tool_call" if i < 3 else "model_response",
                "action": {
                    "tool_name": "read_file",
                    "parameters": {},
                    "data_accessed": ["customer_db"] if i == 0 else ["config"],
                },
                "outcome": {"status": "success"},
                "context": {"turn_number": i},
            })

        # Filter by agent_type
        results = db.query(agent_type="hermes")
        assert len(results) == 5

        # Filter by event_type
        results = db.query(event_type="tool_call")
        assert len(results) == 3

        # Filter by time range
        results = db.query(since="2026-07-05T10:03:00.000Z")
        assert len(results) == 2  # evt_3, evt_4

        results = db.query(until="2026-07-05T10:01:00.000Z")
        assert len(results) == 2  # evt_0, evt_1

        results = db.query(since="2026-07-05T10:01:00.000Z", until="2026-07-05T10:03:00.000Z")
        assert len(results) == 3  # evt_1, evt_2, evt_3

        # Filter by data_accessed
        results = db.query(data_accessed="customer_db")
        assert len(results) == 1
        assert results[0]["event_id"] == "evt_0"

        results = db.query(data_accessed="config")
        assert len(results) == 4

        # Pagination
        results = db.query(limit=2, offset=1)
        assert len(results) == 2

        # Multi-filter
        results = db.query(agent_type="hermes", event_type="tool_call", limit=10)
        assert len(results) == 3

        db.close()
        print("  PASSED")


def test_evidence_chain():
    """Evidence chain reconstructs the decision path around a tool call."""
    print("--- test_evidence_chain ---")

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test_chain.db")
        db = AuditDB(db_path)

        sid = uuid.uuid4().hex

        # Simulate a realistic agent turn:
        # Turn 1: user message -> model_request -> tool_call -> tool_result -> model_response
        events = [
            {   # 0: user message / model request
                "agent": {"type": "hermes", "session_id": sid, "run_id": "r1"},
                "event_type": "model_request",
                "action": {"tool_name": None, "parameters": {}, "data_accessed": []},
                "outcome": {"status": "success", "summary": "Deciding to read config"},
                "context": {"turn_number": 1, "user_message": "Show me the production database config"},
            },
            {   # 1: tool_call
                "agent": {"type": "hermes", "session_id": sid, "run_id": "r1"},
                "event_type": "tool_call",
                "action": {
                    "tool_name": "read_file",
                    "parameters": {"path": "/etc/app/production.yaml"},
                    "target": "/etc/app/production.yaml",
                    "data_accessed": ["prod_config"],
                },
                "outcome": {"status": "success"},
                "context": {"turn_number": 1, "reasoning": "Need to read prod config to answer"},
            },
            {   # 2: tool_result
                "agent": {"type": "hermes", "session_id": sid, "run_id": "r1"},
                "event_type": "tool_result",
                "action": {
                    "tool_name": "read_file",
                    "parameters": {"path": "/etc/app/production.yaml"},
                    "data_accessed": ["prod_config"],
                },
                "outcome": {"status": "success", "summary": "Read 200 lines from production.yaml"},
                "context": {"turn_number": 1},
            },
            {   # 3: model_response
                "agent": {"type": "hermes", "session_id": sid, "run_id": "r1"},
                "event_type": "model_response",
                "action": {"tool_name": None, "parameters": {}, "data_accessed": []},
                "outcome": {"status": "success", "summary": "Database host is db.internal:5432"},
                "context": {"turn_number": 1},
                "cost": {"tokens_in": 1200, "tokens_out": 400, "estimated_usd": 0.003},
            },
            {   # 4: unrelated next turn (should NOT be in chain of turn 1)
                "agent": {"type": "hermes", "session_id": sid, "run_id": "r1"},
                "event_type": "model_request",
                "action": {"tool_name": None, "parameters": {}, "data_accessed": []},
                "outcome": {"status": "success"},
                "context": {"turn_number": 3, "user_message": "Now deploy it"},
            },
        ]

        event_ids = []
        for evt in events:
            eid = db.insert_event(evt)
            event_ids.append(eid)

        # Get evidence chain for the tool_call (event index 1)
        chain = db.get_evidence_chain(event_ids[1])
        assert len(chain) == 4, f"Expected 4 events in chain, got {len(chain)}"

        # Chain should be in chronological order
        assert chain[0]["event_type"] == "model_request"
        assert chain[1]["event_type"] == "tool_call"
        assert chain[2]["event_type"] == "tool_result"
        assert chain[3]["event_type"] == "model_response"

        # Turn 3 event should NOT be in chain
        chain_ids = {e["event_id"] for e in chain}
        assert event_ids[4] not in chain_ids, "Unrelated turn leaked into evidence chain"

        # Chain for non-existent event
        empty_chain = db.get_evidence_chain("nonexistent")
        assert empty_chain == []

        db.close()
        print("  PASSED")


def test_session_access():
    """get_session and list_sessions work correctly."""
    print("--- test_session_access ---")

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test_sessions.db")
        db = AuditDB(db_path)

        # Two sessions, different agents
        sid1 = uuid.uuid4().hex
        sid2 = uuid.uuid4().hex

        for i in range(3):
            db.insert_event({
                "agent": {"type": "hermes", "session_id": sid1, "run_id": "r1"},
                "event_type": "tool_call",
                "action": {"tool_name": "read_file", "parameters": {}, "data_accessed": []},
                "outcome": {"status": "success"},
                "context": {"turn_number": i},
            })

        for i in range(5):
            db.insert_event({
                "agent": {"type": "claude_code", "session_id": sid2, "run_id": "r2"},
                "event_type": "model_request" if i % 2 == 0 else "model_response",
                "action": {"tool_name": None, "parameters": {}, "data_accessed": []},
                "outcome": {"status": "success"},
                "context": {"turn_number": i},
            })

        # get_session
        s1_events = db.get_session(sid1)
        assert len(s1_events) == 3

        s2_events = db.get_session(sid2)
        assert len(s2_events) == 5

        # list_sessions (all)
        sessions = db.list_sessions()
        assert len(sessions) == 2
        session_ids = {s["session_id"] for s in sessions}
        assert sid1 in session_ids
        assert sid2 in session_ids

        # list_sessions filtered by agent_type
        sessions_hermes = db.list_sessions(agent_type="hermes")
        assert len(sessions_hermes) == 1
        assert sessions_hermes[0]["session_id"] == sid1
        assert sessions_hermes[0]["event_count"] == 3

        sessions_codex = db.list_sessions(agent_type="codex")
        assert len(sessions_codex) == 0

        db.close()
        print("  PASSED")


def test_validation_error_on_insert():
    """insert_event raises ValidationError for invalid events."""
    print("--- test_validation_error_on_insert ---")

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test_validation.db")
        db = AuditDB(db_path)

        # Missing agent
        try:
            db.insert_event({
                "event_type": "tool_call",
                "action": {},
                "outcome": {"status": "success"},
                "context": {},
            })
            assert False, "Should have raised ValidationError"
        except ValidationError:
            pass

        db.close()
        print("  PASSED")


def test_concurrent_access():
    """Basic thread-safety test: multiple threads inserting events."""
    print("--- test_concurrent_access ---")

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test_threads.db")
        db = AuditDB(db_path)

        errors = []
        count_per_thread = 50

        def insert_events(thread_id):
            try:
                sid = uuid.uuid4().hex
                for i in range(count_per_thread):
                    db.insert_event({
                        "agent": {"type": "hermes", "session_id": sid, "run_id": "r1"},
                        "event_type": "tool_call",
                        "action": {"tool_name": "read_file", "parameters": {}, "data_accessed": []},
                        "outcome": {"status": "success"},
                        "context": {"turn_number": i, "user_message": f"thread {thread_id} msg {i}"},
                    })
            except Exception as e:
                errors.append(str(e))

        threads = []
        for tid in range(4):
            t = threading.Thread(target=insert_events, args=(tid,))
            threads.append(t)

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"Thread errors: {errors}"

        stats = db.get_stats()
        expected = 4 * count_per_thread
        assert stats["total_events"] == expected, f"Expected {expected} events, got {stats['total_events']}"

        db.close()
        print("  PASSED")


def test_schema_version_table():
    """Schema version table tracks migrations."""
    print("--- test_schema_version_table ---")

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test_version.db")
        db = AuditDB(db_path)

        # Check via direct SQL
        import sqlite3
        conn = sqlite3.connect(db_path)
        cur = conn.execute("SELECT version, applied_at FROM schema_version ORDER BY version DESC LIMIT 1")
        row = cur.fetchone()
        assert row[0] == 1, f"Expected version 1, got {row[0]}"
        assert row[1] is not None
        conn.close()

        db.close()
        print("  PASSED")


if __name__ == "__main__":
    test_redact_secrets()
    test_normalize_event()
    test_validate_event()
    test_db_lifecycle()
    test_query_filters()
    test_evidence_chain()
    test_session_access()
    test_validation_error_on_insert()
    test_concurrent_access()
    test_schema_version_table()
    print("\n=== ALL TESTS PASSED ===")
