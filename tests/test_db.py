#!/usr/bin/env python3
"""Comprehensive tests for the panoptes storage layer.

Covers:
  - DB creation, schema versioning
  - Event insertion with normalization and secret redaction
  - Querying by agent_type, event_type, time range, data_accessed
  - Evidence chain reconstruction (turn-number and call_id paths)
  - Session listing and statistics
  - Validation errors
  - Thread safety (basic)
  - Replay preservation (call_id is correlation, not idempotency)
  - Migration from a v1 database (no call_id column)
"""

import json
import os
import sqlite3
import stat
import sys
import tempfile
import threading
import time
import uuid

import pytest

# Ensure local package is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from panoptes import AuditDB, ValidationError, normalize_event, validate_event
from panoptes.capture import HERMES_AUTHORIZER_CAPABILITIES
from panoptes.db import (
    ChainIntegrityError,
    EventConflictError,
    UnsupportedSchemaVersionError,
    _load_chain_for_append,
)
from panoptes.schema import SCHEMA_VERSION, redact_secrets


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

    # Declared tags are preserved and authoritative derivation is additive.
    assert "prod_config" in norm["action"]["data_accessed"]
    assert "secrets" in norm["action"]["data_accessed"]

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

        # Schema version should match this build.
        stats = db.get_stats()
        assert stats["schema_version"] == SCHEMA_VERSION, (
            f"Expected schema_version={SCHEMA_VERSION}, "
            f"got {stats['schema_version']}"
        )
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


def test_in_memory_database_persists_across_operation_connections():
    """The documented :memory: path shares state across DB operations."""
    print("--- test_in_memory_database_persists_across_operation_connections ---")

    db = AuditDB(":memory:")
    event_id = db.insert_event({
        "agent": {"type": "hermes", "session_id": "memory", "run_id": "run-1"},
        "event_type": "model_request",
        "action": {},
        "outcome": {"status": "success"},
        "context": {},
    })
    assert event_id
    assert db.get_stats()["total_events"] == 1
    assert [event["event_id"] for event in db.query()] == [event_id]
    assert db.get_chain_checkpoint()["event_count"] == 1
    assert db.verify_chain()["valid"]
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
    """Evidence chain reconstructs the decision path around a tool call (turn-number path)."""
    print("--- test_evidence_chain ---")

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test_chain.db")
        db = AuditDB(db_path)

        sid = uuid.uuid4().hex

        # Simulate a realistic agent turn:
        # Turn 1: user message -> model_request -> tool_call -> tool_result -> model_response
        # Each turn shares a run_id; different turns use different run_ids.
        events = [
            {   # 0: user message / model request (turn 1)
                "agent": {"type": "hermes", "session_id": sid, "run_id": "r1"},
                "event_type": "model_request",
                "action": {"tool_name": None, "parameters": {}, "data_accessed": []},
                "outcome": {"status": "success", "summary": "Deciding to read config"},
                "context": {"turn_number": 1, "user_message": "Show me the production database config"},
            },
            {   # 1: tool_call (turn 1) — no explicit call_id, so falls back to turn-number chain
                "agent": {"type": "hermes", "session_id": sid, "run_id": "r1"},
                "event_type": "tool_call",
                "action": {
                    "tool_name": "read_file",
                    "parameters": {"path": "/etc/app/production.yaml"},
                    "data_accessed": ["prod_config"],
                },
                "outcome": {"status": "success"},
                "context": {"turn_number": 1, "reasoning": "Need to read prod config to answer"},
            },
            {   # 2: tool_result (turn 1)
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
            {   # 3: model_response (turn 1)
                "agent": {"type": "hermes", "session_id": sid, "run_id": "r1"},
                "event_type": "model_response",
                "action": {"tool_name": None, "parameters": {}, "data_accessed": []},
                "outcome": {"status": "success", "summary": "Database host is db.internal:5432"},
                "context": {"turn_number": 1},
                "cost": {"tokens_in": 1200, "tokens_out": 400, "estimated_usd": 0.003},
            },
            {   # 4: unrelated next turn (different run_id, turn 3 → should NOT be in chain)
                "agent": {"type": "hermes", "session_id": sid, "run_id": "r2"},
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
        # tool_call has no explicit call_id and no target → falls back to turn-number chain
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


def test_evidence_chain_via_call_id():
    """Evidence chain uses call_id + run_id when available (call_id path)."""
    print("--- test_evidence_chain_via_call_id ---")

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test_chain_callid.db")
        db = AuditDB(db_path)

        sid = uuid.uuid4().hex
        call_id = "call-abc-123"

        # Exchange: model_request + tool_call + tool_result + model_response
        # All share run_id "run-turn1"; tool_call and tool_result share call_id
        events = [
            {
                "agent": {"type": "hermes", "session_id": sid, "run_id": "run-turn1"},
                "event_type": "model_request",
                "action": {"tool_name": None, "parameters": {}, "data_accessed": []},
                "outcome": {"status": "success"},
                "context": {"turn_number": 1},
            },
            {
                "agent": {"type": "hermes", "session_id": sid, "run_id": "run-turn1"},
                "event_type": "tool_call",
                "action": {
                    "tool_name": "bash",
                    "parameters": {"command": "ls /prod/"},
                    "call_id": call_id,
                    "data_accessed": ["prod"],
                },
                "outcome": {"status": "success"},
                "context": {"turn_number": 1},
            },
            {
                "agent": {"type": "hermes", "session_id": sid, "run_id": "run-turn1"},
                "event_type": "tool_result",
                "action": {
                    "tool_name": "bash",
                    "parameters": {},
                    "call_id": call_id,
                    "data_accessed": ["prod"],
                },
                "outcome": {"status": "success", "summary": "config.yaml"},
                "context": {"turn_number": 1},
            },
            {
                "agent": {"type": "hermes", "session_id": sid, "run_id": "run-turn1"},
                "event_type": "model_response",
                "action": {"tool_name": None, "parameters": {}, "data_accessed": []},
                "outcome": {"status": "success", "summary": "Listed files"},
                "context": {"turn_number": 1},
            },
            {   # Unrelated turn 2 with different run_id — must NOT appear in chain
                "agent": {"type": "hermes", "session_id": sid, "run_id": "run-turn2"},
                "event_type": "model_request",
                "action": {"tool_name": None, "parameters": {}, "data_accessed": []},
                "outcome": {"status": "success"},
                "context": {"turn_number": 2},
            },
        ]

        event_ids = []
        for evt in events:
            eid = db.insert_event(evt)
            event_ids.append(eid)

        # Get evidence chain anchored on the tool_call (has explicit call_id)
        chain = db.get_evidence_chain(event_ids[1])

        # Chain should contain all 4 events from run-turn1 (via run_id match)
        # plus the tool_call and tool_result (via call_id match) — total 4 distinct events
        assert len(chain) == 4, f"Expected 4 events in call_id chain, got {len(chain)}"

        chain_types = [e["event_type"] for e in chain]
        assert "tool_call" in chain_types
        assert "tool_result" in chain_types
        assert "model_request" in chain_types
        assert "model_response" in chain_types

        # Unrelated turn 2 event must not be in chain
        chain_ids = {e["event_id"] for e in chain}
        assert event_ids[4] not in chain_ids, "Unrelated turn leaked into call_id chain"

        db.close()
        print("  PASSED")


def test_evidence_chain_temporal_fallback_parses_iso8601():
    """The no-turn fallback compares timestamp instants, not text formats."""
    print("--- test_evidence_chain_temporal_fallback_parses_iso8601 ---")

    with tempfile.TemporaryDirectory() as tmpdir:
        db = AuditDB(os.path.join(tmpdir, "evidence-time.db"))
        timestamps = {
            "before": "2026-07-10T09:59:30.000Z",
            "anchor": "2026-07-10T10:00:00.000Z",
            "after": "2026-07-10T10:00:45.000Z",
            "outside": "2026-07-10T10:01:30.000Z",
        }
        for event_id, timestamp in timestamps.items():
            db.insert_event({
                "event_id": event_id,
                "timestamp": timestamp,
                "agent": {
                    "type": "hermes",
                    "session_id": "time-window",
                    "run_id": event_id,
                },
                "event_type": "model_request",
                "action": {},
                "outcome": {"status": "success"},
                "context": {},
            })

        chain = db.get_evidence_chain("anchor")
        assert [event["event_id"] for event in chain] == [
            "before",
            "anchor",
            "after",
        ]
        db.close()

    print("  PASSED")


def test_tool_result_replays_are_preserved():
    """Repeated tool_result observations with one call_id remain distinct."""
    print("--- test_tool_result_replays_are_preserved ---")

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test_dedup.db")
        db = AuditDB(db_path)

        sid = uuid.uuid4().hex
        call_id = "provider-call-xyz-789"

        base_event = {
            "agent": {"type": "hermes", "session_id": sid, "run_id": "r1"},
            "event_type": "tool_result",
            "action": {
                "tool_name": "bash",
                "parameters": {"output": "hello"},
                "call_id": call_id,
                "data_accessed": [],
            },
            "outcome": {"status": "success", "summary": "done"},
            "context": {"turn_number": 1},
        }

        # Re-delivery is itself audit evidence, even when the payload matches.
        eid1 = db.insert_event(dict(base_event))
        eid2 = db.insert_event(dict(base_event))

        assert eid1 and eid2
        assert eid1 != eid2
        stats = db.get_stats()
        assert stats["total_events"] == 2
        assert db.get_chain_checkpoint()["event_count"] == 2
        assert db.verify_chain()["valid"]

        db.close()
        print("  PASSED")


def test_tool_call_replays_are_preserved():
    """Repeated tool_call observations with one call_id remain distinct."""
    print("--- test_tool_call_replays_are_preserved ---")

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test_dedup_call.db")
        db = AuditDB(db_path)

        sid = uuid.uuid4().hex
        call_id = "call-dedup-001"

        base = {
            "agent": {"type": "claude_code", "session_id": sid, "run_id": "r1"},
            "event_type": "tool_call",
            "action": {
                "tool_name": "Write",
                "parameters": {"file_path": "/tmp/test.txt", "content": "hello"},
                "call_id": call_id,
                "data_accessed": [],
            },
            "outcome": {"status": "success"},
            "context": {"turn_number": 3},
        }

        eid1 = db.insert_event(dict(base))
        eid2 = db.insert_event(dict(base))
        eid3 = db.insert_event(dict(base))

        assert len({eid1, eid2, eid3}) == 3

        results = db.query(event_type="tool_call")
        assert len(results) == 3
        assert db.get_chain_checkpoint()["event_count"] == 3
        assert db.verify_chain()["valid"]

        db.close()
        print("  PASSED")


def test_call_id_is_correlation_not_idempotency():
    """A call_id never suppresses a distinct event, matching or changed."""
    print("--- test_call_id_is_correlation_not_idempotency ---")

    with tempfile.TemporaryDirectory() as tmpdir:
        db = AuditDB(os.path.join(tmpdir, "semantic-dedup.db"))
        base = {
            "event_id": "call-observation-1",
            "timestamp": "2026-07-10T10:00:00.000Z",
            "agent": {
                "type": "claude_code",
                "session_id": "semantic-session",
                "run_id": "run-1",
            },
            "event_type": "tool_call",
            "action": {
                "tool_name": "Write",
                "parameters": {
                    "file_path": "/tmp/test.txt",
                    "content": "hello",
                },
                "call_id": "provider-call-stable",
                "data_accessed": [],
            },
            "outcome": {"status": "success"},
            "context": {"turn_number": 1, "user_message": "first observation"},
        }

        first_id = db.insert_event(base)
        before = db.get_chain_checkpoint()

        # Replayed history can be observed in a later run/turn and receive a
        # new event envelope while still representing the exact same call.
        replay = {
            **base,
            "event_id": "call-observation-2",
            "timestamp": "2026-07-10T10:05:00.000Z",
            "agent": {
                **base["agent"],
                "run_id": "run-2",
            },
            "context": {
                "turn_number": 9,
                "user_message": "history replay",
            },
        }
        replay_id = db.insert_event(replay)
        assert replay_id != first_id
        after_replay = db.get_chain_checkpoint()
        assert after_replay["event_count"] == before["event_count"] + 1
        assert after_replay["head"] != before["head"]
        assert db.get_stats()["total_events"] == 2

        changed_work = {
            **replay,
            "event_id": "call-observation-3",
            "action": {
                **base["action"],
                "parameters": {
                    "file_path": "/tmp/test.txt",
                    "content": "different content",
                },
            },
        }
        changed_id = db.insert_event(changed_work)
        assert len({first_id, replay_id, changed_id}) == 3
        assert db.get_chain_checkpoint()["event_count"] == 3
        assert db.get_stats()["total_events"] == 3
        assert db.verify_chain()["valid"]
        db.close()

    print("  PASSED")


def test_call_id_correlation_across_sessions():
    """The same call_id can correlate events without imposing uniqueness."""
    print("--- test_call_id_correlation_across_sessions ---")

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test_dedup_sessions.db")
        db = AuditDB(db_path)

        call_id = "shared-call-id"

        for sid in ("sess-A", "sess-B"):
            db.insert_event({
                "agent": {"type": "hermes", "session_id": sid, "run_id": "r1"},
                "event_type": "tool_result",
                "action": {
                    "tool_name": "bash",
                    "parameters": {},
                    "call_id": call_id,
                    "data_accessed": [],
                },
                "outcome": {"status": "success"},
                "context": {},
            })

        results = db.query(event_type="tool_result")
        assert len(results) == 2, (
            f"Same call_id in different sessions should produce 2 rows, got {len(results)}"
        )

        db.close()
        print("  PASSED")


def test_migration_v1_to_v2():
    """Opening a v1 DB adds call_id without treating targets as replay keys."""
    print("--- test_migration_v1_to_v2 ---")

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "v1_legacy.db")

        # ── Build a v1 database manually ─────────────────────────────────
        conn = sqlite3.connect(db_path)
        conn.execute("""
            CREATE TABLE schema_version (
                version INTEGER PRIMARY KEY,
                applied_at TEXT NOT NULL DEFAULT (datetime('now'))
            )
        """)
        conn.execute("INSERT INTO schema_version (version) VALUES (1)")
        conn.execute("""
            CREATE TABLE events (
                event_id        TEXT PRIMARY KEY,
                timestamp       TEXT    NOT NULL,
                agent_type      TEXT    NOT NULL DEFAULT 'unknown',
                session_id      TEXT    NOT NULL,
                run_id          TEXT,
                event_type      TEXT    NOT NULL,
                tool_name       TEXT,
                data_accessed   TEXT    DEFAULT '',
                agent           TEXT    NOT NULL,
                user_info       TEXT    NOT NULL,
                action          TEXT    NOT NULL,
                outcome         TEXT    NOT NULL,
                context         TEXT    NOT NULL,
                cost            TEXT    NOT NULL,
                raw_request     TEXT,
                raw_response    TEXT
            )
        """)

        # Two legitimate tool_result rows happen to share a resource target.
        action_json = json.dumps({
            "tool_name": "bash",
            "parameters": {},
            "target": "call-legacy-001",
            "data_accessed": [],
        })
        agent_json = json.dumps({"type": "hermes", "session_id": "sess-v1", "run_id": "r1"})
        for evt_id, ts in [("dup-1", "2026-07-05T09:00:00.000Z"),
                            ("dup-2", "2026-07-05T09:01:00.000Z")]:
            conn.execute(
                "INSERT INTO events VALUES (?, ?, 'hermes', 'sess-v1', 'r1', "
                "'tool_result', 'bash', '', ?, '{}', ?, '{}', '{}', '{}', NULL, NULL)",
                (evt_id, ts, agent_json, action_json),
            )

        # A non-duplicate model_request row (should be unaffected)
        conn.execute(
            "INSERT INTO events VALUES ('unique-1', '2026-07-05T09:00:30.000Z', "
            "'hermes', 'sess-v1', 'r1', 'model_request', NULL, '', ?, '{}', '{}', '{}', '{}', '{}', NULL, NULL)",
            (agent_json,),
        )
        conn.commit()
        conn.close()

        # ── Open with AuditDB — migration should run ──────────────────────
        db = AuditDB(db_path)

        # Verify migration reached the current schema in one transaction.
        stats = db.get_stats()
        assert stats["schema_version"] == SCHEMA_VERSION, (
            f"Expected schema_version={SCHEMA_VERSION} after migration, "
            f"got {stats['schema_version']}"
        )

        db.close()

        # ── Verify via raw sqlite3 ────────────────────────────────────────
        raw = sqlite3.connect(db_path)

        # call_id column must exist
        col_names = {r[1] for r in raw.execute("PRAGMA table_info(events)")}
        assert "call_id" in col_names, "call_id column missing after migration"

        # call_id is indexed for correlation but never constrained unique.
        index_names = {r[1] for r in raw.execute("PRAGMA index_list(events)")}
        assert "idx_events_call_id" in index_names
        assert "idx_events_dedup" not in index_names

        # A target is not a true idempotency key, so both rows survive.
        rows = list(raw.execute(
            "SELECT event_id FROM events WHERE event_type = 'tool_result'"
        ))
        assert {row[0] for row in rows} == {"dup-1", "dup-2"}

        # No explicit action.call_id existed, so no replay key is fabricated.
        call_ids = {
            row[0] for row in raw.execute(
                "SELECT call_id FROM events WHERE event_type = 'tool_result'"
            )
        }
        assert call_ids == {""}

        # Non-duplicate model_request row still present
        rows2 = list(raw.execute(
            "SELECT event_id FROM events WHERE event_type = 'model_request'"
        ))
        assert len(rows2) == 1 and rows2[0][0] == "unique-1"

        raw.close()
        print("  PASSED")


def test_migration_preserves_all_duplicate_call_ids():
    """Migration never erases matching or conflicting legacy call deliveries."""
    print("--- test_migration_preserves_all_duplicate_call_ids ---")

    def create_v1(path, second_content):
        conn = sqlite3.connect(path)
        conn.execute("""
            CREATE TABLE schema_version (
                version INTEGER PRIMARY KEY,
                applied_at TEXT NOT NULL DEFAULT (datetime('now'))
            )
        """)
        conn.execute("INSERT INTO schema_version (version) VALUES (1)")
        conn.execute("""
            CREATE TABLE events (
                event_id        TEXT PRIMARY KEY,
                timestamp       TEXT NOT NULL,
                agent_type      TEXT NOT NULL DEFAULT 'unknown',
                session_id      TEXT NOT NULL,
                run_id          TEXT,
                event_type      TEXT NOT NULL,
                tool_name       TEXT,
                data_accessed   TEXT DEFAULT '',
                agent           TEXT NOT NULL,
                user_info       TEXT NOT NULL,
                action          TEXT NOT NULL,
                outcome         TEXT NOT NULL,
                context         TEXT NOT NULL,
                cost            TEXT NOT NULL,
                raw_request     TEXT,
                raw_response    TEXT
            )
        """)
        for index, content in enumerate(("same", second_content), start=1):
            action = json.dumps({
                "tool_name": "Write",
                "parameters": {"path": "/tmp/a", "content": content},
                "call_id": "legacy-provider-call",
            })
            agent = json.dumps({
                "type": "hermes",
                "session_id": "legacy-session",
                "run_id": f"run-{index}",
            })
            context = json.dumps({"turn_number": index})
            conn.execute(
                """
                INSERT INTO events (
                    event_id, timestamp, agent_type, session_id, run_id,
                    event_type, tool_name, data_accessed, agent, user_info,
                    action, outcome, context, cost, raw_request, raw_response
                ) VALUES (?, ?, 'hermes', 'legacy-session', ?, 'tool_call',
                          'Write', '', ?, '{}', ?, '{"status":"success"}',
                          ?, '{}', NULL, NULL)
                """,
                (
                    f"legacy-{index}",
                    f"2026-07-10T10:0{index}:00.000Z",
                    f"run-{index}",
                    agent,
                    action,
                    context,
                ),
            )
        conn.commit()
        conn.close()

    with tempfile.TemporaryDirectory() as tmpdir:
        replay_path = os.path.join(tmpdir, "replay.db")
        create_v1(replay_path, "same")
        replay_db = AuditDB(replay_path)
        replay_rows = replay_db.query(event_type="tool_call", limit=10)
        assert {row["event_id"] for row in replay_rows} == {
            "legacy-1",
            "legacy-2",
        }
        checkpoint = replay_db.get_chain_checkpoint()
        assert checkpoint["legacy_event_count"] == 2
        assert checkpoint["event_count"] == 0
        replay_db.close()

        conflict_path = os.path.join(tmpdir, "conflict.db")
        create_v1(conflict_path, "changed")
        conflict_db = AuditDB(conflict_path)
        conflict_rows = conflict_db.query(event_type="tool_call", limit=10)
        assert {row["event_id"] for row in conflict_rows} == {
            "legacy-1",
            "legacy-2",
        }
        assert {
            row["action"]["parameters"]["content"] for row in conflict_rows
        } == {"same", "changed"}
        assert conflict_db.get_chain_checkpoint()["legacy_event_count"] == 2
        conflict_db.close()

        raw = sqlite3.connect(conflict_path)
        indexes = {row[1] for row in raw.execute("PRAGMA index_list(events)")}
        raw.close()
        assert "idx_events_call_id" in indexes
        assert "idx_events_dedup" not in indexes

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
        checkpoint = db.get_chain_checkpoint()
        assert checkpoint["event_count"] == expected
        verification = db.verify_chain()
        assert verification["valid"], verification
        assert verification["checked_events"] == expected

        db.close()
        print("  PASSED")


def test_concurrent_batches_across_db_instances_do_not_fork_chain():
    """Independent writers serialize the shared chain head transactionally."""
    print("--- test_concurrent_batches_across_db_instances_do_not_fork_chain ---")

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "multi-writer.db")
        first = AuditDB(db_path)
        second = AuditDB(db_path)
        errors = []

        def write_batch(db, start):
            try:
                db.insert_events([
                    {
                        "event_id": f"concurrent-{i}",
                        "timestamp": f"2026-07-10T10:00:{i:02d}.000Z",
                        "agent": {
                            "type": "hermes",
                            "session_id": "shared-session",
                            "run_id": f"run-{i}",
                        },
                        "event_type": "model_request",
                        "action": {},
                        "outcome": {"status": "success"},
                        "context": {"turn_number": i},
                    }
                    for i in range(start, start + 20)
                ])
            except Exception as exc:
                errors.append(exc)

        threads = [
            threading.Thread(target=write_batch, args=(first, 0)),
            threading.Thread(target=write_batch, args=(second, 20)),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert not errors, errors
        checkpoint = first.get_chain_checkpoint()
        assert checkpoint["event_count"] == 40
        verification = second.verify_chain()
        assert verification["valid"], verification
        assert verification["checked_events"] == 40

        first.close()
        second.close()
        reopened = AuditDB(db_path)
        assert reopened.verify_chain()["valid"]
        reopened.close()

    print("  PASSED")


def test_short_lived_threads_release_connections():
    """A request thread must not leave its SQLite connection open forever."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db = AuditDB(os.path.join(tmpdir, "connections.db"))

        def read_stats():
            db.get_stats()

        for _ in range(25):
            thread = threading.Thread(target=read_stats)
            thread.start()
            thread.join()

        assert len(db._all_conns) == 0
        db.close()


def test_schema_version_table():
    """Schema version table tracks migrations."""
    print("--- test_schema_version_table ---")

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test_version.db")
        db = AuditDB(db_path)

        # Check via direct SQL
        conn = sqlite3.connect(db_path)
        cur = conn.execute("SELECT version, applied_at FROM schema_version ORDER BY version DESC LIMIT 1")
        row = cur.fetchone()
        assert row[0] == SCHEMA_VERSION, (
            f"Expected version {SCHEMA_VERSION}, got {row[0]}"
        )
        assert row[1] is not None
        conn.close()

        db.close()
        print("  PASSED")


def test_future_schema_version_is_rejected():
    """A newer database must not be interpreted with older code."""
    print("--- test_future_schema_version_is_rejected ---")

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "future.db")
        conn = sqlite3.connect(db_path)
        conn.execute("""
            CREATE TABLE schema_version (
                version INTEGER PRIMARY KEY,
                applied_at TEXT NOT NULL DEFAULT (datetime('now'))
            )
        """)
        conn.execute(
            "INSERT INTO schema_version (version) VALUES (?)",
            (SCHEMA_VERSION + 1,),
        )
        # A future release is free to change the events layout. Version
        # rejection must happen before today's indexes inspect these columns.
        conn.execute("CREATE TABLE events (future_only TEXT)")
        conn.commit()
        conn.close()

        try:
            AuditDB(db_path)
            assert False, "A future schema version must be rejected"
        except UnsupportedSchemaVersionError as exc:
            message = str(exc)
            assert str(SCHEMA_VERSION + 1) in message
            assert str(SCHEMA_VERSION) in message
            assert "refusing to open" in message

        check = sqlite3.connect(db_path)
        columns = [row[1] for row in check.execute("PRAGMA table_info(events)")]
        check.close()
        assert columns == ["future_only"]

    print("  PASSED")


def test_insert_events_batch():
    """insert_events inserts a batch atomically and returns ids in order."""
    print("--- test_insert_events_batch ---")

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test_batch.db")
        db = AuditDB(db_path)

        sid = uuid.uuid4().hex

        def _evt(n):
            return {
                "agent": {"type": "hermes", "session_id": sid, "run_id": "r1"},
                "event_type": "tool_call",
                "action": {
                    "tool_name": f"tool_{n}",
                    "parameters": {},
                    "data_accessed": [],
                },
                "outcome": {"status": "success"},
                "context": {"turn_number": n},
            }

        events = [_evt(i) for i in range(3)]
        ids = db.insert_events(events)

        # Must return the right number of ids
        assert len(ids) == 3, f"Expected 3 ids, got {len(ids)}"
        # All ids must be non-empty strings
        assert all(isinstance(eid, str) and eid for eid in ids), f"Bad ids: {ids}"
        # All ids must be distinct (no accidental dedup across unrelated events)
        assert len(set(ids)) == 3, f"Expected 3 distinct ids, got {ids}"

        # All events must be in the DB
        stats = db.get_stats()
        assert stats["total_events"] == 3
        checkpoint = db.get_chain_checkpoint()
        assert checkpoint["event_count"] == 3
        assert checkpoint["coverage"] == "complete"
        assert checkpoint["checkpoint_scope"] == "database_internal"
        assert checkpoint["external_anchor_required"] is True
        assert db.verify_chain()["valid"]

        # insert_event (single) still works and shares the code path
        eid_single = db.insert_event(_evt(99))
        assert isinstance(eid_single, str) and eid_single

        db.close()
        print("  PASSED")


def test_event_id_conflicts_and_invalid_events_are_never_silent():
    """Only an identical canonical payload may reuse an event_id."""
    print("--- test_event_id_conflicts_and_invalid_events_are_never_silent ---")

    with tempfile.TemporaryDirectory() as tmpdir:
        db = AuditDB(os.path.join(tmpdir, "conflicts.db"))
        event = {
            "event_id": "fixed-event-id",
            "timestamp": "2026-07-10T10:00:00.000Z",
            "agent": {"type": "hermes", "session_id": "s1", "run_id": "r1"},
            "event_type": "model_request",
            "action": {},
            "outcome": {"status": "success", "summary": "original"},
            "context": {"turn_number": 1},
        }

        first = db.insert_event(event)
        before = db.get_chain_checkpoint()
        assert db.insert_event(event) == first
        assert db.get_chain_checkpoint() == before

        conflicting = {
            **event,
            "outcome": {"status": "error", "summary": "rewritten"},
        }
        try:
            db.insert_event(conflicting)
            assert False, "A conflicting event_id must not be silently ignored"
        except EventConflictError as exc:
            assert "different canonical payload" in str(exc)

        invalid = {
            "event_id": "invalid-null-session",
            "agent": {"type": "hermes", "session_id": None, "run_id": "r1"},
            "event_type": "model_request",
            "action": {},
            "outcome": {"status": "success"},
            "context": {},
        }
        try:
            db.insert_event(invalid)
            assert False, "An invalid NOT NULL field must fail visibly"
        except (ValidationError, sqlite3.IntegrityError):
            pass

        rows = db.query(limit=20)
        assert len(rows) == 1
        assert rows[0]["outcome"]["summary"] == "original"
        assert db.get_chain_checkpoint() == before
        assert db.verify_chain()["valid"]
        db.close()

    print("  PASSED")


def test_redaction_cannot_collapse_distinct_secret_bearing_event_replays():
    """Duplicate IDs with erased secret differences must fail, never disappear."""
    print("--- test_redaction_cannot_collapse_distinct_secret_bearing_event_replays ---")

    with tempfile.TemporaryDirectory() as tmpdir:
        db = AuditDB(os.path.join(tmpdir, "redacted-conflicts.db"))
        base = {
            "event_id": "secret-bearing-event",
            "timestamp": "2026-07-10T10:00:00.000Z",
            "agent": {"type": "hermes", "session_id": "s1", "run_id": "r1"},
            "event_type": "tool_call",
            "action": {
                "tool_name": "database_login",
                "parameters": {"username": "alice", "password": "first-secret"},
            },
            "outcome": {"status": "pending"},
            "context": {},
        }

        db.insert_event(base)
        before = db.get_chain_checkpoint()

        for retry in (
            base,
            {
                **base,
                "action": {
                    **base["action"],
                    "parameters": {
                        "username": "alice",
                        "password": "different-secret",
                    },
                },
            },
        ):
            try:
                db.insert_event(retry)
                assert False, "A raw secret-bearing duplicate ID must conflict"
            except EventConflictError as exc:
                assert "cannot be proven identical" in str(exc)

        # A canonical read-back contains only the placeholder and is safe to
        # replay idempotently for transport recovery.
        stored = db.query(limit=1)[0]
        assert stored["action"]["parameters"]["password"] == "[REDACTED]"
        assert db.insert_event(stored) == base["event_id"]
        assert db.get_chain_checkpoint() == before
        assert db.get_stats()["total_events"] == 1
        assert db.verify_chain()["valid"]
        db.close()

    print("  PASSED")


def test_explicit_event_id_requires_stable_timestamp():
    """Generated timestamps cannot underpin stable event_id idempotency."""
    print("--- test_explicit_event_id_requires_stable_timestamp ---")

    with tempfile.TemporaryDirectory() as tmpdir:
        db = AuditDB(os.path.join(tmpdir, "stable-envelope.db"))
        event = {
            "event_id": "stable-id",
            "agent": {"type": "hermes", "session_id": "s1", "run_id": "r1"},
            "event_type": "model_request",
            "action": {},
            "outcome": {"status": "success"},
            "context": {},
        }
        for _ in range(2):
            try:
                db.insert_event(event)
                assert False, "A stable event_id needs a stable timestamp"
            except ValidationError as exc:
                assert "timestamp is required when event_id is provided" in str(exc)

        assert db.get_stats()["total_events"] == 0
        assert db.get_chain_checkpoint()["event_count"] == 0
        db.close()

    print("  PASSED")


def test_query_round_trip_is_idempotent_with_derived_metadata():
    """A stored canonical event can be replayed without advancing the chain."""
    print("--- test_query_round_trip_is_idempotent_with_derived_metadata ---")

    with tempfile.TemporaryDirectory() as tmpdir:
        db = AuditDB(os.path.join(tmpdir, "round-trip.db"))
        event = {
            "event_id": "round-trip-prod",
            "timestamp": "2026-07-10T10:00:00.000Z",
            "agent": {
                "type": "hermes",
                "session_id": "round-trip-session",
                "run_id": "round-trip-run",
            },
            "event_type": "tool_call",
            "action": {
                "tool_name": "read_file",
                "parameters": {"path": "/srv/prod/config.json"},
                "target": "/srv/prod/config.json",
            },
            "outcome": {"status": "success"},
            "context": {"turn_number": 1},
        }

        assert db.insert_event(event) == "round-trip-prod"
        stored = db.query(limit=1)[0]
        assert "prod" in stored["action"]["derived_data_accessed"]
        assert "prod" in stored["action"]["data_accessed"]
        before = db.get_chain_checkpoint()

        assert db.insert_event(stored) == "round-trip-prod"
        assert db.get_chain_checkpoint() == before
        assert db.get_stats()["total_events"] == 1
        assert db.verify_chain()["valid"]
        db.close()

    print("  PASSED")


def test_query_round_trip_is_idempotent_with_safe_capture_metadata():
    """A safe authorization phase label is not mistaken for lost credentials."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db = AuditDB(os.path.join(tmpdir, "capture-replay.db"))
        event = normalize_event({
            "event_id": "capture-replay-event",
            "timestamp": "2026-07-17T12:00:00Z",
            "agent": {
                "type": "hermes",
                "session_id": "capture-session",
                "run_id": "capture-run",
            },
            "event_type": "decision_point",
            "action": {
                "tool_name": "read_file",
                "parameters": {"path": "README.md"},
            },
            "outcome": {"status": "success"},
            "context": {
                "capture": HERMES_AUTHORIZER_CAPABILITIES.as_context(
                    authorization_check="pre_execution",
                ),
            },
        })

        event_id = db.insert_event(event)
        before = db.get_chain_checkpoint()
        stored = db.query(event_type="decision_point", limit=1)[0]

        assert db.insert_event(stored) == event_id
        assert db.get_chain_checkpoint() == before
        db.close()


def test_shared_target_without_call_id_is_not_deduplicated():
    """Repeated calls to one resource remain distinct without a true call_id."""
    print("--- test_shared_target_without_call_id_is_not_deduplicated ---")

    with tempfile.TemporaryDirectory() as tmpdir:
        db = AuditDB(os.path.join(tmpdir, "targets.db"))
        ids = []
        for i, content in enumerate(("first", "second")):
            ids.append(db.insert_event({
                "event_id": f"target-event-{i}",
                "timestamp": f"2026-07-10T10:00:0{i}.000Z",
                "agent": {"type": "hermes", "session_id": "s1", "run_id": "r1"},
                "event_type": "tool_call",
                "action": {
                    "tool_name": "write_file",
                    "target": "/tmp/shared.txt",
                    "parameters": {"content": content},
                },
                "outcome": {"status": "success"},
                "context": {"turn_number": i},
            }))

        assert ids == ["target-event-0", "target-event-1"]
        assert len(db.query(event_type="tool_call", limit=20)) == 2
        assert db.get_chain_checkpoint()["event_count"] == 2
        assert db.verify_chain()["valid"]
        db.close()

    print("  PASSED")


def test_hash_chain_detects_canonical_payload_tampering():
    """Changing a persisted event breaks verification at that event."""
    print("--- test_hash_chain_detects_canonical_payload_tampering ---")

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "tamper.db")
        db = AuditDB(db_path)
        for i in range(3):
            db.insert_event({
                "event_id": f"chain-{i}",
                "timestamp": f"2026-07-10T10:00:0{i}.000Z",
                "agent": {"type": "hermes", "session_id": "s1", "run_id": "r1"},
                "event_type": "model_request",
                "action": {"sequence": i},
                "outcome": {"status": "success"},
                "context": {"turn_number": i},
            })

        checkpoint = db.get_chain_checkpoint()
        assert checkpoint["initialized"]
        assert checkpoint["event_count"] == 3
        assert checkpoint["first_event_id"] == "chain-0"
        assert checkpoint["last_event_id"] == "chain-2"
        assert db.verify_chain()["valid"]

        raw = sqlite3.connect(db_path)
        raw.execute(
            "UPDATE events SET outcome = ? WHERE event_id = 'chain-1'",
            (json.dumps({"status": "blocked", "summary": "forged"}),),
        )
        raw.commit()
        raw.close()

        verification = db.verify_chain()
        assert not verification["valid"]
        assert verification["broken_event_id"] == "chain-1"
        assert "hash mismatch" in verification["error"].lower()
        db.close()

    print("  PASSED")


def test_chain_append_validation_is_indexed_not_history_scanning():
    """The ingest hot path validates only the metadata-addressed chain head."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "append-cost.db")
        db = AuditDB(db_path)
        db.insert_event({
            "event_id": "append-cost-1",
            "timestamp": "2026-07-10T10:00:00.000Z",
            "agent": {
                "type": "hermes",
                "session_id": "append-cost-session",
                "run_id": "append-cost-run",
            },
            "event_type": "model_request",
            "action": {},
            "outcome": {"status": "success"},
            "context": {},
        })

        raw = sqlite3.connect(db_path)
        raw.row_factory = sqlite3.Row
        statements = []

        class _RecordingConnection:
            def execute(self, sql, parameters=()):
                statements.append(" ".join(sql.split()).upper())
                return raw.execute(sql, parameters)

        checkpoint = _load_chain_for_append(_RecordingConnection())
        assert checkpoint["event_count"] == 1
        assert not any("COUNT(" in statement for statement in statements)
        assert any("WHERE EVENT_ID = ?" in statement for statement in statements)
        raw.close()

        # Minimal hot-path validation still refuses a changed recorded head.
        tamper = sqlite3.connect(db_path)
        tamper.execute(
            "UPDATE events SET event_hash = ? WHERE event_id = ?",
            ("0" * 64, "append-cost-1"),
        )
        tamper.commit()
        tamper.close()
        with pytest.raises(ChainIntegrityError, match="recorded head"):
            db.insert_event({
                "agent": {
                    "type": "hermes",
                    "session_id": "append-cost-session",
                    "run_id": "append-cost-run-2",
                },
                "event_type": "model_request",
                "action": {},
                "outcome": {"status": "success"},
                "context": {},
            })
        db.close()


def test_verify_checkpoint_exact_prefix_and_tampering():
    """External checkpoints must identify an exact verified chain prefix."""
    print("--- test_verify_checkpoint_exact_prefix_and_tampering ---")

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "external-checkpoint.db")
        db = AuditDB(db_path)

        def insert(index):
            db.insert_event({
                "event_id": f"checkpoint-{index}",
                "timestamp": f"2026-07-10T10:00:{index:02d}.000Z",
                "agent": {
                    "type": "hermes",
                    "session_id": "checkpoint-session",
                    "run_id": f"run-{index}",
                },
                "event_type": "model_request",
                "action": {},
                "outcome": {"status": "success"},
                "context": {"turn_number": index},
            })

        insert(1)
        insert(2)
        external = db.get_chain_checkpoint()

        exact = db.verify_checkpoint(external)
        assert exact["valid"]
        assert exact["exact"]
        assert exact["appended_events"] == 0
        assert exact["checkpoint_event_count"] == 2
        assert exact["current_event_count"] == 2

        insert(3)
        insert(4)
        prefix = db.verify_checkpoint(external)
        assert prefix["valid"]
        assert not prefix["exact"]
        assert prefix["appended_events"] == 2
        assert prefix["current_event_count"] == 4

        forged_head = {**external, "head": "0" * 64}
        mismatch = db.verify_checkpoint(forged_head)
        assert not mismatch["valid"]
        assert mismatch["appended_events"] is None
        assert "not the chain prefix" in mismatch["error"]

        forged_boundary = {
            **external,
            "legacy_event_count": external["legacy_event_count"] + 1,
        }
        boundary = db.verify_checkpoint(forged_boundary)
        assert not boundary["valid"]
        assert "legacy_event_count" in boundary["error"]

        ahead = {
            **external,
            "event_count": 99,
            "last_event_id": "does-not-exist",
        }
        future = db.verify_checkpoint(ahead)
        assert not future["valid"]
        assert "ahead" in future["error"]

        raw = sqlite3.connect(db_path)
        raw.execute(
            "UPDATE events SET outcome = ? WHERE event_id = 'checkpoint-3'",
            (json.dumps({"status": "blocked"}),),
        )
        raw.commit()
        raw.close()
        corrupt = db.verify_checkpoint(external)
        assert not corrupt["valid"]
        assert corrupt["error"].startswith("Current hash chain is invalid:")
        db.close()

    print("  PASSED")


def test_batch_conflict_rolls_back_events_and_chain_head():
    """A late conflict rolls back earlier batch rows and chain metadata."""
    print("--- test_batch_conflict_rolls_back_events_and_chain_head ---")

    with tempfile.TemporaryDirectory() as tmpdir:
        db = AuditDB(os.path.join(tmpdir, "rollback-chain.db"))
        original = {
            "event_id": "existing",
            "timestamp": "2026-07-10T10:00:00.000Z",
            "agent": {"type": "hermes", "session_id": "s1", "run_id": "r1"},
            "event_type": "model_request",
            "action": {},
            "outcome": {"status": "success"},
            "context": {},
        }
        db.insert_event(original)
        before = db.get_chain_checkpoint()

        new_event = {
            "event_id": "would-have-been-inserted",
            "timestamp": "2026-07-10T10:00:01.000Z",
            "agent": {"type": "hermes", "session_id": "s1", "run_id": "r2"},
            "event_type": "model_request",
            "action": {},
            "outcome": {"status": "success"},
            "context": {},
        }
        conflicting = {
            **original,
            "outcome": {"status": "error"},
        }
        try:
            db.insert_events([new_event, conflicting])
            assert False, "The conflicting tail event must abort the batch"
        except EventConflictError:
            pass

        assert [event["event_id"] for event in db.query(limit=20)] == ["existing"]
        assert db.get_chain_checkpoint() == before
        assert db.verify_chain()["valid"]
        db.close()

    print("  PASSED")


def test_database_permissions_and_symlink_rejection():
    """POSIX storage defaults to owner-only files and rejects DB symlinks."""
    if os.name != "posix":
        return
    print("--- test_database_permissions_and_symlink_rejection ---")

    with tempfile.TemporaryDirectory() as tmpdir:
        private_dir = os.path.join(tmpdir, "private")
        db_path = os.path.join(private_dir, "audit.db")
        db = AuditDB(db_path)
        assert stat.S_IMODE(os.stat(private_dir).st_mode) == 0o700
        assert stat.S_IMODE(os.stat(db_path).st_mode) & 0o177 == 0

        conn = db._get_conn()
        try:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                "UPDATE chain_meta SET value = value WHERE key = 'not-present'"
            )
            for path in (f"{db_path}-wal", f"{db_path}-shm"):
                if os.path.exists(path):
                    assert stat.S_IMODE(os.stat(path).st_mode) & 0o177 == 0
            conn.rollback()
        finally:
            db._put_conn(conn)
        db.close()

        target = os.path.join(tmpdir, "target.db")
        with open(target, "wb"):
            pass
        link = os.path.join(tmpdir, "linked.db")
        os.symlink(target, link)
        try:
            AuditDB(link)
            assert False, "A symlink database path must be rejected"
        except ValueError as exc:
            assert "symlink" in str(exc).lower()

    print("  PASSED")


def test_insert_events_preserves_replays_within_batch():
    """Two generated events sharing call_id are both stored in one batch."""
    print("--- test_insert_events_preserves_replays_within_batch ---")

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test_batch_dedup.db")
        db = AuditDB(db_path)

        sid = uuid.uuid4().hex
        call_id = "call-batch-dedup-001"

        def _tool_result():
            return {
                "agent": {"type": "hermes", "session_id": sid, "run_id": "r1"},
                "event_type": "tool_result",
                "action": {
                    "tool_name": "bash",
                    "parameters": {},
                    "call_id": call_id,
                    "data_accessed": [],
                },
                "outcome": {"status": "success"},
                "context": {},
            }

        # Two observations in one batch get distinct event IDs and chain links.
        ids = db.insert_events([_tool_result(), _tool_result()])
        assert len(ids) == 2
        assert ids[0] != ids[1]

        stats = db.get_stats()
        assert stats["total_events"] == 2
        assert db.get_chain_checkpoint()["event_count"] == 2
        assert db.verify_chain()["valid"]

        db.close()
        print("  PASSED")


def test_insert_events_preserves_replay_against_existing():
    """A later event with the same call_id remains a separate observation."""
    print("--- test_insert_events_preserves_replay_against_existing ---")

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test_batch_preexist.db")
        db = AuditDB(db_path)

        sid = uuid.uuid4().hex
        call_id = "call-preexist-001"

        base = {
            "agent": {"type": "hermes", "session_id": sid, "run_id": "r1"},
            "event_type": "tool_result",
            "action": {
                "tool_name": "bash",
                "parameters": {},
                "call_id": call_id,
                "data_accessed": [],
            },
            "outcome": {"status": "success"},
            "context": {},
        }

        # Pre-insert the event
        existing_id = db.insert_event(dict(base))
        assert existing_id

        # Batch: one repeated call_id plus another event.
        new_event = {
            "agent": {"type": "hermes", "session_id": sid, "run_id": "r1"},
            "event_type": "tool_call",
            "action": {
                "tool_name": "bash",
                "parameters": {},
                "data_accessed": [],
            },
            "outcome": {"status": "success"},
            "context": {},
        }
        ids = db.insert_events([dict(base), new_event])

        assert ids[0] != existing_id
        assert ids[1] and ids[1] != existing_id
        assert ids[0] != ids[1]

        stats = db.get_stats()
        assert stats["total_events"] == 3
        assert db.get_chain_checkpoint()["event_count"] == 3
        assert db.verify_chain()["valid"]

        db.close()
        print("  PASSED")


def test_insert_events_rollback_on_bad_event():
    """A bad event in the batch causes a full rollback — no partial inserts."""
    print("--- test_insert_events_rollback_on_bad_event ---")

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test_batch_rollback.db")
        db = AuditDB(db_path)

        sid = uuid.uuid4().hex

        valid_event = {
            "agent": {"type": "hermes", "session_id": sid, "run_id": "r1"},
            "event_type": "tool_call",
            "action": {"tool_name": "read_file", "parameters": {}, "data_accessed": []},
            "outcome": {"status": "success"},
            "context": {},
        }
        # Invalid: missing agent (will raise ValidationError)
        invalid_event = {
            "event_type": "tool_call",
            "action": {},
            "outcome": {"status": "success"},
            "context": {},
        }

        # Batch with the invalid event — should raise and leave DB empty
        try:
            db.insert_events([valid_event, invalid_event])
            assert False, "Should have raised ValidationError"
        except ValidationError:
            pass

        # DB must be completely unchanged (the valid_event was NOT inserted)
        stats = db.get_stats()
        assert stats["total_events"] == 0, (
            f"Rollback failed: DB has {stats['total_events']} events"
        )

        db.close()
        print("  PASSED")


def test_covering_index_exists():
    """Fresh DB has the covering index idx_events_session_ts on (session_id, timestamp)."""
    print("--- test_covering_index_exists ---")

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test_idx.db")
        db = AuditDB(db_path)
        db.close()

        conn = sqlite3.connect(db_path)
        index_names = {r[1] for r in conn.execute("PRAGMA index_list(events)")}
        conn.close()

        assert "idx_events_session_ts" in index_names, (
            f"Covering index idx_events_session_ts missing. Found: {index_names}"
        )

    print("  PASSED")


def test_v3_fresh_schema():
    """A fresh DB has hash-chain columns and metadata."""
    print("--- test_v3_fresh_schema ---")

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test_v3.db")
        db = AuditDB(db_path)
        checkpoint = db.get_chain_checkpoint()
        assert checkpoint["initialized"]
        assert checkpoint["event_count"] == 0
        assert checkpoint["legacy_event_count"] == 0
        assert checkpoint["coverage"] == "complete"
        assert db.verify_chain()["valid"]
        db.close()

        conn = sqlite3.connect(db_path)

        col_names = {r[1] for r in conn.execute("PRAGMA table_info(events)")}
        assert "prev_hash" in col_names, "prev_hash column missing on fresh DB"
        assert "event_hash" in col_names, "event_hash column missing on fresh DB"

        table_names = {
            r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        assert "chain_meta" in table_names
        assert not {"baselines", "trust_events", "alerts"} & table_names

        conn.close()
        print("  PASSED")


def test_v3_to_v4_drops_call_id_uniqueness_before_legacy_correction():
    """Migration preserves rows whose corrected explicit call_ids converge."""
    print("--- test_v3_to_v4_drops_call_id_uniqueness_before_legacy_correction ---")

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "v3-call-id.db")
        conn = sqlite3.connect(db_path)
        conn.execute("""
            CREATE TABLE schema_version (
                version INTEGER PRIMARY KEY,
                applied_at TEXT NOT NULL DEFAULT (datetime('now'))
            )
        """)
        conn.execute("INSERT INTO schema_version (version) VALUES (3)")
        conn.execute("""
            CREATE TABLE events (
                event_id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                agent_type TEXT NOT NULL DEFAULT 'unknown',
                session_id TEXT NOT NULL,
                run_id TEXT,
                event_type TEXT NOT NULL,
                tool_name TEXT,
                data_accessed TEXT DEFAULT '',
                call_id TEXT DEFAULT '',
                agent TEXT NOT NULL,
                user_info TEXT NOT NULL,
                action TEXT NOT NULL,
                outcome TEXT NOT NULL,
                context TEXT NOT NULL,
                cost TEXT NOT NULL,
                raw_request TEXT,
                raw_response TEXT,
                prev_hash TEXT,
                event_hash TEXT
            )
        """)
        conn.execute("""
            CREATE UNIQUE INDEX idx_events_dedup
            ON events(session_id, event_type, call_id)
            WHERE call_id != ''
              AND event_type IN ('tool_call', 'tool_result')
        """)
        for index, legacy_key in enumerate(
            ("legacy-target-a", "legacy-target-b"),
            start=1,
        ):
            action = json.dumps({
                "tool_name": "bash",
                "parameters": {"attempt": index},
                "target": legacy_key,
                "call_id": "shared-provider-call",
            })
            agent = json.dumps({
                "type": "hermes",
                "session_id": "migration-session",
                "run_id": f"run-{index}",
            })
            conn.execute(
                """
                INSERT INTO events (
                    event_id, timestamp, agent_type, session_id, run_id,
                    event_type, tool_name, data_accessed, call_id, agent,
                    user_info, action, outcome, context, cost
                ) VALUES (?, ?, 'hermes', 'migration-session', ?, 'tool_call',
                          'bash', '', ?, ?, '{}', ?, '{"status":"success"}',
                          '{}', '{}')
                """,
                (
                    f"legacy-event-{index}",
                    f"2026-07-10T10:0{index}:00.000Z",
                    f"run-{index}",
                    legacy_key,
                    agent,
                    action,
                ),
            )
        conn.commit()
        conn.close()

        db = AuditDB(db_path)
        assert db.get_stats()["total_events"] == 2
        checkpoint = db.get_chain_checkpoint()
        assert checkpoint["legacy_event_count"] == 2
        assert checkpoint["event_count"] == 0

        third_id = db.insert_event({
            "event_id": "new-delivery",
            "timestamp": "2026-07-10T10:03:00.000Z",
            "agent": {
                "type": "hermes",
                "session_id": "migration-session",
                "run_id": "run-3",
            },
            "event_type": "tool_call",
            "action": {
                "tool_name": "bash",
                "parameters": {"attempt": 3},
                "call_id": "shared-provider-call",
            },
            "outcome": {"status": "success"},
            "context": {},
        })
        assert third_id == "new-delivery"
        assert db.get_stats()["total_events"] == 3
        assert db.verify_chain()["valid"]
        db.close()

        raw = sqlite3.connect(db_path)
        call_ids = [
            row[0] for row in raw.execute(
                "SELECT call_id FROM events ORDER BY timestamp"
            )
        ]
        indexes = {row[1] for row in raw.execute("PRAGMA index_list(events)")}
        version = raw.execute(
            "SELECT MAX(version) FROM schema_version"
        ).fetchone()[0]
        raw.close()

        assert call_ids == ["shared-provider-call"] * 3
        assert "idx_events_dedup" not in indexes
        assert "idx_events_call_id" in indexes
        assert version == SCHEMA_VERSION

    print("  PASSED")


def test_migration_v2_to_v3():
    """Opening a v2 database adds hash-chain columns and v3 tables, keeps data."""
    print("--- test_migration_v2_to_v3 ---")

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "v2_legacy.db")

        # ── Build a v2 database manually (has call_id, no hash columns) ───
        conn = sqlite3.connect(db_path)
        conn.execute("""
            CREATE TABLE schema_version (
                version INTEGER PRIMARY KEY,
                applied_at TEXT NOT NULL DEFAULT (datetime('now'))
            )
        """)
        conn.execute("INSERT INTO schema_version (version) VALUES (2)")
        conn.execute("""
            CREATE TABLE events (
                event_id        TEXT PRIMARY KEY,
                timestamp       TEXT NOT NULL,
                agent_type      TEXT NOT NULL DEFAULT 'unknown',
                session_id      TEXT NOT NULL,
                run_id          TEXT,
                event_type      TEXT NOT NULL,
                tool_name       TEXT,
                data_accessed   TEXT DEFAULT '',
                call_id         TEXT DEFAULT '',
                agent           TEXT NOT NULL,
                user_info       TEXT NOT NULL,
                action          TEXT NOT NULL,
                outcome         TEXT NOT NULL,
                context         TEXT NOT NULL,
                cost            TEXT NOT NULL,
                raw_request     TEXT,
                raw_response    TEXT
            )
        """)
        agent_json = json.dumps({"type": "hermes", "session_id": "sess-v2", "run_id": "r1"})
        conn.execute(
            "INSERT INTO events VALUES ('v2-evt-1', '2026-07-01T10:00:00.000Z', "
            "'hermes', 'sess-v2', 'r1', 'tool_call', 'terminal', '', 'c1', "
            "?, '{}', '{}', '{\"status\": \"success\"}', '{}', '{}', NULL, NULL)",
            (agent_json,),
        )
        conn.commit()
        conn.close()

        # ── Open with AuditDB — v2 → v3 migration should run ──────────────
        db = AuditDB(db_path)
        stats = db.get_stats()
        assert stats["schema_version"] == SCHEMA_VERSION, (
            f"Expected schema_version={SCHEMA_VERSION} after migration, "
            f"got {stats['schema_version']}"
        )

        # Existing data survives and stays queryable
        events = db.query(session_id="sess-v2")
        assert len(events) == 1 and events[0]["event_id"] == "v2-evt-1"

        # New inserts work against the migrated table
        new_event_id = db.insert_event({
            "agent": {"type": "hermes", "session_id": "sess-v2", "run_id": "r2"},
            "event_type": "tool_call",
            "action": {"tool_name": "read_file", "parameters": {}},
            "outcome": {"status": "success"},
            "context": {},
        })
        checkpoint = db.get_chain_checkpoint()
        assert checkpoint["event_count"] == 1
        assert checkpoint["legacy_event_count"] == 1
        assert checkpoint["coverage"] == "partial"
        assert checkpoint["first_event_id"] == new_event_id
        assert db.verify_chain()["valid"]
        db.close()

        # ── Verify via raw sqlite3 ────────────────────────────────────────
        raw = sqlite3.connect(db_path)
        col_names = {r[1] for r in raw.execute("PRAGMA table_info(events)")}
        assert "prev_hash" in col_names and "event_hash" in col_names, (
            "hash-chain columns missing after v2 → v3 migration"
        )
        legacy_hashes = raw.execute(
            "SELECT prev_hash, event_hash FROM events WHERE event_id = 'v2-evt-1'"
        ).fetchone()
        new_hashes = raw.execute(
            "SELECT prev_hash, event_hash FROM events WHERE event_id = ?",
            (new_event_id,),
        ).fetchone()
        assert legacy_hashes == (None, None)
        assert all(new_hashes)
        table_names = {
            r[0] for r in raw.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        }
        assert "chain_meta" in table_names
        raw.close()
        print("  PASSED")


def test_aggregate_basic():
    """aggregate() groups by dimension and computes whitelisted metrics."""
    print("--- test_aggregate_basic ---")

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test_agg.db")
        db = AuditDB(db_path)

        # hermes: 3 tool_calls (1 error), 100/50 tokens each
        # claude_code: 2 tool_calls (1 blocked), 200/20 tokens each
        sid_h, sid_c = "sess-h", "sess-c"
        for i in range(3):
            db.insert_event({
                "agent": {"type": "hermes", "session_id": sid_h, "run_id": f"h{i}"},
                "event_type": "tool_call",
                "action": {"tool_name": f"tool_{i}", "parameters": {}},
                "outcome": {"status": "error" if i == 0 else "success"},
                "context": {},
                "cost": {"tokens_in": 100, "tokens_out": 50, "estimated_usd": 0.01},
            })
        for i in range(2):
            db.insert_event({
                "agent": {"type": "claude_code", "session_id": sid_c, "run_id": f"c{i}"},
                "event_type": "tool_call",
                "action": {"tool_name": "terminal", "parameters": {}},
                "outcome": {"status": "blocked" if i == 0 else "success"},
                "context": {},
                "cost": {"tokens_in": 200, "tokens_out": 20, "estimated_usd": 0.02},
            })

        rows = db.aggregate(
            group_by=["agent_type"],
            metrics=["count", "tokens_in", "tokens_out", "error_count",
                     "blocked_count", "distinct_tools"],
        )
        by_agent = {r["agent_type"]: r for r in rows}
        assert set(by_agent) == {"hermes", "claude_code"}, f"Got: {by_agent}"

        h = by_agent["hermes"]
        assert h["count"] == 3 and h["tokens_in"] == 300 and h["tokens_out"] == 150
        assert h["error_count"] == 1 and h["blocked_count"] == 0
        assert h["distinct_tools"] == 3

        c = by_agent["claude_code"]
        assert c["count"] == 2 and c["tokens_in"] == 400
        assert c["error_count"] == 0 and c["blocked_count"] == 1
        assert c["distinct_tools"] == 1

        # Default ordering: first metric ("count") descending
        assert rows[0]["agent_type"] == "hermes", f"Expected hermes first: {rows}"

        # Empty group_by → whole-table totals, one row
        totals = db.aggregate(group_by=[], metrics=["count", "distinct_sessions"])
        assert len(totals) == 1
        assert totals[0]["count"] == 5 and totals[0]["distinct_sessions"] == 2

        db.close()
        print("  PASSED")


def test_aggregate_buckets_and_filters():
    """aggregate() supports day/hour buckets and the query() filter set."""
    print("--- test_aggregate_buckets_and_filters ---")

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test_agg_time.db")
        db = AuditDB(db_path)

        timestamps = [
            "2026-07-01T09:00:00.000Z",
            "2026-07-01T15:00:00.000Z",
            "2026-07-02T10:00:00.000Z",
        ]
        for i, ts in enumerate(timestamps):
            db.insert_event({
                "timestamp": ts,
                "agent": {"type": "hermes", "session_id": "s1", "run_id": f"r{i}"},
                "event_type": "tool_call",
                "action": {"tool_name": "terminal", "parameters": {}},
                "outcome": {"status": "success"},
                "context": {},
            })

        # Day buckets, ascending
        days = db.aggregate(group_by=["day"], order_by="day", descending=False)
        assert [(d["day"], d["count"]) for d in days] == [
            ("2026-07-01", 2), ("2026-07-02", 1),
        ], f"Got: {days}"

        # Hour bucket + since filter + first/last seen
        hours = db.aggregate(
            group_by=["hour"],
            metrics=["count", "first_seen", "last_seen"],
            since="2026-07-01T12:00:00.000Z",
            order_by="hour",
            descending=False,
        )
        assert [h["hour"] for h in hours] == ["2026-07-01T15", "2026-07-02T10"]
        assert hours[0]["first_seen"] == "2026-07-01T15:00:00.000Z"

        # Equality filter parity with query()
        filtered = db.aggregate(group_by=["tool_name"], agent_type="codex")
        assert filtered == [], f"Expected no codex rows, got: {filtered}"

        db.close()
        print("  PASSED")


def test_aggregate_validation():
    """aggregate() rejects unknown dimensions, metrics, and order_by keys."""
    print("--- test_aggregate_validation ---")

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test_agg_val.db")
        db = AuditDB(db_path)

        for bad_call in (
            lambda: db.aggregate(group_by=["evil; DROP TABLE events"]),
            lambda: db.aggregate(group_by=["agent_type"], metrics=["1); DELETE"]),
            lambda: db.aggregate(group_by=["agent_type"], order_by="timestamp"),
            lambda: db.aggregate(group_by=[], limit=-1),
            lambda: db.query(limit=-1),
            lambda: db.query(limit=10_001),
            lambda: db.query(offset=-1),
            lambda: db.list_sessions(limit=0),
        ):
            try:
                bad_call()
                assert False, "Expected ValueError"
            except ValueError:
                pass

        db.close()
        print("  PASSED")


if __name__ == "__main__":
    test_redact_secrets()
    test_normalize_event()
    test_validate_event()
    test_db_lifecycle()
    test_in_memory_database_persists_across_operation_connections()
    test_query_filters()
    test_evidence_chain()
    test_evidence_chain_via_call_id()
    test_evidence_chain_temporal_fallback_parses_iso8601()
    test_tool_result_replays_are_preserved()
    test_tool_call_replays_are_preserved()
    test_call_id_is_correlation_not_idempotency()
    test_call_id_correlation_across_sessions()
    test_migration_v1_to_v2()
    test_migration_preserves_all_duplicate_call_ids()
    test_session_access()
    test_validation_error_on_insert()
    test_concurrent_access()
    test_concurrent_batches_across_db_instances_do_not_fork_chain()
    test_schema_version_table()
    test_future_schema_version_is_rejected()
    test_insert_events_batch()
    test_event_id_conflicts_and_invalid_events_are_never_silent()
    test_redaction_cannot_collapse_distinct_secret_bearing_event_replays()
    test_explicit_event_id_requires_stable_timestamp()
    test_query_round_trip_is_idempotent_with_derived_metadata()
    test_shared_target_without_call_id_is_not_deduplicated()
    test_hash_chain_detects_canonical_payload_tampering()
    test_verify_checkpoint_exact_prefix_and_tampering()
    test_batch_conflict_rolls_back_events_and_chain_head()
    test_database_permissions_and_symlink_rejection()
    test_insert_events_preserves_replays_within_batch()
    test_insert_events_preserves_replay_against_existing()
    test_insert_events_rollback_on_bad_event()
    test_covering_index_exists()
    test_v3_fresh_schema()
    test_v3_to_v4_drops_call_id_uniqueness_before_legacy_correction()
    test_migration_v2_to_v3()
    test_aggregate_basic()
    test_aggregate_buckets_and_filters()
    test_aggregate_validation()
    print("\n=== ALL DB TESTS PASSED ===")


def test_verify_detects_duplicate_keys_that_keep_the_parsed_hash():
    """Stored JSON must match its written bytes, not just its parsed value.

    SQLite's json_extract keeps the first duplicate key and Python the last,
    so a duplicate-key rewrite would otherwise verify while changing what
    queries and aggregates read.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "audit.db")
        db = AuditDB(db_path)
        db.insert_event({
            "event_id": "evt-dup",
            "timestamp": "2026-07-17T12:00:00.000Z",
            "agent": {"type": "hermes", "session_id": "s1", "run_id": "r1"},
            "event_type": "model_request",
            "action": {},
            "outcome": {"status": "blocked"},
            "context": {},
        })
        assert db.verify_chain()["valid"] is True
        conn = db._get_conn()
        try:
            stored = conn.execute(
                "SELECT outcome FROM events WHERE event_id = 'evt-dup'"
            ).fetchone()[0]
            forged = stored.replace(
                '"status": "blocked"', '"status": "success", "status": "blocked"'
            )
            assert forged != stored
            conn.execute(
                "UPDATE events SET outcome = ? WHERE event_id = 'evt-dup'", (forged,)
            )
            conn.commit()
        finally:
            db._put_conn(conn)
        result = db.verify_chain()
        db.close()
        assert result["valid"] is False
        assert result["broken_event_id"] == "evt-dup"


def test_read_only_audit_db_never_writes():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "audit.db")
        writer = AuditDB(db_path)
        writer.close()
        os.chmod(db_path, 0o644)

        reader = AuditDB(db_path, read_only=True)
        try:
            assert reader.verify_chain()["valid"] is True
            with pytest.raises(sqlite3.OperationalError):
                reader.insert_event({
                    "agent": {"type": "hermes", "session_id": "s1", "run_id": "r1"},
                    "event_type": "model_request",
                    "action": {},
                    "outcome": {"status": "success"},
                    "context": {},
                })
        finally:
            reader.close()
        assert stat.S_IMODE(os.stat(db_path).st_mode) == 0o644

        # A read-only open never creates the file it was pointed at.
        missing = os.path.join(tmpdir, "missing.db")
        with pytest.raises(sqlite3.Error):
            AuditDB(missing, read_only=True)
        assert not os.path.exists(missing)
