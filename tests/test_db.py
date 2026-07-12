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
  - Deduplication of replayed tool_result events (call_id unique index)
  - Migration from a v1 database (no call_id column)
"""

import json
import os
import sqlite3
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

    # data_accessed preserved when explicitly set (no derivation override)
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

        # Schema version should be 3
        stats = db.get_stats()
        assert stats["schema_version"] == 3, f"Expected schema_version=3, got {stats['schema_version']}"
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


def test_tool_result_dedup():
    """Replayed tool_result events with the same call_id are deduplicated."""
    print("--- test_tool_result_dedup ---")

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

        # Insert the same logical tool_result twice (as happens when agents replay history)
        eid1 = db.insert_event(dict(base_event))
        eid2 = db.insert_event(dict(base_event))

        # Both calls should return an event_id (the first one's id on dedup)
        assert eid1, "First insert should return event_id"
        assert eid2, "Second insert should return event_id"

        # Second insert should return the SAME event_id (the original row)
        assert eid1 == eid2, (
            f"Duplicate tool_result should return same event_id, got {eid1!r} vs {eid2!r}"
        )

        # Only one row should exist in the DB
        stats = db.get_stats()
        assert stats["total_events"] == 1, (
            f"Expected 1 event after dedup, got {stats['total_events']}"
        )

        db.close()
        print("  PASSED")


def test_tool_call_dedup():
    """Replayed tool_call events with the same call_id are also deduplicated."""
    print("--- test_tool_call_dedup ---")

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
        eid3 = db.insert_event(dict(base))  # Third replay

        assert eid1 == eid2 == eid3, (
            f"All replays should return same event_id, got {eid1!r}, {eid2!r}, {eid3!r}"
        )

        results = db.query(event_type="tool_call")
        assert len(results) == 1, f"Expected 1 row after dedup, got {len(results)}"

        db.close()
        print("  PASSED")


def test_dedup_different_sessions():
    """Same call_id in different sessions is NOT deduplicated."""
    print("--- test_dedup_different_sessions ---")

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

        # Two rows, different sessions — no dedup
        results = db.query(event_type="tool_result")
        assert len(results) == 2, (
            f"Same call_id in different sessions should produce 2 rows, got {len(results)}"
        )

        db.close()
        print("  PASSED")


def test_migration_v1_to_v2():
    """Opening a v1 database triggers migration: adds call_id, index, and deduplicates."""
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

        # Two duplicate tool_result rows for the same logical call
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

        # Verify schema version updated to 3 (v1 → v2 → v3 in one pass)
        stats = db.get_stats()
        assert stats["schema_version"] == 3, (
            f"Expected schema_version=3 after migration, got {stats['schema_version']}"
        )

        db.close()

        # ── Verify via raw sqlite3 ────────────────────────────────────────
        raw = sqlite3.connect(db_path)

        # call_id column must exist
        col_names = {r[1] for r in raw.execute("PRAGMA table_info(events)")}
        assert "call_id" in col_names, "call_id column missing after migration"

        # Dedup index must exist
        index_names = {r[1] for r in raw.execute("PRAGMA index_list(events)")}
        assert "idx_events_dedup" in index_names, "Dedup index missing after migration"

        # Duplicate tool_result rows collapsed to the earliest one
        rows = list(raw.execute(
            "SELECT event_id FROM events WHERE event_type = 'tool_result'"
        ))
        assert len(rows) == 1, (
            f"Expected 1 tool_result after dedup, got {len(rows)}: {rows}"
        )
        assert rows[0][0] == "dup-1", (
            f"Earliest row (dup-1) should survive, got {rows[0][0]}"
        )

        # call_id backfilled from target
        row = raw.execute(
            "SELECT call_id FROM events WHERE event_id = 'dup-1'"
        ).fetchone()
        assert row[0] == "call-legacy-001", (
            f"call_id not backfilled from target, got {row[0]!r}"
        )

        # Non-duplicate model_request row still present
        rows2 = list(raw.execute(
            "SELECT event_id FROM events WHERE event_type = 'model_request'"
        ))
        assert len(rows2) == 1 and rows2[0][0] == "unique-1"

        raw.close()
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
        conn = sqlite3.connect(db_path)
        cur = conn.execute("SELECT version, applied_at FROM schema_version ORDER BY version DESC LIMIT 1")
        row = cur.fetchone()
        assert row[0] == 3, f"Expected version 3, got {row[0]}"
        assert row[1] is not None
        conn.close()

        db.close()
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

        # insert_event (single) still works and shares the code path
        eid_single = db.insert_event(_evt(99))
        assert isinstance(eid_single, str) and eid_single

        db.close()
        print("  PASSED")


def test_insert_events_dedup_within_batch():
    """Two events with the same dedup key in one batch: both return the first's id."""
    print("--- test_insert_events_dedup_within_batch ---")

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

        # Two identical events in the same batch — first wins
        ids = db.insert_events([_tool_result(), _tool_result()])
        assert len(ids) == 2
        # Both should return the same event_id (the one that actually inserted)
        assert ids[0] == ids[1], (
            f"Dedup within batch should return same id, got {ids[0]!r} vs {ids[1]!r}"
        )

        # Only one row should be in the DB
        stats = db.get_stats()
        assert stats["total_events"] == 1, (
            f"Expected 1 event after intra-batch dedup, got {stats['total_events']}"
        )

        db.close()
        print("  PASSED")


def test_insert_events_dedup_against_existing():
    """Batch dedup against a pre-existing row returns the pre-existing event_id."""
    print("--- test_insert_events_dedup_against_existing ---")

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

        # Batch: one duplicate (same call_id) + one genuinely new event
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

        # Duplicate should return the pre-existing row's id
        assert ids[0] == existing_id, (
            f"Duplicate in batch should return pre-existing id {existing_id!r}, got {ids[0]!r}"
        )
        # New event should get a fresh id
        assert ids[1] and ids[1] != existing_id, (
            f"New event in batch should get distinct id, got {ids[1]!r}"
        )

        # Total: 2 rows (the pre-existing and the new one)
        stats = db.get_stats()
        assert stats["total_events"] == 2, (
            f"Expected 2 events total, got {stats['total_events']}"
        )

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
    """A fresh DB has hash-chain columns and the v3 auxiliary tables."""
    print("--- test_v3_fresh_schema ---")

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test_v3.db")
        db = AuditDB(db_path)
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
        for table in ("chain_meta", "baselines", "trust_events", "alerts"):
            assert table in table_names, f"v3 table '{table}' missing: {table_names}"

        index_names = {
            r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'index'"
            )
        }
        for idx in ("idx_trust_events_session", "idx_alerts_timestamp", "idx_alerts_severity"):
            assert idx in index_names, f"v3 index '{idx}' missing"

        conn.close()
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
        assert stats["schema_version"] == 3, (
            f"Expected schema_version=3 after migration, got {stats['schema_version']}"
        )

        # Existing data survives and stays queryable
        events = db.query(session_id="sess-v2")
        assert len(events) == 1 and events[0]["event_id"] == "v2-evt-1"

        # New inserts work against the migrated table
        db.insert_event({
            "agent": {"type": "hermes", "session_id": "sess-v2", "run_id": "r2"},
            "event_type": "tool_call",
            "action": {"tool_name": "read_file", "parameters": {}},
            "outcome": {"status": "success"},
            "context": {},
        })
        db.close()

        # ── Verify via raw sqlite3 ────────────────────────────────────────
        raw = sqlite3.connect(db_path)
        col_names = {r[1] for r in raw.execute("PRAGMA table_info(events)")}
        assert "prev_hash" in col_names and "event_hash" in col_names, (
            "hash-chain columns missing after v2 → v3 migration"
        )
        table_names = {
            r[0] for r in raw.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        }
        for table in ("chain_meta", "baselines", "trust_events", "alerts"):
            assert table in table_names, f"v3 table '{table}' missing after migration"
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
    test_query_filters()
    test_evidence_chain()
    test_evidence_chain_via_call_id()
    test_tool_result_dedup()
    test_tool_call_dedup()
    test_dedup_different_sessions()
    test_migration_v1_to_v2()
    test_session_access()
    test_validation_error_on_insert()
    test_concurrent_access()
    test_schema_version_table()
    test_insert_events_batch()
    test_insert_events_dedup_within_batch()
    test_insert_events_dedup_against_existing()
    test_insert_events_rollback_on_bad_event()
    test_covering_index_exists()
    test_v3_fresh_schema()
    test_migration_v2_to_v3()
    test_aggregate_basic()
    test_aggregate_buckets_and_filters()
    test_aggregate_validation()
    print("\n=== ALL DB TESTS PASSED ===")
