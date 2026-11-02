"""The hash chain is optional, and never dropped or faked silently."""

import hashlib
import shutil
import sqlite3
from pathlib import Path

import pytest

from panoptes import AuditDB, ChainIntegrityError, EventConflictError

FIXTURES = Path(__file__).parent / "fixtures"


def event(n, **overrides):
    base = {
        "event_id": f"e{n}",
        "timestamp": f"2026-11-02T10:00:{n:02d}.000Z",
        "event_type": "agent_step",
        "agent": {"type": "t", "session_id": "s"},
        "action": {"tool_names": []},
        "outcome": {"status": "success"},
        "context": {},
    }
    base.update(overrides)
    return base


def hash_columns(path):
    conn = sqlite3.connect(path)
    try:
        return conn.execute(
            "SELECT COUNT(*), COUNT(prev_hash), COUNT(event_hash) FROM events"
        ).fetchone()
    finally:
        conn.close()


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


# ── unchained databases ──────────────────────────────────────────────────────

def test_unchained_database_stores_events_without_hashes(tmp_path):
    path = tmp_path / "plain.db"
    db = AuditDB(str(path), chain=False)
    db.insert_events([event(1), event(2)])
    assert [e["event_id"] for e in db.query(limit=10)] == ["e2", "e1"]
    db.close()
    assert hash_columns(path) == (2, 0, 0)


@pytest.mark.parametrize("populated", [False, True])
def test_unchained_database_never_verifies_as_valid(tmp_path, populated):
    db = AuditDB(str(tmp_path / "plain.db"), chain=False)
    if populated:
        db.insert_event(event(1))
    result = db.verify_chain()
    assert result["chain"] == "absent"
    assert result["valid"] is False
    assert result["initialized"] is False
    assert result["event_count"] == 0
    assert "unchained" in result["error"]
    checkpoint = db.get_chain_checkpoint()
    assert checkpoint["chain"] == "absent" and checkpoint["initialized"] is False
    proof = db.verify_checkpoint({
        "format_version": "1", "algorithm": "sha256", "anchor": "a", "head": "a",
        "event_count": 0, "legacy_event_count": 0,
    })
    assert proof["valid"] is False
    db.close()


def test_an_unchained_database_stays_unchained_when_reopened_by_default(tmp_path):
    path = tmp_path / "plain.db"
    AuditDB(str(path), chain=False).close()
    db = AuditDB(str(path))
    db.insert_event(event(1))
    assert db.verify_chain()["chain"] == "absent"
    db.close()
    assert hash_columns(path) == (1, 0, 0)


def test_unchained_replays_are_idempotent_and_conflicts_still_fail(tmp_path):
    db = AuditDB(str(tmp_path / "plain.db"), chain=False)
    db.insert_event(event(1))
    db.insert_event(db.query()[0])
    assert db.get_stats()["total_events"] == 1
    with pytest.raises(EventConflictError):
        db.insert_event(event(1, outcome={"status": "error"}))
    db.close()


def test_unchained_database_opens_read_only_and_reports_absent(tmp_path):
    path = tmp_path / "plain.db"
    db = AuditDB(str(path), chain=False)
    db.insert_event(event(1))
    db.close()
    before = sha(path)
    reader = AuditDB.open_readonly(str(path))
    try:
        assert reader.verify_chain()["chain"] == "absent"
        assert reader.get_stats()["total_events"] == 1
    finally:
        reader.close()
    assert sha(path) == before


# ── a chain is never silently dropped ────────────────────────────────────────

def test_chain_false_is_refused_on_a_chained_database(tmp_path):
    path = tmp_path / "chained.db"
    db = AuditDB(str(path))
    db.insert_event(event(1))
    db.close()
    before = sha(path)
    with pytest.raises(ChainIntegrityError, match="cannot be dropped"):
        AuditDB(str(path), chain=False)
    assert sha(path) == before


@pytest.mark.parametrize("chain", [None, True])
def test_a_chained_database_stays_chained(tmp_path, chain):
    path = tmp_path / "chained.db"
    first = AuditDB(str(path))
    first.insert_event(event(1))
    first.close()
    db = AuditDB(str(path), chain=chain)
    db.insert_event(event(2))
    result = db.verify_chain()
    assert result["valid"] and result["chain"] == "intact" and result["event_count"] == 2
    db.close()
    assert hash_columns(path) == (2, 2, 2)


def test_an_empty_chained_database_is_intact(tmp_path):
    db = AuditDB(str(tmp_path / "new.db"))
    assert db.verify_chain()["chain"] == "intact"
    db.close()


def test_a_stripped_chain_is_refused_whatever_chain_says(tmp_path):
    path = tmp_path / "chained.db"
    db = AuditDB(str(path))
    db.insert_event(event(1))
    db.close()
    conn = sqlite3.connect(path)
    conn.execute("DELETE FROM chain_meta")
    conn.commit()
    conn.close()
    for chain in (None, True, False):
        with pytest.raises(ChainIntegrityError):
            AuditDB(str(path), chain=chain)


def test_swapping_the_chain_for_a_disabled_marker_is_refused(tmp_path):
    path = tmp_path / "chained.db"
    db = AuditDB(str(path))
    db.insert_event(event(1))
    db.close()
    conn = sqlite3.connect(path)
    conn.execute("DELETE FROM chain_meta")
    conn.execute("INSERT INTO chain_meta (key, value) VALUES ('chain_disabled', '1')")
    conn.commit()
    conn.close()
    with pytest.raises(ChainIntegrityError, match="hash-chained events"):
        AuditDB(str(path))
    reader = AuditDB.open_readonly(str(path))
    try:
        result = reader.verify_chain()
        assert result["valid"] is False and result["chain"] == "broken"
    finally:
        reader.close()


def test_a_marker_next_to_a_live_chain_is_refused(tmp_path):
    path = tmp_path / "chained.db"
    AuditDB(str(path)).close()
    conn = sqlite3.connect(path)
    conn.execute("INSERT INTO chain_meta (key, value) VALUES ('chain_disabled', '1')")
    conn.commit()
    conn.close()
    with pytest.raises(ChainIntegrityError):
        AuditDB(str(path))


# ── enabling a chain on an unchained database ────────────────────────────────

def test_chain_true_starts_a_chain_after_the_existing_rows(tmp_path):
    path = tmp_path / "plain.db"
    plain = AuditDB(str(path), chain=False)
    plain.insert_events([event(1), event(2)])
    plain.close()

    db = AuditDB(str(path), chain=True)
    db.insert_event(event(3))
    result = db.verify_chain()
    assert result["valid"] and result["chain"] == "intact"
    assert result["event_count"] == 1
    assert result["legacy_event_count"] == 2
    assert result["coverage"] == "partial"
    db.close()
    assert hash_columns(path) == (3, 1, 1)


# ── databases that predate the chain ─────────────────────────────────────────

def test_a_pre_chain_file_reads_and_reports_absent(tmp_path):
    path = tmp_path / "v2.db"
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE schema_version (version INTEGER PRIMARY KEY, "
                 "applied_at TEXT NOT NULL DEFAULT (datetime('now')))")
    conn.execute("INSERT INTO schema_version (version) VALUES (2)")
    conn.execute("""
        CREATE TABLE events (
            event_id TEXT PRIMARY KEY, timestamp TEXT NOT NULL,
            agent_type TEXT NOT NULL DEFAULT 'unknown', session_id TEXT NOT NULL,
            run_id TEXT, event_type TEXT NOT NULL, tool_name TEXT,
            data_accessed TEXT DEFAULT '', call_id TEXT DEFAULT '',
            agent TEXT NOT NULL, user_info TEXT NOT NULL, action TEXT NOT NULL,
            outcome TEXT NOT NULL, context TEXT NOT NULL, cost TEXT NOT NULL,
            raw_request TEXT, raw_response TEXT)
    """)
    conn.execute(
        "INSERT INTO events (event_id, timestamp, agent_type, session_id, run_id, "
        "event_type, agent, user_info, action, outcome, context, cost) VALUES "
        "('old', '2026-01-01T00:00:00.000Z', 'hermes', 's', 'r', 'agent_start', "
        "'{\"type\":\"hermes\",\"session_id\":\"s\",\"run_id\":\"r\"}', '{}', '{}', "
        "'{\"status\":\"success\"}', '{}', '{}')"
    )
    conn.commit()
    conn.close()
    before = sha(path)

    reader = AuditDB.open_readonly(str(path))
    try:
        assert [e["event_id"] for e in reader.iter_events()] == ["old"]
        assert reader.query(correlation_id="x") == []
        result = reader.verify_chain()
        assert result["chain"] == "absent" and result["valid"] is False
        assert result["legacy_event_count"] == 1
        assert reader.get_chain_checkpoint()["chain"] == "absent"
    finally:
        reader.close()
    assert sha(path) == before

    # A writer migrates it, and the old row stays outside the new chain.
    shutil.copy(path, tmp_path / "migrated.db")
    db = AuditDB(str(tmp_path / "migrated.db"))
    db.insert_event(event(1))
    result = db.verify_chain()
    assert result["valid"] and result["legacy_event_count"] == 1
    db.close()


# ── arguments ────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("bad", ["yes", 1, 0])
def test_chain_must_be_a_bool_or_none(tmp_path, bad):
    with pytest.raises(ValueError, match="chain must be"):
        AuditDB(str(tmp_path / "x.db"), chain=bad)


def test_read_only_cannot_select_a_chain():
    with pytest.raises(ValueError):
        AuditDB("whatever.db", read_only=True, chain=True)


def test_v4_fixtures_are_unaffected_by_the_chain_modes(tmp_path):
    path = tmp_path / "v4.db"
    shutil.copy(FIXTURES / "panoptes_v4.db", path)
    with pytest.raises(ChainIntegrityError, match="cannot be dropped"):
        AuditDB(str(path), chain=False)
    db = AuditDB(str(path), chain=True)
    assert db.verify_chain()["valid"]
    db.close()
