"""v4 -> v5 migration, over databases real v4 writers produced.

``agentgate_v4.db`` is the audit log ``agentgate demo`` wrote with the released
Panoptes 0.1.1 (schema 4); ``panoptes_v4.db`` was written by this repository at
commit 7fc2704 (see tests/fixtures/make_panoptes_v4.py). Neither is touched by
the tests: each is copied first.
"""

import hashlib
import shutil
import sqlite3
from pathlib import Path

import pytest

from panoptes import AuditDB
from panoptes.schema import SCHEMA_VERSION

FIXTURES = Path(__file__).parent / "fixtures"
V4_FIXTURES = {
    "agentgate_v4.db": 91,
    "panoptes_v4.db": 9,
}


def copy_fixture(name, tmp_path):
    target = tmp_path / name
    shutil.copy(FIXTURES / name, target)
    return target


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def stored_versions(path):
    conn = sqlite3.connect(path)
    try:
        return [r[0] for r in conn.execute("SELECT version FROM schema_version ORDER BY 1")]
    finally:
        conn.close()


@pytest.mark.parametrize("name", V4_FIXTURES)
def test_fixtures_really_are_schema_v4(name):
    conn = sqlite3.connect(f"{(FIXTURES / name).as_uri()}?mode=ro", uri=True)
    try:
        assert conn.execute("SELECT MAX(version) FROM schema_version").fetchone()[0] == 4
        columns = {r[1] for r in conn.execute("PRAGMA table_info(events)")}
        assert not columns & {"correlation_id", "parent_run_id", "attributes"}
        count, chained = conn.execute("SELECT COUNT(*), COUNT(event_hash) FROM events").fetchone()
        assert count == chained == V4_FIXTURES[name]
    finally:
        conn.close()


@pytest.mark.parametrize("name, total", V4_FIXTURES.items())
def test_v4_database_migrates_and_still_verifies(tmp_path, name, total):
    path = copy_fixture(name, tmp_path)
    db = AuditDB(str(path))
    try:
        stats = db.get_stats()
        assert stats["schema_version"] == SCHEMA_VERSION == 5
        assert stats["total_events"] == total
        verification = db.verify_chain()
        assert verification["valid"], verification
        assert verification["event_count"] == total
        assert verification["legacy_event_count"] == 0
        assert verification["checked_events"] == total
    finally:
        db.close()
    assert stored_versions(path) == [4, 5]


@pytest.mark.parametrize("name", V4_FIXTURES)
def test_migrated_rows_are_unchanged_and_read_with_empty_v5_fields(tmp_path, name):
    raw_before = sqlite3.connect(FIXTURES / name)
    expected = raw_before.execute(
        "SELECT event_id, agent, user_info, action, context, event_hash FROM events ORDER BY rowid"
    ).fetchall()
    raw_before.close()

    path = copy_fixture(name, tmp_path)
    db = AuditDB(str(path))
    try:
        events = db.query(limit=1000)
        assert len(events) == len(expected)
        assert all(e["correlation_id"] is None and e["attributes"] == {} for e in events)
        assert all(e["agent"].get("parent_run_id") is None for e in events)
    finally:
        db.close()

    raw_after = sqlite3.connect(path)
    after = raw_after.execute(
        "SELECT event_id, agent, user_info, action, context, event_hash FROM events ORDER BY rowid"
    ).fetchall()
    raw_after.close()
    assert after == expected


@pytest.mark.parametrize("name", V4_FIXTURES)
def test_v5_events_append_to_a_migrated_v4_chain(tmp_path, name):
    path = copy_fixture(name, tmp_path)
    db = AuditDB(str(path))
    try:
        before = db.get_chain_checkpoint()
        db.insert_event({
            "event_id": "after-migration",
            "timestamp": "2026-11-02T12:00:00.000Z",
            "event_type": "agentgate.allow",
            "agent": {"type": "agentgate", "session_id": "s", "parent_run_id": "p"},
            "correlation_id": "corr-new",
            "attributes": {"reason": "ok"},
            "action": {},
            "outcome": {"status": "success"},
            "context": {},
        })
        verification = db.verify_chain()
        assert verification["valid"], verification
        assert verification["event_count"] == before["event_count"] + 1
        # The checkpoint taken before the upgrade is still an exact prefix.
        prefix = db.verify_checkpoint(before)
        assert prefix["valid"] and prefix["appended_events"] == 1
        assert [e["event_id"] for e in db.query(correlation_id="corr-new")] == ["after-migration"]
    finally:
        db.close()


@pytest.mark.parametrize("name", V4_FIXTURES)
def test_v4_events_replay_idempotently_after_migration(tmp_path, name):
    path = copy_fixture(name, tmp_path)
    db = AuditDB(str(path))
    try:
        stored = db.query(limit=1000)
        db.insert_events(stored)
        assert db.get_stats()["total_events"] == len(stored)
        assert db.verify_chain()["valid"]
    finally:
        db.close()


@pytest.mark.parametrize("name", V4_FIXTURES)
def test_tampering_with_a_migrated_v4_row_is_still_detected(tmp_path, name):
    path = copy_fixture(name, tmp_path)
    AuditDB(str(path)).close()
    conn = sqlite3.connect(path)
    conn.execute(
        "UPDATE events SET outcome = json_set(outcome, '$.summary', 'rewritten') "
        "WHERE rowid = 3"
    )
    conn.commit()
    conn.close()
    db = AuditDB(str(path))
    try:
        result = db.verify_chain()
        assert not result["valid"] and result["broken_event_id"]
    finally:
        db.close()


def test_stripping_a_v5_field_from_a_row_breaks_the_chain(tmp_path):
    db = AuditDB(str(tmp_path / "v5.db"))
    db.insert_event({
        "event_id": "e1", "timestamp": "2026-11-02T10:00:00.000Z",
        "event_type": "agent_step", "agent": {"type": "t", "session_id": "s"},
        "action": {"tool_names": []}, "outcome": {"status": "success"},
        "context": {}, "correlation_id": "corr", "attributes": {"a": 1},
    })
    assert db.verify_chain()["valid"]
    db.close()
    for statement in (
        "UPDATE events SET correlation_id = NULL",
        "UPDATE events SET correlation_id = 'forged'",
        "UPDATE events SET attributes = NULL",
        "UPDATE events SET attributes = '{\"a\": 2}'",
        "UPDATE events SET parent_run_id = 'forged'",
    ):
        copy = tmp_path / "copy.db"
        shutil.copy(tmp_path / "v5.db", copy)
        conn = sqlite3.connect(copy)
        conn.execute(statement)
        conn.commit()
        conn.close()
        check = AuditDB(str(copy))
        try:
            assert not check.verify_chain()["valid"], statement
        finally:
            check.close()


def test_adding_a_v5_field_to_a_v4_row_breaks_the_chain(tmp_path):
    path = copy_fixture("panoptes_v4.db", tmp_path)
    AuditDB(str(path)).close()
    conn = sqlite3.connect(path)
    conn.execute("UPDATE events SET correlation_id = 'injected' WHERE rowid = 2")
    conn.commit()
    conn.close()
    db = AuditDB(str(path))
    try:
        assert not db.verify_chain()["valid"]
    finally:
        db.close()


def test_a_v6_database_is_refused(tmp_path):
    from panoptes.db import UnsupportedSchemaVersionError

    path = copy_fixture("panoptes_v4.db", tmp_path)
    conn = sqlite3.connect(path)
    conn.execute("INSERT INTO schema_version (version) VALUES (6)")
    conn.commit()
    conn.close()
    with pytest.raises(UnsupportedSchemaVersionError):
        AuditDB(str(path))
