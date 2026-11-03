"""AuditDB.open_readonly: reads evidence without changing it."""

import hashlib
import os
import shutil
import sqlite3
import stat
from pathlib import Path

import pytest

from panoptes import AuditDB
from panoptes.db import NotAnAuditDatabaseError, UnsupportedSchemaVersionError

FIXTURES = Path(__file__).parent / "fixtures"


def snapshot(path):
    """Everything observable about a database file and its directory."""
    info = os.stat(path)
    return {
        "sha256": hashlib.sha256(Path(path).read_bytes()).hexdigest(),
        "mtime_ns": info.st_mtime_ns,
        "mode": stat.S_IMODE(info.st_mode),
        "dir": sorted(os.listdir(Path(path).parent)),
    }


@pytest.fixture(params=["agentgate_v4.db", "panoptes_v4.db"])
def v4_path(request, tmp_path):
    target = tmp_path / request.param
    shutil.copy(FIXTURES / request.param, target)
    os.chmod(target, 0o644)
    return target


def test_a_v4_log_reads_and_verifies_without_being_migrated(v4_path):
    before = snapshot(v4_path)
    db = AuditDB.open_readonly(str(v4_path))
    try:
        stats = db.get_stats()
        assert stats["schema_version"] == 4
        assert stats["total_events"] > 0
        assert len(db.query(limit=1000)) == stats["total_events"]
        verification = db.verify_chain()
        assert verification["valid"], verification
        assert verification["checked_events"] == stats["total_events"]
        checkpoint = db.get_chain_checkpoint()
        proof = db.verify_checkpoint(checkpoint)
        assert proof["valid"] and proof["exact"]
    finally:
        db.close()
    assert snapshot(v4_path) == before


def test_v5_fields_read_as_empty_on_a_v4_log(v4_path):
    db = AuditDB.open_readonly(str(v4_path))
    try:
        events = db.query(limit=1000)
        assert all(e["correlation_id"] is None and e["attributes"] == {} for e in events)
        assert db.query(correlation_id="anything") == []
        assert db.query(parent_run_id="anything") == []
        grouped = db.aggregate(["correlation_id"], ["count"])
        assert grouped == [{"correlation_id": None, "count": len(events)}]
        first = events[-1]
        assert db.get_session(first["agent"]["session_id"])
        assert db.get_evidence_chain(first["event_id"])
        assert db.list_sessions()
    finally:
        db.close()


def test_no_chain_is_started_for_a_log_that_lost_its_metadata(tmp_path):
    path = tmp_path / "stripped.db"
    shutil.copy(FIXTURES / "panoptes_v4.db", path)
    conn = sqlite3.connect(path)
    conn.execute("DELETE FROM chain_meta")
    conn.commit()
    conn.close()
    before = snapshot(path)

    db = AuditDB.open_readonly(str(path))
    try:
        result = db.verify_chain()
        assert result["valid"] is False
    finally:
        db.close()
    assert snapshot(path) == before
    conn = sqlite3.connect(path)
    assert conn.execute("SELECT COUNT(*) FROM chain_meta").fetchone()[0] == 0
    conn.close()


def test_file_mode_is_not_changed(tmp_path):
    path = tmp_path / "audit.db"
    AuditDB(str(path)).close()
    os.chmod(path, 0o644)
    AuditDB.open_readonly(str(path)).close()
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o644


def test_writes_are_refused(v4_path):
    db = AuditDB.open_readonly(str(v4_path))
    try:
        with pytest.raises(sqlite3.OperationalError):
            db.insert_event({
                "agent": {"type": "t", "session_id": "s"},
                "event_type": "agent_step",
                "action": {"tool_names": []},
                "outcome": {"status": "success"},
                "context": {},
            })
    finally:
        db.close()


def test_missing_path_raises_and_creates_nothing(tmp_path):
    path = tmp_path / "nope.db"
    with pytest.raises(FileNotFoundError):
        AuditDB.open_readonly(str(path))
    assert not path.exists()
    assert list(tmp_path.iterdir()) == []


def test_memory_path_is_refused():
    with pytest.raises(ValueError):
        AuditDB.open_readonly(":memory:")


def test_garbage_and_foreign_files_are_not_audit_databases(tmp_path):
    garbage = tmp_path / "garbage.db"
    garbage.write_bytes(b"this is not sqlite" * 100)
    with pytest.raises(NotAnAuditDatabaseError):
        AuditDB.open_readonly(str(garbage))

    foreign = tmp_path / "foreign.db"
    conn = sqlite3.connect(foreign)
    conn.execute("CREATE TABLE other (x)")
    conn.commit()
    conn.close()
    before = snapshot(foreign)
    with pytest.raises(NotAnAuditDatabaseError):
        AuditDB.open_readonly(str(foreign))
    assert snapshot(foreign) == before

    empty = tmp_path / "empty.db"
    empty.write_bytes(b"")
    with pytest.raises(NotAnAuditDatabaseError):
        AuditDB.open_readonly(str(empty))


def test_a_newer_log_is_refused(v4_path):
    conn = sqlite3.connect(v4_path)
    conn.execute("INSERT INTO schema_version (version) VALUES (99)")
    conn.commit()
    conn.close()
    with pytest.raises(UnsupportedSchemaVersionError):
        AuditDB.open_readonly(str(v4_path))


def test_a_log_a_writer_has_open_can_be_read(tmp_path):
    path = tmp_path / "live.db"
    writer = AuditDB(str(path))
    writer.insert_event({
        "agent": {"type": "t", "session_id": "s"},
        "event_type": "agent_step",
        "action": {"tool_names": []},
        "outcome": {"status": "success"},
        "context": {},
    })
    reader = AuditDB.open_readonly(str(path))
    try:
        assert reader.get_stats()["total_events"] == 1
        writer.insert_event({
            "agent": {"type": "t", "session_id": "s"},
            "event_type": "agent_step",
            "action": {"tool_names": []},
            "outcome": {"status": "success"},
            "context": {},
        })
        assert reader.get_stats()["total_events"] == 2
        assert reader.verify_chain()["valid"]
    finally:
        reader.close()
        writer.close()
