"""open_readonly on WAL databases: what it touches, and how it fails."""

import hashlib
import os
import shutil
import sqlite3
from pathlib import Path

import pytest

from panoptes import AuditDB, NotAnAuditDatabaseError
from panoptes.db import ReadOnlyMediaError

EVENT = {
    "agent": {"type": "t", "session_id": "s"},
    "event_type": "agent_step",
    "action": {"tool_names": []},
    "outcome": {"status": "success"},
    "context": {},
}

needs_non_root = pytest.mark.skipif(
    hasattr(os, "geteuid") and os.geteuid() == 0,
    reason="directory permissions do not bind root",
)


def directory_state(directory, *, ignore_suffixes=()):
    """Every file in the directory: name, size, mode and content hash."""
    state = {}
    for entry in sorted(Path(directory).iterdir()):
        if entry.name.endswith(ignore_suffixes):
            continue
        info = entry.stat()
        state[entry.name] = (
            info.st_size,
            info.st_mode,
            hashlib.sha256(entry.read_bytes()).hexdigest(),
        )
    return state


SIDECARS = ("-wal", "-shm")


def assert_only_empty_sidecars_added(directory, before):
    """The database was untouched; at most empty WAL sidecars appeared."""
    after = directory_state(directory)
    for name, state in before.items():
        assert after[name] == state, f"{name} changed"
    added = set(after) - set(before)
    assert all(name.endswith(SIDECARS) for name in added), added
    for name in added:
        if name.endswith("-wal"):
            assert after[name][0] == 0, "a read-only open wrote WAL content"


def use(reader):
    reader.get_stats()
    reader.query()
    list(reader.iter_events())
    reader.verify_chain()
    reader.get_chain_checkpoint()


def test_reading_a_cleanly_closed_wal_database_adds_only_empty_sidecars(tmp_path):
    """SQLite needs -wal/-shm to read a WAL database, and a read-only handle
    cannot remove them again. They hold no data; the database is untouched."""
    path = tmp_path / "audit.db"
    writer = AuditDB(str(path))
    writer.insert_event(EVENT)
    writer.close()
    assert sorted(os.listdir(tmp_path)) == ["audit.db"]
    before = directory_state(tmp_path)

    reader = AuditDB.open_readonly(str(path))
    use(reader)
    reader.close()

    assert_only_empty_sidecars_added(tmp_path, before)


def test_a_writer_cleans_up_after_a_reader_and_the_chain_still_verifies(tmp_path):
    path = tmp_path / "audit.db"
    writer = AuditDB(str(path))
    writer.insert_event(EVENT)
    writer.close()
    reader = AuditDB.open_readonly(str(path))
    use(reader)
    reader.close()

    again = AuditDB(str(path))
    again.insert_event({**EVENT, "event_id": "later",
                        "timestamp": "2026-11-02T11:00:00.000Z"})
    assert again.verify_chain()["valid"]
    again.close()
    assert sorted(os.listdir(tmp_path)) == ["audit.db"]


def test_a_live_writers_files_are_not_changed_by_a_reader(tmp_path):
    path = tmp_path / "audit.db"
    writer = AuditDB(str(path))
    writer.insert_event(EVENT)
    held = writer._get_conn()
    held.execute("SELECT COUNT(*) FROM events").fetchall()  # keeps -wal/-shm alive
    try:
        names = sorted(os.listdir(tmp_path))
        assert names == ["audit.db", "audit.db-shm", "audit.db-wal"]
        # -shm is shared memory that every reader updates; the data files are
        # what a reader must not touch.
        before = directory_state(tmp_path, ignore_suffixes=("-shm",))

        reader = AuditDB.open_readonly(str(path))
        use(reader)
        reader.close()

        assert sorted(os.listdir(tmp_path)) == names
        assert directory_state(tmp_path, ignore_suffixes=("-shm",)) == before
    finally:
        writer._put_conn(held)
        writer.close()


def test_only_wal_sidecars_may_appear_while_a_reader_is_open(tmp_path):
    path = tmp_path / "audit.db"
    writer = AuditDB(str(path))
    for n in range(3):
        writer.insert_event({**EVENT, "event_id": f"e{n}",
                             "timestamp": f"2026-11-02T10:00:0{n}.000Z"})
    writer.close()

    reader = AuditDB.open_readonly(str(path))
    iterator = reader.iter_events(batch_size=1)
    next(iterator)
    extra = set(os.listdir(tmp_path)) - {"audit.db"}
    assert extra <= {"audit.db-wal", "audit.db-shm"}
    list(iterator)
    reader.close()
    assert set(os.listdir(tmp_path)) - {"audit.db"} <= {"audit.db-wal", "audit.db-shm"}


@needs_non_root
def test_a_wal_database_cannot_be_read_from_a_read_only_directory_without_sidecars(tmp_path):
    path = tmp_path / "audit.db"
    writer = AuditDB(str(path))
    writer.insert_event(EVENT)
    writer.close()
    before = directory_state(tmp_path)
    os.chmod(tmp_path, 0o500)
    try:
        with pytest.raises(ReadOnlyMediaError, match="not writable") as raised:
            AuditDB.open_readonly(str(path))
    finally:
        os.chmod(tmp_path, 0o700)
    assert not isinstance(raised.value, NotAnAuditDatabaseError)
    assert directory_state(tmp_path) == before


@needs_non_root
def test_it_reads_from_a_read_only_directory_once_the_sidecars_exist(tmp_path):
    path = tmp_path / "audit.db"
    writer = AuditDB(str(path))
    writer.insert_event(EVENT)
    writer.close()
    AuditDB.open_readonly(str(path)).close()  # leaves the empty sidecars
    before = directory_state(tmp_path)
    os.chmod(tmp_path, 0o500)
    try:
        reader = AuditDB.open_readonly(str(path))
        use(reader)
        assert reader.get_stats()["total_events"] == 1
        reader.close()
    finally:
        os.chmod(tmp_path, 0o700)
    assert directory_state(tmp_path) == before


@needs_non_root
def test_an_unclean_wal_database_in_a_read_only_directory_says_so(tmp_path):
    source = tmp_path / "src"
    target = tmp_path / "dst"
    source.mkdir()
    target.mkdir()
    writer = AuditDB(str(source / "audit.db"))
    writer.insert_event(EVENT)
    held = writer._get_conn()
    held.execute("SELECT COUNT(*) FROM events").fetchall()
    for name in ("audit.db", "audit.db-wal"):
        shutil.copy(source / name, target / name)
    writer._put_conn(held)
    writer.close()

    before = directory_state(target)
    os.chmod(target, 0o500)
    try:
        with pytest.raises(ReadOnlyMediaError, match="not writable") as raised:
            AuditDB.open_readonly(str(target / "audit.db"))
    finally:
        os.chmod(target, 0o700)
    assert not isinstance(raised.value, NotAnAuditDatabaseError)
    assert isinstance(raised.value.__cause__, sqlite3.OperationalError)
    assert directory_state(target) == before


def test_a_locked_database_is_not_reported_as_foreign(tmp_path, monkeypatch):
    """Operational failures keep their own type instead of 'not a Panoptes log'."""
    path = tmp_path / "audit.db"
    AuditDB(str(path), chain=False).close()
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA journal_mode=DELETE")
    conn.commit()
    conn.execute("BEGIN EXCLUSIVE")
    real_get_conn = AuditDB._get_conn

    def quick_get_conn(self):
        conn = real_get_conn(self)
        conn.execute("PRAGMA busy_timeout=50")
        return conn

    monkeypatch.setattr(AuditDB, "_get_conn", quick_get_conn)
    try:
        with pytest.raises(sqlite3.OperationalError, match="locked"):
            AuditDB.open_readonly(str(path))
    finally:
        conn.rollback()
        conn.close()


def test_a_corrupt_file_is_still_not_an_audit_database(tmp_path):
    path = tmp_path / "audit.db"
    path.write_bytes(b"SQLite format 3\x00" + b"\xff" * 4096)
    with pytest.raises(NotAnAuditDatabaseError):
        AuditDB.open_readonly(str(path))
