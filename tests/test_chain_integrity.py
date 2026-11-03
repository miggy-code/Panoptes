"""A stripped or forged chain never reads as an intact one."""

import shutil
import sqlite3
from pathlib import Path

import pytest

from panoptes import AuditDB, ChainIntegrityError

FIXTURES = Path(__file__).parent / "fixtures"


def event(n):
    return {
        "event_id": f"e{n}",
        "timestamp": f"2026-11-02T10:00:{n:02d}.000Z",
        "event_type": "agent_step",
        "agent": {"type": "t", "session_id": "s"},
        "action": {"tool_names": []},
        "outcome": {"status": "success"},
        "context": {},
    }


def chained_db(path, count=5):
    db = AuditDB(str(path))
    db.insert_events([event(n) for n in range(count)])
    db.close()
    return path


def edit(path, *statements):
    conn = sqlite3.connect(path)
    for statement in statements:
        conn.execute(statement)
    conn.commit()
    conn.close()


STRIP = (
    "DELETE FROM chain_meta",
    "UPDATE events SET prev_hash = NULL, event_hash = NULL",
)
FORGE_MARKER = "INSERT INTO chain_meta (key, value) VALUES ('chain_disabled', '1')"


def read_only_verify(path):
    reader = AuditDB.open_readonly(str(path))
    try:
        return reader.verify_chain()
    finally:
        reader.close()


# ── the stripped-and-restarted chain ─────────────────────────────────────────

def test_a_stripped_chain_reopened_with_chain_true_is_not_valid(tmp_path):
    path = chained_db(tmp_path / "audit.db", 5)
    edit(path, *STRIP, FORGE_MARKER)

    db = AuditDB(str(path), chain=True)
    try:
        result = db.verify_chain()
    finally:
        db.close()
    assert result["valid"] is False
    assert result["chain"] == "partial"
    assert result["event_count"] == 0
    assert result["legacy_event_count"] == 5
    assert "5 events" in result["error"]

    # Read-only agrees with read-write on the same file.
    assert read_only_verify(path)["chain"] == "partial"
    assert read_only_verify(path)["valid"] is False


def test_the_same_file_reopened_by_default_reads_as_unchained(tmp_path):
    path = chained_db(tmp_path / "audit.db", 3)
    edit(path, *STRIP, FORGE_MARKER)
    db = AuditDB(str(path))
    try:
        result = db.verify_chain()
    finally:
        db.close()
    assert result["chain"] == "absent" and result["valid"] is False


def test_a_chain_that_covers_events_alongside_legacy_ones_stays_intact(tmp_path):
    path = tmp_path / "audit.db"
    plain = AuditDB(str(path), chain=False)
    plain.insert_events([event(0), event(1)])
    plain.close()
    db = AuditDB(str(path), chain=True)
    assert db.verify_chain()["chain"] == "partial"          # nothing covered yet
    db.insert_event(event(2))
    result = db.verify_chain()
    db.close()
    assert result["valid"] is True and result["chain"] == "intact"
    assert result["coverage"] == "partial"                   # still disclosed


def test_an_empty_chained_database_is_still_intact(tmp_path):
    db = AuditDB(str(tmp_path / "audit.db"))
    result = db.verify_chain()
    db.close()
    assert result["valid"] and result["chain"] == "intact"


# ── read-only and read-write agree ───────────────────────────────────────────

TAMPERED = {
    "metadata deleted, hashes nulled": STRIP,
    "metadata deleted only": ("DELETE FROM chain_meta",),
    "chain_meta table dropped": ("DROP TABLE chain_meta",),
}


@pytest.mark.parametrize("name", TAMPERED)
def test_a_chain_stripped_from_a_schema_4_plus_database_is_broken_everywhere(tmp_path, name):
    path = chained_db(tmp_path / "audit.db", 4)
    edit(path, *TAMPERED[name])

    result = read_only_verify(path)
    assert result["valid"] is False
    assert result["chain"] == "broken", result

    with pytest.raises(ChainIntegrityError):
        AuditDB(str(path))                      # the writer refuses it too
    reader = AuditDB.open_readonly(str(path))
    try:
        with pytest.raises(ChainIntegrityError):
            reader.get_chain_checkpoint()
    finally:
        reader.close()


def test_an_empty_database_missing_its_chain_metadata_is_broken(tmp_path):
    path = chained_db(tmp_path / "audit.db", 0)
    edit(path, "DELETE FROM chain_meta")
    assert read_only_verify(path)["chain"] == "broken"
    with pytest.raises(ChainIntegrityError):
        AuditDB(str(path))


def test_a_pre_chain_schema_without_metadata_is_absent_not_broken(tmp_path):
    path = tmp_path / "v3.db"
    shutil.copy(FIXTURES / "panoptes_v4.db", path)
    edit(path, "DELETE FROM chain_meta", "UPDATE schema_version SET version = 3")
    result = read_only_verify(path)
    assert result["chain"] == "broken"          # hashed events without metadata
    edit(path, "UPDATE events SET prev_hash = NULL, event_hash = NULL")
    result = read_only_verify(path)
    assert result["chain"] == "absent" and result["valid"] is False


# ── a forged marker ──────────────────────────────────────────────────────────

def test_a_disabled_marker_beside_a_live_chain_is_broken_everywhere(tmp_path):
    path = chained_db(tmp_path / "audit.db", 3)
    edit(path, FORGE_MARKER)

    result = read_only_verify(path)
    assert result["valid"] is False and result["chain"] == "broken"
    assert "both" in result["error"]
    with pytest.raises(ChainIntegrityError):
        AuditDB(str(path))
    reader = AuditDB.open_readonly(str(path))
    try:
        with pytest.raises(ChainIntegrityError, match="both"):
            reader.get_chain_checkpoint()
        assert reader.verify_checkpoint({
            "format_version": "1", "algorithm": "sha256", "anchor": "a",
            "head": "a", "event_count": 0, "legacy_event_count": 0,
        })["valid"] is False
    finally:
        reader.close()


# ── checkpoints carry a consistent chain key ─────────────────────────────────

def test_checkpoints_always_say_whether_a_chain_is_present(tmp_path):
    chained = AuditDB(str(tmp_path / "a.db"))
    chained.insert_event(event(0))
    checkpoint = chained.get_chain_checkpoint()
    assert checkpoint["chain"] == "present" and checkpoint["initialized"] is True
    # A stored checkpoint (with the extra key) still verifies.
    assert chained.verify_checkpoint(checkpoint)["valid"]
    chained.close()

    plain = AuditDB(str(tmp_path / "b.db"), chain=False)
    checkpoint = plain.get_chain_checkpoint()
    assert checkpoint["chain"] == "absent" and checkpoint["initialized"] is False
    plain.close()


def test_the_v4_fixtures_still_verify_intact_read_only():
    for name in ("agentgate_v4.db", "panoptes_v4.db"):
        reader = AuditDB.open_readonly(str(FIXTURES / name))
        try:
            result = reader.verify_chain()
        finally:
            reader.close()
        assert result["valid"] and result["chain"] == "intact", name
