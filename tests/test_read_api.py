"""The public read API: query, get_session, aggregate and iter_events."""

import shutil
import threading
from pathlib import Path

import pytest

from panoptes import AuditDB

FIXTURES = Path(__file__).parent / "fixtures"


def event(n, **overrides):
    base = {
        "event_id": f"e{n:04d}",
        # Timestamps deliberately do not follow insertion order.
        "timestamp": f"2026-11-02T10:{(n * 7) % 60:02d}:00.000Z",
        "event_type": "agent_step",
        "agent": {"type": "a" if n % 2 else "b", "session_id": f"s{n % 3}"},
        "action": {"tool_names": []},
        "outcome": {"status": "success"},
        "context": {},
    }
    base.update(overrides)
    return base


@pytest.fixture
def db():
    database = AuditDB(":memory:")
    database.insert_events([event(n) for n in range(1, 31)])
    yield database
    database.close()


def ids(events):
    return [e["event_id"] for e in events]


def test_iter_events_streams_in_write_order_by_default(db):
    assert ids(db.iter_events()) == [f"e{n:04d}" for n in range(1, 31)]


@pytest.mark.parametrize("batch_size", [1, 4, 30, 500])
def test_batching_never_skips_or_repeats(db, batch_size):
    expected = [f"e{n:04d}" for n in range(1, 31)]
    assert ids(db.iter_events(batch_size=batch_size)) == expected
    assert ids(db.iter_events(batch_size=batch_size, order="-rowid")) == expected[::-1]


@pytest.mark.parametrize("batch_size", [1, 3, 500])
def test_timestamp_order_pages_correctly_with_ties(db, batch_size):
    db.insert_events([
        event(100 + i, timestamp="2026-11-02T11:00:00.000Z") for i in range(5)
    ])
    forward = list(db.iter_events(order="timestamp", batch_size=batch_size))
    stamps = [(e["timestamp"], e["event_id"]) for e in forward]
    assert len(forward) == 35 and len(set(ids(forward))) == 35
    assert stamps == sorted(stamps)
    backward = list(db.iter_events(order="-timestamp", batch_size=batch_size))
    assert ids(backward) == ids(forward)[::-1]


def test_filters_match_query(db):
    streamed = ids(db.iter_events(agent_type="a", session_id="s1"))
    queried = ids(reversed(db.query(agent_type="a", session_id="s1", limit=1000)))
    assert streamed == sorted(queried) and streamed


def test_every_documented_filter_narrows_to_the_matching_event(db):
    db.insert_event(event(
        200, correlation_id="c1", event_type="tool_call",
        timestamp="2030-01-01T00:00:00.000Z",
        agent={"type": "x", "session_id": "s", "run_id": "r", "parent_run_id": "p"},
        action={"tool_name": "bash", "target": "prod"},
    ))
    exact = {
        "agent_type": "x", "event_type": "tool_call", "session_id": "s",
        "run_id": "r", "parent_run_id": "p", "correlation_id": "c1",
        "tool_name": "bash", "data_accessed": "prod",
        "since": "2029-01-01T00:00:00.000Z",
    }
    for name, value in exact.items():
        assert ids(db.iter_events(**{name: value})) == ["e0200"], name
    assert ids(db.iter_events(until="2026-12-31T00:00:00.000Z")) == [
        f"e{n:04d}" for n in range(1, 31)
    ]
    assert ids(db.iter_events(**exact)) == ["e0200"]


def test_has_no_row_cap(db):
    db.insert_events([event(1000 + n) for n in range(300)])
    assert sum(1 for _ in db.iter_events(batch_size=50)) == 330


def test_events_appended_during_iteration_are_included_once(db):
    seen = []
    for index, e in enumerate(db.iter_events(batch_size=5)):
        seen.append(e["event_id"])
        if index == 2:
            db.insert_event(event(500))
    assert seen[-1] == "e0500" and len(seen) == len(set(seen)) == 31


def test_iteration_does_not_block_a_writer(db):
    iterator = db.iter_events(batch_size=2)
    next(iterator)
    done = threading.Event()

    def write():
        db.insert_event(event(600))
        done.set()

    threading.Thread(target=write).start()
    assert done.wait(5), "a half-consumed iterator blocked the writer"
    iterator.close()


@pytest.mark.parametrize("kwargs", [{"order": "newest"}, {"batch_size": 0}, {"batch_size": True}])
def test_bad_arguments_are_rejected(db, kwargs):
    with pytest.raises(ValueError):
        list(db.iter_events(**kwargs))


def test_misspelled_filters_fail_instead_of_matching_everything(db):
    with pytest.raises(ValueError, match="Unknown filter"):
        db.query(agent="a")
    with pytest.raises(ValueError, match="Unknown filter"):
        db.aggregate(["agent_type"], agent="a")
    with pytest.raises(TypeError):
        db.iter_events(agent="a")


def test_get_session_is_chronological_and_complete(db):
    session = db.get_session("s1")
    stamps = [e["timestamp"] for e in session]
    assert stamps == sorted(stamps)
    assert ids(session) and all(e["agent"]["session_id"] == "s1" for e in session)


def test_read_api_works_on_a_v4_log_opened_read_only(tmp_path):
    path = tmp_path / "audit.db"
    shutil.copy(FIXTURES / "agentgate_v4.db", path)
    reader = AuditDB.open_readonly(str(path))
    try:
        streamed = list(reader.iter_events(agent_type="agentgate"))
        assert len(streamed) == 91
        assert list(reader.iter_events(correlation_id="x")) == []
        assert ids(reader.iter_events(order="-rowid", batch_size=10)) == ids(streamed)[::-1]
        assert all(e["event_type"] == "decision_point" for e in streamed)
    finally:
        reader.close()
