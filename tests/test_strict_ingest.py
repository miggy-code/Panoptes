"""Strict ingest: identifier fields are stored exactly as given or not at all."""

import pytest

from panoptes import AuditDB, ValidationError
from panoptes.schema import IdentifierRewriteError

URL_WITH_SECRET = "https://user:hunter2@db.internal/prod"


def make_event(**overrides):
    event = {
        "event_id": "strict-1",
        "timestamp": "2026-11-02T10:00:00.000Z",
        "event_type": "tool_call",
        "agent": {"type": "t", "session_id": "s", "run_id": "r"},
        "action": {"tool_name": "fetch", "target": "https://example.com/a"},
        "outcome": {"status": "success", "summary": "ok"},
        "context": {},
    }
    event.update(overrides)
    return event


@pytest.fixture
def db():
    database = AuditDB(":memory:")
    yield database
    database.close()


def test_clean_identifiers_pass_unchanged(db):
    event = make_event(
        correlation_id="c-1",
        user={"id": "alice", "auth_method": "oauth"},
        attributes={"rule_ids": ["r1", "r2"]},
    )
    db.insert_event(event, strict=True, strict_paths=("attributes.rule_ids[]",))
    assert db.query()[0]["action"]["target"] == "https://example.com/a"


def test_default_mode_still_redacts_a_target_in_place(db):
    db.insert_event(make_event(action={"tool_name": "fetch", "target": URL_WITH_SECRET}))
    assert "hunter2" not in db.query()[0]["action"]["target"]


def test_strict_refuses_a_target_redaction_would_rewrite(db):
    event = make_event(action={"tool_name": "fetch", "target": URL_WITH_SECRET})
    with pytest.raises(IdentifierRewriteError, match="action.target") as raised:
        db.insert_event(event, strict=True)
    assert "hunter2" not in str(raised.value)
    assert db.get_stats()["total_events"] == 0


def test_strict_error_is_a_validation_error():
    assert issubclass(IdentifierRewriteError, ValidationError)


def test_strict_refuses_an_agent_version_that_would_be_rewritten(db):
    event = make_event()
    event["agent"]["version"] = "Bearer abcdefghijklmnopqrstuvwxyz0123456789"
    with pytest.raises(IdentifierRewriteError, match="agent.version"):
        db.insert_event(event, strict=True)
    db.insert_event(event)  # not strict: redacted and stored
    assert "abcdefgh" not in db.query()[0]["agent"]["version"]


def test_strict_still_redacts_free_text(db):
    event = make_event(outcome={
        "status": "success",
        "summary": "used sk-proj-fakefakefakefake0123456789 here",
    })
    db.insert_event(event, strict=True)
    assert "sk-proj" not in db.query()[0]["outcome"]["summary"]


def test_strict_paths_cover_caller_named_fields(db):
    event = make_event(attributes={
        "policy_version": "v1",
        "rule_ids": ["ok", "Bearer abcdefghijklmnopqrstuvwxyz0123456789"],
    })
    db.insert_event(event, strict=True)  # attributes are free-form by default
    with pytest.raises(IdentifierRewriteError, match=r"attributes.rule_ids\[\]"):
        db.insert_event(
            make_event(event_id="strict-2", attributes=event["attributes"]),
            strict_paths=("attributes.rule_ids[]",),
        )
    with pytest.raises(IdentifierRewriteError, match="attributes.policy_version"):
        db.insert_event(
            make_event(event_id="strict-3", attributes={
                "policy_version": "https://u:p4ssw0rd@h/x",
            }),
            strict_paths=("attributes.policy_version",),
        )


def test_absent_and_defaulted_fields_are_not_errors(db):
    # No user, no correlation id, no target: nothing to compare.
    db.insert_event(make_event(action={"tool_name": "fetch"}), strict=True)


def test_refusal_aborts_the_whole_batch_before_any_write(db):
    good = make_event(event_id="good")
    bad = make_event(
        event_id="bad",
        action={"tool_name": "fetch", "target": URL_WITH_SECRET},
    )
    with pytest.raises(IdentifierRewriteError):
        db.insert_events([good, bad], strict=True)
    assert db.get_stats()["total_events"] == 0
    assert db.verify_chain()["event_count"] == 0


def test_strict_replay_of_a_stored_event_is_idempotent(db):
    db.insert_event(make_event(), strict=True)
    db.insert_event(db.query()[0], strict=True)
    assert db.get_stats()["total_events"] == 1
