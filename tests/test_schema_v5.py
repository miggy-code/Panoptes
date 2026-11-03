"""Schema v5: open vocabulary, optional run/user, attributes, correlation."""

import copy

import pytest

from panoptes import AuditDB, ValidationError, normalize_event, validate_event
from panoptes.schema import MAX_ATTRIBUTES_BYTES, SCHEMA_VERSION, is_valid_event_type


def make_event(**overrides):
    event = {
        "event_id": "v5-event-1",
        "timestamp": "2026-11-02T10:00:00.000Z",
        "event_type": "agent_step",
        "agent": {"type": "my_agent", "session_id": "sess-1"},
        "action": {"tool_names": ["read"]},
        "outcome": {"status": "success"},
        "context": {},
    }
    event.update(overrides)
    return event


@pytest.fixture
def db():
    database = AuditDB(":memory:")
    yield database
    database.close()


def test_current_schema_version_is_five():
    assert SCHEMA_VERSION == 5
    assert normalize_event(make_event())["context"]["schema_version"] == 5


# ── agent.type is an open validated identifier ───────────────────────────────

@pytest.mark.parametrize("agent_type", ["my_agent", "acme.review-bot", "x" * 256])
def test_agent_type_is_open(db, agent_type):
    event = make_event()
    event["agent"]["type"] = agent_type
    db.insert_event(event)
    assert db.query(agent_type=agent_type)[0]["agent"]["type"] == agent_type


@pytest.mark.parametrize(
    "agent_type",
    ["", "   ", None, 7, "x" * 257, "bad\ntype", "sk-proj-fakefakefakefake0123456789"],
)
def test_agent_type_must_still_be_a_clean_identifier(agent_type):
    event = make_event()
    event["agent"]["type"] = agent_type
    with pytest.raises(ValidationError):
        validate_event(event)
    with pytest.raises(ValidationError):
        normalize_event(event)


def test_agent_type_is_required():
    event = make_event()
    del event["agent"]["type"]
    with pytest.raises(ValidationError, match="Missing agent fields"):
        validate_event(event)


def test_declared_v4_events_keep_the_closed_agent_list():
    event = make_event(context={"schema_version": 4})
    event["agent"]["run_id"] = "run-1"
    with pytest.raises(ValidationError, match="Invalid agent type"):
        validate_event(event)


# ── run_id optional, parent_run_id ───────────────────────────────────────────

def test_run_id_is_optional_and_never_invented(db):
    db.insert_event(make_event())
    stored = db.query()[0]
    assert stored["agent"]["run_id"] is None
    assert stored["agent"]["parent_run_id"] is None
    assert db.query(run_id="anything") == []


def test_explicit_null_run_id_is_the_same_as_none(db):
    event = make_event()
    event["agent"]["run_id"] = None
    assert normalize_event(event)["agent"]["run_id"] is None


def test_declared_v4_events_still_require_run_id():
    event = make_event(context={"schema_version": 4})
    event["agent"]["type"] = "hermes"
    with pytest.raises(ValidationError, match="Missing agent fields"):
        validate_event(event)


def test_parent_run_id_round_trips_and_is_queryable(db):
    child = make_event(event_id="child")
    child["agent"].update(run_id="run-child", parent_run_id="run-parent")
    db.insert_event(child)
    db.insert_event(make_event(event_id="other"))
    found = db.query(parent_run_id="run-parent")
    assert [e["event_id"] for e in found] == ["child"]
    assert found[0]["agent"]["parent_run_id"] == "run-parent"
    assert db.aggregate(["parent_run_id"], ["count"], parent_run_id="run-parent") == [
        {"parent_run_id": "run-parent", "count": 1}
    ]


@pytest.mark.parametrize("bad", ["", "x" * 257, "a\x00b", 3])
def test_parent_run_id_is_validated(bad):
    event = make_event()
    event["agent"]["parent_run_id"] = bad
    with pytest.raises(ValidationError):
        validate_event(event)


def test_declared_v4_events_reject_parent_run_id():
    event = make_event(context={"schema_version": 4})
    event["agent"].update(type="hermes", run_id="r", parent_run_id="p")
    with pytest.raises(ValidationError, match="requires context.schema_version 5"):
        validate_event(event)


# ── correlation_id is first-class ────────────────────────────────────────────

def test_correlation_id_is_a_top_level_indexed_field(db):
    db.insert_event(make_event(event_id="a", correlation_id="corr-1"))
    db.insert_event(make_event(event_id="b", correlation_id="corr-2"))
    db.insert_event(make_event(event_id="c"))
    found = db.query(correlation_id="corr-1")
    assert [e["event_id"] for e in found] == ["a"]
    assert found[0]["correlation_id"] == "corr-1"
    assert {e["event_id"]: e["correlation_id"] for e in db.query()} == {
        "a": "corr-1", "b": "corr-2", "c": None,
    }


@pytest.mark.parametrize(
    "bad", ["", "x" * 257, "a\nb", "Bearer abcdefghijklmnopqrstuvwxyz0123", 5]
)
def test_correlation_id_is_validated_not_rewritten(bad):
    with pytest.raises(ValidationError):
        validate_event(make_event(correlation_id=bad))


def test_declared_v4_events_reject_correlation_id():
    event = make_event(context={"schema_version": 4}, correlation_id="c")
    event["agent"].update(type="hermes", run_id="r")
    with pytest.raises(ValidationError, match="requires context.schema_version 5"):
        validate_event(event)


# ── user is optional; no default identity ────────────────────────────────────

def test_missing_user_stays_missing(db):
    db.insert_event(make_event())
    assert db.query()[0]["user"] == {}


def test_partial_user_gets_no_defaults(db):
    db.insert_event(make_event(user={"id": "alice"}))
    assert db.query()[0]["user"] == {"id": "alice"}


def test_auth_method_is_open(db):
    db.insert_event(make_event(user={"auth_method": "agentgate-run-token"}))
    assert db.query()[0]["user"] == {"auth_method": "agentgate-run-token"}


@pytest.mark.parametrize("bad", ["", "x" * 257, "sk-proj-fakefakefakefake0123456789"])
def test_auth_method_must_be_a_clean_identifier(bad):
    with pytest.raises(ValidationError):
        validate_event(make_event(user={"id": "u", "auth_method": bad}))


def test_declared_v4_events_keep_legacy_user_defaults():
    event = make_event(context={"schema_version": 4})
    event["agent"].update(type="hermes", run_id="r")
    user = normalize_event(event)["user"]
    assert user == {"id": "local_user", "auth_method": "cli"}


# ── attributes ───────────────────────────────────────────────────────────────

def test_attributes_round_trip(db):
    attributes = {"rule_ids": ["r1"], "nested": {"n": 1}, "ok": True}
    db.insert_event(make_event(attributes=attributes))
    assert db.query()[0]["attributes"] == attributes


def test_attributes_are_redacted_like_context():
    event = normalize_event(make_event(attributes={
        "api_key": "whatever",
        "note": "uses sk-proj-fakefakefakefake0123456789 in text",
        "fine": "value",
    }))
    assert event["attributes"]["api_key"] == "[REDACTED]"
    assert "sk-proj" not in event["attributes"]["note"]
    assert event["attributes"]["fine"] == "value"


def test_empty_attributes_are_absent(db):
    assert normalize_event(make_event(attributes={}))["attributes"] is None
    db.insert_event(make_event(attributes={}))
    assert db.query()[0]["attributes"] == {}


@pytest.mark.parametrize("bad", [[], "text", 5, ["a"]])
def test_attributes_must_be_an_object(bad):
    with pytest.raises(ValidationError, match="attributes must be a dict"):
        validate_event(make_event(attributes=bad))


def test_attributes_are_size_bounded():
    big = {"blob": "x" * MAX_ATTRIBUTES_BYTES}
    with pytest.raises(ValidationError, match="attributes exceeds"):
        validate_event(make_event(attributes=big))
    validate_event(make_event(attributes={"blob": "x" * 1000}))


def test_attributes_reject_non_json_values():
    with pytest.raises(ValidationError):
        validate_event(make_event(attributes={"v": float("nan")}))
    with pytest.raises(ValidationError):
        validate_event(make_event(attributes={"v": object()}))


def test_declared_v4_events_reject_attributes():
    event = make_event(context={"schema_version": 4}, attributes={"a": 1})
    event["agent"].update(type="hermes", run_id="r")
    with pytest.raises(ValidationError, match="requires context.schema_version 5"):
        validate_event(event)


# ── namespaced event types ───────────────────────────────────────────────────

@pytest.mark.parametrize(
    "event_type",
    ["agentgate.allow", "acme.review.finished", "a1.b_2"],
)
def test_namespaced_event_types_are_accepted(db, event_type):
    db.insert_event(make_event(event_type=event_type, action={}))
    assert db.query(event_type=event_type)[0]["event_type"] == event_type


@pytest.mark.parametrize(
    "event_type",
    [
        "custom", "unknown", "Agentgate.allow", ".allow", "agentgate.",
        "agentgate..allow", "agentgate.Allow", "1agentgate.allow",
        "agentgate.allow now", "a." + "b" * 130, "", None, 7,
    ],
)
def test_other_event_types_stay_rejected(event_type):
    with pytest.raises(ValidationError, match="Invalid event_type"):
        validate_event(make_event(event_type=event_type))


def test_namespaced_types_need_v5():
    assert is_valid_event_type("agentgate.allow")
    assert not is_valid_event_type("agentgate.allow", 4)
    assert not is_valid_event_type("agent_step", 0)
    event = make_event(event_type="agentgate.allow", context={"schema_version": 4})
    event["agent"].update(type="hermes", run_id="r")
    with pytest.raises(ValidationError, match="Invalid event_type"):
        validate_event(event)


def test_custom_events_do_not_get_data_access_tags():
    event = normalize_event(make_event(
        event_type="acme.thing", action={"target": "prod kubectl"},
    ))
    assert event["action"]["derived_data_accessed"] == []


def test_capture_observed_events_accept_namespaced_types():
    capture = {
        "provenance": "adapter_asserted",
        "authenticated": False,
        "observed_events": ["model_request", "acme.thing"],
    }
    validate_event(make_event(context={"capture": capture}))
    capture = dict(capture, observed_events=["Not.valid"])
    with pytest.raises(ValidationError, match="unknown event types"):
        validate_event(make_event(context={"capture": capture}))


# ── replay ───────────────────────────────────────────────────────────────────

def test_v5_event_round_trips_idempotently(db):
    event = make_event(
        correlation_id="corr-1",
        attributes={"k": "v"},
        user={"id": "alice", "auth_method": "oauth"},
    )
    event["agent"].update(run_id="run-1", parent_run_id="run-0")
    db.insert_event(copy.deepcopy(event))
    stored = db.query()[0]
    db.insert_event(stored)
    db.insert_event(copy.deepcopy(event))
    assert db.get_stats()["total_events"] == 1
    assert db.verify_chain()["valid"]
