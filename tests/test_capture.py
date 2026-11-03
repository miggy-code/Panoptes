"""Tests for capture fidelity metadata and enforcement boundaries."""

from __future__ import annotations

import logging
import os
import tempfile
import uuid

from panoptes.capture import (
    CaptureCapabilities,
    HERMES_CAPABILITIES,
    PROXY_CAPABILITIES,
)
from panoptes.hermes_plugin import AuditPlugin
from panoptes.proxy import AuditEventWriter
from panoptes.schema import ALLOWED_EVENT_TYPES


class _AuditDBStub:
    def __init__(self) -> None:
        self.events: list[dict] = []

    def insert_event(self, event: dict) -> None:
        self.events.append(event)

    def insert_events(self, events: list[dict]) -> None:
        self.events.extend(events)


class _HermesContext:
    def __init__(self) -> None:
        self.handlers = {}

    def on(self, name):
        def register(fn):
            self.handlers[name] = fn
            return fn
        return register


def test_capture_extras_cannot_override_reserved_capabilities() -> None:
    try:
        PROXY_CAPABILITIES.as_context(
            adapter="forged",
            execution_observed=True,
        )
    except ValueError as exc:
        assert "reserved fields" in str(exc)
    else:
        raise AssertionError("capture extras must not override capability fields")

    capture = PROXY_CAPABILITIES.as_context(adapter_detail="reverse_proxy")
    assert capture["adapter"] == "http_proxy"
    assert capture["execution_observed"] is False
    assert capture["adapter_detail"] == "reverse_proxy"


def test_capture_capabilities_only_name_schema_event_types() -> None:
    for capabilities in (
        PROXY_CAPABILITIES,
        HERMES_CAPABILITIES,
    ):
        assert set(capabilities.observed_events) <= ALLOWED_EVENT_TYPES

    try:
        CaptureCapabilities(
            adapter="invalid",
            fidelity="test",
            observed_events=("made_up_event",),
            observation_boundary="test",
        )
    except ValueError as exc:
        assert "outside the audit schema" in str(exc)
    else:
        raise AssertionError("unknown observed event types must be rejected")


def test_capture_context_explicitly_disclaims_authenticated_provenance() -> None:
    capture = PROXY_CAPABILITIES.as_context()
    assert capture["provenance"] == "adapter_asserted"
    assert capture["authenticated"] is False


def _openai_request(stream: bool = False) -> dict:
    return {
        "model": "gpt-4.1",
        "messages": [{"role": "user", "content": "Run the tool"}],
        "stream": stream,
    }


def test_proxy_events_declare_observation_boundary() -> None:
    writer = AuditEventWriter(_AuditDBStub())
    events, _ = writer.build_request_events(
        path="/v1/chat/completions",
        method="POST",
        req_headers={},
        req_body=_openai_request(),
        run_id=uuid.uuid4().hex,
    )

    capture = events[0]["context"]["capture"]
    assert capture["adapter"] == "http_proxy"
    assert capture["fidelity"] == "model_api"
    assert capture["observation_boundary"] == "model_api"
    assert capture["identity_assurance"] == "client_asserted"
    assert capture["execution_observed"] is False
    assert capture["enforcement_mandatory"] is False
    assert "buffered_model_response" in capture["enforcement_points"]
    assert "local tool execution" in capture["notes"]


def test_hermes_concurrent_steps_get_distinct_turn_numbers() -> None:
    import threading

    class _Context:
        def __init__(self):
            self.handlers = {}

        def on(self, name):
            def register(fn):
                self.handlers[name] = fn
                return fn
            return register

    barrier = threading.Barrier(2)

    class _Step(dict):
        def get(self, key, default=None):
            if key == "tool_names":
                barrier.wait(timeout=5)
            return super().get(key, default)

    with tempfile.TemporaryDirectory() as directory:
        plugin = AuditPlugin(
            db_path=os.path.join(directory, "audit.db"),
        )
        ctx = _Context()
        plugin.register(ctx)
        ctx.handlers["agent:start"]({"session_id": "s1", "run_id": "r1"})

        errors = []

        def run(tool_name):
            try:
                ctx.handlers["agent:step"](_Step({
                    "session_id": "s1",
                    "tool_names": [tool_name],
                }))
            except Exception as exc:
                errors.append(exc)

        threads = [
            threading.Thread(target=run, args=("read_file",)),
            threading.Thread(target=run, args=("write_file",)),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=5)

        assert not errors
        assert all(not thread.is_alive() for thread in threads)
        steps = plugin.db.query(event_type="agent_step", limit=10)
        assert sorted(event["context"]["turn_number"] for event in steps) == [1, 2]
        plugin.db.close()


def test_hermes_single_tool_name_string_is_not_split_into_characters() -> None:
    class _Context:
        def __init__(self):
            self.handlers = {}

        def on(self, name):
            def register(fn):
                self.handlers[name] = fn
                return fn
            return register

    with tempfile.TemporaryDirectory() as directory:
        plugin = AuditPlugin(
            db_path=os.path.join(directory, "audit.db"),
        )
        ctx = _Context()
        plugin.register(ctx)
        ctx.handlers["agent:start"]({"session_id": "s1", "run_id": "r1"})
        ctx.handlers["agent:step"]({
            "session_id": "s1",
            "tool_names": "read_file",
            "tool_input": {"path": "/prod/config"},
        })

        steps = plugin.db.query(event_type="agent_step", limit=10)
        assert len(steps) == 1
        assert steps[0]["action"]["tool_name"] == "read_file"
        assert steps[0]["action"]["data_accessed"] == ["prod"]
        plugin.db.close()


def test_hermes_emits_exactly_one_event_for_each_lifecycle_step() -> None:
    class _Context:
        def __init__(self):
            self.handlers = {}

        def on(self, name):
            def register(fn):
                self.handlers[name] = fn
                return fn
            return register

    with tempfile.TemporaryDirectory() as directory:
        plugin = AuditPlugin(
            db_path=os.path.join(directory, "audit.db"),
        )
        ctx = _Context()
        plugin.register(ctx)
        ctx.handlers["agent:start"]({"session_id": "s1", "run_id": "r1"})
        ctx.handlers["agent:step"]({
            "session_id": "s1",
            "tool_names": [],
            "outcome_summary": None,
        })
        ctx.handlers["agent:step"]({
            "session_id": "s1",
            "tool_names": ["read_file", "write_file"],
        })

        steps = plugin.db.query(event_type="agent_step", limit=10)
        assert len(steps) == 2
        by_turn = {event["context"]["turn_number"]: event for event in steps}
        assert by_turn[1]["action"]["tool_names"] == []
        assert by_turn[2]["action"]["tool_names"] == [
            "read_file",
            "write_file",
        ]
        plugin.db.close()


def test_hermes_redacts_lifecycle_text_before_adapter_truncation() -> None:
    class _Context:
        def __init__(self):
            self.handlers = {}

        def on(self, name):
            def register(fn):
                self.handlers[name] = fn
                return fn
            return register

    private_key = (
        "-----BEGIN PRIVATE KEY-----"
        + ("A" * 800)
        + "-----END PRIVATE KEY-----"
    )
    with tempfile.TemporaryDirectory() as directory:
        plugin = AuditPlugin(
            db_path=os.path.join(directory, "audit.db"),
        )
        ctx = _Context()
        plugin.register(ctx)
        ctx.handlers["agent:start"]({
            "session_id": "s1",
            "run_id": "r1",
            "message": private_key,
        })
        ctx.handlers["agent:end"]({
            "session_id": "s1",
            "response": private_key,
        })

        events = plugin.db.query(limit=10)
        serialized = str(events)
        assert "BEGIN PRIVATE KEY" not in serialized
        assert "A" * 50 not in serialized
        assert "[REDACTED PRIVATE KEY]" in serialized
        plugin.db.close()


def test_hermes_concurrent_sessions_do_not_cross_attribute() -> None:
    class _Context:
        def __init__(self):
            self.handlers = {}

        def on(self, name):
            def register(fn):
                self.handlers[name] = fn
                return fn
            return register

    with tempfile.TemporaryDirectory() as directory:
        plugin = AuditPlugin(
            db_path=os.path.join(directory, "audit.db"),
        )
        ctx = _Context()
        plugin.register(ctx)
        ctx.handlers["agent:start"]({"session_id": "s1", "run_id": "r1"})
        ctx.handlers["agent:start"]({"session_id": "s2", "run_id": "r2"})
        ctx.handlers["agent:step"]({
            "session_id": "s1",
            "tool_names": ["read_file"],
            "tool_input": {"path": "one"},
        })
        ctx.handlers["agent:step"]({
            "session_id": "s2",
            "tool_names": ["write_file"],
            "tool_input": {"path": "two"},
        })

        calls = plugin.db.query(event_type="agent_step", limit=10)
        by_tool = {event["action"]["tool_name"]: event["agent"] for event in calls}
        assert by_tool["read_file"]["session_id"] == "s1"
        assert by_tool["read_file"]["run_id"] == "r1"
        assert by_tool["write_file"]["session_id"] == "s2"
        assert by_tool["write_file"]["run_id"] == "r2"
        plugin.db.close()


def test_hermes_duplicate_start_retains_active_session_attribution(
    caplog,
) -> None:
    with tempfile.TemporaryDirectory() as directory:
        plugin = AuditPlugin(
            db_path=os.path.join(directory, "audit.db"),
        )
        ctx = _HermesContext()
        plugin.register(ctx)

        ctx.handlers["agent:start"]({
            "session_id": "session-1",
            "run_id": "original-run",
            "user_id": "original-user",
        })
        ctx.handlers["agent:step"]({
            "session_id": "session-1",
            "tool_names": ["read_file"],
        })

        with caplog.at_level(logging.WARNING, logger="panoptes.hermes"):
            ctx.handlers["agent:start"]({
                "session_id": "session-1",
                "run_id": "replacement-run",
                "user_id": "replacement-user",
            })

        state = plugin._sessions["session-1"]
        assert state["run_id"] == "original-run"
        assert state["user_id"] == "original-user"
        assert state["turn"] == 1

        ctx.handlers["agent:step"]({
            "session_id": "session-1",
            "run_id": "replacement-run",
            "tool_names": ["write_file"],
        })

        starts = plugin.db.query(event_type="agent_start", limit=10)
        duplicate = next(
            event
            for event in starts
            if event["outcome"]["status"] == "warned"
        )
        assert duplicate["agent"]["run_id"] == "original-run"
        assert duplicate["user"]["id"] == "original-user"
        assert duplicate["context"]["turn_number"] == 1
        steps = plugin.db.query(event_type="agent_step", limit=10)
        assert {event["agent"]["run_id"] for event in steps} == {
            "original-run"
        }
        assert sorted(
            event["context"]["turn_number"] for event in steps
        ) == [1, 2]
        assert "retained its established run and user attribution" in caplog.text
        plugin.db.close()


def test_hermes_active_session_tracking_is_hard_capped_and_auditable(
    caplog,
) -> None:
    with tempfile.TemporaryDirectory() as directory:
        plugin = AuditPlugin(
            db_path=os.path.join(directory, "audit.db"),
            max_active_sessions=2,
        )
        ctx = _HermesContext()
        plugin.register(ctx)

        with caplog.at_level(logging.WARNING, logger="panoptes.hermes"):
            for index in range(3):
                ctx.handlers["agent:start"]({
                    "session_id": f"session-{index}",
                    "run_id": f"run-{index}",
                })

            assert len(plugin._sessions) == 2
            assert "session-0" not in plugin._sessions

            # A late callback remains isolated and bounded rather than being
            # attributed to another active session.
            ctx.handlers["agent:step"]({
                "session_id": "session-0",
                "run_id": "run-0",
                "tool_names": ["read_file"],
            })

        assert len(plugin._sessions) == 2
        starts = plugin.db.query(event_type="agent_start", limit=10)
        capped_start = next(
            event
            for event in starts
            if event["agent"]["session_id"] == "session-2"
        )
        assert "session_tracking" not in capped_start["context"]["capture"]
        steps = plugin.db.query(event_type="agent_step", limit=10)
        assert steps[0]["agent"]["session_id"] == "session-0"
        assert steps[0]["agent"]["run_id"] == "run-0"
        assert "session_tracking" not in steps[0]["context"]["capture"]
        assert "active-session limit reached" in caplog.text
        plugin.db.close()


def test_hermes_lifecycle_write_failures_are_observational_and_cleanup_state() -> None:
    class _Context:
        def __init__(self):
            self.handlers = {}

        def on(self, name):
            def register(fn):
                self.handlers[name] = fn
                return fn
            return register

    class _FailingDB:
        def insert_event(self, event):
            raise OSError("disk full")

    with tempfile.TemporaryDirectory() as directory:
        plugin = AuditPlugin(
            db_path=os.path.join(directory, "audit.db"),
        )
        plugin.db.close()
        plugin.db = _FailingDB()
        ctx = _Context()
        plugin.register(ctx)

        ctx.handlers["agent:start"]({"session_id": "s1", "run_id": "r1"})
        assert plugin._sessions["s1"]["turn"] == 0

        ctx.handlers["agent:step"]({
            "session_id": "s1",
            "tool_names": ["read_file"],
        })
        assert plugin._sessions["s1"]["turn"] == 1

        ctx.handlers["agent:end"]({"session_id": "s1"})
        assert plugin._sessions == {}


_BLOCK_TERMINAL = """
name: block-terminal
enabled: true
action: block
message: Terminal blocked
rule:
  event_type: tool_call
  conditions:
    - field: action.tool_name
      operator: ==
      value: terminal
"""


def _deep(levels: int) -> dict:
    value: dict = {}
    for _ in range(levels):
        value = {"a": value}
    return value


