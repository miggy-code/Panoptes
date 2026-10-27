"""Tests for capture fidelity metadata and enforcement boundaries."""

from __future__ import annotations

import io
import json
import logging
import os
import tempfile
import uuid
from pathlib import Path

from panoptes.capture import (
    CaptureCapabilities,
    HERMES_AUTHORIZER_CAPABILITIES,
    HERMES_CAPABILITIES,
    PROXY_CAPABILITIES,
)
from panoptes.hermes_plugin import AuditPlugin
from panoptes.policy import (
    POLICY_ENGINE_SEMANTICS_VERSION,
    PolicyEngine,
    PolicyResult,
)
from panoptes.proxy import AuditEventWriter, ProxyHandler
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
        HERMES_AUTHORIZER_CAPABILITIES,
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


def test_streaming_with_blocking_policy_is_marked_for_buffering() -> None:
    writer = AuditEventWriter(_AuditDBStub())

    class _BlockingEngine:
        has_blocking_policies = True

    writer.policy_engine = _BlockingEngine()
    events, _ = writer.build_request_events(
        path="/v1/chat/completions",
        method="POST",
        req_headers={},
        req_body=_openai_request(stream=True),
        run_id=uuid.uuid4().hex,
    )

    assert writer.requires_stream_buffering
    assert (
        events[0]["context"]["capture"]["stream_delivery"]
        == "buffered_for_enforcement"
    )


def test_buffered_stream_is_checked_before_client_receives_tool_call() -> None:
    db = _AuditDBStub()
    writer = AuditEventWriter(db)

    class _ToolBlockingEngine:
        def check_event(self, event: dict) -> PolicyResult:
            if event["event_type"] == "tool_call":
                return PolicyResult(
                    action="block",
                    violated_policies=[{
                        "policy_name": "no-prod-tool",
                        "message": "Production tool call blocked",
                        "reason": "test",
                    }],
                )
            return PolicyResult(action="allow")

    writer.policy_engine = _ToolBlockingEngine()
    req_events, exchange_ctx = writer.build_request_events(
        path="/v1/chat/completions",
        method="POST",
        req_headers={},
        req_body=_openai_request(stream=True),
        run_id=uuid.uuid4().hex,
    )

    tool_delta = {
        "id": "chatcmpl-1",
        "model": "gpt-4.1",
        "choices": [{
            "index": 0,
            "delta": {"tool_calls": [{
                "index": 0,
                "id": "call-prod",
                "function": {
                    "name": "terminal",
                    "arguments": json.dumps({"command": "kubectl get pods -n prod"}),
                },
            }]},
            "finish_reason": None,
        }],
    }
    finished = {
        "id": "chatcmpl-1",
        "model": "gpt-4.1",
        "choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls"}],
    }
    sse = (
        f"data: {json.dumps(tool_delta)}\n\n"
        f"data: {json.dumps(finished)}\n\n"
        "data: [DONE]\n\n"
    ).encode()

    class _Handler:
        def __init__(self) -> None:
            self.writer = writer
            self.wfile = io.BytesIO()
            self.status = None
            self.headers: list[tuple[str, str]] = []

        def _forward_request(self, *args, **kwargs):
            return 200, {"content-type": "text/event-stream"}, sse

        def send_response(self, status: int) -> None:
            self.status = status

        def send_header(self, key: str, value: str) -> None:
            self.headers.append((key, value))

        def end_headers(self) -> None:
            pass

    handler = _Handler()
    ProxyHandler._handle_buffered(
        handler,
        method="POST",
        scheme="https",
        host="api.openai.com",
        port=443,
        path="/v1/chat/completions",
        req_headers={},
        body=json.dumps(_openai_request(stream=True)).encode(),
        req_body=_openai_request(stream=True),
        req_events=req_events,
        exchange_ctx=exchange_ctx,
        t0=0.0,
    )

    assert handler.status == 403
    assert json.loads(handler.wfile.getvalue())["error"] == "Production tool call blocked"
    assert any(event["event_type"] == "tool_call" for event in db.events)


def test_policy_engine_supports_fail_closed_for_invalid_policy() -> None:
    with tempfile.TemporaryDirectory() as directory:
        path = os.path.join(directory, "invalid.yaml")
        with open(path, "w", encoding="utf-8") as f:
            f.write("name: [unterminated\n")

        event = {
            "agent": {"type": "hermes", "session_id": "s1", "run_id": "r1"},
            "event_type": "tool_call",
            "action": {"tool_name": "terminal", "parameters": {}},
            "outcome": {"status": "success"},
            "context": {},
        }
        open_result = PolicyEngine(directory).evaluate(event)
        closed_result = PolicyEngine(directory, failure_mode="fail_closed").evaluate(event)

        assert open_result.action == "allow"
        assert open_result.evaluation_errors
        assert closed_result.action == "block"
        assert closed_result.violated_policies[0]["policy_name"] == "policy_engine_error"


def test_proxy_normalizes_before_checking_bundled_policy() -> None:
    """Derived access tags must exist before the enforcement decision."""
    with tempfile.TemporaryDirectory() as directory:
        bundled = (
            Path(__file__).parents[1]
            / "panoptes"
            / "default_policies"
            / "no-prod-access.yaml"
        )
        policy_path = Path(directory) / bundled.name
        policy_path.write_text(bundled.read_text(encoding="utf-8"), encoding="utf-8")

        writer = AuditEventWriter(_AuditDBStub(), policies_dir=directory)
        _, exchange_ctx = writer.build_request_events(
            path="/v1/chat/completions",
            method="POST",
            req_headers={},
            req_body=_openai_request(),
            run_id=uuid.uuid4().hex,
        )
        events = writer.build_response_events(
            path="/v1/chat/completions",
            req_body=_openai_request(),
            resp_status=200,
            resp_headers={},
            resp_body={
                "choices": [{
                    "message": {
                        "tool_calls": [{
                            "id": "call-prod",
                            "function": {
                                "name": "terminal",
                                "arguments": json.dumps({
                                    "command": "kubectl get pods -n prod",
                                }),
                            },
                        }],
                    },
                }],
            },
            duration_ms=1,
            exchange_ctx=exchange_ctx,
        )
        tool_call = next(e for e in events if e["event_type"] == "tool_call")

        assert tool_call["action"]["data_accessed"] == ["infra", "prod"]
        assert writer.check_policies([tool_call]).action == "block"


def test_proxy_unexpected_policy_error_respects_failure_mode() -> None:
    """Broad proxy error handling must not override fail-closed mode."""
    class _BrokenWriter:
        def __init__(self, failure_mode: str) -> None:
            self.policy_failure_mode = failure_mode

        def build_request_events(self, **kwargs):
            raise RuntimeError("policy subsystem exploded")

    class _Handler:
        def __init__(self, failure_mode: str) -> None:
            self.writer = _BrokenWriter(failure_mode)
            self.headers = {}
            self.forwarded = False
            self.error: tuple[int, str, dict | None] | None = None

        def _parse_target(self):
            return "https", "api.openai.com", 443, "/v1/chat/completions"

        def _read_body(self):
            return json.dumps(_openai_request()).encode()

        def _send_json_error(self, status, message, extra=None):
            self.error = (status, message, extra)

        def _handle_buffered(self, **kwargs):
            self.forwarded = True

    closed = _Handler("fail_closed")
    ProxyHandler._handle_request(closed, "POST")
    assert not closed.forwarded
    assert closed.error is not None
    assert closed.error[0] == 503
    assert closed.error[2]["policy_error"] is True

    opened = _Handler("fail_open")
    ProxyHandler._handle_request(opened, "POST")
    assert opened.forwarded
    assert opened.error is None


def test_buffered_postflight_error_fails_closed_before_delivery() -> None:
    class _BrokenWriter:
        policy_failure_mode = "fail_closed"

        def build_response_events(self, **kwargs):
            raise RuntimeError("response policy subsystem exploded")

    class _Handler:
        writer = _BrokenWriter()

        def __init__(self) -> None:
            self.wfile = io.BytesIO()
            self.status = None

        def _forward_request(self, *args, **kwargs):
            return 200, {"content-type": "application/json"}, b'{"ok": true}'

        def send_response(self, status):
            self.status = status

        def send_header(self, key, value):
            pass

        def end_headers(self):
            pass

    handler = _Handler()
    ProxyHandler._handle_buffered(
        handler,
        method="POST",
        scheme="https",
        host="api.openai.com",
        port=443,
        path="/v1/chat/completions",
        req_headers={},
        body=json.dumps(_openai_request()).encode(),
        req_body=_openai_request(),
        req_events=[],
        exchange_ctx={"req_info": {"stream": False}},
        t0=0.0,
    )

    assert handler.status == 503
    assert json.loads(handler.wfile.getvalue())["policy_error"] is True


def test_hermes_pre_execution_authorizer_persists_blocked_call() -> None:
    with tempfile.TemporaryDirectory() as directory:
        db_path = os.path.join(directory, "audit.db")
        policies_dir = os.path.join(directory, "policies")
        os.mkdir(policies_dir)
        with open(os.path.join(policies_dir, "block.yaml"), "w", encoding="utf-8") as f:
            f.write(
                """
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
            )

        plugin = AuditPlugin(db_path=db_path, policies_dir=policies_dir)
        decision = plugin.authorize_tool_call({
            "session_id": "session-1",
            "run_id": "run-1",
            "tool_name": "terminal",
            "tool_input": {"command": "kubectl get pods -n prod"},
        })

        assert not decision.allowed
        assert decision.action == "block"
        decisions = plugin.db.query(event_type="decision_point")
        requests = plugin.db.query(event_type="tool_call")
        violations = plugin.db.query(event_type="policy_violation")
        assert len(decisions) == 1
        assert len(requests) == 1
        assert len(violations) == 1
        assert (
            requests[0]["event_id"]
            == decisions[0]["context"]["source_event_id"]
        )
        assert (
            requests[0]["event_id"]
            == violations[0]["context"]["source_event_id"]
        )
        assert decisions[0]["outcome"]["status"] == "blocked"
        assert decisions[0]["context"]["capture"]["authorization_check"] == "pre_execution"
        assert decisions[0]["context"]["capture"]["adapter"] == "hermes_authorizer"
        assert (
            decisions[0]["context"]["capture"]["observation_boundary"]
            == "hermes_host_authorizer"
        )
        assert decisions[0]["context"]["decision_kind"] == "tool_authorization"
        assert (
            decisions[0]["context"]["policy"]["semantics_version"]
            == POLICY_ENGINE_SEMANTICS_VERSION
        )
        plugin.db.close()


def test_hermes_authorizer_derives_access_before_bundled_policy() -> None:
    with tempfile.TemporaryDirectory() as directory:
        db_path = os.path.join(directory, "audit.db")
        policies_dir = os.path.join(directory, "policies")
        os.mkdir(policies_dir)
        bundled = (
            Path(__file__).parents[1]
            / "panoptes"
            / "default_policies"
            / "no-prod-access.yaml"
        )
        Path(policies_dir, bundled.name).write_text(
            bundled.read_text(encoding="utf-8"),
            encoding="utf-8",
        )

        plugin = AuditPlugin(db_path=db_path, policies_dir=policies_dir)
        decision = plugin.authorize_tool_call({
            "session_id": "session-1",
            "run_id": "run-1",
            "tool_name": "terminal",
            "tool_input": {"command": "kubectl get pods -n prod"},
        })

        assert not decision.allowed
        stored = plugin.db.query(event_type="decision_point")
        assert stored[0]["action"]["data_accessed"] == ["infra", "prod"]
        plugin.db.close()


def test_default_hermes_plugin_initializes_policy_engine() -> None:
    """The installed singleton must not silently disable policy evaluation."""
    with tempfile.TemporaryDirectory() as directory:
        plugin = AuditPlugin(db_path=os.path.join(directory, "audit.db"))
        assert plugin.policy_engine is not None
        plugin.db.close()


def test_hermes_deny_survives_audit_write_failure() -> None:
    """A failed evidence write must never turn a deny into a host exception."""
    with tempfile.TemporaryDirectory() as directory:
        policies_dir = os.path.join(directory, "policies")
        os.mkdir(policies_dir)
        Path(policies_dir, "block.yaml").write_text(
            """
name: block-terminal
enabled: true
action: block
rule:
  event_type: tool_call
  conditions:
    - field: action.tool_name
      operator: ==
      value: terminal
""",
            encoding="utf-8",
        )
        plugin = AuditPlugin(
            db_path=os.path.join(directory, "audit.db"),
            policies_dir=policies_dir,
        )

        class _FailingDB:
            def insert_event(self, event):
                raise OSError("disk full")

        plugin.db = _FailingDB()
        decision = plugin.authorize_tool_call({
            "session_id": "session-1",
            "run_id": "run-1",
            "tool_name": "terminal",
            "tool_input": {"command": "rm -rf /"},
        })
        assert not decision.allowed
        assert decision.action == "block"


def test_hermes_fail_closed_denies_without_policy_engine() -> None:
    with tempfile.TemporaryDirectory() as directory:
        plugin = AuditPlugin(
            db_path=os.path.join(directory, "audit.db"),
            policies_dir=None,
            policy_failure_mode="fail_closed",
        )

        decision = plugin.authorize_tool_call({
            "session_id": "session-1",
            "run_id": "run-1",
            "tool_name": "terminal",
            "tool_input": {"command": "echo hello"},
        })

        assert not decision.allowed
        assert decision.action == "block"
        stored = plugin.db.query(event_type="decision_point")
        assert stored[0]["context"]["policy"]["evaluation_errors"]
        plugin.db.close()


def test_hermes_fail_closed_denies_when_allow_decision_cannot_be_persisted() -> None:
    with tempfile.TemporaryDirectory() as directory:
        policies_dir = os.path.join(directory, "policies")
        os.mkdir(policies_dir)
        Path(policies_dir, "allow.yaml").write_text(
            """
name: allow-terminal
enabled: true
action: allow
rule:
  event_type: tool_call
  conditions:
    - field: action.tool_name
      operator: ==
      value: terminal
""",
            encoding="utf-8",
        )
        plugin = AuditPlugin(
            db_path=os.path.join(directory, "audit.db"),
            policies_dir=policies_dir,
            policy_failure_mode="fail_closed",
        )

        class _FailingDB:
            def insert_event(self, event):
                raise OSError("disk full")

        plugin.db = _FailingDB()
        decision = plugin.authorize_tool_call({
            "session_id": "session-1",
            "run_id": "run-1",
            "tool_name": "terminal",
            "tool_input": {"command": "echo hello"},
        })

        assert not decision.allowed
        assert decision.action == "block"
        assert "persisted" in decision.message


def test_hermes_decision_preserves_allow_match_and_policy_snapshot() -> None:
    with tempfile.TemporaryDirectory() as directory:
        policies_dir = os.path.join(directory, "policies")
        os.mkdir(policies_dir)
        Path(policies_dir, "allow.yaml").write_text(
            """
name: allow-reader
enabled: true
action: allow
rule:
  event_type: tool_call
  conditions:
    - field: action.tool_name
      operator: ==
      value: read_file
""",
            encoding="utf-8",
        )
        plugin = AuditPlugin(
            db_path=os.path.join(directory, "audit.db"),
            policies_dir=policies_dir,
        )

        decision = plugin.authorize_tool_call({
            "session_id": "session-1",
            "run_id": "run-1",
            "tool_name": "read_file",
            "tool_input": {"path": "README.md"},
        })

        assert decision.allowed
        stored = plugin.db.query(event_type="decision_point")
        policy = stored[0]["context"]["policy"]
        assert policy["matched_policies"][0]["policy_name"] == "allow-reader"
        assert policy["violated_policies"] == []
        assert policy["snapshot_id"]
        plugin.db.close()


def test_hermes_block_summary_uses_block_not_earlier_warning() -> None:
    with tempfile.TemporaryDirectory() as directory:
        policies_dir = os.path.join(directory, "policies")
        os.mkdir(policies_dir)
        Path(policies_dir, "01-warn.yaml").write_text(
            """
name: warn-terminal
action: warn
message: Warning only
rule:
  conditions:
    - field: action.tool_name
      operator: ==
      value: terminal
""",
            encoding="utf-8",
        )
        Path(policies_dir, "02-block.yaml").write_text(
            """
name: block-terminal
action: block
message: Actual block reason
rule:
  conditions:
    - field: action.tool_name
      operator: ==
      value: terminal
""",
            encoding="utf-8",
        )
        plugin = AuditPlugin(
            db_path=os.path.join(directory, "audit.db"),
            policies_dir=policies_dir,
        )

        decision = plugin.authorize_tool_call({
            "session_id": "session-1",
            "run_id": "run-1",
            "tool_name": "terminal",
            "tool_input": {"command": "echo hello"},
        })

        assert not decision.allowed
        assert decision.message == "Actual block reason"
        stored = plugin.db.query(event_type="decision_point")
        assert stored[0]["outcome"]["summary"] == "Actual block reason"
        plugin.db.close()


def test_hermes_fail_open_fallback_is_warned_and_persisted() -> None:
    with tempfile.TemporaryDirectory() as directory:
        plugin = AuditPlugin(
            db_path=os.path.join(directory, "audit.db"),
            policies_dir=None,
            policy_failure_mode="fail_open",
        )

        decision = plugin.authorize_tool_call({
            "session_id": "session-1",
            "run_id": "run-1",
            "tool_name": "terminal",
            "tool_input": {"unsupported": object()},
        })

        assert decision.allowed
        stored = plugin.db.query(event_type="decision_point")
        assert stored[0]["outcome"]["status"] == "warned"
        assert stored[0]["context"]["policy"]["evaluation_errors"]
        assert (
            stored[0]["context"]["capture"]["input_validation"]
            == "failed"
        )
        assert stored[0]["agent"]["session_id"] == "session-1"
        assert stored[0]["agent"]["run_id"] == "run-1"
        assert stored[0]["action"]["tool_name"] == "terminal"
        plugin.db.close()


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
            policies_dir=None,
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
            policies_dir=None,
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
            policies_dir=None,
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
            policies_dir=None,
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
            policies_dir=None,
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
            policies_dir=None,
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


def test_hermes_authorizer_does_not_cache_unknown_sessions() -> None:
    with tempfile.TemporaryDirectory() as directory:
        plugin = AuditPlugin(
            db_path=os.path.join(directory, "audit.db"),
            policies_dir=None,
        )

        for index in range(100):
            plugin.authorize_tool_call({
                "session_id": f"authorization-only-{index}",
                "run_id": f"run-{index}",
                "tool_name": "read_file",
                "tool_input": {"path": "README.md"},
            })

        assert plugin._sessions == {}
        plugin.db.close()


def test_hermes_authorizer_uses_established_lifecycle_identity() -> None:
    with tempfile.TemporaryDirectory() as directory:
        plugin = AuditPlugin(
            db_path=os.path.join(directory, "audit.db"),
            policies_dir=None,
        )
        ctx = _HermesContext()
        plugin.register(ctx)
        ctx.handlers["agent:start"]({
            "session_id": "session-1",
            "run_id": "lifecycle-run",
            "user_id": "lifecycle-user",
        })

        decision = plugin.authorize_tool_call({
            "session_id": "session-1",
            "run_id": "conflicting-callback-run",
            "user_id": "conflicting-callback-user",
            "tool_name": "read_file",
            "tool_input": {"path": "README.md"},
        })

        assert decision.allowed
        stored = plugin.db.query(event_type="decision_point")
        assert stored[0]["agent"]["session_id"] == "session-1"
        assert stored[0]["agent"]["run_id"] == "lifecycle-run"
        assert stored[0]["user"]["id"] == "lifecycle-user"
        plugin.db.close()


def test_hermes_active_session_tracking_is_hard_capped_and_auditable(
    caplog,
) -> None:
    with tempfile.TemporaryDirectory() as directory:
        plugin = AuditPlugin(
            db_path=os.path.join(directory, "audit.db"),
            policies_dir=None,
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
            policies_dir=None,
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


def test_hermes_malformed_input_cannot_escape_a_block_policy() -> None:
    """Fail-open must not let the caller shape its input around a block."""
    with tempfile.TemporaryDirectory() as directory:
        policies_dir = os.path.join(directory, "policies")
        os.mkdir(policies_dir)
        Path(policies_dir, "block.yaml").write_text(_BLOCK_TERMINAL, encoding="utf-8")
        plugin = AuditPlugin(
            db_path=os.path.join(directory, "audit.db"),
            policies_dir=policies_dir,
        )
        try:
            for tool_input in (["ls"], _deep(70)):
                decision = plugin.authorize_tool_call({
                    "session_id": "session-1",
                    "run_id": "run-1",
                    "tool_name": "terminal",
                    "tool_input": tool_input,
                })
                assert not decision.allowed
                assert decision.action == "block"
        finally:
            plugin.db.close()


def test_hermes_malformed_input_without_block_policies_follows_failure_mode() -> None:
    with tempfile.TemporaryDirectory() as directory:
        plugin = AuditPlugin(
            db_path=os.path.join(directory, "audit.db"), policies_dir=None
        )
        try:
            decision = plugin.authorize_tool_call({
                "session_id": "session-1",
                "run_id": "run-1",
                "tool_name": "terminal",
                "tool_input": ["ls"],
            })
            assert decision.allowed
        finally:
            plugin.db.close()


def test_installed_hermes_plugin_reads_failure_mode_from_environment(
    monkeypatch,
) -> None:
    import panoptes.hermes_plugin as hermes_plugin

    monkeypatch.delenv(hermes_plugin.POLICY_FAILURE_MODE_ENV, raising=False)
    assert hermes_plugin._configured_failure_mode() == "fail_open"
    monkeypatch.setenv(hermes_plugin.POLICY_FAILURE_MODE_ENV, "fail_closed")
    assert hermes_plugin._configured_failure_mode() == "fail_closed"
    # A typo must not silently fall back to the permissive default.
    monkeypatch.setenv(hermes_plugin.POLICY_FAILURE_MODE_ENV, "fail-closed")
    assert hermes_plugin._configured_failure_mode() == "fail_closed"

    with tempfile.TemporaryDirectory() as directory:
        monkeypatch.setattr(
            hermes_plugin, "DB_PATH", os.path.join(directory, "audit.db")
        )
        monkeypatch.setattr(hermes_plugin, "_plugin", None)
        plugin = hermes_plugin.get_plugin()
        try:
            assert plugin.policy_failure_mode == "fail_closed"
            assert plugin.policy_engine.failure_mode == "fail_closed"
        finally:
            plugin.db.close()
            monkeypatch.setattr(hermes_plugin, "_plugin", None)
