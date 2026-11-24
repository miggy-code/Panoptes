"""Tests for panoptes.proxy.

Covers:
  - Shared run_id across events in one exchange
  - Reverse-proxy path routing
  - SSE reassembly for Anthropic and OpenAI formats
  - Request and response event construction and persistence
"""

import gzip
import io
import json
import socket
import uuid
from email.message import Message

import httpx
import pytest

from panoptes._events import _parse_sse_response
from panoptes._forward import (
    Forwarder,
    ForwardReport,
    Outbound,
    UpstreamTarget,
    check_content_encoding,
    default_outbound_headers,
    filter_hop_by_hop,
    upstream_client,
)
from panoptes._request import merge_headers, read_body, route
from panoptes.db import AuditDB
from panoptes.hooks import ProxyHooks
from panoptes.providers import detect as detect_provider
from panoptes.providers.anthropic import (
    AnthropicProvider,
    _reassemble_anthropic_sse,
)
from panoptes.providers.base import SSEParseError, _parse_sse_events
from panoptes.providers.openai import (
    OpenAIProvider,
    _reassemble_openai_sse,
)
from panoptes.proxy import (
    AuditEventWriter,
    AuditWriteError,
    NoUpstreamError,
    ProxyServer,
    RequestBodyTooLarge,
    RequestFramingError,
    ResponseInspectionError,
    UpstreamBodyTooLarge,
    detect_agent_type,
)
from panoptes.schema import ValidationError

# ---------------------------------------------------------------------------
# Minimal in-memory DB stub for unit tests
# ---------------------------------------------------------------------------


class _AuditDBStub:
    """Simple in-memory list store used in proxy unit tests."""

    def __init__(self) -> None:
        self.events: list[dict] = []

    def insert_event(self, event: dict) -> None:
        self.events.append(event)

    def query(self, _filters: dict | None = None) -> list[dict]:
        return list(self.events)


# ---------------------------------------------------------------------------
# A real proxy against the fake upstream (tests/fake_upstream.py)
# ---------------------------------------------------------------------------

ANTHROPIC_BODY = {
    "model": "claude-test",
    "max_tokens": 8,
    "messages": [{"role": "user", "content": "hello"}],
}


class _CountingHooks(ProxyHooks):
    def __init__(self) -> None:
        self.before: list = []
        self.after: list = []

    def before_forward(self, exchange):
        self.before.append(exchange)

    def after_exchange(self, exchange):
        self.after.append(exchange)


class _Proxy:
    """A running proxy. ``recorded()`` stops it, so every write has landed."""

    def __init__(self, db_path, hooks=None) -> None:
        self.db_path = db_path
        self.server = ProxyServer(port=0, db_path=str(db_path), hooks=hooks)
        self.url = f"http://127.0.0.1:{self.server.start()}"

    def recorded(self, event_type=None) -> list[dict]:
        self.server.stop()
        db = AuditDB.open_readonly(str(self.db_path))
        try:
            events = list(db.iter_events())
        finally:
            db.close()
        return [e for e in events if event_type in (None, e["event_type"])]


@pytest.fixture
def proxy(tmp_path, upstream):
    """Start a proxy against the fake upstream; hooks are optional."""
    started: list[_Proxy] = []

    def start(hooks=None) -> _Proxy:
        started.append(_Proxy(tmp_path / f"audit-{len(started)}.db", hooks))
        return started[-1]

    yield start
    for running in started:
        running.server.stop()


def _unused_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def test_provider_detection_prefers_routed_path_and_handles_malformed_messages():
    anthropic = detect_provider(
        "/v1/messages",
        {"model": "claude-test", "messages": [{"role": "user", "content": "hi"}]},
    )
    assert anthropic.name == "anthropic"

    malformed = detect_provider("/custom", {"messages": ["not-a-mapping"]})
    assert malformed.name == "openai"


def test_openai_responses_api_extracts_calls_results_and_usage():
    provider = OpenAIProvider()
    request = {
        "model": "gpt-test",
        "input": [
            {
                "type": "function_call_output",
                "call_id": "call_123",
                "output": "sunny",
            }
        ],
        "tools": [{"type": "function", "name": "weather"}],
    }
    response = {
        "object": "response",
        "output": [
            {
                "id": "fc_123",
                "type": "function_call",
                "call_id": "call_123",
                "name": "weather",
                "arguments": '{"city":"Lima"}',
            }
        ],
        "usage": {"input_tokens": 20, "output_tokens": 7},
    }

    assert provider.extract_request_info(request)["messages_count"] == 1
    assert provider.extract_tool_results(request)[0]["call_id"] == "call_123"
    assert provider.extract_tool_calls(response)[0] == {
        "tool_name": "weather",
        "parameters": {"city": "Lima"},
        "call_id": "call_123",
    }
    assert provider.extract_usage(response) == {"tokens_in": 20, "tokens_out": 7}


def test_proxy_binds_openai_tool_extraction_to_requested_dialect():
    writer = AuditEventWriter(_AuditDBStub())
    req_body = {"model": "gpt-test", "messages": []}
    _, exchange_ctx = writer.build_request_events(
        path="/v1/chat/completions",
        method="POST",
        req_headers={},
        req_body=req_body,
    )

    with pytest.raises(SSEParseError, match="cross-dialect"):
        writer.build_response_events(
            exchange_ctx,
            status=200,
            body={
                "object": "response",
                "output": [
                    {
                        "type": "function_call",
                        "name": "hidden",
                        "arguments": "{}",
                    }
                ],
            },
            duration_ms=20,
        )


def test_openai_responses_stream_uses_completed_response():
    completed = {
        "id": "resp_123",
        "object": "response",
        "output": [
            {
                "type": "function_call",
                "call_id": "call_123",
                "name": "weather",
                "arguments": '{"city":"Lima"}',
            }
        ],
        "usage": {"input_tokens": 20, "output_tokens": 7},
    }
    raw = (
        "event: response.completed\n"
        f"data: {json.dumps({'type': 'response.completed', 'response': completed})}\n\n"
    ).encode()

    assert OpenAIProvider().reassemble_sse(raw) == completed


def test_agent_identity_requires_evidence_not_provider_guessing():
    body = {"model": "gpt-test", "messages": []}
    assert detect_agent_type("/v1/chat/completions", {}, body) == "unknown"
    assert (
        detect_agent_type(
            "/v1beta/models/gemini-pro:generateContent",
            {},
            {"contents": []},
        )
        == "unknown"
    )
    assert (
        detect_agent_type(
            "/v1/chat/completions",
            {"user-agent": "openai-codex/1.0"},
            body,
        )
        == "codex"
    )


def test_sse_parser_honors_eventsource_framing_and_multiline_data():
    raw = (
        b": keepalive\r\n"
        b"event: message\r\n"
        b'data:{"kind":\r\n'
        b'data: "tool"}\r\n'
        b"\r\n"
        b'data: {"sequence": 2}\n\n'
    )

    assert _parse_sse_events(raw) == [
        {"kind": "tool"},
        {"sequence": 2},
    ]


def test_sse_parser_surfaces_malformed_or_ambiguous_events():
    with pytest.raises(SSEParseError, match="invalid JSON"):
        _parse_sse_events(b'data: {"safe": true\ndata: {"hidden_tool": true}\n\n')

    with pytest.raises(SSEParseError, match="invalid UTF-8"):
        _parse_sse_events(b"data: \xff\n\n")


def test_request_body_framing_and_size_are_strict():
    def read(headers, body=b""):
        return read_body(headers, io.BytesIO(body), limit=4)

    duplicate = Message()
    duplicate.add_header("Content-Length", "1")
    duplicate.add_header("Content-Length", "1")
    with pytest.raises(RequestFramingError, match="Multiple"):
        read(duplicate, b"x")

    chunked = Message()
    chunked.add_header("Transfer-Encoding", "chunked")
    with pytest.raises(RequestFramingError, match="not supported"):
        read(chunked, b"1\r\nx\r\n0\r\n\r\n")

    oversized = Message()
    oversized.add_header("Content-Length", "5")
    with pytest.raises(RequestBodyTooLarge):
        read(oversized, b"12345")

    incomplete = Message()
    incomplete.add_header("Content-Length", "4")
    with pytest.raises(RequestFramingError, match="ended before"):
        read(incomplete, b"12")


@pytest.mark.parametrize("host", ["0.0.0.0", "::", "192.0.2.10", "proxy.local"])
def test_proxy_rejects_non_loopback_bind_without_explicit_opt_in(host):
    with pytest.raises(ValueError, match="Refusing non-loopback"):
        ProxyServer(host=host, port=0)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"client_socket_timeout_seconds": 0},
        {"max_concurrent_requests": 0},
        {"max_tool_events_per_exchange": 0},
    ],
)
def test_proxy_rejects_nonpositive_resource_limits(kwargs):
    with pytest.raises(ValueError, match="must be positive"):
        ProxyServer(port=0, **kwargs)


def test_proxy_start_failure_releases_partial_resources(monkeypatch):
    def _fail_server(*args, **kwargs):
        raise OSError("bind failed")

    monkeypatch.setattr("panoptes.proxy.BoundedThreadingHTTPServer", _fail_server)
    server = ProxyServer(port=0)

    with pytest.raises(OSError, match="bind failed"):
        server.start()

    assert server._server is None
    assert server._thread is None
    assert server._http_client is None
    assert server._db is None
    assert server._tmp_db_path is None
    assert server.writer is None


def test_upstream_client_ignores_proxy_environment(monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9")
    client = upstream_client(5.0)
    try:
        assert client.trust_env is False
    finally:
        client.close()


def test_proxy_does_not_merge_headerless_requests_into_one_session():
    writer = AuditEventWriter(_AuditDBStub())
    _, first = writer.build_request_events(
        path="/v1/chat/completions",
        method="POST",
        req_headers={},
        req_body={"model": "gpt-test", "messages": []},
        run_id="run-1",
    )
    _, second = writer.build_request_events(
        path="/v1/chat/completions",
        method="POST",
        req_headers={},
        req_body={"model": "gpt-test", "messages": []},
        run_id="run-2",
    )
    _, explicit = writer.build_request_events(
        path="/v1/chat/completions",
        method="POST",
        req_headers={"x-panoptes-session": "session-explicit"},
        req_body={"model": "gpt-test", "messages": []},
        run_id="run-3",
    )

    assert first.session_id != second.session_id
    assert explicit.session_id == "session-explicit"


def test_proxy_does_not_forward_internal_identity_headers():
    forwarded = default_outbound_headers(
        {
            "Host": "localhost",
            "Authorization": "Bearer upstream-token",
            "X-Panoptes-Agent": "codex",
            "x-panoptes-session": "session-1",
        }
    )

    assert forwarded["Authorization"] == "Bearer upstream-token"
    assert not any(key.lower().startswith("x-panoptes-") for key in forwarded)


# ---------------------------------------------------------------------------
# Shared run_id
# ---------------------------------------------------------------------------


def test_shared_run_id():
    """All events from a single exchange must share the same run_id."""
    db = _AuditDBStub()
    writer = AuditEventWriter(db)

    req_body = {
        "model": "gpt-4",
        "messages": [
            {"role": "user", "content": "Hello"},
            {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": "call_abc",
                        "type": "function",
                        "function": {"name": "bash", "arguments": '{"cmd": "ls"}'},
                    }
                ],
            },
            {
                "role": "tool",
                "tool_call_id": "call_abc",
                "name": "bash",
                "content": "file.txt",
            },
        ],
        "stream": False,
    }
    resp_body = {
        "choices": [
            {"message": {"role": "assistant", "content": "Done", "tool_calls": []}}
        ],
        "usage": {"prompt_tokens": 20, "completion_tokens": 5, "total_tokens": 25},
    }

    events = writer.write_events(
        path="/v1/chat/completions",
        method="POST",
        req_headers={},
        req_body=req_body,
        resp_status=200,
        resp_headers={"content-type": "application/json"},
        resp_body=resp_body,
        duration_ms=150,
    )

    assert len(events) >= 3, f"Expected at least 3 events, got {len(events)}"
    run_ids = {e["agent"]["run_id"] for e in events}
    assert len(run_ids) == 1, f"Expected 1 run_id across all events, got {run_ids}"


# ---------------------------------------------------------------------------
# turn_number in context
# ---------------------------------------------------------------------------


def test_turn_number_in_context():
    """Events should carry turn_number = count of assistant messages in request."""
    db = _AuditDBStub()
    writer = AuditEventWriter(db)

    req_body = {
        "model": "gpt-4",
        "messages": [
            {"role": "user", "content": "Hi"},
            {"role": "assistant", "content": "Hello"},
            {"role": "user", "content": "How are you?"},
            {"role": "assistant", "content": "Good"},
            {"role": "user", "content": "Bye"},
        ],
        "stream": False,
    }

    req_events, ctx = writer.build_request_events(
        path="/v1/chat/completions",
        method="POST",
        req_headers={},
        req_body=req_body,
        run_id=uuid.uuid4().hex,
    )

    assert ctx.turn_number == 2
    for e in req_events:
        assert e["context"]["turn_number"] == 2


# ---------------------------------------------------------------------------
# call_id on tool events
# ---------------------------------------------------------------------------


def test_call_id_on_tool_events():
    """tool_call and tool_result events must populate action.call_id."""
    db = _AuditDBStub()
    writer = AuditEventWriter(db)

    req_body = {
        "model": "gpt-4",
        "messages": [
            {
                "role": "tool",
                "tool_call_id": "call_xyz",
                "name": "read_file",
                "content": "data",
            },
        ],
        "stream": False,
    }
    resp_body = {
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "tool_calls": [
                        {
                            "id": "call_new",
                            "type": "function",
                            "function": {
                                "name": "write_file",
                                "arguments": '{"path": "/tmp/x"}',
                            },
                        }
                    ],
                }
            }
        ],
        "usage": {"prompt_tokens": 10, "completion_tokens": 5},
    }

    run_id = uuid.uuid4().hex
    req_events, ctx = writer.build_request_events(
        path="/v1/chat/completions",
        method="POST",
        req_headers={},
        req_body=req_body,
        run_id=run_id,
    )
    resp_events = writer.build_response_events(
        ctx, status=200, body=resp_body, duration_ms=100
    )

    tool_results = [e for e in req_events if e["event_type"] == "tool_result"]
    assert tool_results, "Expected tool_result event"
    assert tool_results[0]["action"]["call_id"] == "call_xyz"

    tool_calls = [e for e in resp_events if e["event_type"] == "tool_call"]
    assert tool_calls, "Expected tool_call event"
    assert tool_calls[0]["action"]["call_id"] == "call_new"
    assert tool_calls[0]["outcome"]["status"] == "pending"
    assert "execution was not observed" in tool_calls[0]["outcome"]["summary"]


def test_proxy_redacts_tool_result_before_summary_truncation():
    private_key = (
        "-----BEGIN PRIVATE KEY-----" + ("A" * 800) + "-----END PRIVATE KEY-----"
    )
    writer = AuditEventWriter(_AuditDBStub())
    events, _ = writer.build_request_events(
        path="/v1/chat/completions",
        method="POST",
        req_headers={},
        req_body={
            "model": "gpt-test",
            "messages": [
                {
                    "role": "tool",
                    "tool_call_id": "call-secret",
                    "name": "read_secret",
                    "content": private_key,
                }
            ],
        },
    )
    tool_result = next(
        event for event in events if event["event_type"] == "tool_result"
    )
    summary = tool_result["outcome"]["summary"]
    assert "BEGIN PRIVATE KEY" not in summary
    assert "A" * 50 not in summary
    assert "[REDACTED PRIVATE KEY]" in summary
    assert tool_result["action"]["result"] == "[REDACTED PRIVATE KEY]"
    assert tool_result["action"]["result_complete"] is True


def test_request_event_exposes_complete_tool_capability_summary():
    writer = AuditEventWriter(_AuditDBStub())
    events, _ = writer.build_request_events(
        path="/v1/responses",
        method="POST",
        req_headers={},
        req_body={
            "model": "gpt-test",
            "input": "search",
            "tools": [
                {"type": "function", "name": "local_tool"},
                {"type": "web_search_preview"},
                {
                    "type": "mcp",
                    "server_label": "docs",
                    "server_url": "https://mcp.example.test",
                },
            ],
        },
    )

    action = events[0]["action"]
    assert action["requested_tools"] == [
        "function:local_tool",
        "web_search_preview",
        "mcp",
    ]
    assert action["client_side_tools"] == ["function:local_tool"]
    assert action["server_side_tools"] == ["web_search_preview", "mcp"]
    assert "server_url:https://mcp.example.test" in action["requested_tool_targets"]


def test_request_tool_capability_count_is_bounded():
    writer = AuditEventWriter(
        _AuditDBStub(),
        max_tool_events_per_exchange=1,
    )
    with pytest.raises(ValidationError, match="per-exchange limit"):
        writer.build_request_events(
            path="/v1/responses",
            method="POST",
            req_headers={},
            req_body={
                "model": "gpt-test",
                "input": "search",
                "tools": [
                    {"type": "function", "name": "one"},
                    {"type": "function", "name": "two"},
                ],
            },
        )


def test_provider_hosted_action_records_upstream_execution_truth():
    writer = AuditEventWriter(_AuditDBStub())
    req_body = {"model": "gpt-test", "input": "search"}
    _, exchange_ctx = writer.build_request_events(
        path="/v1/responses",
        method="POST",
        req_headers={},
        req_body=req_body,
    )
    events = writer.build_response_events(
        exchange_ctx,
        status=200,
        body={
            "object": "response",
            "output": [
                {
                    "id": "ws_1",
                    "type": "web_search_call",
                    "status": "completed",
                    "action": {"query": "Panoptes"},
                }
            ],
        },
        duration_ms=20,
    )

    tool_call = next(event for event in events if event["event_type"] == "tool_call")
    assert tool_call["action"]["execution_scope"] == "provider"
    assert tool_call["action"]["provider_item_type"] == "web_search_call"
    assert tool_call["outcome"]["status"] == "success"
    assert "completed upstream" in tool_call["outcome"]["summary"]


def test_provider_hosted_result_is_redacted_and_bounded():
    writer = AuditEventWriter(_AuditDBStub())
    req_body = {"model": "claude-test", "messages": []}
    _, exchange_ctx = writer.build_request_events(
        path="/v1/messages",
        method="POST",
        req_headers={},
        req_body=req_body,
    )
    events = writer.build_response_events(
        exchange_ctx,
        status=200,
        body={
            "content": [
                {
                    "type": "server_tool_use",
                    "id": "srv_1",
                    "name": "web_search",
                    "input": {"query": "Panoptes"},
                },
                {
                    "type": "web_search_tool_result",
                    "tool_use_id": "srv_1",
                    "content": "result-" + ("x" * 1000),
                },
            ],
        },
        duration_ms=20,
    )

    tool_call = next(event for event in events if event["event_type"] == "tool_call")
    assert tool_call["outcome"]["status"] == "success"
    assert len(tool_call["action"]["server_result_summary"]) == 500
    assert tool_call["action"]["server_result_complete"] is False
    assert "server_result" not in tool_call["action"]


def test_protocols_without_call_ids_remain_valid():
    writer = AuditEventWriter(_AuditDBStub())
    req_body = {
        "model": "gemini-test",
        "contents": [{"role": "user", "parts": [{"text": "weather"}]}],
    }
    _, exchange_ctx = writer.build_request_events(
        path="/v1beta/models/gemini-test:generateContent",
        method="POST",
        req_headers={},
        req_body=req_body,
    )
    events = writer.build_response_events(
        exchange_ctx,
        status=200,
        body={
            "candidates": [
                {
                    "content": {
                        "parts": [
                            {
                                "functionCall": {
                                    "name": "weather",
                                    "args": {"city": "Lima"},
                                },
                            }
                        ],
                    },
                }
            ],
        },
        duration_ms=20,
    )

    tool_call = next(event for event in events if event["event_type"] == "tool_call")
    assert tool_call["action"]["call_id"] is None
    assert tool_call["action"]["target"] is None


# ---------------------------------------------------------------------------
# Reverse-proxy routing
# ---------------------------------------------------------------------------


@pytest.fixture
def default_upstreams(monkeypatch):
    """Route to each provider's public API, whatever the shell exports."""
    for provider in ("ANTHROPIC", "OPENAI", "GEMINI"):
        monkeypatch.delenv(f"PANOPTES_UPSTREAM_{provider}", raising=False)


def test_reverse_proxy_routing(default_upstreams):
    """Origin-form paths route to the provider that owns them."""
    target, name = route("/v1/messages", {})
    assert (target.scheme, target.host, target.port) == (
        "https",
        "api.anthropic.com",
        443,
    )
    assert name == "anthropic"

    target, _ = route("/v1/messages?beta=true", {})
    assert target.host == "api.anthropic.com"

    assert route("/v1/chat/completions", {})[0].host == "api.openai.com"
    assert route("/v1/models", {})[0].host == "api.openai.com"
    for path in (
        "/v1beta/models/gemini-pro:generateContent",
        "/v1beta/models/gemini-pro:streamGenerateContent",
    ):
        assert "googleapis" in route(path, {})[0].host

    # Absolute-form targets are never accepted by the reverse proxy.
    with pytest.raises(ValueError, match="Absolute-form"):
        route("http://api.openai.com/v1/chat/completions", {})


def test_reverse_proxy_no_upstream_raises():
    """Unmatched provider paths are rejected."""
    with pytest.raises(NoUpstreamError):
        route("/unknown/endpoint", {})


def test_proxy_errors_and_request_logs_do_not_expose_query_secrets(proxy, caplog):
    caplog.set_level("INFO", logger="panoptes")
    running = proxy()

    response = httpx.post(
        f"{running.url}/unknown/endpoint?key=gemini-secret", json={}, timeout=10
    )
    running.server.stop()  # every log line is written

    assert response.status_code == 502
    assert "gemini-secret" not in response.text
    assert "gemini-secret" not in caplog.text
    assert "/unknown/endpoint" in caplog.text


# ---------------------------------------------------------------------------
# SSE parsing — Anthropic
# ---------------------------------------------------------------------------


def _anthropic_sse_bytes(text_content: str = "Hello world!") -> bytes:
    """Build synthetic Anthropic SSE stream bytes."""
    words = text_content.split(" ")
    lines = [
        b"event: message_start",
        (
            b'data: {"type":"message_start","message":{"id":"msg_xxx","type":"message",'
            b'"role":"assistant","content":[],"model":"claude-opus-4-5",'
            b'"stop_reason":null,"stop_sequence":null,'
            b'"usage":{"input_tokens":25,"output_tokens":1}}}'
        ),
        b"",
        b"event: content_block_start",
        b'data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}',
        b"",
    ]
    for i, word in enumerate(words):
        sep = " " if i < len(words) - 1 else ""
        delta_text = word + sep
        lines.append(b"event: content_block_delta")
        lines.append(
            json.dumps(
                {
                    "type": "content_block_delta",
                    "index": 0,
                    "delta": {"type": "text_delta", "text": delta_text},
                }
            )
            .encode()
            .replace(b'"', b'"')
        )
        lines.append(b"")
    lines += [
        b"event: content_block_stop",
        b'data: {"type":"content_block_stop","index":0}',
        b"",
        b"event: message_delta",
        b'data: {"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null},"usage":{"output_tokens":10}}',
        b"",
        b"event: message_stop",
        b'data: {"type":"message_stop"}',
    ]
    return b"\n".join(lines)


def test_sse_parsing_anthropic_text():
    """Anthropic SSE: text content blocks are reassembled correctly."""
    sse = b"\n".join(
        [
            b"event: message_start",
            b'data: {"type":"message_start","message":{"id":"msg_1","type":"message","role":"assistant","content":[],"model":"claude-opus-4-5","stop_reason":null,"stop_sequence":null,"usage":{"input_tokens":25,"output_tokens":1}}}',
            b"",
            b"event: content_block_start",
            b'data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}',
            b"",
            b"event: content_block_delta",
            b'data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hello "}}',
            b"",
            b"event: content_block_delta",
            b'data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"world!"}}',
            b"",
            b"event: content_block_stop",
            b'data: {"type":"content_block_stop","index":0}',
            b"",
            b"event: message_delta",
            b'data: {"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null},"usage":{"output_tokens":10}}',
            b"",
            b"event: message_stop",
            b'data: {"type":"message_stop"}',
        ]
    )

    events = _parse_sse_events(sse)
    # Should parse: message_start, content_block_start, 2x delta, content_block_stop, message_delta, message_stop
    assert len(events) >= 5, f"Expected ≥5 parsed events, got {len(events)}"

    result = _reassemble_anthropic_sse(events)
    assert result["type"] == "message"
    assert result["role"] == "assistant"
    assert result["model"] == "claude-opus-4-5"
    assert result["stop_reason"] == "end_turn"
    assert len(result["content"]) == 1
    assert result["content"][0]["type"] == "text"
    assert result["content"][0]["text"] == "Hello world!"
    assert result["usage"]["input_tokens"] == 25
    assert result["usage"]["output_tokens"] == 10


def test_sse_parsing_anthropic_tool_use():
    """Anthropic SSE: tool_use blocks with input_json_delta reassemble correctly."""
    sse = b"\n".join(
        [
            b'data: {"type":"message_start","message":{"id":"msg_2","type":"message","role":"assistant","content":[],"model":"claude-opus-4-5","stop_reason":null,"stop_sequence":null,"usage":{"input_tokens":100,"output_tokens":1}}}',
            b'data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_abc","name":"calculator","input":{}}}',
            b'data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\\"expr\\""}}',
            b'data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":": \\"2+2\\"}"}}',
            b'data: {"type":"content_block_stop","index":0}',
            b'data: {"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":50}}',
            b'data: {"type":"message_stop"}',
        ]
    )

    events = _parse_sse_events(sse)
    result = _reassemble_anthropic_sse(events)

    assert len(result["content"]) == 1
    block = result["content"][0]
    assert block["type"] == "tool_use"
    assert block["id"] == "toolu_abc"
    assert block["name"] == "calculator"
    assert block["input"] == {"expr": "2+2"}, f"Got {block['input']}"
    assert result["usage"]["input_tokens"] == 100
    assert result["usage"]["output_tokens"] == 50


def test_sse_parsing_anthropic_via_parse_sse_response():
    """_parse_sse_response dispatches to Anthropic reassembly for 'anthropic' format."""
    sse = b"\n".join(
        [
            b'data: {"type":"message_start","message":{"id":"m","type":"message","role":"assistant","content":[],"model":"claude-3","stop_reason":null,"stop_sequence":null,"usage":{"input_tokens":5,"output_tokens":1}}}',
            b'data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}',
            b'data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hi"}}',
            b'data: {"type":"content_block_stop","index":0}',
            b'data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":3}}',
            b'data: {"type":"message_stop"}',
        ]
    )
    result = _parse_sse_response(sse, "anthropic")
    assert result is not None
    assert result["content"][0]["text"] == "Hi"
    assert result["usage"]["output_tokens"] == 3


@pytest.mark.parametrize(
    "events",
    [
        [
            {
                "type": "content_block_start",
                "index": 0,
                "content_block": {
                    "type": "tool_use",
                    "id": "danger",
                    "name": "terminal",
                },
            },
            {
                "type": "content_block_start",
                "index": 0,
                "content_block": {"type": "text", "text": "harmless"},
            },
        ],
        [
            {
                "type": "content_block_start",
                "index": 0,
                "content_block": {
                    "type": "tool_use",
                    "id": "danger",
                    "name": "terminal",
                },
            },
            {
                "type": "content_block_delta",
                "index": 0,
                "delta": {
                    "type": "input_json_delta",
                    "partial_json": '{"command":"kubectl delete',
                },
            },
        ],
        [
            {
                "type": "content_block_start",
                "index": 0,
                "content_block": {
                    "type": "tool_use",
                    "id": "danger",
                    "name": "terminal",
                },
            },
            {
                "type": "content_block_delta",
                "index": 0,
                "delta": {
                    "type": "input_json_delta",
                    "partial_json": '{"command":"kubectl delete',
                },
            },
            {"type": "content_block_stop", "index": 0},
        ],
    ],
)
def test_anthropic_reassembly_rejects_overwrite_and_incomplete_tool_blocks(events):
    raw = b"".join(b"data:" + json.dumps(event).encode() + b"\n\n" for event in events)
    with pytest.raises(SSEParseError):
        AnthropicProvider().reassemble_sse(raw)


# ---------------------------------------------------------------------------
# SSE parsing — OpenAI
# ---------------------------------------------------------------------------


def test_sse_parsing_openai_text():
    """OpenAI SSE: text content chunks reassemble correctly."""
    sse = b"\n".join(
        [
            b'data: {"id":"chatcmpl-x","object":"chat.completion.chunk","created":1000,"model":"gpt-4","choices":[{"index":0,"delta":{"role":"assistant","content":""},"finish_reason":null}]}',
            b'data: {"id":"chatcmpl-x","object":"chat.completion.chunk","created":1000,"model":"gpt-4","choices":[{"index":0,"delta":{"content":"Hello"},"finish_reason":null}]}',
            b'data: {"id":"chatcmpl-x","object":"chat.completion.chunk","created":1000,"model":"gpt-4","choices":[{"index":0,"delta":{"content":" world!"},"finish_reason":null}]}',
            b'data: {"id":"chatcmpl-x","object":"chat.completion.chunk","created":1000,"model":"gpt-4","choices":[{"index":0,"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}',
            b"data: [DONE]",
        ]
    )

    events = _parse_sse_events(sse)
    assert len(events) == 4, (
        f"Expected 4 parsed chunks (ignoring [DONE]), got {len(events)}"
    )

    result = _reassemble_openai_sse(events)
    assert result["id"] == "chatcmpl-x"
    assert result["model"] == "gpt-4"
    assert len(result["choices"]) == 1
    assert result["choices"][0]["message"]["content"] == "Hello world!"
    assert result["choices"][0]["finish_reason"] == "stop"
    assert result["usage"]["prompt_tokens"] == 10
    assert result["usage"]["completion_tokens"] == 5


def test_sse_parsing_openai_tool_calls():
    """OpenAI SSE: tool_call arguments accumulate correctly across chunks."""
    sse = b"\n".join(
        [
            b'data: {"id":"cc-y","object":"chat.completion.chunk","created":2000,"model":"gpt-4","choices":[{"index":0,"delta":{"role":"assistant","content":null,"tool_calls":[{"index":0,"id":"call_abc","type":"function","function":{"name":"calculator","arguments":""}}]},"finish_reason":null}]}',
            b'data: {"id":"cc-y","object":"chat.completion.chunk","created":2000,"model":"gpt-4","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\\"expr\\""}}]},"finish_reason":null}]}',
            b'data: {"id":"cc-y","object":"chat.completion.chunk","created":2000,"model":"gpt-4","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":": \\"2+2\\"}"}}]},"finish_reason":"tool_calls"}]}',
            b"data: [DONE]",
        ]
    )

    events = _parse_sse_events(sse)
    result = _reassemble_openai_sse(events)

    assert len(result["choices"]) == 1
    msg = result["choices"][0]["message"]
    assert "tool_calls" in msg, f"No tool_calls in message: {msg}"
    assert len(msg["tool_calls"]) == 1
    tc = msg["tool_calls"][0]
    assert tc["id"] == "call_abc"
    assert tc["function"]["name"] == "calculator"
    parsed_args = json.loads(tc["function"]["arguments"])
    assert parsed_args == {"expr": "2+2"}, f"Got {parsed_args}"


def test_sse_parsing_openai_via_parse_sse_response():
    """_parse_sse_response dispatches to OpenAI reassembly for 'openai' format."""
    sse = b"\n".join(
        [
            b'data: {"id":"cc-z","object":"chat.completion.chunk","created":3000,"model":"gpt-4","choices":[{"index":0,"delta":{"content":"Hi"},"finish_reason":null}]}',
            b'data: {"id":"cc-z","object":"chat.completion.chunk","created":3000,"model":"gpt-4","choices":[{"index":0,"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":5,"completion_tokens":1}}',
            b"data: [DONE]",
        ]
    )
    result = _parse_sse_response(sse, "openai")
    assert result is not None
    assert result["choices"][0]["message"]["content"] == "Hi"


def _responses_sse(*events: dict) -> bytes:
    return b"".join(b"data:" + json.dumps(event).encode() + b"\n\n" for event in events)


def test_openai_responses_final_event_cannot_erase_streamed_tool_call():
    call = {
        "id": "fc_danger",
        "type": "function_call",
        "call_id": "call_danger",
        "name": "terminal",
        "arguments": "",
    }
    completed_call = {
        **call,
        "arguments": '{"command":"kubectl delete namespace production"}',
    }
    raw = _responses_sse(
        {
            "type": "response.output_item.added",
            "output_index": 0,
            "item": call,
        },
        {
            "type": "response.function_call_arguments.delta",
            "output_index": 0,
            "delta": '{"command":"kubectl delete namespace production"}',
        },
        {
            "type": "response.output_item.done",
            "output_index": 0,
            "item": completed_call,
        },
        {
            "type": "response.completed",
            "response": {
                "id": "resp_1",
                "object": "response",
                "output": [],
                "usage": {"input_tokens": 1, "output_tokens": 1},
            },
        },
    )

    provider = OpenAIProvider()
    response = provider.reassemble_sse(raw)
    calls = provider.extract_tool_calls(response)
    assert len(calls) == 1
    assert calls[0]["tool_name"] == "terminal"
    assert calls[0]["parameters"]["command"].endswith("production")


def test_openai_responses_rejects_final_tool_call_contradiction():
    raw = _responses_sse(
        {
            "type": "response.output_item.added",
            "output_index": 0,
            "item": {
                "id": "fc_1",
                "type": "function_call",
                "call_id": "call_1",
                "name": "terminal",
                "arguments": "",
            },
        },
        {
            "type": "response.output_item.done",
            "output_index": 0,
            "item": {
                "id": "fc_1",
                "type": "function_call",
                "call_id": "call_1",
                "name": "terminal",
                "arguments": '{"command":"rm -rf /"}',
            },
        },
        {
            "type": "response.completed",
            "response": {
                "object": "response",
                "output": [
                    {
                        "id": "fc_1",
                        "type": "function_call",
                        "call_id": "call_1",
                        "name": "calculator",
                        "arguments": '{"expr":"2+2"}',
                    }
                ],
            },
        },
    )
    with pytest.raises(SSEParseError, match="contradicted"):
        OpenAIProvider().reassemble_sse(raw)


def test_openai_responses_rejects_incomplete_function_call_stream():
    raw = _responses_sse(
        {
            "type": "response.output_item.added",
            "output_index": 0,
            "item": {
                "id": "fc_1",
                "type": "function_call",
                "call_id": "call_1",
                "name": "terminal",
                "arguments": "",
            },
        },
        {
            "type": "response.function_call_arguments.delta",
            "output_index": 0,
            "delta": '{"command":"rm -rf',
        },
    )
    with pytest.raises(SSEParseError, match="incomplete"):
        OpenAIProvider().reassemble_sse(raw)


@pytest.mark.parametrize("stream", [False, True], ids=["buffered", "streamed"])
def test_an_uninspectable_response_is_delivered_and_recorded_as_incomplete(
    proxy, upstream, stream
):
    malformed = b'data: {"choices": []}\n\ndata: {not-json}\n\n'
    upstream.mode = "raw"
    upstream.raw = (200, [("Content-Type", "text/event-stream")], malformed)
    running = proxy()

    response = httpx.post(
        f"{running.url}/v1/chat/completions",
        json={"model": "gpt-test", "messages": [], "stream": stream},
        timeout=10,
    )

    # Panoptes records what it could not read; it does not withhold the reply.
    assert response.status_code == 200
    assert response.content == malformed
    [recorded] = running.recorded("model_response")
    assert recorded["outcome"]["status"] == "error"
    assert recorded["context"]["capture"]["inspection_status"] == "incomplete"


class _Sink:
    """A client connection that keeps what a stream relayed to it."""

    def __init__(self) -> None:
        self.status: int | None = None
        self.headers: dict[str, str] = {}
        self.body = bytearray()

    def start_stream(self, status, headers):
        self.status, self.headers = status, dict(headers)

    def write_stream(self, chunk):
        self.body.extend(chunk)

    def flush_stream(self):
        pass


_TARGET = UpstreamTarget("https", "api.openai.com", 443)
_OUTBOUND = Outbound({}, "/v1/responses")


def _forwarder(make_response, *, buffered=1024, audit=1024) -> Forwarder:
    """A Forwarder whose upstream answers every request with make_response()."""
    transport = httpx.MockTransport(lambda request: make_response())
    return Forwarder(
        httpx.Client(transport=transport),
        max_buffered_response_bytes=buffered,
        max_audit_stream_bytes=audit,
    )


def test_buffered_and_stream_audit_bodies_are_bounded():
    def chunked():
        return httpx.Response(200, content=iter([b"abc", b"def"]))

    with pytest.raises(UpstreamBodyTooLarge):
        _forwarder(chunked, buffered=5).buffered(
            "POST", _TARGET, _OUTBOUND, b"{}", ForwardReport()
        )

    sink = _Sink()
    reply = _forwarder(chunked, audit=4).stream(
        "POST", _TARGET, _OUTBOUND, b"{}", ForwardReport(), sink, drain_seconds=0
    )
    assert (reply.status, reply.body, reply.truncated) == (200, b"abcd", True)
    assert bytes(sink.body) == b"abcdef"  # the client still gets every byte


def test_connection_nominated_headers_are_removed():
    filtered = filter_hop_by_hop(
        {
            "Connection": "X-Internal, Keep-Alive",
            "X-Internal": "must-not-cross",
            "Keep-Alive": "timeout=5",
            "Content-Type": "application/json",
        }
    )
    assert filtered == {"Content-Type": "application/json"}


def test_relayed_headers_describe_the_decoded_body():
    def gzipped():
        return httpx.Response(
            200,
            headers={"content-type": "application/json", "content-encoding": "gzip"},
            content=gzip.compress(b"{}"),
        )

    def framing(headers):
        return {key.lower() for key in headers} & {"content-encoding", "content-length"}

    reply = _forwarder(gzipped).buffered(
        "POST", _TARGET, _OUTBOUND, b"{}", ForwardReport()
    )
    assert reply.body == b"{}"
    assert framing(reply.headers) == set()

    sink = _Sink()
    reply = _forwarder(gzipped).stream(
        "POST", _TARGET, _OUTBOUND, b"{}", ForwardReport(), sink, drain_seconds=0
    )
    assert bytes(sink.body) == b"{}"
    assert framing(sink.headers) == framing(reply.headers) == set()


def test_proxy_validates_normalized_identity_before_forwarding():
    writer = AuditEventWriter(_AuditDBStub())
    with pytest.raises(ValidationError, match="control characters"):
        writer.build_request_events(
            path="/v1/responses",
            method="POST",
            req_headers={"x-panoptes-session": "attacker\nforged"},
            req_body={"model": "gpt-test", "input": "hello"},
        )


def test_proxy_rejects_duplicate_request_object_keys_before_forwarding(proxy, upstream):
    running = proxy()

    response = httpx.post(
        f"{running.url}/v1/responses",
        content=b'{"model":"gpt-safe","model":"gpt-confused","input":"hello"}',
        headers={"Content-Type": "application/json"},
        timeout=10,
    )

    assert response.status_code == 400
    assert "unambiguous" in response.json()["error"]
    assert upstream.requests == []


def test_buffered_proxy_rejects_duplicate_response_keys_before_delivery(
    proxy, upstream
):
    ambiguous = (
        b'{"object":"response","output":[],'
        b'"output":[{"type":"function_call","name":"hidden",'
        b'"arguments":"{}"}]}'
    )
    upstream.mode = "raw"
    upstream.raw = (200, [("Content-Type", "application/json")], ambiguous)
    running = proxy()

    response = httpx.post(
        f"{running.url}/v1/responses",
        json={"model": "gpt-test", "input": "hello"},
        timeout=10,
    )

    assert response.status_code == 502
    assert response.headers["x-panoptes-inspection-blocked"] == "true"
    assert response.content != ambiguous
    [recorded] = running.recorded("model_response")
    assert recorded["outcome"]["status"] == "blocked"
    assert recorded["context"]["capture"]["response_delivered"] is False


def test_audit_writer_raises_when_batch_and_fallback_cannot_persist_all_events():
    class _FailingDB:
        def insert_events(self, events):
            raise OSError("batch unavailable")

        def insert_event(self, event):
            raise OSError("single insert unavailable")

    writer = AuditEventWriter(_FailingDB())
    with pytest.raises(AuditWriteError, match="Failed to persist"):
        writer.write([{"event_id": "one"}, {"event_id": "two"}])


# ---------------------------------------------------------------------------
# Event persistence
# ---------------------------------------------------------------------------


def test_request_and_response_events_are_written_together():
    """Both request and response events are written under one run_id."""
    db = _AuditDBStub()
    writer = AuditEventWriter(db)

    req_body = {
        "model": "claude-opus-4-5",
        "messages": [{"role": "user", "content": "Hello"}],
        "stream": False,
    }
    resp_body = {
        "id": "msg_ok",
        "type": "message",
        "role": "assistant",
        "content": [{"type": "text", "text": "Hi there"}],
        "usage": {"input_tokens": 10, "output_tokens": 5},
    }

    run_id = uuid.uuid4().hex
    req_events, ctx = writer.build_request_events(
        path="/v1/messages",
        method="POST",
        req_headers={},
        req_body=req_body,
        run_id=run_id,
    )
    resp_events = writer.build_response_events(
        ctx, status=200, body=resp_body, duration_ms=200
    )
    writer.write(req_events + resp_events)

    stored = db.query()
    types = [e["event_type"] for e in stored]
    assert "model_request" in types
    assert "model_response" in types

    # All share the same run_id
    run_ids = {e["agent"]["run_id"] for e in stored}
    assert len(run_ids) == 1
    assert run_ids.pop() == run_id


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------


def test_upstream_client_never_stores_cookies():
    """One client serves every session, so it must not replay Set-Cookie."""
    import httpx

    client = upstream_client(5.0)
    try:
        request = httpx.Request("POST", "https://api.anthropic.com/v1/messages")
        response = httpx.Response(
            200, headers={"set-cookie": "sess=SECRET; Path=/"}, request=request
        )
        client.cookies.extract_cookies(response)
        assert len(client.cookies.jar) == 0
    finally:
        client.close()


def test_forwarded_accept_encoding_is_replaced_case_insensitively():
    fwd = default_outbound_headers(
        {"accept-encoding": "gzip, br", "content-type": "application/json"}
    )
    assert [k for k in fwd if k.lower() == "accept-encoding"] == ["Accept-Encoding"]
    assert fwd["Accept-Encoding"] == "identity"


def test_undecodable_upstream_content_encoding_is_refused():
    check_content_encoding(httpx.Headers({"Content-Encoding": "gzip"}))
    check_content_encoding(httpx.Headers())
    for coding in ("br", "zstd", "gzip, br"):
        with pytest.raises(ResponseInspectionError):
            check_content_encoding(httpx.Headers({"Content-Encoding": coding}))


def test_repeated_request_headers_are_combined():
    merged = merge_headers(
        [
            ("anthropic-beta", "beta-one"),
            ("Anthropic-Beta", "beta-two"),
            ("Cookie", "a=1"),
            ("cookie", "b=2"),
        ]
    )
    assert merged == {"anthropic-beta": "beta-one, beta-two", "Cookie": "a=1; b=2"}


def test_usage_counts_cached_and_thinking_tokens():
    from panoptes.providers.gemini import GeminiProvider

    usage = AnthropicProvider().extract_usage(
        {
            "usage": {
                "input_tokens": 3,
                "cache_read_input_tokens": 90_000,
                "cache_creation_input_tokens": 5_000,
                "output_tokens": 7,
            }
        }
    )
    assert usage == {
        "tokens_in": 95_003,
        "tokens_out": 7,
        "cached_input_tokens": 90_000,
        "cache_creation_input_tokens": 5_000,
    }

    stream = (
        b'event: message_start\ndata: {"type":"message_start","message":{"id":"m",'
        b'"model":"claude-x","usage":{"input_tokens":3,"cache_read_input_tokens":10,'
        b'"output_tokens":1}}}\n\n'
        b'event: message_delta\ndata: {"type":"message_delta","delta":'
        b'{"stop_reason":"end_turn"},"usage":{"output_tokens":9,'
        b'"cache_read_input_tokens":20}}\n\n'
        b'event: message_stop\ndata: {"type":"message_stop"}\n\n'
    )
    message = _reassemble_anthropic_sse(_parse_sse_events(stream))
    assert AnthropicProvider().extract_usage(message) == {
        "tokens_in": 23,
        "tokens_out": 9,
        "cached_input_tokens": 20,
    }

    gemini = GeminiProvider()
    assert gemini.extract_usage(
        {
            "usageMetadata": {
                "promptTokenCount": 3,
                "candidatesTokenCount": 1,
                "thoughtsTokenCount": 500,
            }
        }
    ) == {"tokens_in": 3, "tokens_out": 501, "reasoning_tokens": 500}
    assert (
        gemini.extract_request_info(
            {"contents": []},
            path="/v1beta/models/gemini-2.5-pro:streamGenerateContent?alt=sse",
        )["model"]
        == "gemini-2.5-pro"
    )


def test_optional_provider_usage_breakdowns_and_streaming():
    from panoptes.providers.anthropic import (
        AnthropicProvider,
        _reassemble_anthropic_sse,
    )
    from panoptes.providers.base import _parse_sse_events
    from panoptes.providers.gemini import GeminiProvider
    from panoptes.providers.openai import OpenAIProvider

    assert OpenAIProvider().extract_usage(
        {
            "usage": {
                "input_tokens": 10,
                "output_tokens": 8,
                "input_tokens_details": {"cached_tokens": 4},
                "output_tokens_details": {"reasoning_tokens": 5},
            }
        }
    ) == {
        "tokens_in": 10,
        "tokens_out": 8,
        "cached_input_tokens": 4,
        "reasoning_tokens": 5,
    }
    assert (
        OpenAIProvider().extract_usage(
            {
                "usage": {
                    "prompt_tokens": 10,
                    "completion_tokens": 8,
                    "completion_tokens_details": {"reasoning_tokens": 0},
                }
            }
        )["reasoning_tokens"]
        == 0
    )
    assert "reasoning_tokens" not in GeminiProvider().extract_usage(
        {"usageMetadata": {"thoughtsTokenCount": True}}
    )
    stream = (
        b'event: message_start\ndata: {"type":"message_start","message":{"content":[],"usage":{"input_tokens":2,"output_tokens":1}}}\n\n'
        b'event: message_delta\ndata: {"type":"message_delta","usage":{"output_tokens":9,"output_tokens_details":{"thinking_tokens":6}}}\n\n'
        b'event: message_stop\ndata: {"type":"message_stop"}\n\n'
    )
    assert (
        AnthropicProvider().extract_usage(
            _reassemble_anthropic_sse(_parse_sse_events(stream))
        )["reasoning_tokens"]
        == 6
    )


def test_thread_start_failure_rolls_back_resources_and_can_restart(monkeypatch):
    import threading

    server = ProxyServer(port=0)
    with monkeypatch.context() as patch:

        def fail_start(thread):
            raise RuntimeError("thread launch failed")

        patch.setattr(threading.Thread, "start", fail_start)
        with pytest.raises(RuntimeError, match="thread launch failed"):
            server.start()
    assert server._server is None
    assert server._thread is None
    assert server._http_client is None
    assert server._db is None
    assert server._tmp_db_path is None
    assert server.writer is None
    try:
        assert server.start() > 0
    finally:
        server.stop()


# ---------------------------------------------------------------------------
# The exchange pipeline, against a real proxy and a fake upstream
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("hooked", [False, True], ids=["observed", "hooked"])
def test_a_request_whose_events_cannot_be_built_is_refused(
    proxy, upstream, monkeypatch, hooked
):
    def broken_fingerprint(self, body):
        raise RuntimeError("fingerprint bug")

    monkeypatch.setattr(AnthropicProvider, "request_fingerprint", broken_fingerprint)
    hooks = _CountingHooks() if hooked else None
    running = proxy(hooks)

    response = httpx.post(f"{running.url}/v1/messages", json=ANTHROPIC_BODY, timeout=10)

    # Forwarding it would leave the exchange unrecorded.
    assert response.status_code == 500
    assert response.json() == {"error": "The request could not be recorded"}
    assert upstream.requests == []
    if hooks is not None:
        assert hooks.before == hooks.after == []


@pytest.mark.parametrize("stream", [False, True], ids=["buffered", "streamed"])
def test_an_unreachable_upstream_is_recorded_the_same_way_in_both_paths(
    proxy, monkeypatch, stream
):
    monkeypatch.setenv(
        "PANOPTES_UPSTREAM_ANTHROPIC", f"http://127.0.0.1:{_unused_port()}"
    )
    running = proxy()

    response = httpx.post(
        f"{running.url}/v1/messages",
        json=dict(ANTHROPIC_BODY, stream=stream),
        timeout=10,
    )

    assert response.status_code == 502
    assert response.json() == {"error": "Bad Gateway"}
    [recorded] = running.recorded("model_response")
    assert recorded["action"]["status_code"] == 502
    assert recorded["outcome"]["status"] == "error"
    assert recorded["outcome"]["summary"] == "Server error HTTP 502"
    # The gateway error is what happened, not an inspection limit.
    assert "inspection_status" not in recorded["context"]["capture"]


@pytest.mark.parametrize("stream", [False, True], ids=["buffered", "streamed"])
def test_response_events_that_fail_to_build_leave_an_incomplete_record(
    proxy, upstream, monkeypatch, stream
):
    def broken_extraction(self, resp_body, *, path=None):
        raise RuntimeError("provider extraction exploded")

    monkeypatch.setattr(AnthropicProvider, "extract_tool_calls", broken_extraction)
    upstream.mode = "stream" if stream else "json"
    running = proxy()

    response = httpx.post(
        f"{running.url}/v1/messages",
        json=dict(ANTHROPIC_BODY, stream=stream),
        timeout=10,
    )

    assert response.status_code == 200  # delivered: Panoptes only observes
    [recorded] = running.recorded("model_response")
    assert recorded["outcome"]["status"] == "error"
    assert "Response event construction failed" in recorded["outcome"]["summary"]
    assert recorded["context"]["capture"]["inspection_status"] == "incomplete"
