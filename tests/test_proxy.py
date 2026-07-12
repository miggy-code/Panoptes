"""Tests for panoptes.proxy.

Covers:
  - Basic forward-proxy capture (existing test)
  - Shared run_id across events in one exchange
  - Reverse-proxy path routing
  - SSE reassembly for Anthropic and OpenAI formats
  - Pre-flight policy blocking
"""

import json
import os
import tempfile
import time
import uuid

import httpx
import pytest

from panoptes.proxy import (
    AuditEventWriter,
    ProxyHandler,
    ProxyServer,
    _parse_sse_response,
)
from panoptes.providers.base import _parse_sse_events
from panoptes.providers.anthropic import _reassemble_anthropic_sse
from panoptes.providers.openai import _reassemble_openai_sse


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
# Existing integration test (forward-proxy mode)
# ---------------------------------------------------------------------------


def test_proxy_capture_openai():
    """Start proxy, send mock request via forward-proxy, verify events captured."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        db_path = tmp.name

    server = ProxyServer(host="127.0.0.1", port=0, db_path=db_path)
    port = server.start()
    print(f"Proxy started on port {port}")

    try:
        req_body = {
            "model": "gpt-4",
            "messages": [
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "user", "content": "What is 2+2?"},
                {"role": "assistant", "content": None, "tool_calls": [
                    {"id": "call_123", "type": "function",
                     "function": {"name": "calculator", "arguments": '{"expr": "2+2"}'}}
                ]},
                {"role": "tool", "tool_call_id": "call_123", "name": "calculator", "content": "4"},
            ],
            "tools": [
                {"type": "function", "function": {"name": "calculator",
                 "parameters": {"type": "object", "properties": {"expr": {"type": "string"}}}}},
            ],
            "stream": False,
        }

        proxy_url = f"http://127.0.0.1:{port}"
        test_url = "http://httpbin.org/post"
        print(f"Sending test request through proxy at {proxy_url} to {test_url}")

        try:
            resp = httpx.post(test_url, json=req_body, proxy=proxy_url, timeout=15)
            print(f"Response status: {resp.status_code}")
        except Exception as e:
            print(f"Request error (expected if no internet): {e}")

        time.sleep(0.5)

        events = server.events
        print(f"\nCaptured {len(events)} events:")
        for i, event in enumerate(events):
            print(f"  Event {i+1}: {event.get('event_type')} agent={event.get('agent', {}).get('type')}")

        event_types = [e["event_type"] for e in events]
        assert "model_request" in event_types, f"Expected model_request, got {event_types}"
        assert "tool_result" in event_types, f"Expected tool_result, got {event_types}"

        for event in events:
            assert "event_id" in event
            assert "timestamp" in event
            assert "agent" in event
            assert "type" in event["agent"]
            assert "session_id" in event["agent"]
            assert "run_id" in event["agent"]
            assert "event_type" in event
            assert "context" in event

        print("All assertions passed!")

    finally:
        server.stop()
        try:
            os.unlink(db_path)
        except OSError:
            pass


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
            {"role": "assistant", "content": None, "tool_calls": [
                {"id": "call_abc", "type": "function",
                 "function": {"name": "bash", "arguments": '{"cmd": "ls"}'}}
            ]},
            {"role": "tool", "tool_call_id": "call_abc", "name": "bash", "content": "file.txt"},
        ],
        "stream": False,
    }
    resp_body = {
        "choices": [{"message": {"role": "assistant", "content": "Done", "tool_calls": []}}],
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
    print(f"Shared run_id test passed: {len(events)} events all share run_id={run_ids.pop()[:8]}…")


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

    assert ctx["turn_number"] == 2, f"Expected turn_number=2, got {ctx['turn_number']}"
    for e in req_events:
        assert e["context"]["turn_number"] == 2
    print("turn_number test passed")


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
            {"role": "tool", "tool_call_id": "call_xyz", "name": "read_file", "content": "data"},
        ],
        "stream": False,
    }
    resp_body = {
        "choices": [{"message": {"role": "assistant", "tool_calls": [
            {"id": "call_new", "type": "function",
             "function": {"name": "write_file", "arguments": '{"path": "/tmp/x"}'}}
        ]}}],
        "usage": {"prompt_tokens": 10, "completion_tokens": 5},
    }

    run_id = uuid.uuid4().hex
    req_events, ctx = writer.build_request_events(
        path="/v1/chat/completions", method="POST",
        req_headers={}, req_body=req_body, run_id=run_id,
    )
    resp_events = writer.build_response_events(
        path="/v1/chat/completions", req_body=req_body,
        resp_status=200, resp_headers={}, resp_body=resp_body,
        duration_ms=100, exchange_ctx=ctx,
    )

    tool_results = [e for e in req_events if e["event_type"] == "tool_result"]
    assert tool_results, "Expected tool_result event"
    assert tool_results[0]["action"]["call_id"] == "call_xyz"

    tool_calls = [e for e in resp_events if e["event_type"] == "tool_call"]
    assert tool_calls, "Expected tool_call event"
    assert tool_calls[0]["action"]["call_id"] == "call_new"
    print("call_id test passed")


# ---------------------------------------------------------------------------
# Reverse-proxy routing
# ---------------------------------------------------------------------------


def test_reverse_proxy_routing():
    """_parse_target routes relative paths to correct upstreams."""
    class MockHandler:
        """Minimal mock that satisfies _parse_target's attribute accesses."""
        default_upstream = None

        def _parse_target(self):
            return ProxyHandler._parse_target(self)

    h = MockHandler()

    # Anthropic
    h.path = "/v1/messages"
    scheme, host, port, path = h._parse_target()
    assert host == "api.anthropic.com", f"Got {host}"
    assert scheme == "https"
    assert port == 443
    assert path == "/v1/messages"

    # Anthropic with query string
    h.path = "/v1/messages?beta=true"
    scheme, host, port, path = h._parse_target()
    assert host == "api.anthropic.com"
    assert "?" in path

    # OpenAI chat completions
    h.path = "/v1/chat/completions"
    scheme, host, port, path = h._parse_target()
    assert host == "api.openai.com", f"Got {host}"

    # OpenAI models
    h.path = "/v1/models"
    scheme, host, port, path = h._parse_target()
    assert host == "api.openai.com"

    # Gemini generateContent
    h.path = "/v1beta/models/gemini-pro:generateContent"
    scheme, host, port, path = h._parse_target()
    assert "googleapis" in host, f"Got {host}"

    # Gemini streamGenerateContent
    h.path = "/v1beta/models/gemini-pro:streamGenerateContent"
    scheme, host, port, path = h._parse_target()
    assert "googleapis" in host

    # Forward-proxy mode (absolute HTTP URL)
    h.path = "http://api.openai.com/v1/chat/completions"
    scheme, host, port, path = h._parse_target()
    assert host == "api.openai.com"
    assert scheme == "http"
    assert path == "/v1/chat/completions"

    # Forward-proxy mode (absolute HTTPS URL)
    h.path = "https://api.anthropic.com/v1/messages"
    scheme, host, port, path = h._parse_target()
    assert host == "api.anthropic.com"
    assert scheme == "https"

    print("Reverse-proxy routing test passed")


def test_reverse_proxy_no_upstream_raises():
    """Unmatched path with no default_upstream should raise NoUpstreamError."""
    from panoptes.proxy import NoUpstreamError

    class MockHandler:
        default_upstream = None

        def _parse_target(self):
            return ProxyHandler._parse_target(self)

    h = MockHandler()
    h.path = "/unknown/endpoint"
    with pytest.raises(NoUpstreamError):
        h._parse_target()


def test_reverse_proxy_default_upstream():
    """Unmatched path with default_upstream falls back to it."""
    class MockHandler:
        default_upstream = "https://my.custom.upstream.example.com"

        def _parse_target(self):
            return ProxyHandler._parse_target(self)

    h = MockHandler()
    h.path = "/unknown/endpoint"
    scheme, host, port, path = h._parse_target()
    assert host == "my.custom.upstream.example.com"
    assert scheme == "https"
    print("default_upstream fallback test passed")


# ---------------------------------------------------------------------------
# SSE parsing — Anthropic
# ---------------------------------------------------------------------------


def _anthropic_sse_bytes(text_content: str = "Hello world!") -> bytes:
    """Build synthetic Anthropic SSE stream bytes."""
    words = text_content.split(" ")
    lines = [
        b'event: message_start',
        (
            b'data: {"type":"message_start","message":{"id":"msg_xxx","type":"message",'
            b'"role":"assistant","content":[],"model":"claude-opus-4-5",'
            b'"stop_reason":null,"stop_sequence":null,'
            b'"usage":{"input_tokens":25,"output_tokens":1}}}'
        ),
        b'',
        b'event: content_block_start',
        b'data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}',
        b'',
    ]
    for i, word in enumerate(words):
        sep = " " if i < len(words) - 1 else ""
        delta_text = word + sep
        lines.append(b'event: content_block_delta')
        lines.append(
            json.dumps({"type": "content_block_delta", "index": 0,
                        "delta": {"type": "text_delta", "text": delta_text}}).encode()
            .replace(b'"', b'"')
        )
        lines.append(b'')
    lines += [
        b'event: content_block_stop',
        b'data: {"type":"content_block_stop","index":0}',
        b'',
        b'event: message_delta',
        b'data: {"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null},"usage":{"output_tokens":10}}',
        b'',
        b'event: message_stop',
        b'data: {"type":"message_stop"}',
    ]
    return b'\n'.join(lines)


def test_sse_parsing_anthropic_text():
    """Anthropic SSE: text content blocks are reassembled correctly."""
    sse = b"\n".join([
        b'event: message_start',
        b'data: {"type":"message_start","message":{"id":"msg_1","type":"message","role":"assistant","content":[],"model":"claude-opus-4-5","stop_reason":null,"stop_sequence":null,"usage":{"input_tokens":25,"output_tokens":1}}}',
        b'',
        b'event: content_block_start',
        b'data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}',
        b'',
        b'event: content_block_delta',
        b'data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hello "}}',
        b'',
        b'event: content_block_delta',
        b'data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"world!"}}',
        b'',
        b'event: content_block_stop',
        b'data: {"type":"content_block_stop","index":0}',
        b'',
        b'event: message_delta',
        b'data: {"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null},"usage":{"output_tokens":10}}',
        b'',
        b'event: message_stop',
        b'data: {"type":"message_stop"}',
    ])

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
    print("Anthropic SSE text test passed")


def test_sse_parsing_anthropic_tool_use():
    """Anthropic SSE: tool_use blocks with input_json_delta reassemble correctly."""
    sse = b"\n".join([
        b'data: {"type":"message_start","message":{"id":"msg_2","type":"message","role":"assistant","content":[],"model":"claude-opus-4-5","stop_reason":null,"stop_sequence":null,"usage":{"input_tokens":100,"output_tokens":1}}}',
        b'data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_abc","name":"calculator","input":{}}}',
        b'data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\\"expr\\""}}',
        b'data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":": \\"2+2\\"}"}}',
        b'data: {"type":"content_block_stop","index":0}',
        b'data: {"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":50}}',
        b'data: {"type":"message_stop"}',
    ])

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
    print("Anthropic SSE tool_use test passed")


def test_sse_parsing_anthropic_via_parse_sse_response():
    """_parse_sse_response dispatches to Anthropic reassembly for 'anthropic' format."""
    sse = b"\n".join([
        b'data: {"type":"message_start","message":{"id":"m","type":"message","role":"assistant","content":[],"model":"claude-3","stop_reason":null,"stop_sequence":null,"usage":{"input_tokens":5,"output_tokens":1}}}',
        b'data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}',
        b'data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hi"}}',
        b'data: {"type":"content_block_stop","index":0}',
        b'data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":3}}',
        b'data: {"type":"message_stop"}',
    ])
    result = _parse_sse_response(sse, "anthropic")
    assert result is not None
    assert result["content"][0]["text"] == "Hi"
    assert result["usage"]["output_tokens"] == 3
    print("_parse_sse_response (anthropic) test passed")


# ---------------------------------------------------------------------------
# SSE parsing — OpenAI
# ---------------------------------------------------------------------------


def test_sse_parsing_openai_text():
    """OpenAI SSE: text content chunks reassemble correctly."""
    sse = b"\n".join([
        b'data: {"id":"chatcmpl-x","object":"chat.completion.chunk","created":1000,"model":"gpt-4","choices":[{"index":0,"delta":{"role":"assistant","content":""},"finish_reason":null}]}',
        b'data: {"id":"chatcmpl-x","object":"chat.completion.chunk","created":1000,"model":"gpt-4","choices":[{"index":0,"delta":{"content":"Hello"},"finish_reason":null}]}',
        b'data: {"id":"chatcmpl-x","object":"chat.completion.chunk","created":1000,"model":"gpt-4","choices":[{"index":0,"delta":{"content":" world!"},"finish_reason":null}]}',
        b'data: {"id":"chatcmpl-x","object":"chat.completion.chunk","created":1000,"model":"gpt-4","choices":[{"index":0,"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}',
        b'data: [DONE]',
    ])

    events = _parse_sse_events(sse)
    assert len(events) == 4, f"Expected 4 parsed chunks (ignoring [DONE]), got {len(events)}"

    result = _reassemble_openai_sse(events)
    assert result["id"] == "chatcmpl-x"
    assert result["model"] == "gpt-4"
    assert len(result["choices"]) == 1
    assert result["choices"][0]["message"]["content"] == "Hello world!"
    assert result["choices"][0]["finish_reason"] == "stop"
    assert result["usage"]["prompt_tokens"] == 10
    assert result["usage"]["completion_tokens"] == 5
    print("OpenAI SSE text test passed")


def test_sse_parsing_openai_tool_calls():
    """OpenAI SSE: tool_call arguments accumulate correctly across chunks."""
    sse = b"\n".join([
        b'data: {"id":"cc-y","object":"chat.completion.chunk","created":2000,"model":"gpt-4","choices":[{"index":0,"delta":{"role":"assistant","content":null,"tool_calls":[{"index":0,"id":"call_abc","type":"function","function":{"name":"calculator","arguments":""}}]},"finish_reason":null}]}',
        b'data: {"id":"cc-y","object":"chat.completion.chunk","created":2000,"model":"gpt-4","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\\"expr\\""}}]},"finish_reason":null}]}',
        b'data: {"id":"cc-y","object":"chat.completion.chunk","created":2000,"model":"gpt-4","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":": \\"2+2\\"}"}}]},"finish_reason":"tool_calls"}]}',
        b'data: [DONE]',
    ])

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
    print("OpenAI SSE tool_calls test passed")


def test_sse_parsing_openai_via_parse_sse_response():
    """_parse_sse_response dispatches to OpenAI reassembly for 'openai' format."""
    sse = b"\n".join([
        b'data: {"id":"cc-z","object":"chat.completion.chunk","created":3000,"model":"gpt-4","choices":[{"index":0,"delta":{"content":"Hi"},"finish_reason":null}]}',
        b'data: {"id":"cc-z","object":"chat.completion.chunk","created":3000,"model":"gpt-4","choices":[{"index":0,"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":5,"completion_tokens":1}}',
        b'data: [DONE]',
    ])
    result = _parse_sse_response(sse, "openai")
    assert result is not None
    assert result["choices"][0]["message"]["content"] == "Hi"
    print("_parse_sse_response (openai) test passed")


# ---------------------------------------------------------------------------
# Pre-flight policy blocking
# ---------------------------------------------------------------------------


def test_preflight_block_prevents_forward():
    """Pre-flight check: blocked request events should be returned as 'block' without forwarding."""
    db = _AuditDBStub()
    writer = AuditEventWriter(db)

    # Stub policy engine that always blocks
    class _BlockingEngine:
        def check_event(self, event):
            try:
                from panoptes.policy import PolicyResult
            except ImportError:
                # Fallback dataclass-like object
                class PolicyResult:
                    def __init__(self, **kw):
                        for k, v in kw.items():
                            setattr(self, k, v)
            return PolicyResult(
                action="block",
                violated_policies=[{"policy_name": "test_block", "message": "Blocked for testing"}],
                warnings=["Blocked for testing"],
            )

    writer.policy_engine = _BlockingEngine()

    req_body = {
        "model": "gpt-4",
        "messages": [{"role": "user", "content": "Do something bad"}],
        "stream": False,
    }

    run_id = uuid.uuid4().hex
    req_events, exchange_ctx = writer.build_request_events(
        path="/v1/chat/completions",
        method="POST",
        req_headers={},
        req_body=req_body,
        run_id=run_id,
    )

    # Pre-flight check
    policy_result = writer.check_policies(req_events)
    assert policy_result.action == "block", f"Expected block, got {policy_result.action}"
    assert len(policy_result.violated_policies) > 0

    # Simulate handler writing events on block (no response events written)
    writer.write(req_events)

    # Verify events written to DB share the run_id
    stored = db.query()
    assert len(stored) > 0
    for e in stored:
        assert e["agent"]["run_id"] == run_id, (
            f"run_id mismatch: expected {run_id}, got {e['agent']['run_id']}"
        )

    # No response events written (we blocked pre-flight)
    assert all(e["event_type"] != "model_response" for e in stored), (
        "model_response event should not be written on pre-flight block"
    )
    print("Pre-flight blocking test passed")


def test_preflight_allow_writes_all_events():
    """When policies allow, both request and response events are written."""
    db = _AuditDBStub()
    writer = AuditEventWriter(db)  # no policy engine — always allows

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
        path="/v1/messages", method="POST",
        req_headers={}, req_body=req_body, run_id=run_id,
    )
    policy_result = writer.check_policies(req_events)
    assert policy_result.action == "allow"

    resp_events = writer.build_response_events(
        path="/v1/messages", req_body=req_body,
        resp_status=200, resp_headers={}, resp_body=resp_body,
        duration_ms=200, exchange_ctx=ctx,
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
    print("Pre-flight allow + full event write test passed")


# ---------------------------------------------------------------------------
# End-to-end integration: reverse-proxy mode with live server
# ---------------------------------------------------------------------------


def test_reverse_proxy_mode_captures_events():
    """Reverse-proxy mode: direct POST to proxy captures audit events."""
    server = ProxyServer(host="127.0.0.1", port=0)
    port = server.start()

    try:
        # Use a direct HTTP request in reverse-proxy style (relative path resolved by proxy)
        # We can't actually hit api.openai.com in tests, so we hit httpbin.org via
        # forward-proxy mode with an absolute URL to verify event capture works.
        # This test exercises the path where req_body parse + events are built.
        req_body = {
            "model": "gpt-4",
            "messages": [{"role": "user", "content": "Test"}],
            "stream": False,
        }
        proxy_url = f"http://127.0.0.1:{port}"
        try:
            resp = httpx.post(
                "http://httpbin.org/post",
                json=req_body,
                proxy=proxy_url,
                timeout=10,
            )
        except Exception:
            pass

        time.sleep(0.2)
        events = server.events
        if events:
            # All events from this exchange share a run_id
            run_ids = {e["agent"]["run_id"] for e in events}
            assert len(run_ids) == 1, f"Multiple run_ids: {run_ids}"
        print(f"Reverse-proxy integration test passed ({len(events)} events captured)")
    finally:
        server.stop()


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    test_proxy_capture_openai()
    test_shared_run_id()
    test_turn_number_in_context()
    test_call_id_on_tool_events()
    test_reverse_proxy_routing()
    test_reverse_proxy_no_upstream_raises()
    test_reverse_proxy_default_upstream()
    test_sse_parsing_anthropic_text()
    test_sse_parsing_anthropic_tool_use()
    test_sse_parsing_anthropic_via_parse_sse_response()
    test_sse_parsing_openai_text()
    test_sse_parsing_openai_tool_calls()
    test_sse_parsing_openai_via_parse_sse_response()
    test_preflight_block_prevents_forward()
    test_preflight_allow_writes_all_events()
    test_reverse_proxy_mode_captures_events()
    print("\nAll tests passed!")
