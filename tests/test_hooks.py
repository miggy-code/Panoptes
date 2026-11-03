"""The proxy hook seam (docs/hooks.md) against a real proxy and a fake upstream."""

import http.server
import json
import logging
import socket
import struct
import threading
import time

import httpx
import pytest

from panoptes.db import AuditDB
from panoptes.hooks import (
    Exchange,
    Identity,
    OutboundHeaders,
    ProxyHooks,
    Reject,
    Upstream,
    User,
)
from panoptes.proxy import ProxyServer

BODY = {"model": "claude-test", "max_tokens": 8,
        "messages": [{"role": "user", "content": "hello"}]}
RESPONSE = {
    "id": "msg_1", "type": "message", "role": "assistant", "model": "claude-test",
    "content": [{"type": "text", "text": "hi"}],
    "usage": {"input_tokens": 3, "output_tokens": 1},
}
SSE_HEAD = (
    b'event: message_start\n'
    b'data: {"type":"message_start","message":{"id":"msg_1","type":"message",'
    b'"role":"assistant","content":[],"model":"claude-test","stop_reason":null,'
    b'"usage":{"input_tokens":3,"output_tokens":1}}}\n\n'
    b'event: content_block_start\n'
    b'data: {"type":"content_block_start","index":0,'
    b'"content_block":{"type":"text","text":""}}\n\n'
    b'event: content_block_delta\n'
    b'data: {"type":"content_block_delta","index":0,'
    b'"delta":{"type":"text_delta","text":"hi"}}\n\n'
)
SSE_TAIL = (
    b'event: content_block_stop\n'
    b'data: {"type":"content_block_stop","index":0}\n\n'
    b'event: message_delta\n'
    b'data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},'
    b'"usage":{"output_tokens":9}}\n\n'
    b'event: message_stop\ndata: {"type":"message_stop"}\n\n'
)


class FakeUpstream:
    """Records what it receives and answers as configured."""

    def __init__(self):
        self.requests = []
        self.mode = "json"
        self.stream_body = False
        self.piece_delay = 0.05            # between the pieces of a stream's tail
        self.gate = threading.Event()      # releases the tail of a gated stream
        self.head_sent = threading.Event()
        self.stall = threading.Event()     # holds a "stalled" stream silent
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                length = int(self.headers.get("Content-Length") or 0)
                outer.requests.append({
                    "path": self.path,
                    "headers": [(k, v) for k, v in self.headers.items()],
                    "body": self.rfile.read(length),
                })
                if outer.mode == "dupkey":
                    payload = b'{"id": "a", "id": "b", "usage": {"input_tokens": 3}}'
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)
                elif outer.mode == "huge":
                    payload = b'{"pad": "' + b"x" * 4096 + b'"}'
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)
                elif outer.mode == "truncated":
                    # A stream that ends after its first events, without a stop.
                    self.send_response(200)
                    self.send_header("Content-Type", "text/event-stream")
                    self.end_headers()
                    self.wfile.write(SSE_HEAD)
                    self.close_connection = True
                elif outer.mode == "hang":
                    outer.gate.wait(10)          # never answers in time
                elif outer.mode == "middrop":
                    self.send_response(200)
                    self.send_header(
                        "Content-Type",
                        "text/event-stream" if outer.stream_body else "application/json")
                    self.send_header("Content-Length", "400")
                    self.end_headers()
                    self.wfile.write(b'{"id": "msg_1", "content": [{"ty')
                    self.wfile.flush()
                    self.close_connection = True   # 400 promised, 35 sent
                elif outer.mode == "hugenolen":
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(b'{"pad": "' + b"x" * 4096 + b'"}')
                    self.close_connection = True
                elif outer.mode == "nousage":
                    payload = json.dumps({k: v for k, v in RESPONSE.items() if k != "usage"}).encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)
                elif outer.mode == "error500nobody":
                    self.send_response(500)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                elif outer.mode == "error500":
                    payload = b'{"error":"boom"}'
                    self.send_response(500)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)
                elif outer.mode == "stalled":
                    self.send_response(200)
                    self.send_header("Content-Type", "text/event-stream")
                    self.end_headers()
                    self.wfile.write(SSE_HEAD)
                    self.wfile.flush()
                    outer.head_sent.set()
                    outer.gate.wait(10)
                    try:
                        for piece in SSE_TAIL.split(b"\n\n")[:2]:
                            self.wfile.write(piece + b"\n\n")
                            self.wfile.flush()
                            time.sleep(0.05)
                        outer.stall.wait(10)         # then goes silent
                    except OSError:
                        pass
                elif outer.mode in ("stream", "gated"):
                    self.send_response(200)
                    self.send_header("Content-Type", "text/event-stream")
                    self.end_headers()
                    self.wfile.write(SSE_HEAD)
                    self.wfile.flush()
                    outer.head_sent.set()
                    if outer.mode == "gated":
                        outer.gate.wait(10)
                    try:
                        # Several writes: the first one after a client leaves
                        # still succeeds locally, a later one fails.
                        for piece in SSE_TAIL.split(b"\n\n"):
                            if piece:
                                self.wfile.write(piece + b"\n\n")
                                self.wfile.flush()
                                time.sleep(outer.piece_delay)
                    except OSError:
                        pass
                else:
                    payload = json.dumps(RESPONSE).encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.port = self.server.server_address[1]
        threading.Thread(
            target=self.server.serve_forever, kwargs={"poll_interval": 0.05},
            daemon=True,
        ).start()

    def header(self, index, name):
        return [v for k, v in self.requests[index]["headers"] if k.lower() == name]

    def close(self):
        self.gate.set()
        self.stall.set()
        self.server.shutdown()
        self.server.server_close()


class Recorder(ProxyHooks):
    """Collects every exchange and delegates to optional callables."""

    def __init__(self, before=None, after=None):
        self.before = before
        self.after = after
        self.before_calls = []
        self.after_calls = []
        self.done = threading.Event()

    def before_forward(self, exchange):
        self.before_calls.append(exchange)
        return self.before(exchange) if self.before else None

    def after_exchange(self, exchange):
        self.after_calls.append(exchange)
        try:
            if self.after:
                self.after(exchange)
        finally:
            self.done.set()


@pytest.fixture
def upstream(monkeypatch):
    fake = FakeUpstream()
    monkeypatch.setenv("PANOPTES_UPSTREAM_ANTHROPIC", f"http://127.0.0.1:{fake.port}")
    yield fake
    fake.close()


@pytest.fixture
def make_proxy(tmp_path, upstream):
    started = []

    def make(hooks, **kwargs):
        db_path = tmp_path / "audit.db"
        server = ProxyServer(port=0, db_path=str(db_path), hooks=hooks, **kwargs)
        port = server.start()
        client = httpx.Client(
            base_url=f"http://127.0.0.1:{port}", trust_env=False, timeout=15
        )
        started.append((server, client))
        return server, client, db_path

    yield make
    for server, client in started:
        client.close()
        server.stop()


def stored(db_path):
    db = AuditDB.open_readonly(str(db_path))
    try:
        return list(db.iter_events())
    finally:
        db.close()


def abort(sock):
    """Close with a TCP reset, so the proxy's next write fails at once."""
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    sock.close()


def wait_after(recorder, timeout=10):
    assert recorder.done.wait(timeout), "after_exchange was never called"
    assert len(recorder.after_calls) == 1
    return recorder.after_calls[0]


# ---------------------------------------------------------------------------
# The success path
# ---------------------------------------------------------------------------


def test_both_hooks_run_once_and_the_exchange_is_settled(make_proxy, upstream):
    hooks = Recorder()
    _, client, db_path = make_proxy(hooks)

    assert client.post("/v1/messages", json=BODY).status_code == 200

    ex = wait_after(hooks)
    assert len(hooks.before_calls) == 1 and hooks.before_calls[0] is ex
    assert (ex.outcome, ex.status, ex.request_sent) == ("forwarded", 200, True)
    assert (ex.produced_output, ex.complete, ex.provider_error) == (True, True, False)
    assert ex.provider == "anthropic" and ex.upstream_name == "anthropic"
    assert ex.upstream_url == f"http://127.0.0.1:{upstream.port}"
    assert ex.usage == {"tokens_in": 3, "tokens_out": 1}
    assert ex.estimated_usd_micros is None            # no pricing table
    assert ex.duration_ms is not None and ex.duration_ms >= 0
    assert ex.correlation_source == "proxy" and ex.correlation_id == ex.exchange_id
    assert [e["event_type"] for e in ex.response_events] == ["model_response"]
    assert ex.request_json == BODY and json.loads(ex.request_body) == BODY

    events = stored(db_path)
    assert {e["attributes"]["exchange_id"] for e in events} == {ex.exchange_id}
    assert {e["attributes"]["identity"]["source"] for e in events} == {"seeded"}
    # Seeded values are what Panoptes derived, never a hook's.
    assert ex.identity.session_id == events[0]["agent"]["session_id"]


def test_the_request_body_is_forwarded_byte_for_byte(make_proxy, upstream):
    hooks = Recorder()
    _, client, _ = make_proxy(hooks)
    raw = b'{"model":  "claude-test",  "max_tokens": 8, "messages":[{"role":"user","content":"x"}]}'
    client.post("/v1/messages", content=raw, headers={"Content-Type": "application/json"})
    wait_after(hooks)
    assert upstream.requests[0]["body"] == raw


def test_exchange_request_fields_are_read_only_and_repr_is_safe(make_proxy):
    seen = {}

    def before(ex):
        with pytest.raises(AttributeError):
            ex.path = "/other"
        with pytest.raises(AttributeError):
            ex.outcome = "forwarded"
        with pytest.raises(TypeError):
            ex.identity = "someone"
        seen["repr"] = repr(ex) + repr(ex.request_headers) + repr(ex.outbound_headers)

    hooks = Recorder(before=before)
    _, client, _ = make_proxy(hooks)
    client.post("/v1/messages", json=BODY, headers={"x-api-key": "sk-ant-SECRETVALUE0123456789"})
    wait_after(hooks)
    assert "SECRETVALUE" not in seen["repr"]


def test_repeated_credential_headers_are_all_visible(make_proxy):
    seen = {}

    def before(ex):
        seen["all"] = ex.request_headers.get_all("authorization")
        seen["first"] = ex.request_headers.get("AUTHORIZATION")

    hooks = Recorder(before=before)
    _, client, _ = make_proxy(hooks)
    client.post("/v1/messages", json=BODY,
                headers=[("Authorization", "Bearer aaa"), ("authorization", "Bearer bbb")])
    wait_after(hooks)
    assert seen["all"] == ["Bearer aaa", "Bearer bbb"] and seen["first"] == "Bearer aaa"


# ---------------------------------------------------------------------------
# Rejection and hook failure
# ---------------------------------------------------------------------------


def test_reject_answers_the_client_and_never_forwards(make_proxy, upstream):
    hooks = Recorder(before=lambda ex: Reject(429, {"detail": "no budget"}, "budget"))
    _, client, db_path = make_proxy(hooks)

    response = client.post("/v1/messages", json=BODY)

    assert response.status_code == 429 and response.json() == {"detail": "no budget"}
    assert response.headers["content-type"] == "application/json"
    ex = wait_after(hooks)
    assert upstream.requests == []
    assert (ex.outcome, ex.request_sent, ex.produced_output, ex.status) == (
        "rejected", False, False, 429)
    assert ex.complete is False and ex.response_events == []
    events = stored(db_path)
    request = next(e for e in events if e["event_type"] == "model_request")
    assert request["outcome"]["status"] == "blocked"
    assert request["attributes"]["hook"] == {
        "action": "reject", "status": 429, "reason": "budget"}
    assert not any(e["event_type"] == "model_response" for e in events)


def test_reject_default_body_is_the_reason(make_proxy):
    hooks = Recorder(before=lambda ex: Reject(403, reason="nope"))
    _, client, _ = make_proxy(hooks)
    response = client.post("/v1/messages", json=BODY)
    assert response.status_code == 403 and response.json() == {"error": "nope"}


@pytest.mark.parametrize("bad", [
    Reject(200, {"x": 1}, "ok"),                 # status outside 400-599
    Reject(403, object(), "weird"),              # body not JSON
    Reject(403, None, "sk-ant-" + "a" * 40),     # secret-shaped reason
    "forbidden",                                 # not None / Reject
])
def test_invalid_hook_answers_fail_closed(make_proxy, upstream, bad):
    hooks = Recorder(before=lambda ex: bad)
    _, client, db_path = make_proxy(hooks)

    response = client.post("/v1/messages", json=BODY)

    assert response.status_code == 502
    ex = wait_after(hooks)
    assert upstream.requests == []
    assert (ex.outcome, ex.request_sent) == ("hook_error", False)
    request = next(e for e in stored(db_path) if e["event_type"] == "model_request")
    assert request["attributes"]["hook"]["action"] == "error"
    assert request["outcome"]["status"] == "blocked"


def test_a_raising_hook_never_means_forward_and_leaks_nothing(make_proxy, upstream):
    def boom(ex):
        ex.identity = Identity(agent_type="evil", session_id="half-set")
        raise RuntimeError("secret internal detail")

    hooks = Recorder(before=boom)
    _, client, db_path = make_proxy(hooks)

    response = client.post("/v1/messages", json=BODY)

    assert response.status_code == 502
    assert "secret internal detail" not in response.text
    ex = wait_after(hooks)
    assert upstream.requests == [] and ex.outcome == "hook_error"
    events = stored(db_path)
    assert {e["agent"]["type"] for e in events} != {"evil"}
    assert "half-set" not in {e["agent"]["session_id"] for e in events}
    assert ex.identity.agent_type != "evil"       # the seeded identity was recorded
    assert {e["attributes"]["identity"]["source"] for e in events} == {"seeded"}


# ---------------------------------------------------------------------------
# Identity
# ---------------------------------------------------------------------------


def test_a_hook_identity_replaces_the_seeded_one_on_every_event(make_proxy):
    identity = Identity(
        agent_type="claude_code", session_id="sess-1", run_id="run-1",
        parent_run_id="run-0", user=User(id="u-1", auth_method="oidc"),
        assurance="vendor-sso",
    )

    def before(ex):
        ex.identity = identity

    hooks = Recorder(before=before, after=lambda ex: setattr(
        ex, "identity", Identity(agent_type="late", session_id="late")))
    _, client, db_path = make_proxy(hooks)
    client.post("/v1/messages", json=BODY,
                headers={"X-Panoptes-Agent": "codex", "X-Panoptes-Session": "claimed"})

    ex = wait_after(hooks)
    assert ex.identity == identity                 # the late assignment was ignored
    events = stored(db_path)
    assert {e["event_type"] for e in events} == {"model_request", "model_response"}
    for e in events:
        assert e["agent"]["type"] == "claude_code"
        assert e["agent"]["session_id"] == "sess-1"
        assert e["agent"]["run_id"] == "run-1"
        assert e["agent"]["parent_run_id"] == "run-0"
        assert e["user"] == {"id": "u-1", "auth_method": "oidc"}
        assert e["attributes"]["identity"] == {"source": "hook", "assurance": "vendor-sso"}
        assert e["context"]["capture"]["identity_assurance"] == "hook_asserted"
        assert e["attributes"]["exchange_id"] == ex.exchange_id


def test_a_hook_identity_without_a_run_id_gets_none_invented(make_proxy):
    hooks = Recorder(before=lambda ex: setattr(
        ex, "identity", Identity(agent_type="custom_agent", session_id="s-9")))
    _, client, db_path = make_proxy(hooks)
    client.post("/v1/messages", json=BODY)
    wait_after(hooks)
    for e in stored(db_path):
        assert e["agent"].get("run_id") is None
        assert e["agent"]["type"] == "custom_agent"


def test_identity_is_validated_on_assignment():
    with pytest.raises(Exception):
        Identity(agent_type="a" * 300, session_id="s")
    with pytest.raises(Exception):
        Identity(agent_type="ok", session_id="line\nbreak")
    with pytest.raises(Exception):
        User(id="sk-ant-" + "a" * 40)


# ---------------------------------------------------------------------------
# Headers and query credentials
# ---------------------------------------------------------------------------


def test_a_hook_replaces_credentials_and_the_invariants_hold(make_proxy, upstream):
    def before(ex):
        for name in ("authorization", "x-api-key"):
            ex.outbound_headers.pop(name, None)
        ex.outbound_headers["x-api-key"] = "provider-key"
        ex.outbound_headers["Content-Length"] = "999"      # discarded
        ex.outbound_headers["Content-Type"] = "text/plain"  # discarded
        ex.outbound_headers["Accept-Encoding"] = "br"       # forced to identity
        ex.outbound_headers["Connection"] = "close"         # hop-by-hop, dropped
        ex.outbound_headers["x-custom"] = "kept"

    hooks = Recorder(before=before)
    _, client, _ = make_proxy(hooks)
    client.post("/v1/messages", json=BODY, headers={
        "x-api-key": "client-key", "Authorization": "Bearer client-token"})
    wait_after(hooks)

    assert upstream.header(0, "x-api-key") == ["provider-key"]
    assert upstream.header(0, "authorization") == []
    assert upstream.header(0, "x-custom") == ["kept"]
    assert upstream.header(0, "accept-encoding") == ["identity"]
    assert upstream.header(0, "content-type") == ["application/json"]
    assert upstream.header(0, "content-length") == [str(len(upstream.requests[0]["body"]))]
    assert "close" not in upstream.header(0, "connection")


def test_a_connection_header_cannot_strip_a_header_the_hook_injected(make_proxy, upstream):
    hooks = Recorder(before=lambda ex: ex.outbound_headers.update({"x-api-key": "injected"}))
    _, client, _ = make_proxy(hooks)
    client.post("/v1/messages", json=BODY,
                headers={"Connection": "x-api-key", "x-api-key": "client"})
    wait_after(hooks)
    assert upstream.header(0, "x-api-key") == ["injected"]


def test_outbound_headers_are_validated_and_case_insensitive():
    headers = OutboundHeaders({"X-Thing": "a"})
    assert headers["x-thing"] == "a" and "X-THING" in headers
    headers["x-thing"] = "b"
    assert list(headers) == ["x-thing"] and len(headers) == 1
    for bad in ("a\r\nInjected: 1", "nul\x00", 5):
        with pytest.raises(ValueError):
            headers["x-bad"] = bad
    with pytest.raises(ValueError):
        headers["bad name"] = "v"


QUERY_PATH = "/v1/messages?API_KEY=SEKRET1&x=1&access_token=SEKRET2&key=SEKRET3"


def test_query_credentials_are_forwarded_unless_the_hook_drops_them(make_proxy, upstream):
    seen = {}
    hooks = Recorder(before=lambda ex: seen.update(
        creds=ex.query_credentials, path=ex.path))
    _, client, db_path = make_proxy(hooks)
    client.post(QUERY_PATH, json=BODY)
    wait_after(hooks)

    assert seen["creds"] == ("SEKRET1", "SEKRET2", "SEKRET3")
    assert seen["path"] == "/v1/messages?x=1"
    assert upstream.requests[0]["path"] == QUERY_PATH      # a logging hook changes nothing
    blob = json.dumps(stored(db_path))
    assert "SEKRET" not in blob


def test_drop_query_credentials_removes_them_from_the_forwarded_url(make_proxy, upstream):
    def before(ex):
        ex.drop_query_credentials()
        ex.drop_query_credentials()          # idempotent
        assert ex.query_credentials == ("SEKRET1", "SEKRET2", "SEKRET3")

    hooks = Recorder(before=before)
    _, client, db_path = make_proxy(hooks)
    client.post(QUERY_PATH, json=BODY)
    wait_after(hooks)
    assert upstream.requests[0]["path"] == "/v1/messages?x=1"
    assert "SEKRET" not in json.dumps(stored(db_path))


# ---------------------------------------------------------------------------
# after_exchange
# ---------------------------------------------------------------------------


def test_an_after_exchange_exception_is_recorded_as_an_event(make_proxy):
    def after(ex):
        raise RuntimeError("settle failed")

    hooks = Recorder(after=after)
    _, client, db_path = make_proxy(hooks)

    assert client.post("/v1/messages", json=BODY).status_code == 200
    ex = wait_after(hooks)

    deadline = time.time() + 5
    while time.time() < deadline:
        errors = [e for e in stored(db_path) if e["event_type"] == "panoptes.hook_error"]
        if errors:
            break
        time.sleep(0.05)
    assert len(errors) == 1
    attributes = errors[0]["attributes"]
    assert attributes["hook"] == "after_exchange"
    assert attributes["exchange_id"] == ex.exchange_id
    assert attributes["error_type"] == "RuntimeError"
    assert "settle failed" in attributes["error"]
    assert errors[0]["outcome"]["status"] == "error"
    assert errors[0]["correlation_id"] == ex.correlation_id
    # The next request is unaffected.
    assert client.post("/v1/messages", json=BODY).status_code == 200


def test_upstream_connect_failure_reports_request_not_sent(make_proxy, upstream, monkeypatch):
    dead = socket.socket()
    dead.bind(("127.0.0.1", 0))
    port = dead.getsockname()[1]
    dead.close()                                    # nothing listens here now
    monkeypatch.setenv("PANOPTES_UPSTREAM_ANTHROPIC", f"http://127.0.0.1:{port}")
    hooks = Recorder()
    _, client, _ = make_proxy(hooks)

    assert client.post("/v1/messages", json=BODY).status_code == 502
    ex = wait_after(hooks)
    assert (ex.outcome, ex.status, ex.request_sent) == ("upstream_error", 502, False)
    assert (ex.produced_output, ex.complete, ex.provider_error) == (False, False, False)


def test_a_provider_error_is_forwarded_and_flagged(make_proxy, upstream):
    upstream.mode = "error500"
    hooks = Recorder()
    _, client, _ = make_proxy(hooks)

    assert client.post("/v1/messages", json=BODY).status_code == 500
    ex = wait_after(hooks)
    assert (ex.outcome, ex.status, ex.request_sent) == ("forwarded", 500, True)
    assert (ex.provider_error, ex.produced_output) == (True, False)
    assert ex.estimated_usd_micros == 0              # an error reply is not billed


def test_pricing_is_reported_in_whole_micro_dollars(make_proxy, tmp_path):
    from panoptes.pricing import PricingTable

    table = PricingTable.from_dict({
        "currency": "USD", "version": "t1", "source": "test",
        "models": {"claude-test": {
            "input_per_million": "1", "cached_input_per_million": "0.1",
            "output_per_million": "2"}},
    })
    hooks = Recorder()
    _, client, _ = make_proxy(hooks, pricing=table)
    client.post("/v1/messages", json=BODY)
    ex = wait_after(hooks)
    assert isinstance(ex.estimated_usd_micros, int) and ex.estimated_usd_micros > 0


# ---------------------------------------------------------------------------
# Streaming
# ---------------------------------------------------------------------------


def test_streaming_is_not_buffered_and_after_exchange_never_delays_the_client(
    make_proxy, upstream
):
    upstream.mode = "gated"
    release = threading.Event()
    hooks = Recorder(after=lambda ex: release.wait(10))
    _, client, _ = make_proxy(hooks)
    body = dict(BODY, stream=True)

    chunks = []
    with client.stream("POST", "/v1/messages", json=body) as response:
        it = response.iter_bytes()
        chunks.append(next(it))                      # arrives while the upstream is held
        assert upstream.head_sent.wait(5) and not hooks.done.is_set()
        upstream.gate.set()
        chunks.extend(it)                            # the stream ends for the client...
    assert b"message_stop" in b"".join(chunks)
    assert not hooks.done.is_set()                   # ...while after_exchange still blocks
    release.set()
    ex = wait_after(hooks)
    assert (ex.outcome, ex.status, ex.complete, ex.produced_output) == (
        "forwarded", 200, True, True)
    assert ex.usage["tokens_out"] == 9


def test_a_client_that_leaves_mid_stream_still_yields_usage(make_proxy, upstream):
    upstream.mode = "gated"
    hooks = Recorder()
    server, client, db_path = make_proxy(hooks)
    body = json.dumps(dict(BODY, stream=True)).encode()

    sock = socket.create_connection(("127.0.0.1", server.port))
    sock.sendall(
        b"POST /v1/messages HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n"
        + f"Content-Length: {len(body)}\r\n\r\n".encode() + body
    )
    assert upstream.head_sent.wait(10)
    sock.recv(4096)
    abort(sock)                                      # the client walks away
    time.sleep(0.2)
    upstream.gate.set()                              # the provider finishes afterwards

    ex = wait_after(hooks)
    assert ex.request_sent is True and ex.outcome == "forwarded"
    assert ex.complete is True                       # Panoptes read the whole stream
    assert ex.usage["tokens_out"] == 9


def test_drain_is_bounded(make_proxy, upstream):
    upstream.mode = "gated"
    upstream.piece_delay = 0.3
    hooks = Recorder()
    server, client, _ = make_proxy(hooks, disconnect_drain_seconds=0.4)
    body = json.dumps(dict(BODY, stream=True)).encode()
    sock = socket.create_connection(("127.0.0.1", server.port))
    sock.sendall(
        b"POST /v1/messages HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n"
        + f"Content-Length: {len(body)}\r\n\r\n".encode() + body
    )
    assert upstream.head_sent.wait(10)
    sock.recv(4096)
    abort(sock)
    upstream.gate.set()                              # the tail trickles in past the bound
    ex = wait_after(hooks)
    assert ex.request_sent is True and ex.complete is False and ex.usage == {}


# ---------------------------------------------------------------------------
# Upstreams, db sharing, lifecycle
# ---------------------------------------------------------------------------


def test_upstreams_override_the_environment_and_name_the_upstream(
    tmp_path, monkeypatch, upstream
):
    monkeypatch.setenv("PANOPTES_UPSTREAM_ANTHROPIC", "http://127.0.0.1:1")  # a dead one
    hooks = Recorder()
    server = ProxyServer(
        port=0, db_path=str(tmp_path / "a.db"), hooks=hooks,
        upstreams={"anthropic": Upstream(f"http://127.0.0.1:{upstream.port}", name="deepseek")},
    )
    port = server.start()
    try:
        r = httpx.post(f"http://127.0.0.1:{port}/v1/messages", json=BODY, timeout=15)
        assert r.status_code == 200
        ex = wait_after(hooks)
        assert ex.provider == "anthropic" and ex.upstream_name == "deepseek"
    finally:
        server.stop()


@pytest.mark.parametrize("url", [
    "https://api.example.com/v1", "https://u:p@api.example.com", "ftp://x",
    "https://x?y=1", "https://x#frag", "https://",
])
def test_upstream_must_be_an_origin(url):
    with pytest.raises(ValueError):
        Upstream(url)


def test_upstream_origin_forms():
    assert Upstream("https://api.deepseek.com/").origin == "https://api.deepseek.com"
    assert Upstream("http://127.0.0.1:8080").origin == "http://127.0.0.1:8080"


def test_proxy_server_rejects_bad_configuration(tmp_path):
    with pytest.raises(ValueError):
        ProxyServer(port=0, upstreams={"nope": Upstream("https://x.example")})
    with pytest.raises(TypeError):
        ProxyServer(port=0, upstreams={"openai": "https://x.example"})
    with pytest.raises(TypeError):
        ProxyServer(port=0, hooks=object())
    with pytest.raises(ValueError):
        ProxyServer(port=0, hooks=ProxyHooks(), policies_dir="/nonexistent")
    with pytest.raises(ValueError):
        ProxyServer(port=0, hooks=ProxyHooks(), policies_dir=str(tmp_path))
    if True:
        db = AuditDB(str(tmp_path / "x.db"))
        with pytest.raises(ValueError):
            ProxyServer(port=0, db=db, db_path=str(tmp_path / "y.db"))


def test_a_shared_db_is_used_and_not_closed_by_the_proxy(tmp_path, upstream):
    db = AuditDB(str(tmp_path / "shared.db"))
    hooks = Recorder()
    server = ProxyServer(port=0, db=db, hooks=hooks)
    port = server.start()
    httpx.post(f"http://127.0.0.1:{port}/v1/messages", json=BODY, timeout=15)
    wait_after(hooks)
    server.stop()
    # Still usable after stop(), and the proxy's events are in it.
    assert {e["event_type"] for e in db.query()} >= {"model_request", "model_response"}
    assert db.verify_chain()["valid"] is True
    db.close()


def test_stop_waits_for_in_flight_after_exchange(make_proxy):
    finished = threading.Event()

    def slow_after(ex):
        time.sleep(0.4)
        finished.set()

    hooks = Recorder(after=slow_after)
    server, client, _ = make_proxy(hooks)
    client.post("/v1/messages", json=BODY)
    server.stop()
    assert finished.is_set()


def test_a_slow_hook_is_logged(make_proxy, caplog):
    hooks = Recorder(before=lambda ex: time.sleep(0.2))
    _, client, _ = make_proxy(hooks, hook_slow_seconds=0.05)
    with caplog.at_level("WARNING", logger="panoptes"):
        client.post("/v1/messages", json=BODY)
        wait_after(hooks)
    assert any("before_forward took" in r.getMessage() for r in caplog.records)


def test_requests_refused_before_the_hook_never_reach_it(make_proxy):
    hooks = Recorder()
    _, client, _ = make_proxy(hooks)
    assert client.post("/v1/messages", content=b"not json").status_code == 400
    assert client.post("/v1/messages", content=b"[1]").status_code == 400
    assert client.post("/nope", json=BODY).status_code >= 400
    time.sleep(0.2)
    assert hooks.before_calls == [] and hooks.after_calls == []


def test_without_hooks_nothing_changes_for_the_request(tmp_path, upstream):
    server = ProxyServer(port=0, db_path=str(tmp_path / "n.db"))
    port = server.start()
    try:
        r = httpx.post(f"http://127.0.0.1:{port}/v1/messages?key=abc", json=BODY, timeout=15)
        assert r.status_code == 200
        assert upstream.requests[0]["path"] == "/v1/messages?key=abc"
    finally:
        server.stop()
    events = stored(tmp_path / "n.db")
    assert all("identity" not in e["attributes"] for e in events)
    assert all(e["agent"].get("run_id") for e in events)


def test_exchange_type_is_exported():
    assert Exchange.__name__ == "Exchange"


# ---------------------------------------------------------------------------
# What the provider did versus what the client was told
# ---------------------------------------------------------------------------


def test_a_200_that_panoptes_refuses_is_still_a_provider_success(make_proxy, upstream):
    """The provider answered 200 and billed it; the 502 is Panoptes' own."""
    upstream.mode = "dupkey"
    hooks = Recorder()
    _, client, _ = make_proxy(hooks)

    assert client.post("/v1/messages", json=BODY).status_code == 502
    ex = wait_after(hooks)
    assert ex.status == 502 and ex.upstream_status == 200
    assert (ex.provider_error, ex.produced_output) == (False, True)
    assert (ex.request_sent, ex.complete) == (True, False)
    assert ex.usage == {}


def test_upstream_status_is_none_when_no_response_arrived(make_proxy, upstream):
    hooks = Recorder(before=lambda ex: Reject(403, reason="no"))
    _, client, _ = make_proxy(hooks)
    client.post("/v1/messages", json=BODY)
    assert wait_after(hooks).upstream_status is None


def test_a_provider_error_reports_its_own_status(make_proxy, upstream):
    upstream.mode = "error500"
    hooks = Recorder()
    _, client, _ = make_proxy(hooks)
    client.post("/v1/messages", json=BODY)
    ex = wait_after(hooks)
    assert (ex.upstream_status, ex.status, ex.provider_error) == (500, 500, True)


@pytest.mark.parametrize("mode", ["huge", "hugenolen"])
def test_an_oversized_buffered_200_still_counts_as_output(make_proxy, upstream, mode):
    upstream.mode = mode
    hooks = Recorder()
    _, client, _ = make_proxy(hooks, max_buffered_response_bytes=100)

    assert client.post("/v1/messages", json=BODY).status_code == 502
    ex = wait_after(hooks)
    assert ex.outcome == "upstream_error" and ex.upstream_status == 200
    assert (ex.request_sent, ex.produced_output, ex.complete) == (True, True, False)
    assert ex.provider_error is False and ex.usage == {}


def test_usage_is_empty_unless_the_provider_reported_some(make_proxy, upstream):
    """Zeros would read as 'the provider charged nothing'."""
    seen = {}
    cases = [
        ("error500", {}),                # a 5xx with a JSON body
        ("nousage", {}),                 # a 200 without a usage object
        ("json", {"tokens_in": 3, "tokens_out": 1}),
    ]
    for mode, expected in cases:
        upstream.mode = mode
        hooks = Recorder()
        _, client, _ = make_proxy(hooks)
        client.post("/v1/messages", json=BODY)
        seen[mode] = (wait_after(hooks).usage, expected)
    assert all(got == want for got, want in seen.values()), seen


def test_usage_is_empty_when_no_response_arrived(make_proxy, upstream, monkeypatch):
    dead = socket.socket()
    dead.bind(("127.0.0.1", 0))
    port = dead.getsockname()[1]
    dead.close()
    monkeypatch.setenv("PANOPTES_UPSTREAM_ANTHROPIC", f"http://127.0.0.1:{port}")
    hooks = Recorder()
    _, client, _ = make_proxy(hooks)
    client.post("/v1/messages", json=BODY)
    ex = wait_after(hooks)
    assert ex.usage == {} and ex.estimated_usd_micros is None


@pytest.mark.parametrize("option", [
    {"policy_failure_mode": "fail_closed"},
    {"policies_dir": "/nonexistent"},
])
def test_hooks_refuse_every_legacy_gating_option(option):
    with pytest.raises(ValueError, match="hooks cannot be combined"):
        ProxyServer(port=0, hooks=ProxyHooks(), **option)


def test_a_hooked_stream_is_relayed_not_buffered(make_proxy, upstream):
    """The first chunk reaches the client while the upstream is still held."""
    upstream.mode = "gated"
    hooks = Recorder()
    _, client, _ = make_proxy(hooks)
    started = time.monotonic()
    with client.stream("POST", "/v1/messages", json=dict(BODY, stream=True)) as response:
        chunks = response.iter_bytes()
        first = next(chunks)
        elapsed = time.monotonic() - started
        assert first.startswith(b"event: message_start") and elapsed < 3
        upstream.gate.set()
        list(chunks)
    wait_after(hooks)


def test_the_drain_bound_is_a_wall_clock_deadline(make_proxy, upstream):
    """A silent upstream must not hold the slot past disconnect_drain_seconds."""
    upstream.mode = "stalled"
    hooks = Recorder()
    server, client, _ = make_proxy(hooks, disconnect_drain_seconds=0.5)
    body = json.dumps(dict(BODY, stream=True)).encode()
    sock = socket.create_connection(("127.0.0.1", server.port))
    sock.sendall(
        b"POST /v1/messages HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n"
        + f"Content-Length: {len(body)}\r\n\r\n".encode() + body
    )
    assert upstream.head_sent.wait(10)
    sock.recv(4096)
    abort(sock)
    started = time.monotonic()
    upstream.gate.set()                              # two pieces, then silence

    ex = wait_after(hooks, timeout=6)
    assert time.monotonic() - started < 4            # the upstream stays silent for 10 s
    assert ex.request_sent is True and ex.complete is False and ex.usage == {}
    assert ex.produced_output is True


TOOLS_BODY = dict(BODY, system="the real system prompt",
                  tools=[{"name": "read_file", "input_schema": {}}])


@pytest.mark.parametrize("assign_identity", [True, False])
def test_a_hook_cannot_change_what_is_recorded(make_proxy, upstream, assign_identity):
    """The upstream gets the original body, so the record must describe it."""
    def before(ex):
        ex.request_json["tools"] = [{"name": "tampered_tool", "input_schema": {}}]
        ex.request_json["system"] = "a tampered system prompt"
        ex.request_json["messages"].append({"role": "user", "content": "injected"})
        if assign_identity:
            ex.identity = Identity(agent_type="custom_agent", session_id="s-1")

    hooks = Recorder(before=before)
    _, client, db_path = make_proxy(hooks)
    client.post("/v1/messages", json=TOOLS_BODY)
    wait_after(hooks)

    sent = json.loads(upstream.requests[0]["body"])
    assert sent["tools"][0]["name"] == "read_file"
    request = next(e for e in stored(db_path) if e["event_type"] == "model_request")
    assert request["action"]["declared_tools"] == ["read_file"]
    assert request["action"]["messages_count"] == 2          # 1 message + system
    assert "tampered" not in json.dumps(stored(db_path))
    assert "injected" not in request["raw_request"]
    assert json.loads(request["raw_request"])["system"] == "the real system prompt"


@pytest.mark.parametrize("hooked", [True, False])
def test_credentialed_urls_never_reach_the_logs(tmp_path, upstream, caplog, hooked):
    for name in ("httpx", "httpcore"):               # undo any earlier proxy's setting
        logging.getLogger(name).setLevel(logging.NOTSET)
    server = ProxyServer(
        port=0, db_path=str(tmp_path / "log.db"), hooks=Recorder() if hooked else None)
    port = server.start()
    try:
        with caplog.at_level(logging.DEBUG):
            r = httpx.post(
                f"http://127.0.0.1:{port}/v1/messages?key=SEKRETLOG&x=1",
                json=BODY, timeout=15)
        assert r.status_code == 200
    finally:
        server.stop()
    assert "SEKRETLOG" not in caplog.text


def test_a_client_that_left_does_not_turn_an_upstream_error_into_aborted(
    make_proxy, upstream, monkeypatch
):
    from panoptes.proxy import ProxyHandler

    dead = socket.socket()
    dead.bind(("127.0.0.1", 0))
    port = dead.getsockname()[1]
    dead.close()
    monkeypatch.setenv("PANOPTES_UPSTREAM_ANTHROPIC", f"http://127.0.0.1:{port}")

    def gone(self, status, message, extra=None):
        raise BrokenPipeError("client is gone")

    monkeypatch.setattr(ProxyHandler, "_send_json_error", gone)
    hooks = Recorder()
    _, client, _ = make_proxy(hooks)
    try:
        client.post("/v1/messages", json=dict(BODY, stream=True))
    except httpx.HTTPError:
        pass
    ex = wait_after(hooks)
    assert ex.outcome == "upstream_error" and ex.status == 502
    assert ex.request_sent is False


# ---------------------------------------------------------------------------
# Ways an exchange can end badly, and what they report
# ---------------------------------------------------------------------------


def _slow_timeout(monkeypatch, seconds=0.5):
    import panoptes.proxy as proxy_module

    real = proxy_module._upstream_client
    monkeypatch.setattr(proxy_module, "_upstream_client", lambda timeout: real(seconds))


def test_a_truncated_stream_reports_what_was_read(make_proxy, upstream):
    upstream.mode = "truncated"
    hooks = Recorder()
    _, client, db_path = make_proxy(hooks)

    response = client.post("/v1/messages", json=dict(BODY, stream=True))
    assert response.status_code == 200               # the client already had the head
    ex = wait_after(hooks)
    assert ex.outcome == "forwarded" and ex.upstream_status == 200
    assert (ex.request_sent, ex.produced_output) == (True, True)
    assert (ex.complete, ex.usage) == (False, {})
    response_event = next(e for e in stored(db_path) if e["event_type"] == "model_response")
    assert response_event["outcome"]["status"] == "error"


@pytest.mark.parametrize("stream", [False, True])
def test_an_upstream_timeout_reports_a_sent_request_with_no_output(
    make_proxy, upstream, monkeypatch, stream
):
    _slow_timeout(monkeypatch)
    upstream.mode = "hang"
    hooks = Recorder()
    _, client, _ = make_proxy(hooks)

    response = client.post("/v1/messages", json=dict(BODY, stream=stream))
    assert response.status_code == 504
    ex = wait_after(hooks)
    assert (ex.outcome, ex.status, ex.upstream_status) == ("upstream_error", 504, None)
    # The provider may have received it and may bill it.
    assert (ex.request_sent, ex.produced_output, ex.complete) == (True, False, False)
    assert ex.usage == {} and ex.provider_error is False


@pytest.mark.parametrize("stream, outcome", [(False, "upstream_error"), (True, "forwarded")])
def test_a_connection_dropped_in_the_middle_of_the_body(
    make_proxy, upstream, stream, outcome
):
    upstream.mode = "middrop"
    upstream.stream_body = stream
    hooks = Recorder()
    _, client, _ = make_proxy(hooks)

    try:
        client.post("/v1/messages", json=dict(BODY, stream=stream))
    except httpx.HTTPError:
        pass                                         # the client's own view varies
    ex = wait_after(hooks)
    assert ex.outcome == outcome and ex.upstream_status == 200
    assert (ex.request_sent, ex.produced_output, ex.complete) == (True, True, False)
    assert ex.usage == {} and ex.provider_error is False
