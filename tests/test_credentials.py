"""Credential injection: provider keys stay in Panoptes, agents hold tokens.

These tests run the real proxy against a local fake upstream, so they check
exactly which credentials reach the provider and what lands in the audit DB.
"""

import http.server
import json
import logging
import os
import sqlite3
import threading

import httpx
import pytest

from panoptes import cli
from panoptes import credentials as credentials_module
from panoptes.credentials import (
    CredentialConfigError,
    SessionTokenStore,
    TokenRejected,
    load_provider_keys,
)
from panoptes.db import AuditDB
from panoptes.proxy import ProxyServer, _strip_query_credentials
from panoptes.schema import ValidationError


# Fake provider keys. They only need the right shape for the injection and redaction
# checks; no real provider accepts them.
FAKE_ANTHROPIC_KEY = "sk-ant-fake-provider-key-0123456789abcdef"
FAKE_OPENAI_KEY = "sk-proj-fake-openai-key-0123456789abcdef"
FAKE_GEMINI_KEY = "AIzaFakeGeminiProviderKey0123456789abcd"

_RESPONSES = {
    "/v1/messages": {
        "id": "msg_1",
        "type": "message",
        "role": "assistant",
        "model": "claude-test",
        "content": [{"type": "text", "text": "hi"}],
        "usage": {"input_tokens": 3, "output_tokens": 1},
    },
    "/v1/chat/completions": {
        "id": "chatcmpl-1",
        "object": "chat.completion",
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": "hi"},
            "finish_reason": "stop",
        }],
        "usage": {"prompt_tokens": 3, "completion_tokens": 1},
    },
    "/v1beta/models/gemini-test:generateContent": {
        "candidates": [{"content": {"role": "model", "parts": [{"text": "hi"}]}}],
        "usageMetadata": {"promptTokenCount": 3, "candidatesTokenCount": 1},
    },
}

ANTHROPIC_BODY = {
    "model": "claude-test",
    "max_tokens": 8,
    "messages": [{"role": "user", "content": "hello"}],
}
OPENAI_BODY = {"model": "gpt-test", "messages": [{"role": "user", "content": "hello"}]}
GEMINI_BODY = {"contents": [{"role": "user", "parts": [{"text": "hello"}]}]}


@pytest.fixture
def upstream(monkeypatch):
    """A local stand-in for all three providers that records what it receives."""
    received: list[dict] = []

    class _Upstream(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            length = int(self.headers.get("Content-Length") or 0)
            received.append({
                "path": self.path,
                "headers": {k.lower(): v for k, v in self.headers.items()},
                "body": self.rfile.read(length),
            })
            payload = json.dumps(_RESPONSES[self.path.split("?")[0]]).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Upstream)
    thread = threading.Thread(
        target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True
    )
    thread.start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    for provider in ("ANTHROPIC", "OPENAI", "GEMINI"):
        monkeypatch.setenv(f"PANOPTES_UPSTREAM_{provider}", base)
    yield received
    server.shutdown()
    server.server_close()


def _start(tmp_path, provider_keys):
    server = ProxyServer(
        port=0, db_path=str(tmp_path / "audit.db"), provider_keys=provider_keys
    )
    port = server.start()
    return server, httpx.Client(base_url=f"http://127.0.0.1:{port}", trust_env=False)


@pytest.fixture
def injecting_proxy(tmp_path, upstream):
    server, client = _start(
        tmp_path,
        {"anthropic": FAKE_ANTHROPIC_KEY, "openai": FAKE_OPENAI_KEY, "gemini": FAKE_GEMINI_KEY},
    )
    yield server, client
    client.close()
    server.stop()


def _stored_bytes(tmp_path) -> bytes:
    data = b""
    for suffix in ("", "-wal"):
        path = tmp_path / f"audit.db{suffix}"
        if path.exists():
            data += path.read_bytes()
    return data


def test_valid_token_is_swapped_for_the_provider_key(injecting_proxy, upstream):
    server, client = injecting_proxy
    token, record = server.token_store.issue("claude_code", "sess-42")

    response = client.post(
        "/v1/messages",
        json=ANTHROPIC_BODY,
        headers={
            "x-api-key": token,
            # Asserted identity headers lose to the token's identity.
            "X-Panoptes-Agent": "codex",
            "X-Panoptes-Session": "someone-elses-session",
        },
    )

    assert response.status_code == 200
    assert len(upstream) == 1
    sent = upstream[0]
    assert sent["headers"]["x-api-key"] == FAKE_ANTHROPIC_KEY
    assert "authorization" not in sent["headers"]
    assert token not in json.dumps(sent["headers"]) + sent["path"]
    assert token.encode() not in sent["body"]

    events = server.events
    assert {e["event_type"] for e in events} == {"model_request", "model_response"}
    for event in events:
        assert event["agent"]["type"] == "claude_code"
        assert event["agent"]["session_id"] == "sess-42"
        capture = event["context"]["capture"]
        assert capture["identity_assurance"] == "panoptes_session_token"
        assert capture["identity_source"] == "panoptes_token"


def test_openai_bearer_token_is_swapped(injecting_proxy, upstream):
    server, client = injecting_proxy
    token, _ = server.token_store.issue("codex", "sess-oa")

    response = client.post(
        "/v1/chat/completions",
        json=OPENAI_BODY,
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    assert upstream[0]["headers"]["authorization"] == f"Bearer {FAKE_OPENAI_KEY}"
    assert token not in json.dumps(upstream[0]["headers"])
    assert server.events[0]["agent"]["session_id"] == "sess-oa"


def test_gemini_query_key_token_never_reaches_upstream_or_audit(
    injecting_proxy, upstream, tmp_path
):
    server, client = injecting_proxy
    token, _ = server.token_store.issue("gemini_cli", "sess-gm")

    response = client.post(
        f"/v1beta/models/gemini-test:generateContent?alt=json&key={token}",
        json=GEMINI_BODY,
    )

    assert response.status_code == 200
    sent = upstream[0]
    assert sent["path"] == "/v1beta/models/gemini-test:generateContent?alt=json"
    assert sent["headers"]["x-goog-api-key"] == FAKE_GEMINI_KEY
    request_event = next(
        e for e in server.events if e["event_type"] == "model_request"
    )
    assert request_event["action"]["path"] == sent["path"]
    assert request_event["agent"]["type"] == "gemini_cli"
    server.stop()
    assert token.encode() not in _stored_bytes(tmp_path)


def test_streaming_requests_also_get_the_provider_key(injecting_proxy, upstream):
    server, client = injecting_proxy
    token, _ = server.token_store.issue("claude_code", "sess-stream")

    response = client.post(
        "/v1/messages",
        json={**ANTHROPIC_BODY, "stream": True},
        headers={"x-api-key": token},
    )

    assert response.status_code == 200
    assert upstream[0]["headers"]["x-api-key"] == FAKE_ANTHROPIC_KEY
    assert token not in json.dumps(upstream[0]["headers"])


def test_injected_key_survives_connection_header_nomination(injecting_proxy, upstream):
    server, client = injecting_proxy
    token, _ = server.token_store.issue("claude_code", "sess-conn")

    response = client.post(
        "/v1/messages",
        json=ANTHROPIC_BODY,
        headers={"x-api-key": token, "Connection": "keep-alive, x-api-key"},
    )

    assert response.status_code == 200
    assert upstream[0]["headers"]["x-api-key"] == FAKE_ANTHROPIC_KEY


def _issue_rejected(server, case, monkeypatch):
    """Return request headers for one rejection case."""
    store = server.token_store
    if case == "missing":
        return {}
    if case == "wrong":
        return {"x-api-key": "pnpt_not-a-token-panoptes-issued"}
    if case == "provider_key":
        # A provider key is not a Panoptes token either.
        return {"x-api-key": FAKE_ANTHROPIC_KEY}
    token, record = store.issue("claude_code", "sess-victim", ttl_seconds=60)
    if case == "expired":
        real_time = credentials_module.time.time
        monkeypatch.setattr(
            credentials_module.time, "time", lambda: real_time() + 3600
        )
    elif case == "revoked":
        assert store.revoke(record["token_id"])
    elif case == "ambiguous":
        other, _ = store.issue("claude_code", "sess-other")
        return {"x-api-key": token, "Authorization": f"Bearer {other}"}
    return {"x-api-key": token}


@pytest.mark.parametrize(
    "case, reason",
    [
        ("missing", "missing"),
        ("wrong", "unknown"),
        ("provider_key", "unknown"),
        ("expired", "expired"),
        ("revoked", "revoked"),
        ("ambiguous", "ambiguous"),
    ],
)
def test_invalid_tokens_get_401_and_a_blocked_event(
    injecting_proxy, upstream, monkeypatch, case, reason
):
    server, client = injecting_proxy
    headers = _issue_rejected(server, case, monkeypatch)
    headers["X-Panoptes-Session"] = "sess-victim"

    response = client.post("/v1/messages", json=ANTHROPIC_BODY, headers=headers)

    assert response.status_code == 401
    body = response.json()
    assert body["reason"] == reason
    assert body["audit_persisted"] is True
    assert upstream == []

    events = server.events
    assert len(events) == 1
    event = events[0]
    assert event["event_type"] == "model_request"
    assert event["outcome"]["status"] == "blocked"
    capture = event["context"]["capture"]
    assert capture["identity_check"] == reason
    assert capture["upstream_forwarded"] is False
    assert capture["identity_assurance"] == "client_asserted"
    # An unauthenticated caller cannot write into another session's timeline.
    assert event["agent"]["session_id"] != "sess-victim"


def test_valid_token_without_a_configured_provider_key_is_denied(tmp_path, upstream):
    server, client = _start(tmp_path, {"anthropic": FAKE_ANTHROPIC_KEY})
    try:
        token, _ = server.token_store.issue("codex", "sess-nokey")
        response = client.post(
            "/v1/chat/completions",
            json=OPENAI_BODY,
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 503
        assert response.json()["reason"] == "no_provider_key"
        assert upstream == []
        event = server.events[0]
        assert event["outcome"]["status"] == "blocked"
        assert event["agent"]["session_id"] == "sess-nokey"
    finally:
        client.close()
        server.stop()


def test_neither_token_nor_key_is_stored_logged_or_returned(
    injecting_proxy, upstream, tmp_path, caplog
):
    caplog.set_level(logging.DEBUG)
    server, client = injecting_proxy
    token, _ = server.token_store.issue("claude_code", "sess-leak")
    revoked, record = server.token_store.issue("claude_code", "sess-leak")
    server.token_store.revoke(record["token_id"])

    responses = [
        client.post("/v1/messages", json=ANTHROPIC_BODY, headers={"x-api-key": token}),
        client.post("/v1/messages", json=ANTHROPIC_BODY, headers={"x-api-key": revoked}),
        client.post(
            f"/v1beta/models/gemini-test:generateContent?key={revoked}",
            json=GEMINI_BODY,
        ),
        client.post(
            "/v1/chat/completions",
            json=OPENAI_BODY,
            headers={"Authorization": f"Bearer {token}"},
        ),
    ]
    assert [r.status_code for r in responses] == [200, 401, 401, 200]
    server.stop()
    panoptes_logs = "\n".join(
        record.getMessage()
        for record in caplog.records
        if record.name.startswith("panoptes")
    )
    assert panoptes_logs

    stored = _stored_bytes(tmp_path)
    returned = b"".join(r.content for r in responses) + json.dumps(
        [dict(r.headers) for r in responses]
    ).encode()
    for secret in (token, revoked, FAKE_ANTHROPIC_KEY, FAKE_OPENAI_KEY, FAKE_GEMINI_KEY):
        assert secret.encode() not in stored
        assert secret.encode() not in returned
        assert secret not in panoptes_logs


def test_without_injection_client_credentials_and_headers_pass_through(
    tmp_path, upstream
):
    server, client = _start(tmp_path, None)
    try:
        assert server.token_store is None
        response = client.post(
            "/v1/messages",
            json=ANTHROPIC_BODY,
            headers={
                "x-api-key": "client-own-key",
                "X-Panoptes-Agent": "codex",
                "X-Panoptes-Session": "sess-header",
            },
        )
        assert response.status_code == 200
        assert upstream[0]["headers"]["x-api-key"] == "client-own-key"
        event = server.events[0]
        assert event["agent"]["type"] == "codex"
        assert event["agent"]["session_id"] == "sess-header"
        capture = event["context"]["capture"]
        assert capture["identity_assurance"] == "client_asserted"
        assert "identity_source" not in capture
    finally:
        client.close()
        server.stop()

    # The token table only exists once credential mode or the CLI creates it.
    with sqlite3.connect(tmp_path / "audit.db") as conn:
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master")}
    assert "session_tokens" not in tables


def test_strip_query_credentials_keeps_other_parameters():
    assert _strip_query_credentials("/m:generateContent?alt=sse&key=abc&x=%20") == (
        "/m:generateContent?alt=sse&x=%20",
        ["abc"],
    )
    assert _strip_query_credentials("/m?key=a&key=b") == ("/m", ["a", "b"])
    assert _strip_query_credentials("/v1/messages") == ("/v1/messages", [])


# ---------------------------------------------------------------------------
# Token store and provider key loading
# ---------------------------------------------------------------------------


def test_token_store_keeps_only_a_hash(tmp_path):
    db = AuditDB(str(tmp_path / "audit.db"))
    store = SessionTokenStore(db)
    token, record = store.issue("hermes", "sess-1", ttl_seconds=60)
    assert token.startswith("pnpt_")
    assert store.resolve(token).session_id == "sess-1"
    db.close()
    assert token.encode() not in _stored_bytes(tmp_path)

    with pytest.raises(TokenRejected) as rejected:
        store.resolve(token, now=record["expires_at"])
    assert rejected.value.reason == "expired"


@pytest.mark.parametrize(
    "agent, session, ttl",
    [
        ("unknown", "s", 60),
        ("not-an-agent", "s", 60),
        ("codex", "", 60),
        ("codex", "s", 0),
        ("codex", "s", 10**9),
    ],
)
def test_token_issue_validates_inputs(tmp_path, agent, session, ttl):
    store = SessionTokenStore(AuditDB(str(tmp_path / "audit.db")))
    with pytest.raises(ValidationError):
        store.issue(agent, session, ttl)


def test_provider_keys_load_from_environment():
    keys = load_provider_keys(environ={
        "PANOPTES_ANTHROPIC_API_KEY": FAKE_ANTHROPIC_KEY,
        "PANOPTES_GEMINI_API_KEY": "",
        "ANTHROPIC_API_KEY": "ignored",
    })
    assert keys == {"anthropic": FAKE_ANTHROPIC_KEY}
    with pytest.raises(CredentialConfigError):
        load_provider_keys(environ={})


def test_credentials_file_must_be_owner_only(tmp_path):
    path = tmp_path / "keys.yaml"
    path.write_text(f"anthropic: {FAKE_ANTHROPIC_KEY}\nopenai: {FAKE_OPENAI_KEY}\n")
    os.chmod(path, 0o644)
    with pytest.raises(CredentialConfigError, match="chmod 600") as exc:
        load_provider_keys(str(path))
    assert FAKE_ANTHROPIC_KEY not in str(exc.value)

    os.chmod(path, 0o600)
    assert load_provider_keys(str(path)) == {
        "anthropic": FAKE_ANTHROPIC_KEY,
        "openai": FAKE_OPENAI_KEY,
    }

    path.write_text("mistral: abc\n")
    with pytest.raises(CredentialConfigError, match="unknown providers"):
        load_provider_keys(str(path))


def test_token_cli_issue_list_and_revoke(tmp_path, capsys):
    db_path = str(tmp_path / "audit.db")
    cli.main([
        "token", "issue", "--agent", "claude_code", "--session", "sess-cli",
        "--ttl", "600", "--db-path", db_path,
    ])
    out, err = capsys.readouterr()
    token = out.strip()
    assert token.startswith("pnpt_") and "\n" not in token
    token_id = err.split()[2]
    assert "sess-cli" in err and token not in err

    cli.main(["token", "list", "--db-path", db_path])
    listed = capsys.readouterr().out
    assert token_id in listed and "live" in listed and token not in listed

    cli.main(["token", "revoke", token_id, "--db-path", db_path])
    assert f"Revoked token {token_id}" in capsys.readouterr().out
    with pytest.raises(SystemExit):
        cli.main(["token", "revoke", token_id, "--db-path", db_path])

    store = SessionTokenStore(AuditDB(db_path))
    with pytest.raises(TokenRejected):
        store.resolve(token)


def test_proxy_cli_requires_flag_for_credentials_file(tmp_path):
    with pytest.raises(SystemExit):
        cli.main(["proxy", "--credentials-file", str(tmp_path / "keys.yaml")])


@pytest.mark.parametrize(
    "method, path",
    [
        ("POST", "/v1/messages/batches"),
        ("GET", "/v1/messages/batches/msgbatch_1/results"),
        ("GET", "/v1/files?x=/models"),
        ("POST", "/v1/fine_tuning/jobs?route=/chat/completions"),
        ("POST", "/v1beta/openai/chat/completions"),
        ("GET", "/v1beta/cachedContents"),
    ],
)
def test_only_inspectable_model_routes_receive_an_injected_key(
    injecting_proxy, upstream, method, path
):
    """Routes are matched exactly on the path, never by substring or query.

    Other provider endpoints would get the real key and return responses
    the parsers cannot inspect, which then read as "no tool calls".
    """
    server, client = injecting_proxy
    token, _ = server.token_store.issue("claude_code", "sess-route")
    response = client.request(
        method, path, headers={"x-api-key": token, "Authorization": f"Bearer {token}"},
        json={} if method == "POST" else None,
    )
    assert response.status_code == 502
    assert "No supported provider route" in response.json()["error"]
    assert upstream == []


def test_unauthenticated_denial_records_no_client_identity_or_content(
    injecting_proxy, upstream
):
    server, client = injecting_proxy
    response = client.post(
        "/v1/messages",
        json={**ANTHROPIC_BODY, "messages": [{"role": "user", "content": "attacker text"}]},
        headers={"x-api-key": "pnpt_not-a-token-panoptes-issued", "User-Agent": "claude-code/2.0"},
    )
    assert response.status_code == 401
    [event] = server.events
    assert event["agent"]["type"] == "unknown"
    assert "attacker text" not in json.dumps(event)


def test_credentials_file_that_is_a_fifo_fails_fast(tmp_path):
    path = tmp_path / "keys.yaml"
    os.mkfifo(path)
    with pytest.raises(CredentialConfigError, match="regular file"):
        load_provider_keys(str(path))


def test_bare_session_tokens_are_redacted(injecting_proxy):
    from panoptes.schema import redact_secrets

    server, _ = injecting_proxy
    token, _ = server.token_store.issue("claude_code", "sess-redact")
    assert token not in redact_secrets(f"echo {token}")
