"""Every proxied exchange has a correlation id and a unique exchange id."""

import http.server
import json
import threading

import httpx
import pytest

from panoptes.db import AuditDB
from panoptes.proxy import ProxyServer

BODY = {"model": "claude-test", "max_tokens": 8,
        "messages": [{"role": "user", "content": "hello"}]}
RESPONSE = {
    "id": "msg_1", "type": "message", "role": "assistant", "model": "claude-test",
    "content": [{"type": "text", "text": "hi"}],
    "usage": {"input_tokens": 3, "output_tokens": 1},
}


@pytest.fixture
def proxy(tmp_path, monkeypatch):
    class _Upstream(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length") or 0))
            payload = json.dumps(RESPONSE).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    upstream = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Upstream)
    threading.Thread(
        target=upstream.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True
    ).start()
    monkeypatch.setenv(
        "PANOPTES_UPSTREAM_ANTHROPIC", f"http://127.0.0.1:{upstream.server_address[1]}"
    )
    db_path = tmp_path / "audit.db"
    server = ProxyServer(port=0, db_path=str(db_path))
    port = server.start()
    client = httpx.Client(base_url=f"http://127.0.0.1:{port}", trust_env=False)
    yield client, db_path
    client.close()
    server.stop()
    upstream.shutdown()
    upstream.server_close()


def stored(db_path):
    db = AuditDB.open_readonly(str(db_path))
    try:
        return list(db.iter_events())
    finally:
        db.close()


def test_a_request_without_the_header_still_gets_a_correlation_id(proxy):
    client, db_path = proxy
    assert client.post("/v1/messages", json=BODY).status_code == 200

    events = stored(db_path)
    assert {e["event_type"] for e in events} >= {"model_request", "model_response"}
    ids = {e["correlation_id"] for e in events}
    exchange_ids = {e["attributes"]["exchange_id"] for e in events}
    assert len(ids) == 1 and None not in ids
    assert ids == exchange_ids          # no client value: the exchange id is the key
    assert {e["attributes"]["correlation_source"] for e in events} == {"proxy"}
    assert all("client_correlation_id" not in e["context"]["capture"] for e in events)
    assert len(next(iter(ids))) == 32


def test_each_request_gets_its_own_exchange_id(proxy):
    client, db_path = proxy
    for _ in range(3):
        assert client.post("/v1/messages", json=BODY).status_code == 200
    events = stored(db_path)
    per_exchange = {}
    for e in events:
        per_exchange.setdefault(e["attributes"]["exchange_id"], set()).add(e["correlation_id"])
    assert len(per_exchange) == 3
    assert all(len(ids) == 1 for ids in per_exchange.values())


def test_a_client_value_is_kept_as_asserted_and_the_exchange_id_still_differs(proxy):
    client, db_path = proxy
    for _ in range(2):  # the same client id, reused
        assert client.post(
            "/v1/messages", json=BODY,
            headers={"X-Panoptes-Correlation-Id": "attempt-7"},
        ).status_code == 200

    events = stored(db_path)
    assert {e["correlation_id"] for e in events} == {"attempt-7"}
    assert {e["attributes"]["correlation_source"] for e in events} == {"client"}
    assert {e["context"]["capture"]["client_correlation_id"] for e in events} == {"attempt-7"}
    exchange_ids = {e["attributes"]["exchange_id"] for e in events}
    assert len(exchange_ids) == 2 and "attempt-7" not in exchange_ids


def test_an_invalid_client_value_is_refused_not_replaced(proxy):
    client, db_path = proxy
    response = client.post(
        "/v1/messages", json=BODY,
        headers={"X-Panoptes-Correlation-Id": "x" * 300},
    )
    assert response.status_code == 400
    assert stored(db_path) == []
