"""Rate tables and the cost annotation on proxied responses."""

import http.server
import json
import threading

import httpx
import pytest

from panoptes.pricing import PricingError, PricingTable, usd_to_micros
from panoptes.proxy import ProxyServer

# $1 per input token and $2 per output token makes the fake upstream's 3-in/1-out
# response cost exactly $5.
RATES = {
    "version": "test-rates-1",
    "source": "unit test",
    "currency": "USD",
    "models": {
        "gpt-test": {
            "input_per_million": 1_000_000,
            "cached_input_per_million": 500_000,
            "output_per_million": 2_000_000,
        }
    },
}


def test_cost_is_priced_from_reported_tokens_and_rounded_up():
    table = PricingTable.from_dict(RATES)
    assert table.cost_micros("gpt-test", {"tokens_in": 3, "tokens_out": 1}) == 5_000_000
    assert table.cost_micros(
        "gpt-test", {"tokens_in": 4, "tokens_out": 0, "cached_input_tokens": 2}
    ) == 3_000_000
    tiny = PricingTable.from_dict(
        {**RATES, "models": {"m": {"input_per_million": "0.1", "cached_input_per_million": 0, "output_per_million": 0}}}
    )
    assert tiny.cost_micros("m", {"tokens_in": 1, "tokens_out": 0}) == 1


@pytest.mark.parametrize(
    "model, cost",
    [
        ("other-model", {"tokens_in": 3, "tokens_out": 1}),
        ("gpt-test", {"tokens_in": 3}),
        ("gpt-test", {"tokens_in": 3, "tokens_out": True}),
        ("gpt-test", {"tokens_in": 1, "tokens_out": 1, "cached_input_tokens": 2}),
        (None, {"tokens_in": 3, "tokens_out": 1}),
    ],
)
def test_unpriceable_responses_are_reported_as_unpriced(model, cost):
    assert PricingTable.from_dict(RATES).cost_micros(model, cost) is None


@pytest.mark.parametrize(
    "mutation",
    [
        {"currency": "EUR"},
        {"version": ""},
        {"source": None},
        {"models": {}},
        {"models": {"m": {"input_per_million": -1, "cached_input_per_million": 0, "output_per_million": 0}}},
        {"models": {"m": {"input_per_million": 1}}},
    ],
)
def test_malformed_rate_tables_are_rejected(mutation):
    with pytest.raises(PricingError):
        PricingTable.from_dict({**RATES, **mutation})


@pytest.mark.parametrize("value", [0, -1, "nan", "abc", None])
def test_dollar_amounts_must_be_positive_numbers(value):
    with pytest.raises(PricingError):
        usd_to_micros(value)


OPENAI_BODY = {"model": "gpt-test", "messages": [{"role": "user", "content": "hello"}]}
OPENAI_REPLY = {
    "id": "chatcmpl-1",
    "object": "chat.completion",
    "choices": [{
        "index": 0,
        "message": {"role": "assistant", "content": "hi"},
        "finish_reason": "stop",
    }],
    "usage": {"prompt_tokens": 3, "completion_tokens": 1},
}


@pytest.fixture
def priced_proxy(tmp_path, monkeypatch):
    class _Upstream(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length") or 0))
            payload = json.dumps(OPENAI_REPLY).encode()
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
        "PANOPTES_UPSTREAM_OPENAI", f"http://127.0.0.1:{upstream.server_address[1]}"
    )
    server = ProxyServer(
        port=0,
        db_path=str(tmp_path / "audit.db"),
        pricing=PricingTable.from_dict(RATES),
    )
    port = server.start()
    client = httpx.Client(base_url=f"http://127.0.0.1:{port}", trust_env=False)
    yield server, client
    client.close()
    server.stop()
    upstream.shutdown()
    upstream.server_close()


def test_responses_carry_the_priced_cost(priced_proxy):
    server, client = priced_proxy
    response = client.post("/v1/chat/completions", json=OPENAI_BODY)

    assert response.status_code == 200
    (event,) = [e for e in server.events if e["event_type"] == "model_response"]
    assert event["cost"]["estimated_usd"] == 5.0
    assert event["cost"]["pricing_version"] == "test-rates-1"


def test_an_unlisted_model_is_recorded_unpriced_and_still_forwarded(priced_proxy):
    server, client = priced_proxy
    response = client.post(
        "/v1/chat/completions", json={**OPENAI_BODY, "model": "unlisted-model"}
    )

    assert response.status_code == 200
    (event,) = [e for e in server.events if e["event_type"] == "model_response"]
    assert event["cost"].get("estimated_usd") is None


def test_pricing_file_loads_from_disk(tmp_path):
    path = tmp_path / "rates.json"
    path.write_text(json.dumps(RATES))
    assert PricingTable.load(str(path)).version == "test-rates-1"
    with pytest.raises(PricingError):
        PricingTable.load(str(tmp_path / "missing.json"))
