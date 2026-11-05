"""Rate tables and the cost annotation on proxied responses."""

import http.server
import json
import threading
import time

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


# --- Prompt-cache writes -----------------------------------------------------

# $1 per uncached input token, $0.10 per cache read, $1.25 per 5-minute cache
# write, $2 per 1-hour cache write, $5 per output token.
CACHE_RATES = {
    "version": "cache-rates-1",
    "source": "unit test",
    "currency": "USD",
    "models": {
        "claude-test": {
            "input_per_million": 1_000_000,
            "cached_input_per_million": 100_000,
            "cache_write_per_million": 1_250_000,
            "cache_write_1h_per_million": 2_000_000,
            "output_per_million": 5_000_000,
        },
        "claude-5m-only": {
            "input_per_million": 1_000_000,
            "cached_input_per_million": 100_000,
            "cache_write_per_million": 1_250_000,
            "output_per_million": 5_000_000,
        },
        "claude-no-write-rate": {
            "input_per_million": 1_000_000,
            "cached_input_per_million": 100_000,
            "output_per_million": 5_000_000,
        },
    },
}


@pytest.mark.parametrize(
    "split",
    [
        {"ephemeral_5m_input_tokens": "bad", "ephemeral_1h_input_tokens": None},
        {"ephemeral_5m_input_tokens": "4", "ephemeral_1h_input_tokens": "0"},
        {"ephemeral_5m_input_tokens": 4, "ephemeral_1h_input_tokens": -1},
        {"ephemeral_5m_input_tokens": True, "ephemeral_1h_input_tokens": 0},
        "4/0",
    ],
)
def test_an_unreadable_reply_split_leaves_the_response_unpriced(split):
    """Extraction drops unreadable counts; the writes must not then look unsplit and be
    priced at the 5-minute rate."""
    from panoptes.providers.anthropic import AnthropicProvider

    usage = AnthropicProvider().extract_usage({"usage": {
        "input_tokens": 1, "output_tokens": 1, "cache_creation_input_tokens": 4,
        "cache_creation": split,
    }})
    assert usage.get("cache_creation_split_invalid") is True
    assert PricingTable.from_dict(CACHE_RATES).cost_micros("claude-5m-only", usage) is None


def test_a_readable_reply_split_is_priced():
    from panoptes.providers.anthropic import AnthropicProvider

    usage = AnthropicProvider().extract_usage({"usage": {
        "input_tokens": 1, "output_tokens": 1, "cache_creation_input_tokens": 4,
        "cache_creation": {"ephemeral_5m_input_tokens": 4, "ephemeral_1h_input_tokens": 0},
    }})
    assert "cache_creation_split_invalid" not in usage
    # 1 uncached input + 4 five-minute writes at 1.25 + 1 output at 5.
    assert PricingTable.from_dict(CACHE_RATES).cost_micros("claude-5m-only", usage) == 11_000_000


def test_cache_writes_are_priced_at_their_own_rates():
    table = PricingTable.from_dict(CACHE_RATES)
    # 3 uncached + 10 read + 4 written (1 of them 1-hour) = 17 prompt tokens.
    cost = {"tokens_in": 17, "tokens_out": 2, "cached_input_tokens": 10,
            "cache_creation_input_tokens": 4, "cache_creation_5m_input_tokens": 3,
            "cache_creation_1h_input_tokens": 1}
    # 3*1 + 10*0.1 + 3*1.25 + 1*2 + 2*5 = 19.75
    assert table.cost_micros("claude-test", cost) == 19_750_000
    # All writes 5-minute, reported with a zero 1-hour share.
    assert table.cost_micros(
        "claude-5m-only", {**cost, "cache_creation_5m_input_tokens": 4, "cache_creation_1h_input_tokens": 0}
    ) == 3_000_000 + 1_000_000 + 5_000_000 + 10_000_000
    # A provider without a TTL breakdown (OpenAI-style cache_write_tokens).
    no_split = {k: v for k, v in cost.items() if not k.startswith(("cache_creation_5m", "cache_creation_1h"))}
    assert table.cost_micros("claude-5m-only", no_split) == 3_000_000 + 1_000_000 + 5_000_000 + 10_000_000


@pytest.mark.parametrize(
    "model, cost",
    [
        # Cache writes and no write rate: never priced at the input rate.
        ("claude-no-write-rate", {"tokens_in": 5, "tokens_out": 1, "cache_creation_input_tokens": 4}),
        ("claude-no-write-rate", {"tokens_in": 5, "tokens_out": 1, "cache_creation_input_tokens": 4,
                                  "cache_creation_5m_input_tokens": 4, "cache_creation_1h_input_tokens": 0}),
        ("gpt-test", {"tokens_in": 5, "tokens_out": 1, "cache_creation_input_tokens": 4}),
        # 1-hour writes and no 1-hour rate.
        ("claude-5m-only", {"tokens_in": 5, "tokens_out": 1, "cache_creation_input_tokens": 4,
                            "cache_creation_5m_input_tokens": 3, "cache_creation_1h_input_tokens": 1}),
        # A 1-hour rate exists but the response does not say which writes were 1-hour.
        ("claude-test", {"tokens_in": 5, "tokens_out": 1, "cache_creation_input_tokens": 4}),
        # Inconsistent counts.
        ("claude-test", {"tokens_in": 5, "tokens_out": 1, "cached_input_tokens": 3,
                         "cache_creation_input_tokens": 3, "cache_creation_5m_input_tokens": 3,
                         "cache_creation_1h_input_tokens": 0}),
        ("claude-test", {"tokens_in": 5, "tokens_out": 1, "cache_creation_input_tokens": 2,
                         "cache_creation_1h_input_tokens": 3}),
        ("claude-test", {"tokens_in": 5, "tokens_out": 1, "cache_creation_input_tokens": -1}),
        ("claude-test", {"tokens_in": 5, "tokens_out": 1, "cache_creation_input_tokens": 2,
                         "cache_creation_5m_input_tokens": 2, "cache_creation_1h_input_tokens": True}),
        # A TTL split that does not sum to the total writes.
        ("claude-test", {"tokens_in": 10, "tokens_out": 1, "cache_creation_input_tokens": 10,
                         "cache_creation_5m_input_tokens": 9, "cache_creation_1h_input_tokens": 0}),
        # A nonzero split with zero or absent total writes.
        ("claude-test", {"tokens_in": 5, "tokens_out": 1, "cache_creation_input_tokens": 0,
                         "cache_creation_5m_input_tokens": 0, "cache_creation_1h_input_tokens": 1}),
        ("claude-test", {"tokens_in": 5, "tokens_out": 1,
                         "cache_creation_5m_input_tokens": 0, "cache_creation_1h_input_tokens": 1}),
        # A partial split (one half missing).
        ("claude-test", {"tokens_in": 5, "tokens_out": 1, "cache_creation_input_tokens": 4,
                         "cache_creation_1h_input_tokens": 1}),
        ("claude-5m-only", {"tokens_in": 5, "tokens_out": 1, "cache_creation_input_tokens": 4,
                            "cache_creation_5m_input_tokens": 4}),
    ],
)
def test_cache_writes_without_a_matching_rate_are_unpriced(model, cost):
    table = PricingTable.from_dict({**CACHE_RATES, "models": {**CACHE_RATES["models"], **RATES["models"]}})
    assert table.cost_micros(model, cost) is None


def test_responses_without_cache_writes_price_as_before():
    # An old table (no optional rates) still loads and prices reads and output.
    table = PricingTable.from_dict(RATES)
    assert "cache_write_per_million" not in table.models["gpt-test"]
    assert table.cost_micros(
        "gpt-test", {"tokens_in": 4, "tokens_out": 1, "cached_input_tokens": 2}
    ) == 5_000_000
    assert table.cost_micros(
        "gpt-test", {"tokens_in": 4, "tokens_out": 1, "cache_creation_input_tokens": 0}
    ) == 6_000_000
    # A write rate on the table changes nothing for a response without writes.
    cache_table = PricingTable.from_dict(CACHE_RATES)
    assert cache_table.cost_micros(
        "claude-test", {"tokens_in": 4, "tokens_out": 1, "cached_input_tokens": 2}
    ) == 2_000_000 + 200_000 + 5_000_000


@pytest.mark.parametrize("field", ["cache_write_per_million", "cache_write_1h_per_million"])
@pytest.mark.parametrize("value", [-1, "nan", "abc", None])
def test_malformed_optional_rates_are_rejected(field, value):
    rate = {**RATES["models"]["gpt-test"], field: value}
    with pytest.raises(PricingError):
        PricingTable.from_dict({**RATES, "models": {"m": rate}})


ANTHROPIC_BODY = {
    "model": "claude-test",
    "max_tokens": 16,
    "messages": [{"role": "user", "content": "hello"}],
}
ANTHROPIC_USAGE = {
    "input_tokens": 3,
    "cache_read_input_tokens": 10,
    "cache_creation_input_tokens": 4,
    "cache_creation": {"ephemeral_5m_input_tokens": 3, "ephemeral_1h_input_tokens": 1},
    "output_tokens": 2,
}
ANTHROPIC_REPLY = {
    "id": "msg_1",
    "type": "message",
    "role": "assistant",
    "model": "claude-test",
    "content": [{"type": "text", "text": "hi"}],
    "stop_reason": "end_turn",
    "stop_sequence": None,
    "usage": ANTHROPIC_USAGE,
}


def _sse(*events):
    return b"".join(
        f"event: {e['type']}\ndata: {json.dumps(e)}\n\n".encode() for e in events
    )


# Anthropic streams report the prompt counts on message_start; message_delta
# carries the final (cumulative) output count.
ANTHROPIC_STREAM = _sse(
    {"type": "message_start", "message": {
        "id": "msg_1", "type": "message", "role": "assistant", "model": "claude-test",
        "content": [], "stop_reason": None,
        "usage": {**ANTHROPIC_USAGE, "output_tokens": 1}}},
    {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}},
    {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "hi"}},
    {"type": "content_block_stop", "index": 0},
    {"type": "message_delta", "delta": {"stop_reason": "end_turn", "stop_sequence": None},
     "usage": {"output_tokens": 2}},
    {"type": "message_stop"},
)


@pytest.fixture
def anthropic_proxy(tmp_path, monkeypatch):
    replies = {}

    class _Upstream(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)))
            content_type, payload = replies["stream" if body.get("stream") else "json"]
            self.send_response(200)
            self.send_header("Content-Type", content_type)
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
    server = ProxyServer(
        port=0,
        db_path=str(tmp_path / "audit.db"),
        pricing=PricingTable.from_dict(CACHE_RATES),
    )
    port = server.start()
    client = httpx.Client(base_url=f"http://127.0.0.1:{port}", trust_env=False, timeout=15)
    yield server, client, replies
    client.close()
    server.stop()
    upstream.shutdown()
    upstream.server_close()


def _model_response(server):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        found = [e for e in server.events if e["event_type"] == "model_response"]
        if found:
            return found[0]
        time.sleep(0.02)
    raise AssertionError("no model_response event was recorded")


@pytest.mark.parametrize("stream", [False, True])
def test_anthropic_cache_reads_and_writes_are_priced(anthropic_proxy, stream):
    server, client, replies = anthropic_proxy
    replies["json"] = ("application/json", json.dumps(ANTHROPIC_REPLY).encode())
    replies["stream"] = ("text/event-stream", ANTHROPIC_STREAM)

    response = client.post("/v1/messages", json={**ANTHROPIC_BODY, "stream": stream})
    assert response.status_code == 200

    cost = _model_response(server)["cost"]
    # tokens_in is the whole prompt: uncached + reads + writes, each counted once.
    assert cost["tokens_in"] == 17
    assert cost["cached_input_tokens"] == 10
    assert cost["cache_creation_input_tokens"] == 4
    assert cost["cache_creation_5m_input_tokens"] == 3
    assert cost["cache_creation_1h_input_tokens"] == 1
    assert cost["tokens_out"] == 2
    # 3*1 + 10*0.1 + 3*1.25 + 1*2 + 2*5 = 19.75; at the input rate it was 18.0.
    assert cost["estimated_usd"] == 19.75
    assert cost["pricing_version"] == "cache-rates-1"


@pytest.mark.parametrize("stream", [False, True])
def test_anthropic_cache_writes_without_a_rate_are_unpriced(anthropic_proxy, stream):
    server, client, replies = anthropic_proxy
    replies["json"] = ("application/json", json.dumps(ANTHROPIC_REPLY).encode())
    replies["stream"] = ("text/event-stream", ANTHROPIC_STREAM)

    response = client.post(
        "/v1/messages",
        json={**ANTHROPIC_BODY, "model": "claude-no-write-rate", "stream": stream},
    )
    assert response.status_code == 200
    cost = _model_response(server)["cost"]
    assert cost["cache_creation_input_tokens"] == 4
    assert cost.get("estimated_usd") is None
    assert "pricing_version" not in cost


def test_openai_cached_tokens_price_unchanged(priced_proxy):
    server, client = priced_proxy
    from panoptes.providers.openai import OpenAIProvider

    usage = OpenAIProvider().extract_usage({"usage": {
        "prompt_tokens": 4, "completion_tokens": 1,
        "prompt_tokens_details": {"cached_tokens": 2},
    }})
    assert usage == {"tokens_in": 4, "tokens_out": 1, "cached_input_tokens": 2}
    # 2 uncached * $1 + 2 cached * $0.5 + 1 output * $2, as before this change.
    assert PricingTable.from_dict(RATES).cost_micros("gpt-test", usage) == 5_000_000


def test_pricing_is_exact_and_never_rounds_down_before_the_ceiling():
    # 1 token at just over $1 per million is just over 1 micro-dollar: it must bill 2, not 1.
    rate = "1.0000000000000000000000000001"
    table = PricingTable.from_dict({"version": "exact-1", "source": "unit test", "currency": "USD", "models": {
        "m": {"input_per_million": rate, "cached_input_per_million": rate, "output_per_million": rate,
              "cache_write_per_million": rate, "cache_write_1h_per_million": rate}}})
    assert table.cost_micros("m", {"tokens_in": 1, "tokens_out": 0}) == 2
    assert table.cost_micros("m", {"tokens_in": 1, "tokens_out": 0, "cache_creation_input_tokens": 1,
                                   "cache_creation_5m_input_tokens": 1, "cache_creation_1h_input_tokens": 0}) == 2
    # Exact whole micro-dollars stay exact.
    whole = PricingTable.from_dict({"version": "exact-2", "source": "unit test", "currency": "USD", "models": {
        "m": {"input_per_million": "3", "cached_input_per_million": "0.3", "output_per_million": "15"}}})
    assert whole.cost_micros("m", {"tokens_in": 10, "tokens_out": 2, "cached_input_tokens": 10}) == 3 + 30
