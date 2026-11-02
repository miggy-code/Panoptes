"""Rate tables and per-token dollar caps."""

import json

import httpx
import pytest

from panoptes import cli
from panoptes.credentials import SessionTokenStore, TokenRejected
from panoptes.db import AuditDB
from panoptes.pricing import PricingError, PricingTable, usd_to_micros
from panoptes.proxy import ProxyServer
from panoptes.schema import ValidationError

from tests.test_credentials import (  # noqa: F401  (fixture re-export)
    FAKE_OPENAI_KEY,
    OPENAI_BODY,
    upstream,
)

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


def _post(client, token, model="gpt-test"):
    return client.post(
        "/v1/chat/completions",
        json={**OPENAI_BODY, "model": model},
        headers={"authorization": f"Bearer {token}"},
    )


@pytest.fixture
def priced_proxy(tmp_path, upstream):
    server = ProxyServer(
        port=0,
        db_path=str(tmp_path / "audit.db"),
        provider_keys={"openai": FAKE_OPENAI_KEY},
        pricing=PricingTable.from_dict(RATES),
    )
    port = server.start()
    client = httpx.Client(base_url=f"http://127.0.0.1:{port}", trust_env=False)
    yield server, client
    client.close()
    server.stop()


def _row(server, record):
    (row,) = [t for t in server.token_store.list_tokens() if t["token_id"] == record["token_id"]]
    return row


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


def test_dollar_cap_is_enforced_from_priced_responses(priced_proxy, upstream):
    server, client = priced_proxy
    token, record = server.token_store.issue(
        "antigravity", "trial-usd", max_usd="12", reserve_usd="5"
    )
    statuses = [_post(client, token).status_code for _ in range(3)]

    assert statuses == [200, 200, 429]
    assert len(upstream) == 2
    denied = [e for e in server.events if e["outcome"]["status"] == "blocked"]
    assert [e["context"]["capture"]["identity_check"] for e in denied] == ["usd_budget_exhausted"]
    responses = [e for e in server.events if e["event_type"] == "model_response"]
    assert [e["cost"]["estimated_usd"] for e in responses] == [5.0, 5.0]
    assert {e["cost"]["pricing_version"] for e in responses} == {"test-rates-1"}
    row = _row(server, record)
    assert (row["usd_used_micros"], row["usd_reserved_micros"], row["max_usd_micros"]) == (10_000_000, 0, 12_000_000)


def test_unpriced_responses_are_charged_the_full_reservation(priced_proxy, upstream):
    server, client = priced_proxy
    token, record = server.token_store.issue(
        "antigravity", "trial-unpriced", max_usd="15", reserve_usd="7"
    )
    statuses = [_post(client, token, model="unlisted-model").status_code for _ in range(3)]

    assert statuses == [200, 200, 429]
    row = _row(server, record)
    assert row["usd_used_micros"] == 14_000_000
    responses = [e for e in server.events if e["event_type"] == "model_response"]
    assert all(e["cost"].get("estimated_usd") is None for e in responses)


def test_holds_count_against_the_cap_until_settled(tmp_path):
    store = SessionTokenStore(AuditDB(str(tmp_path / "audit.db")))
    token, record = store.issue("codex", "s", max_usd="12", reserve_usd="5")
    first = store.resolve(token, consume=True)
    second = store.resolve(token, consume=True)
    with pytest.raises(TokenRejected) as rejected:
        store.resolve(token, consume=True)
    assert rejected.value.reason == "usd_budget_exhausted"
    store.settle(first, 1_000_000)
    store.settle(second, 1_000_000)
    assert store.resolve(token, consume=True).reserved_usd_micros == 5_000_000


def test_request_and_dollar_budgets_report_their_own_reason(tmp_path):
    store = SessionTokenStore(AuditDB(str(tmp_path / "audit.db")))
    token, _ = store.issue("codex", "s", max_requests=1, max_usd="20", reserve_usd="5")
    store.resolve(token, consume=True)
    with pytest.raises(TokenRejected) as rejected:
        store.resolve(token, consume=True)
    assert rejected.value.reason == "budget_exhausted"


@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_usd": "5"},
        {"reserve_usd": "5"},
        {"max_usd": "5", "reserve_usd": "6"},
        {"max_usd": "0", "reserve_usd": "1"},
        {"max_usd": "x", "reserve_usd": "1"},
    ],
)
def test_invalid_dollar_caps_are_rejected(tmp_path, kwargs):
    store = SessionTokenStore(AuditDB(str(tmp_path / "audit.db")))
    with pytest.raises(ValidationError):
        store.issue("codex", "s", **kwargs)


def test_token_cli_issues_and_lists_dollar_caps(tmp_path, capsys):
    db = str(tmp_path / "audit.db")
    cli.main(["token", "issue", "--db-path", db, "--agent", "codex", "--session", "s",
              "--max-usd", "2.5", "--reserve-usd", "0.5"])
    capsys.readouterr()
    cli.main(["token", "list", "--db-path", db])
    assert "usd 0.000000/2.500000" in capsys.readouterr().out


def test_pricing_file_loads_from_disk(tmp_path):
    path = tmp_path / "rates.json"
    path.write_text(json.dumps(RATES))
    assert PricingTable.load(str(path)).version == "test-rates-1"
    with pytest.raises(PricingError):
        PricingTable.load(str(tmp_path / "missing.json"))
