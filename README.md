# Panoptes

<p align="center">
  <strong>Agent observability and local audit trails.</strong><br>
  A local record of OpenAI-, Anthropic-, Gemini-, and Hermes-based agent workflows.
</p>

<p align="center">
  <a href="https://github.com/miggy-code/Panoptes/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/miggy-code/Panoptes/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://pypi.org/project/panoptes-observe/"><img alt="PyPI" src="https://img.shields.io/pypi/v/panoptes-observe.svg"></a>
  <a href="LICENSE"><img alt="Apache 2.0" src="https://img.shields.io/badge/license-Apache%202.0-blue.svg"></a>
  <img alt="Python 3.10+" src="https://img.shields.io/badge/python-3.10%2B-3776AB.svg">
</p>

Panoptes records what your agents and models do. Point a model client at the
local reverse proxy. Panoptes then writes each request, response, tool call,
and token count to a SQLite audit trail that you can query.

```text
$ panoptes session demo-session        # output shortened
Session: demo-session (7 of 7 events)
2026-11-23T20:07:34.246Z  model_request  claude-example  SUCCESS
2026-11-23T20:07:34.252Z  model_response  claude-example  SUCCESS (6 ms)
2026-11-23T20:07:34.252Z  tool_call  terminal  PENDING
  command=kubectl get pods -n prod | Model proposed this tool call; local execution was not observed
2026-11-23T20:07:34.266Z  tool_result  unknown  SUCCESS
  api-7d9f 1/1 Running | execution=client-reported
...
```

Panoptes runs on your machine. It needs no external service, and its core has
no runtime dependencies.

## Why

Agent logs are usually specific to one provider, short-lived, and hard to
compare. Panoptes answers a small set of questions well:

- Which model requests and tool calls went through the proxy?
- How many tokens did each exchange use, and what did it cost?
- Which events belong to the same run, and which run started which?
- Did the stored history change after a checkpoint?

All adapters write the same event shape. Each event also records how it was
captured, so you can tell a model's *proposal* from an action the host
*reported*.

## Quick start

Install the command-line tool. The proxy needs the `proxy` extra:

```bash
pipx install 'panoptes-observe[proxy]'
# or
uv tool install 'panoptes-observe[proxy]'
```

The package name is `panoptes-observe`. The command is `panoptes`.

Start the proxy in one terminal:

```bash
panoptes proxy --port 8081
```

Point a client at it from a second terminal:

```bash
ANTHROPIC_BASE_URL=http://127.0.0.1:8081 claude
```

Read what Panoptes recorded:

```bash
panoptes status
panoptes query --event-type tool_call --limit 10
```

To see the full flow without a real provider, follow
[Investigating a session](docs/investigating-a-session.md). It runs the proxy
against a local fake upstream.

## What Panoptes does and does not do

Panoptes records. It does not make policy decisions: it does not allow, deny,
rewrite, or rate-limit requests. A separate package can add those decisions
through the [hook interface](docs/hooks.md).

Panoptes *fails closed* on traffic that it cannot record correctly:

- It refuses provider endpoints that are not on its allowlist, such as batch
  and file uploads.
- It refuses requests that are malformed, too large, or have duplicate JSON
  keys.
- It replaces a buffered reply with HTTP 502 when the reply has a duplicate
  JSON key. The client and the audit trail could read different values.
- It replaces a buffered reply with HTTP 502 when the reply is larger than the
  inspection limit.

Panoptes does not prove that a tool ran. A `tool_call` event is a model's
proposal. It stays `pending` until a host reports an outcome. Panoptes is not
a security boundary. For the full trust model, read [SECURITY.md](SECURITY.md).

## Usage

### Run the proxy

```bash
panoptes proxy --port 8081 --pricing rates.json
```

- The proxy forwards each request and relays each stream as it arrives.
- `--pricing` loads a versioned JSON rate table. Responses then carry an
  estimated cost. A response that Panoptes cannot price is marked unpriced.
- The proxy binds only to loopback addresses.
- `--client-timeout` sets the client socket timeout (default 30 seconds).
- `--max-concurrent-requests` sets the request limit (default 64).

Send `X-Panoptes-Session: <id>` to group exchanges into one session. Without
it, each exchange is its own session. The `X-Panoptes-*` headers are client
claims, not authenticated identities. Panoptes removes them before it forwards
the request.

### Embed the proxy and add hooks

You can run the proxy inside another process. A hook runs before Panoptes
forwards a request and after the exchange ends. A hook can reject a request,
set the recorded identity, change outbound headers, and settle the cost.

```python
from panoptes.hooks import ProxyHooks, Reject
from panoptes.proxy import ProxyServer

class Gate(ProxyHooks):
    def before_forward(self, exchange):
        if exchange.provider == "openai":
            return Reject(403, reason="openai_not_allowed")

server = ProxyServer(port=0, db_path="~/.panoptes/audit.db", hooks=Gate())
port = server.start()        # Returns at once. Call server.stop() when done.
```

The full contract is in [docs/hooks.md](docs/hooks.md). Lifecycle rules are in
[docs/lifecycle-invariants.md](docs/lifecycle-invariants.md).

### Record Hermes lifecycle events

```bash
python -m panoptes.install_hermes_plugin
```

Then add `panoptes` to `plugins.enabled` in Hermes. The Panoptes package must
be importable in the Hermes environment.

The plugin records `on_session_start`, `post_tool_call`, and `on_session_end`
as lifecycle events. `on_session_finalize` ends a session. The hooks record
only. They never block Hermes.

To send events from an isolated agent to a separate listener, start a sink:

```python
from panoptes.hermes_ingest import make_server

make_server(("127.0.0.1", 8083), "/private/audit.sqlite",
            "/private/hermes-events.jsonl").serve_forever()
```

Then set `PANOPTES_HERMES_SINK=http://127.0.0.1:8083/lifecycle` in Hermes. In
a container, bind the listener only to the isolated network. The listener does
not authenticate the host.

### Query and verify

```bash
panoptes query --agent hermes --event-type agent_step --limit 50
panoptes session <session-id> [--limit N] [--json]
panoptes evidence <event-id>

panoptes verify                              # check the local hash chain
panoptes checkpoint > checkpoint.json        # store this file somewhere else
panoptes verify --checkpoint checkpoint.json # later: prove history only grew
```

- `session` shows a timeline with status, tool or model, duration, and IDs.
- `evidence` shows the events related to one event, in the same format.
- `session` selects up to 10,000 of the newest events. When it shows only
  part of a session, it prints the selected and matching counts.
- Read-only commands need an existing audit database. A missing or empty
  `--db-path` exits with status 2. Panoptes does not create a new database.

### Check your setup

```bash
panoptes doctor
```

`doctor` opens the database read-only. It checks the schema and the newest
event time. It warns when the history is empty or older than 24 hours. It
exits with 0 when checks pass and 2 when a check fails. It does not verify the
hash chain. Use `panoptes verify` for that.

### Export to OpenTelemetry

```bash
pip install 'panoptes-observe[otel]'
panoptes export-otel --endpoint http://127.0.0.1:4318/v1/traces --limit 1000
```

The export reads committed events and sends metadata only. It never sends
prompts, tool arguments, or results. For the mapping and delivery limits, read
[docs/otel-export.md](docs/otel-export.md).

## Commands

| Command | Purpose |
|---|---|
| `panoptes proxy` | Start the loopback-only model API reverse proxy |
| `panoptes status` | Show event counts |
| `panoptes doctor` | Check the audit database (read-only) |
| `panoptes query` | Find events by agent, type, tool, or time |
| `panoptes session <id>` | Show a session timeline |
| `panoptes evidence <id>` | Show the events related to one event |
| `panoptes verify` | Verify the local chain or a stored checkpoint |
| `panoptes checkpoint` | Print the current chain checkpoint |
| `panoptes export-otel` | Export event metadata over OTLP/HTTP |
| `panoptes --version` | Show the installed version |

## Supported protocols

| Protocol | Capture method |
|---|---|
| Anthropic Messages API | Reverse proxy |
| OpenAI Chat Completions and Responses APIs | Reverse proxy |
| Gemini `generateContent` and `streamGenerateContent` | Reverse proxy |
| Hermes Agent | Plugin (host-reported lifecycle) |

An agent works with the proxy if you can change its model API base URL and it
uses a supported protocol.

The parsers recognize these tool types:

- **OpenAI:** function, custom, computer, shell, apply-patch, and hosted tools.
- **Anthropic:** client and server tool blocks.
- **Gemini:** function, built-in tool, and code-execution parts.

Panoptes records an unrecognized tool type under `action.unknown_tool_types`.
It never treats an unknown type as safe. New provider features need a parser
update and test fixtures before Panoptes supports them.

## Architecture

```text
adapter → normalize → SQLite → read API / CLI
```

Each adapter converts what it observes into one event schema. Before Panoptes
stores an event, it does these steps:

1. It validates identifiers, timestamps, outcomes, and costs.
2. It redacts common secret formats.
3. It adds heuristic data-access tags, such as `prod` or `infra`.

Then the store commits the event, with an optional local hash chain.

Redaction and tags are best-effort. Redaction can miss a secret format, and a
tag can be wrong.

### Event schema

```json
{
  "event_id": "uuid",
  "timestamp": "2026-07-17T14:30:00.000Z",
  "agent": {"type": "claude_code", "session_id": "abc123", "run_id": "run456"},
  "event_type": "tool_call",
  "correlation_id": "c0ffee",
  "attributes": {"exchange_id": "…", "correlation_source": "proxy"},
  "action": {
    "tool_name": "terminal",
    "parameters": {"command": "kubectl get pods -n prod"},
    "data_accessed": ["infra", "prod"]
  },
  "outcome": {
    "status": "pending",
    "summary": "Model proposed this tool call; local execution was not observed"
  },
  "context": {
    "turn_number": 12,
    "capture": {
      "adapter": "http_proxy",
      "observation_boundary": "model_api",
      "execution_observed": false
    }
  },
  "cost": {"tokens_in": 800, "tokens_out": 150}
}
```

The current schema is version 5:

- `agent.type` accepts any valid identifier. The built-in adapter names are a
  list, not an enforced set.
- `run_id` is optional. The store never makes one up. `agent.parent_run_id`
  links a child agent to its parent. `session_id` is required.
- `user` is optional. There is no default user.
- `correlation_id` is an indexed field. `attributes` is an open JSON object
  with a size limit.
- Other producers name their event types `<namespace>.<name>`, for example
  `acme.allow`.
- Version 1 to 4 databases migrate in place. Their hash chains still verify.

Request events also store a system prompt hash, a history hash, and the
declared tool names. They store no prompt text in those fields.

For the Python API and the hash-chain modes, read [docs/api.md](docs/api.md).

### Token and cost fields

Response events store `cost.tokens_in` and `cost.tokens_out` as totals. When
the provider reports them, Panoptes also stores these breakdowns:

| Field | Meaning |
|---|---|
| `cost.reasoning_tokens` | Reasoning or thinking tokens. Part of `tokens_out`. |
| `cost.cached_input_tokens` | Cache reads. Part of `tokens_in`. |
| `cost.cache_creation_input_tokens` | Cache writes. Part of `tokens_in`. |
| `cost.cache_creation_5m_input_tokens` | Anthropic 5-minute cache writes. |
| `cost.cache_creation_1h_input_tokens` | Anthropic 1-hour cache writes. |
| `cost.tool_prompt_tokens` | Gemini tool prompt tokens. Separate from its prompt count. |

A missing field means the provider did not report it. It does not mean zero.
Anthropic thinking tokens are an estimate. Token counts from different
providers are not always comparable.

## Project status

| Component | Status |
|---|---|
| Model API reverse proxy and hooks | Alpha |
| Hermes lifecycle plugin | Alpha |
| SQLite storage and local hash chain | Available |
| Query and integrity CLI | Available |
| OpenTelemetry export | Alpha |

CI runs the tests on Python 3.10 to 3.13. It also builds the package and runs
a smoke test on the installed wheel.

## Development

```bash
git clone https://github.com/miggy-code/Panoptes.git
cd Panoptes
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev,release]"
python -m pytest -q
```

The tests run locally and need no network. A change is ready for review when
the full suite passes and `git diff --check` is clean. The release process is
in [RELEASING.md](RELEASING.md).

Write tests for observable behavior: capture, the hook contract, storage and
integrity, and CLI flows.

## Contributing

Bug reports, protocol fixtures, and focused adapters are welcome. The most
useful work makes an existing boundary stronger, for example external
append-only audit sinks or adversarial provider fixtures. Report security
issues through the private process in [SECURITY.md](SECURITY.md).

## License

Apache 2.0. See [LICENSE](LICENSE).
