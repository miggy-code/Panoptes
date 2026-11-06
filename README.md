# Panoptes

<p align="center">
  <strong>Agent observability and local audit trails.</strong><br>
  A local-first record of OpenAI-, Anthropic-, Gemini-, and Hermes-based workflows.
</p>

<p align="center">
  <a href="https://github.com/miggy-code/Panoptes/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/miggy-code/Panoptes/actions/workflows/ci.yml/badge.svg"></a>
  <a href="LICENSE"><img alt="Apache 2.0" src="https://img.shields.io/badge/license-Apache%202.0-blue.svg"></a>
  <img alt="Python 3.10+" src="https://img.shields.io/badge/python-3.10%2B-3776AB.svg">
</p>

Panoptes records what agents and models did and lets you read it back. Point a
supported model client at the local reverse proxy and Panoptes turns requests,
responses, tool instructions, and cost data into a queryable SQLite audit trail.
Hermes integrations can also report lifecycle events.

Panoptes observes. It never decides and never blocks: nothing in it allows,
denies, rewrites, or rate-limits a request. Anything that decides plugs in
through the [hook seam](docs/hooks.md) from another package.

It runs locally with no external service. It records model API traffic and
host-reported lifecycle events; tool calls emitted by a model remain requests
unless the host reports an execution outcome.

## Why

Agent logs tend to be provider-specific, short-lived, and hard to compare.
Panoptes is built to answer a smaller set of operational questions well:

- Which model requests and tool instructions crossed the observed API path?
- What did each exchange cost, and how many tokens did it use?
- Which events belong to the same run, and which run spawned which?
- Has the locally stored event history changed since a checkpoint?

Every supported adapter writes the same event shape. Every event carries
capture metadata describing where it came from and how strong that observation
is. That gives you one dependable record for tracing agent behavior,
investigating incidents, and testing ideas, without the operational weight of a
distributed observability stack.

## Quick Start

Install Panoptes as an isolated command-line application. The proxy needs the
`proxy` extra; the store and the CLI's query commands do not:

```bash
pipx install 'panoptes-observe[proxy]'
```

Or use `uv`:

```bash
uv tool install 'panoptes-observe[proxy]'
```

The distribution is named `panoptes-observe`; the installed command remains
`panoptes`. To work on the source instead:

```bash
git clone https://github.com/miggy-code/Panoptes.git
cd Panoptes
python -m pip install -e ".[dev]"   # includes the proxy extra's httpx
```

### Capture model API traffic

Start Panoptes in one terminal:

```bash
panoptes proxy --port 8081
```

Then point a supported client at it from another terminal:

```bash
ANTHROPIC_BASE_URL=http://127.0.0.1:8081 claude
```

After the run, inspect what Panoptes recorded:

```bash
panoptes status
panoptes query --event-type tool_call --limit 10
```

The proxy forwards every request and relays every stream as it arrives. Add
`--pricing rates.json` (a versioned JSON rate table) and responses carry an
estimated cost; a response that cannot be priced is recorded as unpriced.

The proxy only binds to loopback. Client sockets have a 30-second I/O timeout
and the server accepts at most 64 concurrent requests by default; tune these
with `--client-timeout` and `--max-concurrent-requests`.

### Embed the proxy and decide with hooks

The proxy can run inside another process, with a hook that is called before a
request is forwarded and after the exchange ends. A hook can reject a request,
set the identity it is recorded under, set the outbound headers (that is how a
gateway injects a provider key) and settle the cost afterwards. The proxy itself
never decides anything.

```python
from panoptes.hooks import ProxyHooks, Reject
from panoptes.proxy import ProxyServer

class Gate(ProxyHooks):
    def before_forward(self, exchange):
        if exchange.provider == "openai":
            return Reject(403, reason="openai_not_allowed")

server = ProxyServer(port=0, db_path="~/.panoptes/audit.db", hooks=Gate())
port = server.start()        # non-blocking; server.stop() when done
```

The full contract is in [docs/hooks.md](docs/hooks.md).
Lifecycle and capture guarantees are summarized in
[docs/lifecycle-invariants.md](docs/lifecycle-invariants.md).

### Install Hermes lifecycle hooks

```bash
python -m panoptes.install_hermes_plugin
```

The installer supplies the current Hermes `plugin.yaml` and `register(ctx)`
interface, plus legacy entrypoints. Add `panoptes` to Hermes `plugins.enabled`;
the Panoptes package must be importable in the Hermes environment for local
capture. Current Hermes `on_session_start`, `post_tool_call`, and `on_session_end`
observations become Panoptes lifecycle events; `on_session_finalize` ends a
session. Those hooks observe; they do not block. For isolated agents,
`PANOPTES_HERMES_SINK` can direct observations to a separately protected
Panoptes listener; this does not authenticate the host or prove tool execution.
For example, start a sink on a protected local network with:

```python
from panoptes.hermes_ingest import make_server

make_server(("127.0.0.1", 8083), "/private/audit.sqlite",
            "/private/hermes-events.jsonl").serve_forever()
```

Set `PANOPTES_HERMES_SINK=http://127.0.0.1:8083/lifecycle` in Hermes. In a
container, bind the listener only to the isolated network. Lifecycle events
are written to the Panoptes audit database; the optional JSONL journal holds
host-reported child links and request fingerprints for reconciliation.

### Query and verify

```bash
panoptes query --agent hermes --event-type agent_step --limit 50
panoptes session <session-id>
panoptes session <session-id> --limit 50
panoptes session <session-id> --json
panoptes evidence <event-id>

# Verify local hash links and export a checkpoint for separate storage
panoptes verify
panoptes checkpoint > checkpoint.json

# Later, prove that separately stored checkpoint is a prefix of current history
panoptes verify --checkpoint checkpoint.json
```

Read-only database commands require an existing initialized audit database. A
missing, mistyped, or empty `--db-path` exits with status 2 instead of creating
a new database.

`session` shows a chronological timeline with event status, tool or model,
available duration, and event/run/call IDs. Model proposals remain distinct from
reported execution outcomes. By default it selects up to 10,000 newest events;
`--limit` selects fewer. Partial timelines state the selected and matching
counts. `--json` returns full stored events with those counts and a `partial`
flag. Events written by an earlier version or by another producer may carry
decision records; the timeline shows them as recorded.

### Check your setup

```bash
panoptes doctor
```

Doctor checks an existing database and schema, reports the latest audit
timestamp, and warns when history is empty or older than 24 hours. It opens the
database read-only, does not repair files or attempt audit writes, and makes no
provider requests. Exit status is 0 when checks pass (warnings may remain), or 2
when a check fails. It does not discover a running proxy's settings, prove
client routing, or verify the hash chain; use `panoptes verify` for the chain
check.

## Architecture

```text
adapter → normalize → SQLite → read API / CLI
```

Each adapter normalizes what it observes into the schema below, and the store
commits it with an optional local hash chain. `capture.py` describes each
adapter's fidelity so consumers can distinguish a model instruction from a
host-reported action.

### Capture adapters

| Adapter | Observes |
|---------|----------|
| Reverse proxy | Supported model requests, responses, tool instructions, and client-reported tool results |
| Hermes plugin | Host-reported `agent_start`, `agent_step`, and `agent_end` events |

The reverse proxy sees only traffic that crosses it. It cannot see an arbitrary
local file read after the agent receives a response, and an agent that still
holds provider credentials can bypass it. At the boundary itself, Panoptes
withholds a buffered reply whose JSON repeats an object key, because the client
and the audit trail could otherwise read different values, and it refuses a
buffered reply larger than its limit.

For reliable cross-request timelines, adapters should send
`X-Panoptes-Session: <stable-session-id>`. Without it, each exchange is
isolated. `X-Panoptes-Agent` and session headers are client assertions, not
authenticated workload identities, and are removed before upstream forwarding.
An embedding hook can set the identity itself; the event then records that a hook
asserted it.

Every proxied exchange gets a `run_id` and a `correlation_id`. The correlation
id is the client's `X-Panoptes-Correlation-Id` when it sends a valid one (a
client assertion, not proof of anything) and otherwise the exchange's own id;
`attributes.correlation_source` says which. Events also carry
`attributes.exchange_id`, which is unique per request even when a client reuses
its correlation id.

### Audit schema

```json
{
  "event_id": "uuid",
  "timestamp": "2026-07-17T14:30:00.000Z",
  "agent": {
    "type": "claude_code",
    "session_id": "abc123",
    "run_id": "run456",
    "parent_run_id": null
  },
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

**Schema v5** (this release) opens the vocabulary and removes invented
defaults:

- `agent.type` and `user.auth_method` are any validated identifier. The adapters
  Panoptes ships (`claude_code`, `codex`, `hermes`, …) are a list of known
  names, not an enforced set.
- `run_id` is optional and never invented by the store, and `agent.parent_run_id`
  links a child agent to its parent. `session_id` is still required.
- `user` is optional. There is **no default user**: an event without one stores
  an empty `user`, where earlier versions filled in `local_user` and `cli`.
- `correlation_id` is a first-class, indexed field, and `attributes` is an open,
  size-bounded JSON object redacted like `context`.
- Another producer names its events `<namespace>.<name>` (for example
  `acme.allow`); the built-in event types stay a closed set.
- An event that declares `context.schema_version` 1 to 4 keeps the rules of that
  version, and v1–v4 databases migrate in place with their hash chains still
  verifying.

The Python API for writing, strict ingest, read-only reading, `iter_events` and
the optional hash chain is in [docs/api.md](docs/api.md). By default a new
database is hash-chained and an existing one keeps its mode; `AuditDB(path,
chain=False)` creates one without a chain, which then verifies as `absent`,
never as valid.

Before an event reaches disk, Panoptes validates its identifiers, timestamps,
outcomes, and costs; redacts common secret forms; and derives heuristic
data-access tags from the action. Those tags are useful for investigation, but
they can be wrong. Treat both redaction and classification as defense in depth,
not as complete data-loss prevention.

Request events include complete bounded summaries of requested client-side,
provider-hosted, and unknown tool capabilities, plus a system-prompt hash, a
history hash and the declared tool names (no text is stored). Client-executed
model tool proposals remain `pending`; recognized provider-hosted actions record
whether they completed, failed, or remain pending upstream. Hosted result
excerpts are redacted and bounded. A tool type Panoptes does not recognize is
recorded under `action.unknown_tool_types`, never treated as known-safe.

## Supported Protocols and Adapters

| Protocol / adapter | Capture method |
|--------------------|----------------|
| Anthropic Messages API | Reverse proxy |
| OpenAI Chat Completions and Responses APIs | Reverse proxy |
| Gemini `generateContent` and `streamGenerateContent` | Reverse proxy |
| Hermes Agent | Native plugin (host-reported lifecycle) |

An agent is proxy-compatible only if it lets you replace its model API base URL
and emits a supported protocol. That is not equivalent to a tested native
integration.

Current action parsing covers OpenAI function/custom/computer/shell/apply-patch
and hosted-tool output items, Anthropic client and server tool blocks, and
Gemini function, built-in tool, and code-execution parts. A tool declaration or
response item type that Panoptes does not recognize is recorded as unknown and
never becomes an implicit safe result. Provider features introduced after this
release, including OpenAI programmatic tool-calling output, require an adapter
update and adversarial fixtures before they are supported.

## Commands

```text
panoptes proxy          Start the loopback-only model-API reverse proxy
panoptes --version      Show the installed Panoptes version
panoptes status         Show event statistics
panoptes doctor         Check the audit database (read-only)
panoptes query          Query events by agent, type, tool, or time
panoptes session <id>   Show a chronological timeline (--limit N, --json)
panoptes evidence <id>  Reconstruct a related event path
panoptes verify         Verify the local chain or a separately stored checkpoint
panoptes checkpoint     Print the current chain checkpoint
```

## Project Status

| Component | Status |
|-----------|--------|
| Model-API reverse proxy and hook seam | Alpha |
| Hermes lifecycle plugin | Alpha |
| SQLite storage and local hash chain | Available; external checkpoints remain operator-managed |
| Query and integrity CLI | Available |

The project targets Python 3.10 through 3.13 and runs its tests, distribution
validation, and wheel smoke test in GitHub Actions. Passing tests do not expand
the adapter guarantees described in [SECURITY.md](SECURITY.md).

The core has no runtime dependencies. The proxy needs `httpx`
(`pip install 'panoptes-observe[proxy]'`).

## Development

Create an environment, install the development extra, and run the suite:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev,release]"
python -m pytest -q
python -m build
python -m twine check --strict dist/*
```

The tests are local and network-independent. A change is ready to review when
the full suite passes and `git diff --check` is clean. Release ownership and
the tagged publishing flow are documented in [RELEASING.md](RELEASING.md).

Focus tests on observable behavior: capture, the hook contract, audit storage
and integrity, and CLI flows. Use shared setup and parameterized cases for
repeated inputs. Test helpers through those behaviors unless a separate test
protects a distinct data-loss boundary.

## Contributing

Bug reports, protocol fixtures, and focused adapters are welcome. The most
useful contributions strengthen an existing boundary: external append-only audit
sinks and adversarial provider fixtures. For security issues, please use the
private reporting path in [SECURITY.md](SECURITY.md).

## License

Apache 2.0 — see [LICENSE](LICENSE).

### Provider usage breakdowns

Model response events retain `cost.tokens_in` and `cost.tokens_out` as totals.
When reported by the provider, `cost.reasoning_tokens` records Gemini thought
tokens, OpenAI reasoning tokens, or Anthropic thinking tokens; these are
subsets of output tokens. `cost.cached_input_tokens` records cache reads, and
Anthropic and OpenAI may also report `cost.cache_creation_input_tokens`. Gemini may
also report `cost.tool_prompt_tokens`, separate from its prompt token count.
A missing breakdown means unavailable, not zero. Anthropic's thinking count
is an estimate from re-tokenization, and providers' token counts and caching
semantics are not necessarily directly comparable.

`AuditDB.aggregate` supports these breakdown names and their corresponding
`_reported` counts. Sums are null when no events reported the metric; use the
counts to assess coverage before comparing runs. Existing events are unchanged.

### Optional OpenTelemetry output

Export committed audit observations separately from capture:

```bash
pip install 'panoptes-observe[otel]'
panoptes export-otel --db-path ~/.panoptes/audit.db \
  --endpoint http://127.0.0.1:4318/v1/traces --limit 1000
# Optional selection: --session-id SESSION --since ISO8601 --until ISO8601
```

This reads the newest selected events without modifying the database. It sends
metadata only, including identifiers and capture fidelity; prompts, tool arguments,
results and raw bodies are excluded. Each record is a zero-duration observation,
not proof of tool execution. Export failures exit nonzero; earlier batches may
have succeeded. Repeating export can produce duplicates at the receiver. Capture
has no OTel dependency unless this extra is installed and the command is invoked.
See the [architecture review and mapping](docs/architecture-review.md) for lifecycle
changes, delivery limits and the exact privacy boundary.
