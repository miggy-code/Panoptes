# Panoptes

<p align="center">
  <strong>Agent observability, local audit trails, and policy gates.</strong><br>
  A local-first view of OpenAI-, Anthropic-, Gemini-, and Hermes-based workflows.
</p>

<p align="center">
  <a href="https://github.com/miggy-code/Panoptes/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/miggy-code/Panoptes/actions/workflows/ci.yml/badge.svg"></a>
  <a href="LICENSE"><img alt="Apache 2.0" src="https://img.shields.io/badge/license-Apache%202.0-blue.svg"></a>
  <img alt="Python 3.10+" src="https://img.shields.io/badge/python-3.10%2B-3776AB.svg">
</p>

Panoptes gives AI-agent traffic one place to land. Point a supported model
client at the local reverse proxy and Panoptes turns requests, responses, tool
instructions, policy decisions, and cost data into a queryable SQLite audit
trail. Hermes integrations can also report lifecycle events and ask Panoptes
for a synchronous pre-tool decision.

Panoptes runs locally with no external service. It records model API traffic
and host-reported lifecycle events; tool calls emitted by a model remain
requests unless the host reports an execution outcome.

## Why

Agent logs tend to be provider-specific, short-lived, and hard to compare.
Panoptes is built to answer a smaller set of operational questions well:

- Which model requests and tool instructions crossed the controlled API path?
- Which tool requests did a native adapter authorize or deny?
- Which policy snapshot informed each recorded authorization decision or violation?
- Has the locally stored event history changed since a checkpoint?

Every supported adapter writes the same event shape. Every event carries
capture metadata describing where it came from and how strong that observation
is. That gives you one dependable record for tracing agent behavior, reviewing
policy decisions, investigating incidents, and testing ideas—without the
operational weight of a distributed observability stack.

## Quick Start

Install Panoptes as an isolated command-line application:

```bash
pipx install panoptes-observe
```

Or use `uv`:

```bash
uv tool install panoptes-observe
```

The distribution is named `panoptes-observe`; the installed command remains
`panoptes`. To work on the source instead:

```bash
git clone https://github.com/miggy-code/Panoptes.git
cd Panoptes
python -m pip install -e ".[dev]"
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

Observation is fail-open by default. For enforcement, provide a valid policy
directory and choose `fail_closed` explicitly:

```bash
panoptes proxy \
  --port 8081 \
  --policies-dir ~/.panoptes/policies \
  --policy-failure-mode fail_closed
```

The proxy only binds to loopback. Client sockets have a 30-second I/O timeout
and the server accepts at most 64 concurrent requests by default; tune these
with `--client-timeout` and `--max-concurrent-requests`.

### Keep provider keys out of the agent

With `--inject-credentials`, the provider API keys live only in Panoptes. The
agent gets a Panoptes session token instead, and Panoptes swaps it for the real
key on every request. An agent without the real key cannot skip the proxy and
call the provider directly.

```bash
# Panoptes holds the keys (or pass --credentials-file, a 0600 YAML file
# mapping anthropic/openai/gemini to keys).
PANOPTES_ANTHROPIC_API_KEY=sk-ant-... panoptes proxy --port 8081 --inject-credentials

# Issue a token for one agent session. Only the token is printed to stdout.
TOKEN=$(panoptes token issue --agent claude_code --session my-run --ttl 28800)

ANTHROPIC_BASE_URL=http://127.0.0.1:8081 ANTHROPIC_API_KEY=$TOKEN claude
```

The agent sends the token where its SDK already sends a key: `x-api-key` or
`Authorization: Bearer` for Anthropic, `Authorization: Bearer` for OpenAI, and
`x-goog-api-key` or `?key=` for Gemini. A missing, unknown, expired, revoked,
or ambiguous token gets HTTP 401 and a blocked audit event, and nothing reaches
the provider. Panoptes stores only a SHA-256 hash of each token, and never
writes a token or a provider key to the audit log or its own logs.

The token also fixes the event identity: its agent type and session id replace
the `X-Panoptes-Agent` and `X-Panoptes-Session` headers, and those events carry
`context.capture.identity_assurance: "panoptes_session_token"`. Revoke a token
with `panoptes token revoke <id>`; `panoptes token list` shows ids and status.
Run Panoptes as a separate OS user or container and block direct provider
egress, or the agent can still read the keys. See [SECURITY.md](SECURITY.md).

### Install Hermes lifecycle hooks

```bash
python -m panoptes.install_hermes_plugin
```

The installer adds lifecycle hooks for `agent:start`, `agent:step`, and
`agent:end`. Those hooks observe; they do not block. Local tool enforcement
requires the Hermes host to call `authorize_tool_call()` synchronously and
honor `allowed=False`. In `fail_closed` mode, an authorization whose evidence
cannot be stored is denied.

### Query and verify

```bash
panoptes query --agent hermes --event-type agent_step --limit 50
panoptes query --agent hermes --event-type decision_point --limit 50
panoptes session <session-id>
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

## Architecture

```text
Enforcement plane: adapter → normalize → policy gate → model/API boundary
                                     │
Audit plane:       adapter → normalized event → SQLite → CLI
```

The design has two intentionally small paths. The enforcement path makes a
decision before a controlled boundary. The audit path commits normalized
evidence to SQLite and keeps it available through the CLI. `capture.py`
describes each adapter's fidelity so consumers can distinguish a model
instruction from a host-reported or pre-authorized action.

### Capture adapters

| Adapter | Observes | Enforcement boundary |
|---------|----------|----------------------|
| Reverse proxy | Supported model requests, responses, tool instructions, and client-reported tool results | Request preflight and fully buffered model responses |
| Hermes plugin | Host-reported `agent_start`, `agent_step`, and `agent_end` events | Optional host-callable pre-tool authorizer, recorded as `decision_point` |

The reverse proxy is a real boundary only for traffic that crosses it. It
cannot see an arbitrary local file read after the agent receives a response,
and an agent can bypass it if it still holds provider credentials. Stronger
deployments must isolate those credentials and block direct provider egress.
At the boundary itself, Panoptes rejects ambiguous JSON instead of guessing
which duplicate value should inform a policy decision.

For reliable cross-request timelines, adapters should send
`X-Panoptes-Session: <stable-session-id>`. Without it, each exchange is
isolated. `X-Panoptes-Agent` and session headers are client assertions, not
authenticated workload identities, and are removed before upstream forwarding.
In credential-injection mode the session token supplies both values instead,
and the headers are ignored.

### Audit schema

```json
{
  "event_id": "uuid",
  "timestamp": "2026-07-17T14:30:00.000Z",
  "agent": {
    "type": "claude_code",
    "session_id": "abc123",
    "run_id": "run456"
  },
  "event_type": "tool_call",
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

Before an event reaches disk, Panoptes validates its identifiers, timestamps,
outcomes, and costs; redacts common secret forms; and derives heuristic
data-access tags from the action. Those tags are useful inputs for local policy
and investigation, but they can be wrong. Treat both redaction and
classification as defense in depth, not as complete data-loss prevention.

Request events include complete bounded summaries of requested client-side,
provider-hosted, and unknown tool capabilities. Client-executed model tool
proposals remain `pending`; recognized provider-hosted actions record whether
they completed, failed, or remain pending upstream. Hosted result excerpts are
redacted and bounded. Unknown requested tool types are denied in
`fail_closed`; `fail_open` records and logs a warning.

### Policy engine

Policies are YAML files in `~/.panoptes/policies/`:

```yaml
name: "no-prod-access"
description: "Block tool calls classified as production access"
enabled: true
scope:
  agents: ["*"]
rule:
  event_type: "tool_call"
  conditions:
    - field: "action.data_accessed"
      operator: "contains"
      value: "prod"
  logic: "AND"
action: block
message: "Production access blocked. Request approval first."
```

- Operators: `==`, `!=`, `contains`, `in`, `matches`, `gt`, `lt`, `gte`, `lte`
- Logic: `AND` / `OR`
- Scopes: agent and session
- Actions: `allow`, `warn`, `block`
- Loading: one validated, content-digested policy set at startup; restart the
  proxy after changing policy files
- Failure posture: explicit `fail_open` or `fail_closed`

Policies are strict on purpose. Unknown fields, malformed conditions, duplicate
YAML keys, an empty directory, or any invalid file make the set fail to load.
That turns a typo into a visible startup problem instead of a silently weaker
rule.

## Supported Protocols and Adapters

| Protocol / adapter | Capture method | Boundary |
|--------------------|----------------|----------|
| Anthropic Messages API | Reverse proxy | Model API |
| OpenAI Chat Completions and Responses APIs | Reverse proxy | Model API |
| Gemini `generateContent` and `streamGenerateContent` | Reverse proxy | Model API |
| Hermes Agent | Native plugin | Host-reported lifecycle; optional pre-tool authorization |

An agent is proxy-compatible only if it lets you replace its model API base URL
and emits a supported protocol. That is not equivalent to a tested native
integration.

Current action parsing covers OpenAI function/custom/computer/shell/apply-patch
and hosted-tool output items, Anthropic client and server tool blocks, and
Gemini function, built-in tool, and code-execution parts. Unknown tool
declarations or response item types never become an implicit safe result:
`fail_closed` denies them, while `fail_open` records degraded inspection.
Provider features introduced after this release, including OpenAI programmatic
tool-calling output, require an adapter update and adversarial fixtures before
they are supported.

## Commands

```text
panoptes proxy          Start the loopback-only model-API reverse proxy
panoptes --version      Show the installed Panoptes version
panoptes status         Show event statistics
panoptes query          Query events by agent, type, tool, or time
panoptes session <id>   Show up to 10,000 newest session events
panoptes evidence <id>  Reconstruct a related decision path
panoptes verify         Verify the local chain or a separately stored checkpoint
panoptes checkpoint     Print the current chain checkpoint
panoptes policy list    List the active policy snapshot
panoptes policy add     Add a policy file
panoptes policy check   Scan a bounded newest-event selection; errors exit nonzero
panoptes policy test    Test one policy against one event
panoptes token issue    Issue a session token for credential injection
panoptes token revoke   Revoke a session token by id
panoptes token list     List session tokens and their status (never values)
```

## Project Status

| Component | Status |
|-----------|--------|
| Model-API reverse proxy | Alpha |
| Hermes lifecycle plugin and authorizer API | Alpha |
| SQLite storage and local hash chain | Available; external checkpoints remain operator-managed |
| Query, policy, and integrity CLI | Available |
| YAML policy engine | Alpha |
| Mandatory local execution broker | Out of scope today |

The project targets Python 3.10 through 3.13 and runs its tests, distribution
validation, and wheel smoke test in GitHub Actions. Passing tests do not expand
the adapter guarantees described in [SECURITY.md](SECURITY.md).

Runtime dependencies are intentionally small: `httpx` and `PyYAML`.

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

## Contributing

Bug reports, protocol fixtures, and focused adapters are welcome. The most
useful contributions strengthen an existing boundary: native pre-execution
adapters, external append-only audit sinks, signed policy distribution, and
adversarial provider fixtures. For security issues, please use the private
reporting path in [SECURITY.md](SECURITY.md).

## License

Apache 2.0 — see [LICENSE](LICENSE).
