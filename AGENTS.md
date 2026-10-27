# Panoptes — Development Guide

Adapter-based agent observability, local audit trails, and policy gates.
Current adapters cover supported OpenAI-, Anthropic-, and Gemini-compatible
model API traffic plus Hermes host-reported lifecycle events.

## Project Purpose

Normalize observations from supported adapters into a queryable audit trail and
evaluate policies at explicit model-API and host-authorizer boundaries. A
normalized event is not proof that a local tool executed, and Panoptes does not
yet provide mandatory mediation of every local action.

## Architecture

```
Enforcement plane   ←  adapter → normalize → policy gate → model/API boundary
Audit plane         ←  adapter → normalized event → SQLite → CLI
```

## File Map

| File | Purpose |
|------|---------|
| `panoptes/__init__.py` | Public package exports |
| `panoptes/capture.py` | Adapter fidelity and enforcement capability contracts |
| `panoptes/schema.py` | Event validation, normalization, classification, and secret redaction |
| `panoptes/db.py` | SQLite storage, query API, evidence paths, and local hash-chain integrity |
| `panoptes/proxy.py` | Reverse proxy capture and policy gates at the model API boundary |
| `panoptes/credentials.py` | Provider key loading and Panoptes session tokens for credential injection |
| `panoptes/providers/` | Strict provider request, response, and streaming parsers |
| `panoptes/policy.py` | Validated YAML policy sets and nine condition operators |
| `panoptes/cli.py` | Proxy, query, integrity, token, and policy commands |
| `panoptes/hermes_plugin.py` | Hermes lifecycle hooks and optional host-callable authorizer |
| `panoptes/install_hermes_plugin.py` | One-command Hermes plugin installer |
| `panoptes/default_policies/` | Bundled example policies |
| `tests/` | Unit, integration, migration, concurrency, and adversarial tests |
| `pyproject.toml` | Package metadata and `panoptes` entry point |

## The Universal Audit Schema

```python
{
    "event_id": "uuid",
    "timestamp": "ISO8601",
    "agent": {"type": "claude_code|codex|hermes|antigravity", "session_id": "...", "run_id": "..."},
    "user": {"id": "...", "auth_method": "..."},
    "event_type": "model_request|model_response|tool_call|tool_result|decision_point|policy_violation|agent_start|agent_step|agent_end",
    "action": {"tool_name": "...", "parameters": {}, "target": "...", "data_accessed": []},
    "outcome": {"status": "success|error|blocked|timeout|pending|warned", "summary": "...", "error": null},
    "context": {"schema_version": 4, "turn_number": N, "capture": {}},
    "cost": {"tokens_in": N, "tokens_out": N, "estimated_usd": N}
}
```

## Build Status

- 🧪 Proxy Capture — experimental model-API observation and buffered policy gates
- 🧪 Hermes Plugin — experimental lifecycle hooks and host-callable authorization API
- ✅ Storage Engine — SQLite, WAL mode, idempotent event IDs, and local hash chain
- ✅ CLI — source-installable query, integrity, proxy, and policy commands
- 🧪 Policy Engine — strict YAML policy sets, nine operators, and blocking
- ⏳ Mandatory local execution broker — not implemented

## Key Integration Points

### AuditDB (db.py)
```python
from panoptes.db import AuditDB
db = AuditDB("~/.panoptes/audit.db")
eid = db.insert_event(event_dict)
results = db.query(agent_type="hermes", event_type="agent_step", limit=50)
stats = db.get_stats()
chain = db.get_evidence_chain(event_id)
verification = db.verify_chain()
checkpoint = db.get_chain_checkpoint()
prefix_proof = db.verify_checkpoint(checkpoint)
```

### PolicyEngine (policy.py)
```python
from panoptes.policy import PolicyEngine
engine = PolicyEngine("~/.panoptes/policies/")
result = engine.check_event(event)
if result.action == "block":
    # refuse the request
```

### Hermes Plugin
Installed at `~/.hermes/plugins/panoptes/`. Hooks agent:start, agent:step, agent:end.
The hooks record host-reported lifecycle observations. Tool blocking requires
the Hermes host to call `authorize_tool_call()` before execution and honor its
result. Install: `python -m panoptes.install_hermes_plugin`

## Running Tests

```bash
cd /path/to/Panoptes
python -m pip install -e ".[dev]"
python -m pytest -q
```

The complete current test suite must pass before considering a change
mergeable.

## Conventions

- Python 3.10+ (tested on 3.12)
- Thread-safe DB (WAL mode, connection-per-operation; thread-locals are avoided because ThreadingHTTPServer request threads are short-lived and would leak one connection each)
- Policy failure mode is explicit: fail-open by default; fail-closed is available for enforcement
- Proxy binds are loopback-only
- Proxy upstream HTTP clients use `trust_env=False`; ambient shell proxy variables are not routing configuration
- Proxy JSON boundaries reject duplicate object keys; provider dialect and request path stay bound through response/SSE extraction
- Client socket timeouts, bounded concurrent requests, body limits, and per-exchange tool-event limits must remain enforced
- Hermes lifecycle writes are best-effort observations; fail-closed semantics apply to the synchronous authorizer, not lifecycle callbacks
- Secret redaction in normalize_event() before storage
- `action.data_accessed` includes server-derived heuristic tags, not authoritative proof of resource access
- Read-only CLI database commands reject missing and uninitialized paths instead of creating a database
- Policy scans surface evaluation errors and exit nonzero rather than reporting a clean scan
- Bounded CLI scans and session selections must state their selected and matching counts; never describe a newest-N selection as the full history
- Client-proposed tool calls remain pending, while recognized provider-hosted actions carry their upstream execution outcome and only bounded redacted result excerpts
- Unknown requested tool types are a built-in fail-closed denial and a fail-open auditable warning, independent of user policy coverage
- `call_id` is a correlation field, not a deduplication key; every observed delivery is retained
- Only the same `event_id` with the same canonical payload is idempotent
- Local chain verification covers chained events from the recorded migration boundary; external checkpoints are needed to detect whole-history rewrites
- All paths use os.path.expanduser() for ~ expansion
