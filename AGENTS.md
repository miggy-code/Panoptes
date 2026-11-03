# Panoptes — Development Guide

Adapter-based agent observability and local audit trails.
Current adapters cover supported OpenAI-, Anthropic-, and Gemini-compatible
model API traffic plus Hermes host-reported lifecycle events.

## Project Purpose

Normalize observations from supported adapters into a queryable audit trail.
Panoptes records and never decides: nothing in it allows, denies, rewrites or
rate-limits a request. Anything that decides plugs in through the proxy hook seam
(`docs/hooks.md`) from another package. A normalized event is not proof that a
local tool executed, and Panoptes is not a security boundary.

## Architecture

```
adapter → normalize → SQLite → read API / CLI
```

## File Map

| File | Purpose |
|------|---------|
| `panoptes/__init__.py` | Public package exports |
| `panoptes/capture.py` | Adapter fidelity capability contracts |
| `panoptes/schema.py` | Event validation, normalization, classification, and secret redaction |
| `panoptes/db.py` | SQLite storage, query API, evidence paths, and local hash-chain integrity |
| `panoptes/proxy.py` | Observe-only reverse proxy: routing, forwarding, server lifecycle |
| `panoptes/_events.py` | Private: how an exchange becomes audit events, and provider reply parsing |
| `panoptes/_hooked.py` | Private: the hook machinery the proxy handler mixes in |
| `panoptes/hooks.py` | Public hook types: `ProxyHooks`, `Exchange`, `Reject`, `Upstream` (no HTTP dependency) |
| `panoptes/_server.py` | Bounded threaded HTTP server shared by the proxy and the Hermes ingest |
| `panoptes/pricing.py` | Versioned rate tables; cost is an annotation on responses |
| `panoptes/providers/` | Strict provider request, response, and streaming parsers |
| `panoptes/cli.py` | Proxy, query, integrity, and doctor commands |
| `panoptes/hermes_plugin.py` | Hermes lifecycle observation hooks |
| `panoptes/hermes_hooks.py`, `hermes_ingest.py` | Current Hermes hook entrypoints and the separate ingest listener |
| `panoptes/install_hermes_plugin.py` | One-command Hermes plugin installer |
| `tests/` | Unit, integration, migration, concurrency, and adversarial tests |
| `pyproject.toml` | Package metadata and `panoptes` entry point |

## The Universal Audit Schema

```python
{
    "event_id": "uuid",
    "timestamp": "ISO8601",
    "agent": {"type": "claude_code|codex|hermes|antigravity|...", "session_id": "...", "run_id": "..."},
    "user": {"id": "...", "auth_method": "..."},
    "event_type": "model_request|model_response|tool_call|tool_result|decision_point|policy_violation|agent_start|agent_step|agent_end|<namespace>.<name>",
    "action": {"tool_name": "...", "parameters": {}, "target": "...", "data_accessed": []},
    "outcome": {"status": "success|error|blocked|timeout|pending|warned", "summary": "...", "error": null},
    "context": {"schema_version": 5, "turn_number": N, "capture": {}},
    "cost": {"tokens_in": N, "tokens_out": N, "estimated_usd": N}
}
```

`decision_point` and `policy_violation` stay in the vocabulary so earlier
databases and other producers' records remain readable; Panoptes itself no
longer writes them.

## Build Status

- 🧪 Proxy Capture — experimental model-API observation and hook seam
- 🧪 Hermes Plugin — experimental lifecycle observation hooks
- ✅ Storage Engine — SQLite, WAL mode, idempotent event IDs, and optional local hash chain
- ✅ CLI — source-installable query, integrity, proxy, and doctor commands

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

### Proxy hooks (hooks.py)
```python
from panoptes.hooks import ProxyHooks, Reject
from panoptes.proxy import ProxyServer

class Hook(ProxyHooks):
    def before_forward(self, exchange):
        ...  # return Reject(...) to refuse; mutate exchange.outbound_headers
    def after_exchange(self, exchange):
        ...  # called once per entered exchange

ProxyServer(port=0, db_path="~/.panoptes/audit.db", hooks=Hook()).start()
```

### Hermes Plugin
Installed at `~/.hermes/plugins/panoptes/`. Hooks agent:start, agent:step, agent:end.
The hooks record host-reported lifecycle observations and never block.
Install: `python -m panoptes.install_hermes_plugin`

## Running Tests

```bash
cd /path/to/Panoptes
python -m pip install -e ".[dev]"   # includes the proxy extra's httpx
python -m pytest -q
```

The complete current test suite must pass before considering a change
mergeable.

## Conventions

- Python 3.10+ (tested on 3.12); no third-party runtime dependency in the core, httpx only in the `proxy` extra
- Panoptes code never imports or names a consumer such as a gateway; dependencies run one way
- Thread-safe DB (WAL mode, connection-per-operation; thread-locals are avoided because ThreadingHTTPServer request threads are short-lived and would leak one connection each)
- Proxy binds are loopback-only
- Proxy upstream HTTP clients use `trust_env=False`; ambient shell proxy variables are not routing configuration
- Proxy JSON boundaries reject duplicate object keys; provider dialect and request path stay bound through response/SSE extraction
- Client socket timeouts, bounded concurrent requests, body limits, and per-exchange tool-event limits must remain enforced
- Streams are relayed as they arrive; capture of them is bounded and marked incomplete when it is cut short
- Hermes lifecycle writes are best-effort observations
- Secret redaction in normalize_event() before storage
- `action.data_accessed` includes server-derived heuristic tags, not authoritative proof of resource access
- Read-only CLI database commands reject missing and uninitialized paths instead of creating a database
- Bounded CLI scans and session selections must state their selected and matching counts; never describe a newest-N selection as the full history
- Client-proposed tool calls remain pending, while recognized provider-hosted actions carry their upstream execution outcome and only bounded redacted result excerpts
- Unknown requested tool types are recorded under `action.unknown_tool_types`, never treated as known-safe
- `call_id` is a correlation field, not a deduplication key; every observed delivery is retained
- Only the same `event_id` with the same canonical payload is idempotent
- Local chain verification covers chained events from the recorded migration boundary; external checkpoints are needed to detect whole-history rewrites
- All paths use os.path.expanduser() for ~ expansion
