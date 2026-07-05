# Panoptes — Development Guide

Universal agent observability, audit trail, and policy enforcement.
Works with Claude Code, OpenAI Codex, Google Antigravity, and Hermes Agent.

## Project Purpose

Capture every tool call, decision, and data access across AI coding agents. Normalize into a single queryable audit trail. Enforce policies that block dangerous actions before they execute.

## Architecture

```
Query & Compliance  ←  CLI (query, status, session, evidence, policy)
Normalization       ←  schema.py (universal event schema, validation, redaction)
Storage             ←  db.py (SQLite, thread-safe WAL, 7 indices)
Capture Adapters    ←  proxy.py (MITM HTTP proxy) + hermes_plugin.py (Hermes hooks)
```

## File Map

| File | Lines | Purpose |
|------|-------|---------|
| `panoptes/__init__.py` | 32 | Package exports, version |
| `panoptes/schema.py` | 319 | Event validation, normalization, secret redaction |
| `panoptes/db.py` | 447 | AuditDB — SQLite storage, query API, evidence chains |
| `panoptes/proxy.py` | 964 | HTTP forward proxy — intercepts LLM API traffic |
| `panoptes/policy.py` | 497 | PolicyEngine — YAML policies, 8 operators, rate limiting |
| `panoptes/cli.py` | 368 | CLI — proxy, query, status, session, evidence, policy |
| `panoptes/hermes_plugin.py` | 162 | Hermes plugin — hooks agent:start, agent:step, agent:end |
| `panoptes/install_hermes_plugin.py` | 206 | One-command plugin installer |
| `panoptes/default_policies/` | 19 | Bundled example: no-prod-access.yaml |
| `tests/test_db.py` | 537 | 10 storage/schema tests |
| `tests/test_policy.py` | 1128 | 30 policy engine tests |
| `test_proxy.py` | ~80 | Proxy integration test |
| `pyproject.toml` | 30 | Package config, `panoptes` entry point |

## The Universal Audit Schema

```python
{
    "event_id": "uuid",
    "timestamp": "ISO8601",
    "agent": {"type": "claude_code|codex|hermes|antigravity", "session_id": "...", "run_id": "..."},
    "user": {"id": "...", "auth_method": "..."},
    "event_type": "model_request|model_response|tool_call|tool_result|decision_point|policy_violation",
    "action": {"tool_name": "...", "parameters": {}, "target": "...", "data_accessed": []},
    "outcome": {"status": "success|error|blocked|timeout", "summary": "...", "error": null},
    "context": {"turn_number": N, "user_message": "..."},
    "cost": {"tokens_in": N, "tokens_out": N, "estimated_usd": N}
}
```

## Build Status

- ✅ Proxy Capture — intercepts OpenAI/Anthropic/Gemini from any agent
- ✅ Hermes Plugin — native hooks, installed at ~/.hermes/plugins/panoptes/
- ✅ Storage Engine — SQLite, WAL mode, 10/10 tests pass
- ✅ CLI — 9 subcommands, pip-installable
- ✅ Policy Engine — YAML rules, 8 operators, blocking, 30/30 tests pass
- ⏳ Dashboard — planned

## Key Integration Points

### AuditDB (db.py)
```python
from panoptes.db import AuditDB
db = AuditDB("~/.panoptes/audit.db")
eid = db.insert_event(event_dict)
results = db.query(agent_type="hermes", event_type="tool_call", limit=50)
stats = db.get_stats()
chain = db.get_evidence_chain(event_id)
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
Auto-captures every tool call. Install: `python -m panoptes.install_hermes_plugin`

## Running Tests

```bash
cd /Users/user/Projects/agent-audit   # or wherever cloned
/opt/anaconda3/bin/python3 -m pytest tests/ -v --tb=short
/opt/anaconda3/bin/python3 test_proxy.py
```

All 40 tests must pass before considering any change mergeable.

## Conventions

- Python 3.10+ (tested on 3.12)
- Thread-safe DB (WAL mode, connection-per-thread)
- Fail-open for policy errors (never block legitimate use)
- Secret redaction in normalize_event() before storage
- All paths use os.path.expanduser() for ~ expansion
