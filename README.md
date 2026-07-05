# Panoptes

<p align="center">
  <strong>Universal agent observability, audit trail, and policy enforcement.</strong><br>
  Works with Claude Code, OpenAI Codex, Google Antigravity, and Hermes Agent.
</p>

---

Panoptes watches your AI agents and tells you what they actually did — every tool call, every file read, every shell command, every decision. It captures agent activity across multiple agent frameworks into a single, queryable audit trail, and can **block dangerous actions before they execute** via configurable policies.

Named after [Argos Panoptes](https://en.wikipedia.org/wiki/Argus_Panoptes), the all-seeing giant of Greek mythology with a hundred eyes — because your agents need a watcher that never blinks.

## Why

Companies are deploying AI coding agents (Claude Code, Codex, Hermes, Antigravity, Cursor) at scale. These agents have access to filesystems, shells, APIs, and production infrastructure. But nobody can answer basic questions like:

- "What did the agent actually do yesterday?"
- "Did it access production credentials?"
- "Which files did it read and modify?"
- "How many shell commands did it run?"

Each agent stores its own format — Claude Code JSONL, Codex session files, Hermes hooks, Antigravity nothing. Panoptes normalizes everything into a single, queryable database with a universal schema, a CLI, and a policy engine that can **block** dangerous operations before they happen.

## Quick Start

```bash
pip install panoptes
```

### Capture agent activity

```bash
# Option 1: Start the proxy and route any agent through it
panoptes proxy --port 8081 &
HTTP_PROXY=http://localhost:8081 claude-code

# Option 2: Hermes plugin (auto-captures every session)
python -m panoptes.install_hermes_plugin
```

### Query what happened

```bash
# Overview
panoptes status

# Find tool calls
panoptes query --agent hermes --event-type tool_call

# See a full session timeline
panoptes session <session-id>

# Reconstruct the evidence chain for any event
panoptes evidence <event-id>
```

### Enforce policies

```bash
# List active policies
panoptes policy list

# Add a policy
panoptes policy add no-prod-access.yaml

# Check policies against recent events
panoptes policy check
```

## Architecture

```
 Query & Compliance  ←  CLI (query, status, session, evidence, policy)
 Normalization       ←  schema.py (universal event schema, validation, redaction)
 Storage             ←  db.py (SQLite, thread-safe WAL, 7 indices)
 Capture Adapters    ←  proxy.py (MITM HTTP proxy) + hermes_plugin.py (Hermes hooks)
```

### Capture adapters

| Adapter | How it works | Coverage |
|---------|-------------|----------|
| **Proxy** | MITM HTTP proxy intercepting LLM API traffic | Any agent that hits an LLM API over HTTP |
| **Hermes Plugin** | Native Hermes hooks (`agent:step`, `agent:end`) | Hermes Agent — deepest integration |

### Universal audit schema

Every event, from every agent, normalized to one format:

```json
{
  "event_id": "uuid",
  "timestamp": "2026-07-04T14:30:00Z",
  "agent": {"type": "claude_code", "session_id": "abc123"},
  "event_type": "tool_call",
  "action": {
    "tool_name": "terminal",
    "parameters": {"command": "kubectl apply -f deploy.yaml"},
    "target": "kubectl apply -f deploy.yaml",
    "data_accessed": ["prod_deploy"]
  },
  "outcome": {"status": "success", "summary": "deployment applied"},
  "context": {"turn_number": 12, "user_message": "deploy to prod"},
  "cost": {"tokens_in": 800, "tokens_out": 150}
}
```

### Policy engine

Policies are YAML files in `~/.panoptes/policies/`. Example:

```yaml
name: "no-prod-access"
description: "Block tool calls that access production configs"
enabled: true
scope:
  agents: ["hermes", "claude_code", "codex"]
rule:
  event_type: "tool_call"
  conditions:
    - field: "action.data_accessed"
      operator: "contains"
      value: "prod"
    - field: "action.tool_name"
      operator: "in"
      value: ["terminal", "write_file", "browser_navigate"]
  logic: "AND"
action: block
message: "Production access blocked. Request approval first."
```

**8 condition operators:** `==`, `!=`, `contains`, `in`, `matches` (regex), `gt`, `lt`, `gte`, `lte`  
**Logic:** AND / OR  
**Scoping:** filter by agent type, session ID, event type  
**Rate limiting:** per-session counters (in-memory for v1)  
**Actions:** allow, warn, block  

## Supported Agents

| Agent | Capture Method | Depth |
|-------|---------------|-------|
| **Claude Code** | Proxy (HTTP interception) | Full API traffic |
| **OpenAI Codex** | Proxy (HTTP interception) | Full API traffic |
| **Google Antigravity** | Proxy (HTTP interception) | Full API traffic |
| **Hermes Agent** | Native plugin (hooks) | Every tool call, turn, and decision |
| **Gemini CLI** | Proxy | Full API traffic |
| **Cursor CLI** | Proxy | Full API traffic |
| **Any HTTP-based agent** | Proxy | Full API traffic |

## Commands

```
panoptes proxy          Start the MITM audit proxy
panoptes status         Show event statistics
panoptes query          Query events (filter by agent, type, tool, time)
panoptes session <id>   Full session timeline
panoptes evidence <id>  Decision chain for an event
panoptes policy list    List loaded policies
panoptes policy add     Add a policy file
panoptes policy check   Scan events for violations
panoptes policy test    Test a policy against a JSON event
```

## Installation

```bash
# From PyPI (coming soon)
pip install panoptes

# From source
git clone https://github.com/miggy-code/Panoptes.git
cd Panoptes
pip install -e .
```

Requires Python 3.10+. Zero external dependencies beyond `httpx` and `pyyaml`.

## Project Status

Panoptes is in active development. Core infrastructure is built and tested:

| Phase | Status |
|-------|--------|
| Proxy capture (HTTP MITM) | ✅ Complete |
| Hermes plugin (native hooks) | ✅ Complete |
| Storage engine (SQLite) | ✅ Complete |
| CLI (9 commands) | ✅ Complete |
| Policy engine (YAML rules) | ✅ Complete |
| Dashboard (web UI) | ⏳ Planned |

**40/40 tests pass.**

## License

Apache 2.0 — see [LICENSE](LICENSE).

## Contributing

Panoptes is an open-source contribution to the AI agent infrastructure layer. PRs welcome.

Areas where help is especially valuable:
- Additional agent adapters (OTel receiver, MCP tracing)
- Dashboard / web UI
- Postgres storage backend
- Policy packs for compliance frameworks (SOC 2, EU AI Act)

## Inspiration

- [claude-code-trace](https://github.com/delexw/claude-code-trace) — Claude Code session viewer
- [claude-tap](https://github.com/liaohch3/claude-tap) — Universal agent proxy
- [Langfuse](https://langfuse.com) — Open-source LLM tracing
- [Arize Phoenix](https://github.com/Arize-AI/phoenix) — Open-source observability
