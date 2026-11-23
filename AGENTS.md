# Panoptes development guide

Panoptes converts observations from adapters into one queryable audit trail.
The adapters are a model API reverse proxy (OpenAI, Anthropic, and Gemini
protocols) and Hermes lifecycle hooks.

Panoptes **records**. It makes no policy decisions: it never allows, denies,
rewrites, or rate-limits a request. Decisions plug in from another package
through the proxy hooks (`docs/hooks.md`). An event is not proof that a local
tool ran, and Panoptes is not a security boundary.

```text
adapter → normalize → SQLite → read API / CLI
```

## File map

| File | Purpose |
|---|---|
| `panoptes/__init__.py` | Public package exports |
| `panoptes/capture.py` | Capture fidelity metadata that each adapter attaches |
| `panoptes/schema.py` | Event validation, normalization, data-access tags, secret redaction |
| `panoptes/db.py` | SQLite storage, read API, evidence paths, local hash chain |
| `panoptes/proxy.py` | Reverse proxy: routing, forwarding, server lifecycle |
| `panoptes/_events.py` | Private: converts an exchange into audit events |
| `panoptes/_hooked.py` | Private: hook machinery that the proxy handler mixes in |
| `panoptes/hooks.py` | Public hook types; imports no HTTP client |
| `panoptes/_server.py` | Bounded threaded HTTP server for the proxy and Hermes ingest |
| `panoptes/_json.py` | Strict JSON decoding (rejects duplicate keys) for all input boundaries |
| `panoptes/pricing.py` | Versioned rate tables; cost is an annotation |
| `panoptes/providers/` | Strict provider request, response, and stream parsers |
| `panoptes/otel.py` | Optional read-only OpenTelemetry export |
| `panoptes/cli.py` | All `panoptes` commands |
| `panoptes/hermes_plugin.py` | Hermes lifecycle hooks |
| `panoptes/hermes_hooks.py`, `hermes_ingest.py` | Hermes hook entry points and the separate ingest listener |
| `panoptes/install_hermes_plugin.py` | Hermes plugin installer |

## Where the contracts live

- Event schema, read API, hash chain, and pricing: `docs/api.md`.
- Proxy hook contract: `docs/hooks.md`.
- Lifecycle rules: `docs/lifecycle-invariants.md`.
- Trust model: `SECURITY.md`.

Update the matching doc when you change one of these contracts. Write docs in
simplified technical English with American spelling: short sentences, active
voice, one idea per sentence.

## Tests

```bash
python -m pip install -e ".[dev]"
python -m pytest -q
```

A change is mergeable only when the full suite passes.

## Conventions

These rules are not visible from the config. Keep them true.

**Dependencies**
- The core has no third-party runtime dependency. `httpx` is only in the
  `proxy` extra. OpenTelemetry is only in the `otel` extra.
- Panoptes code never imports or names a consumer, such as a gateway.
  Dependencies go one way.
- Expand every path with `os.path.expanduser()`.

**Storage**
- Open one SQLite connection per operation (WAL mode). Do not use
  thread-locals: `ThreadingHTTPServer` threads are short-lived, so each one
  would leak a connection.
- Redact secrets in `normalize_event()`, before storage.
- Only the same `event_id` with the same canonical payload is idempotent.
  `call_id` links events. It never removes duplicates, so keep every delivery.
- Local chain verification starts at the recorded migration boundary.
  Detecting a full-history rewrite needs an external checkpoint.

**Proxy**
- Bind to loopback only.
- Upstream HTTP clients use `trust_env=False`. Shell proxy variables are not
  routing configuration.
- Reject duplicate JSON keys at every boundary. Keep the provider protocol and
  request path bound through response and SSE parsing.
- Keep these limits enforced: client socket timeout, concurrent requests, body
  size, and tool events per exchange.
- Relay streams as they arrive. Capture is bounded and marked incomplete when
  cut short.

**Evidence**
- A client-proposed tool call stays `pending`. A recognized provider-hosted
  action carries its upstream outcome and only a short, redacted result excerpt.
- Record unknown tool types under `action.unknown_tool_types`. Never treat
  them as safe.
- `action.data_accessed` tags are heuristic, not proof of access.
- Hermes lifecycle writes are best-effort.
- `decision_point` and `policy_violation` stay in the schema so older records
  stay readable. Panoptes no longer writes them.

**CLI**
- Read-only commands reject a missing or uninitialized database path. They
  never create a database.
- A bounded scan or session selection prints its selected and matching counts.
  Never describe the newest N events as the full history.
