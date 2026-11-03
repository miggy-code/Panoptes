# Changelog

All notable changes to Panoptes are recorded here. Releases follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Breaking

- **The policy engine and the Hermes authorizer are removed.** Panoptes records
  and never decides. Gone: `panoptes.policy` and the `Policy`, `PolicyEngine`,
  `PolicyResult` and `POLICY_ENGINE_SEMANTICS_VERSION` names exported from
  `panoptes`; the `panoptes policy list|add|check|test` commands; `--policies-dir`
  and `--policy-failure-mode` (on `proxy` and `doctor`); the bundled
  `default_policies/`; `ProxyServer(policies_dir=, policy_failure_mode=)`;
  `AuditPlugin.authorize_tool_call`, `AuditPlugin(policies_dir=, policy_failure_mode=)`,
  `PANOPTES_POLICY_FAILURE_MODE`, `AuthorizationDecision` and
  `HERMES_AUTHORIZER_CAPABILITIES`; and the PyYAML dependency. The Hermes plugin
  keeps its observation hooks. A consumer that decides does so in a proxy hook.
- Streamed responses are always relayed as they arrive; nothing is buffered for
  inspection. A response Panoptes cannot read is delivered and recorded as
  incomplete (`inspection_status: "incomplete"`). A buffered reply whose JSON
  repeats an object key is still withheld, and an oversized buffered reply is
  still refused with 502.
- `ALLOWED_AGENT_TYPES` and `ALLOWED_AUTH_METHODS` are removed; use
  `KNOWN_AGENT_TYPES` and `LEGACY_AUTH_METHODS`.
- **Event schema v5.** A database migrates in place on its first writable open
  (nullable columns only; every v1–v4 hash chain still verifies). Once
  migrated, an older Panoptes refuses it. An event that declares
  `context.schema_version` 1–4 keeps the rules of that version.
  - A missing user is no longer filled in as `local_user` / `cli`. `user` is
    optional and stored as `{}` when absent.
  - `run_id` is optional and is no longer invented when absent (the proxy still
    assigns one per exchange). `session_id` stays required.
  - `agent.type` and `user.auth_method` are open validated identifiers. The
    closed lists are now `KNOWN_AGENT_TYPES` (informational, not enforced) and
    `LEGACY_AUTH_METHODS` (the v1–v4 rule).
  - Custom events use a namespaced type `<namespace>.<name>`; the built-in
    event types stay closed.
- `httpx` is no longer a base dependency. The proxy needs the new `[proxy]`
  extra (`pip install 'panoptes-observe[proxy]'`); `panoptes proxy` says so when
  it is missing. The store, schema, hooks types and Hermes ingest need no HTTP
  client.
- `AuditDB.query()` and `aggregate()` raise `ValueError` on an unknown filter
  name. Before, a misspelled filter silently matched every event.
- `verify_chain()` results carry `chain`: `intact`, `broken`, `partial` or
  `absent`. A log with no hash chain is never `valid`. A chain that covers no
  event while events exist outside it (`event_count 0`, `legacy_event_count >
  0`), such as a legacy database that was just opened and never written to, is
  now `partial` and not valid; it was `valid` before. A schema 4+ database
  without chain metadata is `broken`, not "not initialized".
- `AuditDB(path, read_only=True)` now opens any schema version up to the current
  one instead of refusing a database that needs migrating.

### Added

- `AuditDB.open_readonly(path)`: reads a log without migrating, re-anchoring,
  re-permissioning or writing the database. It can leave empty `-wal`/`-shm`
  files beside a WAL database; a WAL database in an unwritable directory raises
  `ReadOnlyMediaError`.
- Strict ingest: `insert_event(..., strict=True, strict_paths=...)` raises
  `IdentifierRewriteError` before any write when redaction would change an
  identifier field, instead of storing it altered.
- `AuditDB.iter_events(...)`: streams every matching event in write or timestamp
  order with keyset paging and no row cap.
- Optional hash chain: `AuditDB(path, chain=None | True | False)`. An unchained
  database verifies as `absent`; a chained one refuses `chain=False`.
- Event fields `attributes` (open, size-bounded JSON), `agent.parent_run_id`
  and a first-class indexed `correlation_id`. `query`, `iter_events` and
  `aggregate` filter on `parent_run_id` and `correlation_id`.
- The proxy gives every exchange a `correlation_id` (the client's
  `X-Panoptes-Correlation-Id`, else the exchange id) and records
  `attributes.correlation_source` and `attributes.exchange_id` on its events.
- Proxy hooks (`panoptes.hooks`, `docs/hooks.md`): `ProxyServer(hooks=...)` calls
  `before_forward` (reject, set the identity, set outbound headers, drop query
  credentials) and `after_exchange` (settle: outcome, `request_sent`,
  `produced_output`, `complete`, usage, `estimated_usd_micros`) for every
  entered exchange. A hook never forces buffering; a client that leaves
  mid-stream is drained for up to `disconnect_drain_seconds`. Credential
  injection, budgets and any decision belong in a hook. `Exchange.upstream_status`
  carries the provider's own status, and `provider_error` and `produced_output`
  follow it rather than the status Panoptes returned.
- `ProxyServer(db=..., chain=..., upstreams={"openai": Upstream(url, name=...)})`
  and `ProxyServer.stop()` now waits for in-flight exchanges. `upstreams=`
  overrides the `PANOPTES_UPSTREAM_*` variables. `db_path` now defaults to
  `None` (an in-memory proxy database) and is mutually exclusive with `db`.
- Model-request events carry `declared_tools`, `system_prompt_sha256` and
  `history_sha256` (hashes and names only, no prompt text).
- `import panoptes` loads only the schema and the store. The package ships
  `py.typed`, and the threaded server shared by the proxy and Hermes ingest is
  `panoptes._server`.
- `docs/api.md`, the supported Python API.
- `panoptes proxy --pricing FILE` loads a versioned JSON rate table (`version`,
  `source`, `currency: USD`, per-model `input_per_million`,
  `cached_input_per_million`, `output_per_million`). Priced responses record
  `cost.estimated_usd` and `cost.pricing_version`. A response is never priced from
  a guessed rate: unknown models or missing token counts stay unpriced.
- `X-Panoptes-Correlation-Id` request header: a validated, client-asserted ID
  recorded as `context.capture.client_correlation_id` on every event of the
  exchange so an external journal can be joined to Panoptes events one-to-one.
  It is stripped before forwarding and never changes agent type, session, or
  identity assurance. Invalid values get HTTP 400.
- `panoptes doctor` checks local database access and recent audit activity
  without modifying audit data or contacting providers.
- `panoptes session` displays a chronological CLI timeline with execution
  provenance, durations, and correlation IDs. `--limit` bounds the
  newest selection; `--json` returns full events and selection counts.
- `AuditDB(path, read_only=True)` opens an existing database without creating,
  migrating, re-anchoring, or changing file modes.

### Changed

- The proxy routes only exact model-API paths (query strings ignored):
  `/v1/messages`, `/v1/messages/count_tokens`, `/v1/chat/completions`,
  `/v1/completions`, `/v1/responses[/<id>]`, `/v1/models[/<id>]`, and
  `/v1[beta|alpha]/models/<model>:(stream)generateContent`. Batches, files,
  fine-tuning, Gemini's OpenAI-compatible routes, and every other path are
  refused instead of forwarded with an injected key.
- `verify`, `checkpoint`, `query`, `status`, `session`, `evidence` and `doctor`
  open the database read-only.
- `verify` reports a database whose events have no hash-chain metadata as
  invalid, and opening a schema v4 database whose chain metadata is missing
  raises `ChainIntegrityError` instead of starting a new chain.
- `verify` requires each stored JSON column to be byte-identical to what
  Panoptes wrote, so duplicate keys or re-encodings are detected.
- Recorded `tokens_in` includes Anthropic cache read and write tokens, and
  Gemini `tokens_out` includes thinking tokens. Gemini events record the model
  named in the route.
- `cost` integers above 2^53 are rejected so SQLite sums cannot overflow.

### Fixed

- The shared upstream client no longer stores cookies, which replayed one
  session's upstream cookies on other sessions' requests.
- A client's lowercase `accept-encoding` is replaced rather than forwarded
  beside `identity`; upstream bodies in an encoding httpx cannot decode get 502.
- Repeated request headers are combined instead of keeping only the last.
- Lone UTF-16 surrogates and timestamps outside the UTC range are validation
  errors instead of failures at storage or normalization time.
- Bare `pnpt_` session tokens are redacted from stored text.
- The Hermes manifest reports the installed version, and uninstall removes only
  the files the installer wrote.
- A successful reply without a usage object is unpriced (`estimated_usd: null`,
  `Exchange.estimated_usd_micros is None`) instead of priced at zero tokens.

## [0.1.1] - 2026-10-21

### Added

- `agentgate` as an accepted `agent.type` for schema version 4 events, so
  agentgate gate decisions are recorded under their own agent type instead of
  `unknown`.

## [0.1.0] - 2026-08-05

### Added

- Strict OpenAI, Anthropic, and Gemini request, response, and streaming
  adapters.
- A loopback reverse proxy for normalized model-API capture and policy gates.
- A validated YAML policy engine with explicit fail-open and fail-closed modes.
- SQLite audit storage with idempotent event IDs and a local hash chain.
- Query, evidence, integrity, checkpoint, proxy, and policy CLI commands.
- Installed-package version reporting through `panoptes --version`.
- Hermes lifecycle hooks and an optional synchronous tool authorizer.
- Python 3.10–3.13 CI, distribution validation, and installed-wheel smoke tests.

[Unreleased]: https://github.com/miggy-code/Panoptes/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/miggy-code/Panoptes/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/miggy-code/Panoptes/releases/tag/v0.1.0
