# Changelog

All notable changes to Panoptes are recorded here. Releases follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Breaking

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
    `LEGACY_AUTH_METHODS` (the v1–v4 rule). `ALLOWED_AGENT_TYPES` and
    `ALLOWED_AUTH_METHODS` remain as deprecated aliases until the gateway
    modules are removed.
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
  mid-stream is drained for up to `disconnect_drain_seconds`. A hooked proxy
  cannot also use credential injection or the policy engine.
- `ProxyServer(db=..., chain=..., upstreams={"openai": Upstream(url, name=...)})`
  and `ProxyServer.stop()` now waits for in-flight exchanges. `upstreams=`
  overrides the `PANOPTES_UPSTREAM_*` variables. `db_path` now defaults to
  `None` (an in-memory proxy database) and is mutually exclusive with `db`.
- Model-request events carry `declared_tools`, `system_prompt_sha256` and
  `history_sha256` (hashes and names only, no prompt text).
- `import panoptes` no longer loads the policy engine or PyYAML; the policy names
  are still importable from `panoptes`. The package ships `py.typed`, and the
  threaded server shared by the proxy and Hermes ingest is `panoptes._server`.
- `docs/api.md`, the supported Python API.
- `panoptes token issue --max-requests N` caps how many proxied requests a token
  may authorize. Each request presenting a live token spends one unit atomically,
  including requests the provider later rejects. Once spent, the proxy answers
  HTTP 429, never forwards upstream, and records a blocked event attributed to the
  token's session (`identity_check: budget_exhausted`). `token list` shows
  used/maximum. Older token tables gain the columns on first write access.
- `panoptes proxy --pricing FILE` loads a versioned JSON rate table (`version`,
  `source`, `currency: USD`, per-model `input_per_million`,
  `cached_input_per_million`, `output_per_million`). Priced responses record
  `cost.estimated_usd` and `cost.pricing_version`. A response is never priced from
  a guessed rate: unknown models or missing token counts stay unpriced.
- `panoptes token issue --max-usd CAP --reserve-usd HOLD` gives a token a dollar cap.
  Admission holds the reservation atomically, so concurrent requests cannot jointly
  pass the cap; settlement replaces the hold with the priced cost, or charges the
  whole reservation when the response cannot be priced (provider errors are not
  billed). Once the cap cannot fit another reservation the proxy answers HTTP 429
  and records `identity_check: usd_budget_exhausted`. The cap is hard while no single
  response costs more than the reservation. `token list` shows spend.
- `X-Panoptes-Correlation-Id` request header: a validated, client-asserted ID
  recorded as `context.capture.client_correlation_id` on every event of the
  exchange so an external journal can be joined to Panoptes events one-to-one.
  It is stripped before forwarding and never changes agent type, session, or
  identity assurance. Invalid values get HTTP 400.
- `panoptes doctor` checks local database access, policy configuration, optional
  credential injection setup, and recent audit activity without modifying audit
  data or contacting providers. Reports requested settings separately from
  unverified running-proxy and client-routing state.
- `panoptes session` displays a chronological CLI timeline with policy decisions,
  execution provenance, durations, and correlation IDs. `--limit` bounds the
  newest selection; `--json` returns full events and selection counts.
- Credential injection for the reverse proxy. With `--inject-credentials`,
  provider API keys load from `PANOPTES_<PROVIDER>_API_KEY` or an owner-only
  `--credentials-file` and never reach the agent. Agents present a Panoptes
  session token, which the proxy swaps for the routed provider's key. Missing,
  unknown, expired, revoked, or ambiguous tokens get HTTP 401 and a blocked
  audit event, and are never forwarded.
- `panoptes token issue`, `revoke`, and `list`. Only a SHA-256 hash of each
  token is stored, in a `session_tokens` table in the audit database.
- Token-authenticated identity: in credential mode the token's agent type and
  session id replace the `X-Panoptes-*` headers, and events record
  `identity_assurance: "panoptes_session_token"`.
- `PANOPTES_POLICY_FAILURE_MODE` sets the installed Hermes plugin's failure
  mode. An unrecognized value selects `fail_closed`.
- `panoptes policy add --force` replaces a policy file of the same name.
- `AuditDB(path, read_only=True)` opens an existing database without creating,
  migrating, re-anchoring, or changing file modes.

### Changed

- The proxy routes only exact model-API paths (query strings ignored):
  `/v1/messages`, `/v1/messages/count_tokens`, `/v1/chat/completions`,
  `/v1/completions`, `/v1/responses[/<id>]`, `/v1/models[/<id>]`, and
  `/v1[beta|alpha]/models/<model>:(stream)generateContent`. Batches, files,
  fine-tuning, Gemini's OpenAI-compatible routes, and every other path are
  refused instead of forwarded with an injected key.
- An event that fails normalization or validation is denied in both failure
  modes while any enabled block policy is active, so a caller cannot shape its
  input around a block. Without a block policy the failure mode still applies.
- `verify`, `checkpoint`, `query`, `status`, `session`, `evidence`,
  `policy check`, and `token list` open the database read-only.
- `verify` reports a database whose events have no hash-chain metadata as
  invalid, and opening a schema v4 database whose chain metadata is missing
  raises `ChainIntegrityError` instead of starting a new chain.
- `verify` requires each stored JSON column to be byte-identical to what
  Panoptes wrote, so duplicate keys or re-encodings are detected.
- `panoptes policy add` validates the new file together with the existing set
  before copying it, and refuses to overwrite without `--force`.
- Recorded `tokens_in` includes Anthropic cache read and write tokens, and
  Gemini `tokens_out` includes thinking tokens. Gemini events record the model
  named in the route.
- `cost` integers above 2^53 are rejected so SQLite sums cannot overflow.
- Unauthenticated credential denials ignore the request body and User-Agent.

### Fixed

- The shared upstream client no longer stores cookies, which replayed one
  session's upstream cookies on other sessions' requests.
- A client's lowercase `accept-encoding` is replaced rather than forwarded
  beside `identity`; upstream bodies in an encoding httpx cannot decode get 502.
- Repeated request headers are combined instead of keeping only the last.
- Lone UTF-16 surrogates and timestamps outside the UTC range are validation
  errors instead of failures at storage or normalization time.
- A FIFO in place of the credentials file fails fast instead of hanging.
- Bare `pnpt_` session tokens are redacted from stored text.
- The Hermes manifest reports the installed version, and uninstall removes only
  the files the installer wrote.

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
