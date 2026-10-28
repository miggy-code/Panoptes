# Changelog

All notable changes to Panoptes are recorded here. Releases follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

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
- `verify`, `checkpoint`, `query`, `status`, `session`, `evidence`, and
  `policy check` open the database read-only.
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
