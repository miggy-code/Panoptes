# Changelog

All notable changes to Panoptes are recorded here. Releases follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

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
