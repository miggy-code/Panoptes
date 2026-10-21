# Changelog

All notable changes to Panoptes are recorded here. Releases follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

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

[Unreleased]: https://github.com/miggy-code/Panoptes/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/miggy-code/Panoptes/releases/tag/v0.1.0
