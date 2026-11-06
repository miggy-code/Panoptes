# Architecture review: lifecycle state and optional OpenTelemetry

Reviewed 2026-11-06 against the working tree, including the existing duplicate-start
fix, lifecycle notes and OTel research. Reconciled with the corrected
[implicit-state-machine inventory](t3-thread://v2/f5e16fa5-bb16-4c2f-90a4-b1c080bdb3ab/8da6ee91-185c-4bbe-9221-b08047df36b0),
including its recommendation to prioritize demonstrated bugs and enforceable
invariants. That thread produced the duplicate-start fix and lifecycle guide
already present in the working tree; this review builds on those changes.

## Findings and disposition

1. **Verified startup rollback bug (fixed).** If `Thread.start()` raises,
   cleanup tried to join an unstarted thread, masking the original failure and
   skipping HTTP client, DB and temporary-file cleanup. Join only a live thread.
   A fault-injection test reproduced the original error, then verified cleanup
   and successful restart after the fix.

2. **Proxy resource ownership is the highest-impact concurrency boundary.**
   `ProxyServer.start()` acquires a DB, HTTP client, listener and thread in stages;
   `stop()` tears down those same fields. A duplicate-start guard alone is a
   check-then-act race: concurrent starts can both pass it and overwrite owned
   resources, while stop can race partial initialization. Serialize lifecycle
   operations with one per-instance lock, retaining the existing startup rollback
   and external-database ownership rules. Implemented, with concurrent start,
   repeated stop, restart, and caller-owned DB checks. No general FSM library is
   needed for a synchronous resource owner.

3. **Hook callback debt should have one owner and one phase.**
   `_ExchangeRun.entered` and `.finished` encoded prepared, entered and settled
   states, including a representable contradictory state. `_serve_request` already
   owns settlement in `finally`; preserve that structure. Replace the booleans
   with a private phase and guarded entry/finish operations. Claim completion
   before calling consumer code so a callback failure cannot cause another call.
   Implemented. This is an invariant simplification, not evidence that existing
   request paths were double-calling hooks. Forwarding, upstream status, client
   disconnect and inspection completeness remain independent observations.

4. **Provider parsing state is intrinsic and should stay local.**
   Anthropic indexed blocks and OpenAI Responses output items must reconcile
   incremental fragments, terminal markers and final evidence. Removing that
   state or merging it into a universal exchange enum would lose protocol checks.
   Keep reconstruction in `providers/`, separate from transport and hook debt.
   Existing adversarial parser tests remain the regression boundary. No rewrite.

5. **Export should not introduce another capture lifecycle.**
   Exporting in DB writes or `after_exchange` would couple capture availability to
   telemetry queues, retries and receiver availability. Add explicit read-only
   post-capture export. It has a bounded selection, synchronous bounded batches,
   visible failure and no persistent delivery cursor or application retry loop.
   Implemented as `panoptes.otel` and `panoptes export-otel`, without changes to
   SQLite writes, Hermes or forwarding paths.

## Disposition of the original inventory

The original inventory identified ten lifecycles plus batch writes and plugin
installation. Their best ownership boundaries remain narrow:

| Original inventory | Best home | Disposition in this change |
| --- | --- | --- |
| Proxy server lifecycle | `ProxyServer` resource owner | Serialize start/stop; fix thread-launch rollback; test restart and shared DB ownership. |
| Request admission/workers | `BoundedThreadingHTTPServer` semaphore and condition | Retain admission/release ownership and bounded shutdown; no new phase enum. |
| Hooked exchange | `_ExchangeRun` plus `_serve_request` finally block | Make callback obligation explicit with one phase and guarded settlement. |
| Identity mutability | `Exchange._freeze_identity` | Retain the existing boundary after `before_forward`; separate from transport state. |
| Response/stream capture | Proxy forwarding report and `_note_response` | Retain separate upstream, delivery and inspection observations; existing disconnect/drain tests pass. No new completion guarantee. |
| SSE framing | `providers/base.py` | Retain framing accumulator and parse errors below provider reconstruction. |
| Anthropic blocks | `providers/anthropic.py` | Keep indexed start/delta/stop validation provider-local. |
| OpenAI items/arguments | `providers/openai.py` | Keep item reconciliation and terminal evidence provider-local. |
| Hermes sessions | `hermes_plugin.py` | Retain bounded host-reported attribution; no durable identity inference. |
| Schema/chain mode | `db.py` SQLite transactions | Retain transactional migration and chain-mode checks. |
| Audit batches | `AuditDB.insert_events` transaction | Retain atomic batch/chain-head commit and event-ID replay rules. |
| Plugin installation | Installer's atomic per-file replacement | Retain rerunnable installation; no multi-file transaction added. |

This implements the first priority from that thread and adds optional export at
the committed-read boundary. The explicit hook phase is a small representation
simplification; it is not a reproduced callback bug. Existing stream/provider,
Hermes and storage tests passed, but no new exhaustive transition or fault-injection
campaign was performed for those subsystems. If a further extraction is justified
by a failing sequence, address stream capture/completeness next in the forwarding
report, preserving transport completion separately from provider terminal evidence.
Do not collapse those independent facts into one success/failure state.

## Residual lifecycle limits

- Shutdown still waits only the configured grace period for requests before
  closing owned resources. A slow in-flight exchange can lose final capture;
  serializing start/stop does not solve request cancellation or durability.
- Calling `stop()` synchronously inside a hook can wait for its own request until
  the grace period elapses. Lifecycle control belongs to the server owner.
- Hermes attribution is bounded, volatile host-reported state; eviction and
  missing lifecycle callbacks can leave gaps. Persisting it would need a separate
  identity/recovery contract, not an OTel feature.
- Migration and chain-head transitions stay inside SQLite transactions; do not
  replace them with application flags or attach network effects to their commit.

## Export mapping v1

One committed event becomes one INTERNAL root span named
`panoptes.observation.<event_type>`, at its recorded timestamp with zero duration.
No parent, execution span or model latency is inferred. A `tool_call` remains an
observation, including pending status and capture assertions. SHA-256-derived
trace/span IDs are stable for the same event ID, allowing receiver deduplication
where supported; replay can still create duplicates. IDs identify observations,
not sessions. Session, run, parent-run, exchange and correlation IDs are attributes.

Only explicit metadata fields are exported: identifiers, model/tool names,
execution scope, status, token/cost annotations and selected capture fidelity,
provenance, completeness and delivery fields. Raw payloads, prompts, parameters,
results, user identity, summaries, errors, headers and arbitrary attributes are
excluded. Existing redaction is also applied to metadata; metadata itself can be
sensitive. No raw-content export switch is provided.

The CLI requires an explicit OTLP/HTTP traces URL. Standard OTel exporter
credentials/TLS configuration remain available through OTel environment variables.
The SDK handles transport retries; Panoptes adds none. A non-success batch stops
export with a nonzero exit and the previously acknowledged count. A failed batch
may already have reached the receiver. Repeating a command repeats its selection.
Selection and total counts use separate short reads and can differ under concurrent
writes. Export never migrates the source DB or extends its local evidence chain.

Validated with a local HTTP/protobuf receiver and the SDK in-memory exporter.
No Langfuse/Phoenix UI compatibility or production collector persistence claim.
The [official exporter interface](https://opentelemetry-python.readthedocs.io/en/latest/exporter/otlp/otlp.html)
provides the synchronous batch result used here; see also
[OpenTelemetry Python exporters](https://opentelemetry.io/docs/languages/python/exporters/).

## Validation

- Tests changed/assessed: hook lifecycle, proxy startup rollback, CLI optional
  dependency behavior, new OTel mapping and real local OTLP/HTTP payload tests;
  existing full suite retained.
- Behavior covered: concurrent start ownership, repeated stop/restart, callback
  settlement, startup failure cleanup, source DB unchanged by export, metadata
  exclusion, exact timestamp/correlation retention, stable IDs, bounded selection,
  partial batch failure, error exit and exporter shutdown.
- Commands run: `.venv/bin/python -m pytest -q`, `pip check`, `git diff --check`,
  isolated `python -m build`, `twine check --strict`, clean-wheel core smoke test.
- Results: 515 tests passed on local Python 3.13; dependency, diff, package build
  and strict distribution checks passed.
- CI status: not run remotely.
- TDD evidence: thread-start failure regression failed with the original cleanup
  error before the fix and passed after it. Other additions were tested after
  implementation; no broader TDD claim.
- Gaps/risks: no remote collector/backend UI verification, no Python 3.10–3.12
  run in this session, no exactly-once export guarantee; shutdown grace limitation
  remains as described above.
- Follow-ups: validate the intended receiver's storage/deduplication and UI before
  adopting backend-specific GenAI semantics or continuous export.
