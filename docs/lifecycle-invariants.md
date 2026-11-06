# Lifecycle invariants

These describe the current implementation, not a guarantee that every external
provider or host follows a complete lifecycle. An audit event is an observation,
not proof that a client-side tool executed.

## Servers and exchanges

- A `ProxyServer` owns at most one running listener. `start()` rejects a second
  start; `stop()` releases owned resources, but does not close a caller-owned
  database. A per-instance lock serializes start/stop operations, including startup
  rollback.
- The shared HTTP server admits a request only when a worker slot is available.
  Each admitted worker releases its slot when it exits; shutdown waits only for
  the configured grace period.
- An exchange that enters `before_forward` is settled once and receives one
  `after_exchange` call, including rejection and error paths. A prepared → entered
  → finished phase owns that callback debt; completion is claimed before calling
  consumer code. Requests rejected
  before hook entry do not receive that callback. Hook identity freezes after
  `before_forward`; later identity assignments have no effect.
- In hook mode, request intent must be written before forwarding. A failed write
  prevents forwarding. Hook rejection and hook errors are recorded best effort.
- A response is complete for the hook only when the upstream answered, no upstream
  error occurred, the body was read in full, inspection succeeded, and the
  exchange was forwarded. A client disconnect can trigger a bounded drain in
  hook mode; reaching a capture limit or drain timeout makes capture incomplete.
  Client-facing and upstream statuses are separate observations.

## Streams

- SSE framing accumulates data until an event can be dispatched; malformed UTF-8,
  JSON, or non-object event data is rejected. The parser also accepts compatible
  streams that omit separators between independently complete JSON objects.
- Anthropic content blocks are indexed: a block must start before its deltas and
  stop once; unfinished or contradictory blocks fail inspection.
- OpenAI Responses items and their argument or input fragments are tracked by
  output index. Completion and final output are reconciled against prior action
  evidence; conflicting or incomplete action evidence fails inspection. Chat
  Completions and Gemini use their respective reconstruction rules.
- Stream capture is bounded. A transport ending does not by itself prove that
  every provider protocol terminal marker was observed.

## Hermes and storage

- Hermes sessions track identity and turn count in memory. A step may create a
  session even without a start; an end removes its tracked session. Duplicate
  starts retain existing attribution, and the capacity bound can evict an
  active session. Persistence is best effort, so lifecycle records can be absent.
- Schema migration and chain-mode selection occur in a database transaction. A
  chain started on existing unchained data begins at a boundary; it does not
  retroactively cover earlier rows. A chained database cannot be opened with
  the chain disabled. Local verification alone cannot detect a wholesale
  history rewrite without an independently retained checkpoint.
- A batch is validated and normalized before writing, then committed or rolled
  back as a unit with its chain-head update. Only the same `event_id` and same
  canonical payload are idempotent; `call_id` correlates observations and does
  not deduplicate them.
- Plugin installation replaces each owned file atomically, but the files are not
  installed as one transaction. An interrupted install can require a rerun.
