# Lifecycle invariants

These rules describe the current implementation. They do not promise that every
provider or host sends a complete lifecycle. An audit event is an observation.
It is not proof that a client-side tool ran.

## Servers and exchanges

- **One listener per server.** A `ProxyServer` runs at most one listener.
  A second `start()` fails. A lock on each instance serializes `start()` and
  `stop()`, including the rollback after a failed start.
- **Resource ownership.** `stop()` releases the resources that the server
  opened. It does not close a database that the caller passed in.
- **Request slots.** The HTTP server accepts a request only when a worker slot
  is free. Each worker releases its slot when it ends.
- **One `after_exchange` per entered exchange.** An exchange that enters
  `before_forward` gets exactly one `after_exchange` call. This includes
  rejections and errors. Panoptes marks the exchange finished before it calls
  the hook. A request that Panoptes refuses before the hook gets no callback.
- **Identity freezes.** Panoptes reads the identity when `before_forward`
  returns. Later changes have no effect.
- **Request intent comes first.** With hooks, Panoptes writes the request
  events before it forwards the request. If that write fails, Panoptes does
  not forward. Rejections and hook errors are recorded on a best-effort basis.
- **A complete response.** For a hook, a response is complete only when all of
  these are true: the upstream answered without an error, Panoptes read the
  full body, inspection succeeded, and Panoptes forwarded the exchange.
- **Client disconnects.** With hooks, a client disconnect can start a drain of
  the upstream, with a time limit. If the drain hits its time or size limit,
  the capture is incomplete.
- **Two statuses.** The status sent to the client and the upstream status are
  separate observations.

## Streams

- **SSE framing.** The parser collects data until it has a full event. It
  rejects malformed UTF-8, malformed JSON, and event data that is not a JSON
  object. It also accepts compatible streams that put complete JSON objects
  one after another without separators.
- **Anthropic blocks.** Content blocks have an index. A block must start before
  its deltas and stop once. An unfinished or contradictory block fails
  inspection.
- **OpenAI Responses items.** The parser tracks items and their argument
  fragments by output index. It checks the final output against the earlier
  fragments. Conflicting or incomplete evidence fails inspection.
- **Other protocols.** Chat Completions and Gemini use their own reconstruction
  rules.
- **Bounded capture.** Stream capture has a size limit. The end of the
  transport does not prove that Panoptes saw the provider's final marker.

## Hermes and storage

- **Hermes sessions.** The plugin keeps session identity and turn count in
  memory. A step can create a session without a start event. An end event
  removes the session. A second start keeps the existing attribution. The
  capacity limit can remove an active session. Writes are best-effort, so
  some lifecycle records can be missing.
- **Migrations.** Schema migration and chain-mode selection happen inside one
  database transaction.
- **Chains on old data.** A chain started on existing unchained data begins at
  a boundary. It does not cover earlier rows.
- **Chain mode is fixed.** You cannot open a chained database with the chain
  turned off.
- **Full rewrites.** Local verification cannot find a full rewrite of the
  history. You need a checkpoint stored somewhere else.
- **Batches.** Panoptes validates and normalizes a batch before it writes. It
  commits or rolls back the batch and the chain-head update as one unit.
- **Idempotency.** Only the same `event_id` with the same canonical payload is
  idempotent. `call_id` links observations. It does not remove duplicates.
- **Plugin installation.** The installer replaces each file atomically, but
  not all files in one transaction. If an install stops partway, run it again.

## Known limits

- **Shutdown.** `stop()` waits for open requests only for the configured grace
  period. After that, it closes its resources. A slow exchange can lose its
  final capture.
- **Stopping from a hook.** A hook that calls `stop()` waits for its own
  request until the grace period ends. Let the server owner control the
  lifecycle.
- **Hermes attribution.** Hermes attribution lives in memory and has a size
  limit. Missing callbacks or evicted sessions can leave gaps.
- **Transactions.** Migrations and chain-head changes stay inside SQLite
  transactions. Do not replace them with application flags. Do not attach
  network calls to their commit.
