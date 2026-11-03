# Panoptes Python API

Panoptes records what agents and models did and lets you read it back. This is
the supported Python surface for writing events, reading them back and checking
the log. Nothing here needs raw SQL; the table layout is not part of the API.

```python
from panoptes import AuditDB

db = AuditDB("~/.panoptes/audit.db")            # read-write, creates/migrates
log = AuditDB.open_readonly("~/.panoptes/audit.db")   # reads, changes nothing
```

## Event schema (v5)

```python
{
    "event_id": "uuid",                 # optional; generated if absent
    "timestamp": "ISO8601",             # optional; required with event_id
    "event_type": "model_request",      # built-in, or "<namespace>.<name>"
    "correlation_id": "...",            # optional identifier, indexed
    "agent": {
        "type": "my_agent",             # required; any validated identifier
        "session_id": "...",            # required
        "run_id": "...",                # optional; never invented
        "parent_run_id": "...",         # optional; set for a child agent
        "version": "...",
    },
    "user": {"id": "...", "auth_method": "..."},   # optional; no defaults
    "action": {"tool_name": ..., "parameters": {}, "target": ..., "call_id": ...},
    "outcome": {"status": "success|error|blocked|timeout|pending|warned",
                "summary": ..., "error": ...},
    "context": {"schema_version": 5, "turn_number": N, "capture": {}},
    "cost": {"tokens_in": N, "tokens_out": N, "estimated_usd": N},
    "attributes": {},                   # optional open JSON object
}
```

- **Identifiers** (`agent.type`, `session_id`, `run_id`, `parent_run_id`,
  `correlation_id`, `user.id`, `user.auth_method`, `tool_name`, `call_id`,
  `event_id`) are non-empty strings of at most 256 characters with no control
  characters and no secret-shaped content. Otherwise `ValidationError` is
  raised: these are refused, not rewritten. Other fields that name something,
  notably `action.target` and `agent.version`, are **not** refused: a secret
  inside them is redacted in place and the event is stored changed. Use
  [strict ingest](#strict-ingest) to refuse that instead.
- **`agent.type` and `user.auth_method` are open.** `KNOWN_AGENT_TYPES` lists
  the adapters Panoptes ships; it is informational and not enforced.
- **Event types.** The built-in set is closed: `model_request`,
  `model_response`, `tool_call`, `tool_result`, `decision_point`,
  `policy_violation`, `agent_start`, `agent_step`, `agent_end`. Another producer
  names its own events `<namespace>.<name>` (lower-case, for example
  `agentgate.allow`; at most 128 characters). Custom types get no derived
  `data_accessed` tags.
- **`attributes`** is an open JSON object, at most 64 KiB serialized, redacted
  like `context` (secret-shaped keys and values). An empty object is stored as
  absent.
- **`user`** is optional and is stored as `{}` when absent. There is no default
  identity.
- **`correlation_id`** joins events across producers. The proxy sets it from the
  `X-Panoptes-Correlation-Id` request header. It is client-asserted: an
  identifier to join on, not proof of anything.
- **Older schemas.** An event that declares `context.schema_version` 1-4 is
  validated under the rules of that version (closed agent types and auth
  methods, required `run_id`, legacy user defaults, no v5 fields). Stored v1-v4
  rows read and verify unchanged.

## Writing

```python
event_id = db.insert_event(event)
event_ids = db.insert_events([event, ...])     # one transaction
```

Replaying an identical canonical event is idempotent; reusing an `event_id`
for a different payload raises `EventConflictError`. `call_id` is a correlation
field, never a deduplication key.

### Strict ingest

```python
db.insert_event(event, strict=True, strict_paths=("attributes.rule_ids[]",))
```

Redaction is right for free text and wrong for an identifier: a rewritten id
names a different thing. With `strict=True`, an event whose identifier fields
redaction would change raises `IdentifierRewriteError` (a `ValidationError`)
before anything is written, and the error names the field, never the value.
The identifier fields are `panoptes.schema.STRICT_IDENTIFIER_PATHS`
(including `action.target` and `agent.version`, which are otherwise redacted
in place); `strict_paths` adds dotted paths of your own (`[]` means every list
element) and implies `strict`. Free text is still redacted.

## Reading

All read methods work on both `AuditDB(...)` and `AuditDB.open_readonly(...)`.

| Method | Returns |
|---|---|
| `query(**filters, limit=100, offset=0)` | newest-first list of events (limit at most 10,000) |
| `get_session(session_id)` | up to 10,000 events of a session, oldest first |
| `iter_events(*, ..., order="rowid", batch_size=500)` | iterator over every matching event, no row cap |
| `aggregate(group_by, metrics, ...)` | grouped counts, token and cost totals |
| `list_sessions(agent_type=None, limit=50)` | sessions by latest activity |
| `get_evidence_chain(event_id)` | the surrounding exchange of one event |
| `get_stats()` | totals and the file's schema version |

**Filters**, shared by `query`, `iter_events` and `aggregate`: `agent_type`,
`session_id`, `run_id`, `parent_run_id`, `correlation_id`, `event_type`,
`tool_name`, `since`, `until` (ISO8601, inclusive), `data_accessed` (partial
match). An unknown filter name raises `ValueError`; it never silently matches
everything.

**`iter_events`** takes the same filters as keyword arguments plus
`order` (`"rowid"` = the order events were written and chained, `"-rowid"`,
`"timestamp"`, `"-timestamp"`) and `batch_size`. It reads in keyset-paginated
batches, each its own short read, so it holds no transaction open and cannot
block a writer. No event is yielded twice.

Only `"rowid"` order is safe against concurrent appends: an event appended
during iteration always sorts after the cursor, so it is included. In
`"timestamp"` order (either direction) an event inserted mid-iteration with a
timestamp the cursor has already passed is **skipped**, and one inserted at or
after the cursor is included. Iterate by `"rowid"` to read a log that is still
being written.

**Event dicts** from reads have the shape above plus `raw_request` and
`raw_response`. For rows an older schema wrote, `correlation_id` is `None` and
`attributes` is `{}`.

## Read-only open

`AuditDB.open_readonly(path)` never modifies the database file, migrates a
schema, starts or re-anchors a hash chain, or changes a file mode. Any schema
version up to the current one is readable as it stands; columns an older file
lacks read as empty.

**It can create files beside the database.** SQLite needs `-wal` and `-shm`
files to read a database in WAL mode (the mode Panoptes creates), and a
read-only handle cannot remove them when it closes. After a read-only open of a
cleanly closed database you may find an empty `audit.db-wal` and a
`audit.db-shm` next to it. They hold no data and are safe to delete when no
process has the database open; the next writer reuses and then removes them.
Where the directory is not writable:

- a database that already has its `-wal`/`-shm` files can still be read;
- one that does not, raises `ReadOnlyMediaError` (a `RuntimeError`) saying so.
  Copy the database, with any `-wal` file, to a writable directory.

Other errors: `FileNotFoundError` (missing path), `NotAnAuditDatabaseError` (a
`ValueError`: not an initialized Panoptes log, or not a database at all),
`UnsupportedSchemaVersionError` (written by a newer Panoptes). Operational
failures such as a locked file keep their own `sqlite3.OperationalError`.
Inserting raises `sqlite3.OperationalError`.

## Hash chain

`AuditDB(path, chain=None | True | False)`:

| `chain` | New database | Existing chained | Existing unchained |
|---|---|---|---|
| `None` (default) | chained | stays chained | stays unchained |
| `True` | chained | stays chained | starts a chain at this point; existing rows are outside it |
| `False` | unchained | **refused** (`ChainIntegrityError`) | stays unchained |

A chain is never dropped by opening a file differently, and a database whose
chain metadata was deleted is refused rather than re-anchored. An unchained
database records that choice, so stripping a chain is distinguishable from
never having one.

`verify_chain()` always reports `result["chain"]`, and a read-only handle gives
the same answer as a read-write one for the same file:

| `chain` | `valid` | Meaning |
|---|---|---|
| `"intact"` | `True` | verified end to end |
| `"broken"` | `False` | tampering or corruption, or a chain missing from a database that must have one: schema 4+ with no chain metadata, or a "no chain" marker beside a live chain. `error` and `broken_event_id` say where |
| `"partial"` | `False` | the chain is sound but covers no event while events exist outside it (`event_count == 0` and `legacy_event_count > 0`). A chain stripped and restarted looks like this |
| `"absent"` | `False` | the database carries no chain and is not expected to (created unchained, or older than the chain); nothing was verified |

`valid` is never `True` for a log that was not actually verified. An empty
chained database is `"intact"`. A chain covering some events beside older
legacy ones is `"intact"` with `coverage: "partial"`, which is disclosed.

`get_chain_checkpoint()` returns the chain head with `chain: "present"`, or
`chain: "absent"` and `initialized: False` for an unchained database. It raises
`ChainIntegrityError` for the same inconsistent states `verify_chain` calls
`"broken"`. `verify_checkpoint(checkpoint)` is unchanged and ignores the extra
key in a stored checkpoint.

**What the chain does not protect against.** The chain, its metadata and the
"created unchained" marker all live in the same SQLite file, so anyone who can
write the file can delete the chain, null the hashes and add the marker (or
re-chain the rewritten history). The result is detected when it leaves
`event_count == 0` with events outside the chain (`"partial"`), but a
well-formed rewrite of the whole history is not detectable from the file alone.
To detect that, store a checkpoint (`get_chain_checkpoint()`: `head`,
`event_count`, `anchor`) **outside the database**, in a store the writer cannot
alter, and verify with `verify_checkpoint`. Do that periodically if the log is
evidence.

## Pricing

Panoptes prices a response as an annotation (`cost.estimated_usd`,
`cost.pricing_version`); it enforces nothing with it. A consumer that reserves
or settles money against the same rate table (agentgate does) relies on the
format and the rounding below. They are **stable**: a change that alters a
figure for an existing table is a breaking change, announced in the changelog
and a version bump.

**Rate table** (JSON, loaded with `PricingTable.load(path)` or
`PricingTable.from_dict(obj)`):

```json
{
  "version": "2026-11-01",
  "source": "https://provider.example/pricing",
  "currency": "USD",
  "models": {
    "gpt-example": {
      "input_per_million": "0.15",
      "cached_input_per_million": "0.075",
      "output_per_million": "0.60"
    }
  }
}
```

`currency` must be `"USD"`; `version` and `source` are required non-empty
strings; every model names all three rates, finite and non-negative. Rates may
be JSON numbers or strings and are read as exact decimals. A malformed table
raises `PricingError`. Models are matched by exact name.

**Formula** (`PricingTable.cost_micros(model, cost)`), with the response's
`cost` counts:

```
billed_in = tokens_in - cached_input_tokens + tool_prompt_tokens
usd = (billed_in * input + cached_input_tokens * cached_input
       + tokens_out * output) / 1_000_000
```

`tokens_out` already includes reasoning tokens. Absent optional counts
(`cached_input_tokens`, `tool_prompt_tokens`) are zero, which never
under-counts. The result is `None` (unpriced) when the model is not in the
table, `tokens_in` or `tokens_out` is missing or invalid, or
`cached_input_tokens > tokens_in`. Panoptes never guesses a rate.

**Rounding.** The whole response is priced exactly in decimal, then rounded
**up** once to a whole micro-dollar (`ROUND_CEILING`): the figure never
under-counts, and any response whose exact price is above zero costs at least
one micro-dollar. `cost.estimated_usd` is that integer divided by
1,000,000 as a float; use the integer for money. `usd_to_micros(amount)`
applies the same rule to a dollar amount (positive, finite), and
`MICROS_PER_USD` is 1,000,000. Public names in `panoptes.pricing`:
`PricingTable`, `PricingError`, `usd_to_micros`, `MICROS_PER_USD`.

## Errors

| Exception | Meaning |
|---|---|
| `ValidationError` | the event is malformed; nothing was written |
| `IdentifierRewriteError` | strict ingest refused an identifier redaction would change |
| `EventConflictError` | `event_id` reused for a different payload |
| `ChainIntegrityError` | a chain is corrupt, stripped, or would be dropped |
| `UnsupportedSchemaVersionError` | the log is from a newer Panoptes |
| `ReadOnlyMediaError` | a WAL database cannot be read because its directory is not writable and it lacks `-wal`/`-shm` files |
| `NotAnAuditDatabaseError` | the path is not an initialized Panoptes log |
