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
  raised; an identifier is refused, never rewritten.
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
block a writer. In ascending order an event appended during iteration is
included, and no event is yielded twice.

**Event dicts** from reads have the shape above plus `raw_request` and
`raw_response`. For rows an older schema wrote, `correlation_id` is `None` and
`attributes` is `{}`.

## Read-only open

`AuditDB.open_readonly(path)` never creates a file, migrates a schema, starts or
re-anchors a hash chain, changes file mode or writes. Any schema version up to
the current one is readable as it stands; columns an older file lacks read as
empty. It raises `FileNotFoundError` (missing path), `NotAnAuditDatabaseError`
(a `ValueError`: not an initialized Panoptes log) or
`UnsupportedSchemaVersionError` (written by a newer Panoptes). Inserting raises
`sqlite3.OperationalError`.

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

`verify_chain()` always reports `result["chain"]`:

- `"intact"`: verified end to end; `valid` is `True`.
- `"broken"`: tampering or corruption; `valid` is `False`, with `error` and
  `broken_event_id`.
- `"absent"`: the database carries no chain, so nothing was verified; `valid`
  is **always `False`**.

`get_chain_checkpoint()` and `verify_checkpoint(checkpoint)` are unchanged. The
chain is local tamper evidence: a checkpoint stored outside the database is
needed to detect a rewrite of the whole history.

## Errors

| Exception | Meaning |
|---|---|
| `ValidationError` | the event is malformed; nothing was written |
| `IdentifierRewriteError` | strict ingest refused an identifier redaction would change |
| `EventConflictError` | `event_id` reused for a different payload |
| `ChainIntegrityError` | a chain is corrupt, stripped, or would be dropped |
| `UnsupportedSchemaVersionError` | the log is from a newer Panoptes |
| `NotAnAuditDatabaseError` | the path is not an initialized Panoptes log |
