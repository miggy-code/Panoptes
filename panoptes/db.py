"""SQLite storage, querying, evidence paths, and local tamper evidence."""

import hashlib
import json
import logging
import os
import secrets
import sqlite3
import stat
import threading
from typing import Any, Dict, List, Optional, Tuple

from .schema import (
    SCHEMA_VERSION,
    ValidationError,
    _redact_capture_metadata,
    extract_index_fields,
    normalize_event,
    redact_secrets,
    validate_event,
)

log = logging.getLogger("panoptes.db")

# ── SQL DDL ───────────────────────────────────────────────────────────────────

CREATE_SCHEMA_VERSION = """
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL DEFAULT (datetime('now'))
)
"""

CREATE_EVENTS = """
CREATE TABLE IF NOT EXISTS events (
    event_id        TEXT PRIMARY KEY,
    timestamp       TEXT    NOT NULL,
    agent_type      TEXT    NOT NULL DEFAULT 'unknown',
    session_id      TEXT    NOT NULL,
    run_id          TEXT,
    event_type      TEXT    NOT NULL,
    tool_name       TEXT,
    data_accessed   TEXT    DEFAULT '',
    call_id         TEXT    DEFAULT '',

    -- JSON columns (stored as TEXT)
    agent           TEXT    NOT NULL,
    user_info       TEXT    NOT NULL,
    action          TEXT    NOT NULL,
    outcome         TEXT    NOT NULL,
    context         TEXT    NOT NULL,
    cost            TEXT    NOT NULL,
    raw_request     TEXT,
    raw_response    TEXT,

    -- Tamper-evidence hash chain (v3; populated atomically on every insert)
    prev_hash       TEXT,
    event_hash      TEXT
)
"""

# ── v3 hash-chain metadata ───────────────────────────────────────────

CREATE_CHAIN_META = """
CREATE TABLE IF NOT EXISTS chain_meta (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
)
"""

CREATE_INDICES = [
    "CREATE INDEX IF NOT EXISTS idx_events_agent_type   ON events(agent_type)",
    # idx_events_session_id is omitted for new DBs: the covering index below
    # (session_id, timestamp) satisfies all session-id-only queries via its
    # left-most prefix.  Old DBs may still carry the standalone index — fine.
    "CREATE INDEX IF NOT EXISTS idx_events_session_ts   ON events(session_id, timestamp)",
    "CREATE INDEX IF NOT EXISTS idx_events_event_type   ON events(event_type)",
    "CREATE INDEX IF NOT EXISTS idx_events_timestamp    ON events(timestamp)",
    "CREATE INDEX IF NOT EXISTS idx_events_tool_name    ON events(tool_name)",
    "CREATE INDEX IF NOT EXISTS idx_events_run_id       ON events(run_id)",
    "CREATE INDEX IF NOT EXISTS idx_events_data_accessed ON events(data_accessed)",
    # idx_events_call_id is created after ensuring the call_id column exists.
]

CREATE_CALL_ID_INDEX = (
    "CREATE INDEX IF NOT EXISTS idx_events_call_id ON events(call_id)"
)

# Historical builds treated call_id as an idempotency key. That loses audit
# evidence when the same provider call is delivered or executed more than once:
# those occurrences are exactly what a visibility layer must retain. v4 drops
# the uniqueness constraint and keeps call_id as a non-unique correlation key.
DROP_DEDUP_INDEX = "DROP INDEX IF EXISTS idx_events_dedup"

# Shared INSERT statement used by both insert_event and insert_events. Conflict
# handling is deliberately explicit in insert_events(): broad OR IGNORE would
# also suppress primary-key and NOT NULL failures, which is unacceptable for an
# audit log.
_INSERT_SQL = """
INSERT INTO events (
    event_id, timestamp, agent_type, session_id, run_id,
    event_type, tool_name, data_accessed, call_id,
    agent, user_info, action, outcome, context, cost,
    raw_request, raw_response, prev_hash, event_hash
) VALUES (
    ?, ?, ?, ?, ?,
    ?, ?, ?, ?,
    ?, ?, ?, ?, ?, ?,
    ?, ?, ?, ?
)
"""

# ── Helpers ───────────────────────────────────────────────────────────────────

_EVENT_PAYLOAD_COLUMNS = (
    "event_id", "timestamp", "agent_type", "session_id", "run_id",
    "event_type", "tool_name", "data_accessed", "call_id",
    "agent", "user_info", "action", "outcome", "context", "cost",
    "raw_request", "raw_response",
)
_EVENT_JSON_COLUMNS = frozenset({
    "agent", "user_info", "action", "outcome", "context", "cost",
})

_CHAIN_FORMAT_VERSION = "1"
_CHAIN_ALGORITHM = "sha256"
_CHAIN_META_KEYS = frozenset({
    "chain_format_version",
    "chain_algorithm",
    "chain_anchor",
    "chain_head",
    "chain_event_count",
    "chain_legacy_event_count",
    "chain_started_at",
    "chain_first_event_id",
    "chain_last_event_id",
})


class EventConflictError(ValueError):
    """Raised when an event_id is reused for a different canonical event."""


class ChainIntegrityError(RuntimeError):
    """Raised when new events cannot safely append to a corrupt hash chain."""


class UnsupportedSchemaVersionError(RuntimeError):
    """Raised when a database was created by a newer Panoptes schema."""


def _serialize(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False)


def _input_requires_redaction(event: Dict[str, Any]) -> bool:
    """Whether canonicalization would erase a distinction in this input.

    An existing redacted row cannot prove that a second raw secret equals the
    first raw secret. Treating such a retry as identical could silently discard
    a distinct sensitive action. Canonical rows read back from AuditDB remain
    replayable because their sensitive values are already placeholders.
    """
    redacted = redact_secrets(event)
    context = event.get("context")
    if isinstance(context, dict) and "capture" in context:
        # ``authorization_check`` is a safe hook-phase label within capture
        # metadata, not an HTTP credential. Match normalize_event's contextual
        # treatment so a canonical authorization decision remains replayable.
        redacted_context = redacted.get("context")
        if isinstance(redacted_context, dict):
            redacted_context["capture"] = _redact_capture_metadata(
                context["capture"]
            )
    return redacted != event


def _canonical_json(value: Any) -> str:
    """Return deterministic JSON used for equality and chain hashing."""
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def _deserialize(raw: Optional[str]) -> Optional[Dict[str, Any]]:
    if raw is None:
        return None
    return json.loads(raw)


def _row_to_event(row: sqlite3.Row) -> Dict[str, Any]:
    """Convert a SQLite row to the canonical event dict."""
    return {
        "event_id": row["event_id"],
        "timestamp": row["timestamp"],
        "agent": _deserialize(row["agent"]),
        "user": _deserialize(row["user_info"]),
        "event_type": row["event_type"],
        "action": _deserialize(row["action"]),
        "outcome": _deserialize(row["outcome"]),
        "context": _deserialize(row["context"]),
        "cost": _deserialize(row["cost"]),
        "raw_request": row["raw_request"],
        "raw_response": row["raw_response"],
    }


def _as_sql_text(value: Any) -> Optional[str]:
    """Coerce a value to the representation SQLite stores in a TEXT column."""
    return None if value is None else str(value)


def _raw_payload_text(value: Any) -> Optional[str]:
    """Store structured raw payloads as JSON while preserving existing strings."""
    if value is None or isinstance(value, str):
        return value
    return _serialize(value)


def _build_params(normalized: Dict[str, Any], flat: Dict[str, Any]) -> tuple:
    """Build the non-hash SQL values for one event INSERT."""
    return (
        _as_sql_text(normalized["event_id"]),
        _as_sql_text(normalized["timestamp"]),
        _as_sql_text(flat["agent_type"]),
        _as_sql_text(flat["session_id"]),
        _as_sql_text(flat["run_id"]),
        _as_sql_text(normalized["event_type"]),
        _as_sql_text(flat["tool_name"]),
        _as_sql_text(flat["data_accessed"]),
        _as_sql_text(flat["call_id"]) or "",
        _serialize(normalized["agent"]),
        _serialize(normalized["user"]),
        _serialize(normalized["action"]),
        _serialize(normalized["outcome"]),
        _serialize(normalized["context"]),
        _serialize(normalized["cost"]),
        _raw_payload_text(normalized.get("raw_request")),
        _raw_payload_text(normalized.get("raw_response")),
    )


def _canonical_payload_from_values(values: tuple) -> Dict[str, Any]:
    """Build the canonical event payload from values destined for SQLite."""
    payload: Dict[str, Any] = dict(zip(_EVENT_PAYLOAD_COLUMNS, values))
    for column in _EVENT_JSON_COLUMNS:
        payload[column] = json.loads(payload[column])
    return payload


def _canonical_payload_from_row(row: sqlite3.Row) -> Dict[str, Any]:
    """Build the canonical event payload from a stored SQLite row."""
    values = tuple(row[column] for column in _EVENT_PAYLOAD_COLUMNS)
    return _canonical_payload_from_values(values)


def _event_hash(prev_hash: str, payload: Dict[str, Any]) -> str:
    """Hash one canonical event and its predecessor with an unambiguous frame."""
    material = _canonical_json({
        "event": payload,
        "prev_hash": prev_hash,
    }).encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def _read_chain_meta(conn: sqlite3.Connection) -> Dict[str, str]:
    placeholders = ", ".join("?" for _ in _CHAIN_META_KEYS)
    rows = conn.execute(
        f"SELECT key, value FROM chain_meta WHERE key IN ({placeholders})",
        tuple(sorted(_CHAIN_META_KEYS)),
    )
    return {row["key"]: row["value"] for row in rows}


def _checkpoint_from_meta(meta: Dict[str, str]) -> Dict[str, Any]:
    missing = _CHAIN_META_KEYS - set(meta)
    if missing:
        raise ChainIntegrityError(
            f"Hash-chain metadata is incomplete; missing: {sorted(missing)}"
        )
    try:
        event_count = int(meta["chain_event_count"])
        legacy_event_count = int(meta["chain_legacy_event_count"])
    except (TypeError, ValueError) as exc:
        raise ChainIntegrityError("Hash-chain counts are not valid integers") from exc
    if event_count < 0 or legacy_event_count < 0:
        raise ChainIntegrityError("Hash-chain counts cannot be negative")
    return {
        "initialized": True,
        "format_version": meta["chain_format_version"],
        "algorithm": meta["chain_algorithm"],
        "anchor": meta["chain_anchor"],
        "head": meta["chain_head"],
        "event_count": event_count,
        "legacy_event_count": legacy_event_count,
        "started_at": meta["chain_started_at"],
        "first_event_id": meta["chain_first_event_id"] or None,
        "last_event_id": meta["chain_last_event_id"] or None,
        "coverage": "partial" if legacy_event_count else "complete",
        "checkpoint_scope": "database_internal",
        "external_anchor_required": True,
    }


def _initialize_chain(conn: sqlite3.Connection) -> Dict[str, Any]:
    """Create a chain boundary without retroactively blessing legacy rows."""
    hashed_count = conn.execute(
        "SELECT COUNT(*) FROM events WHERE event_hash IS NOT NULL"
    ).fetchone()[0]
    partial_count = conn.execute(
        """
        SELECT COUNT(*) FROM events
        WHERE (prev_hash IS NULL AND event_hash IS NOT NULL)
           OR (prev_hash IS NOT NULL AND event_hash IS NULL)
        """
    ).fetchone()[0]
    if hashed_count or partial_count:
        raise ChainIntegrityError(
            "Hashed events exist but hash-chain metadata is missing"
        )

    legacy_count = conn.execute(
        "SELECT COUNT(*) FROM events WHERE prev_hash IS NULL AND event_hash IS NULL"
    ).fetchone()[0]
    anchor = secrets.token_hex(32)
    started_at = conn.execute(
        "SELECT strftime('%Y-%m-%dT%H:%M:%fZ', 'now')"
    ).fetchone()[0]
    values = {
        "chain_format_version": _CHAIN_FORMAT_VERSION,
        "chain_algorithm": _CHAIN_ALGORITHM,
        "chain_anchor": anchor,
        "chain_head": anchor,
        "chain_event_count": "0",
        "chain_legacy_event_count": str(legacy_count),
        "chain_started_at": started_at,
        "chain_first_event_id": "",
        "chain_last_event_id": "",
    }
    conn.executemany(
        "INSERT INTO chain_meta (key, value) VALUES (?, ?)",
        values.items(),
    )
    return _checkpoint_from_meta(values)


def _load_chain_for_append(conn: sqlite3.Connection) -> Dict[str, Any]:
    """Load and minimally validate the chain head while holding a write lock.

    Appends are on the ingestion hot path.  Full-table count/link validation
    belongs to ``verify_chain()``; doing it before every insert makes capture
    O(total_history) per exchange and eventually turns the audit control into
    its own denial of service.  The metadata and event insert are committed in
    one ``BEGIN IMMEDIATE`` transaction, so an append only needs to validate
    that the indexed last event still anchors the recorded head.
    """
    meta = _read_chain_meta(conn)
    checkpoint = _checkpoint_from_meta(meta) if meta else _initialize_chain(conn)
    if (
        checkpoint["format_version"] != _CHAIN_FORMAT_VERSION
        or checkpoint["algorithm"] != _CHAIN_ALGORITHM
    ):
        raise ChainIntegrityError(
            "Unsupported hash-chain format "
            f"{checkpoint['format_version']!r}/{checkpoint['algorithm']!r}"
        )

    if checkpoint["event_count"] == 0:
        if checkpoint["head"] != checkpoint["anchor"]:
            raise ChainIntegrityError("Empty hash chain has a non-anchor head")
        if (
            checkpoint["first_event_id"] is not None
            or checkpoint["last_event_id"] is not None
        ):
            raise ChainIntegrityError("Empty hash chain has event boundaries")
    else:
        if (
            checkpoint["first_event_id"] is None
            or checkpoint["last_event_id"] is None
        ):
            raise ChainIntegrityError("Non-empty hash chain is missing boundaries")
        head = conn.execute(
            "SELECT prev_hash, event_hash FROM events WHERE event_id = ?",
            (checkpoint["last_event_id"],),
        ).fetchone()
        if head is None:
            raise ChainIntegrityError("Hash-chain last event is missing")
        if head["prev_hash"] is None or head["event_hash"] is None:
            raise ChainIntegrityError("Hash-chain last event is not fully chained")
        if head["event_hash"] != checkpoint["head"]:
            raise ChainIntegrityError(
                "Hash-chain last event does not match the recorded head"
            )
    return checkpoint


def _persist_chain_checkpoint(
    conn: sqlite3.Connection,
    checkpoint: Dict[str, Any],
) -> None:
    updates = {
        "chain_head": checkpoint["head"],
        "chain_event_count": str(checkpoint["event_count"]),
        "chain_first_event_id": checkpoint["first_event_id"] or "",
        "chain_last_event_id": checkpoint["last_event_id"] or "",
    }
    conn.executemany(
        "UPDATE chain_meta SET value = ? WHERE key = ?",
        ((value, key) for key, value in updates.items()),
    )


def _reject_symlink(path: str, label: str = "database") -> None:
    """Reject an existing symlink without following it."""
    try:
        mode = os.lstat(path).st_mode
    except FileNotFoundError:
        return
    if stat.S_ISLNK(mode):
        raise ValueError(f"Refusing to use symlink {label} path: {path}")


def _restrict_file_permissions(path: str) -> None:
    """Cap an existing regular file at 0600 without adding permissions."""
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return
    if stat.S_ISLNK(info.st_mode):
        raise ValueError(f"Refusing to use symlink database file: {path}")
    if not stat.S_ISREG(info.st_mode):
        raise ValueError(f"Database storage path is not a regular file: {path}")
    current = stat.S_IMODE(info.st_mode)
    restricted = current & 0o600
    if restricted != current:
        os.chmod(path, restricted)


def _prepare_database_path(path: str) -> None:
    """Create local database storage with owner-only default permissions."""
    if path == ":memory:":
        return

    parent = os.path.dirname(path) or "."
    os.makedirs(parent, mode=0o700, exist_ok=True)
    _reject_symlink(path)
    if not os.path.exists(path):
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            fd = os.open(path, flags, 0o600)
        except FileExistsError:
            # Another Panoptes process may have won the creation race.
            _reject_symlink(path)
        else:
            os.close(fd)
    _restrict_file_permissions(path)


def _restrict_database_files(path: str) -> None:
    """Restrict the main DB and any currently present WAL/SHM sidecars."""
    if path == ":memory:":
        return
    for candidate in (path, f"{path}-wal", f"{path}-shm"):
        _restrict_file_permissions(candidate)


_FILTER_FIELDS = ("agent_type", "session_id", "run_id", "event_type", "tool_name")
MAX_QUERY_LIMIT = 10_000
MAX_QUERY_OFFSET = 10_000_000


def _validate_page_value(
    value: Any,
    name: str,
    *,
    minimum: int,
    maximum: int,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be an integer")
    if value < minimum or value > maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return value


def _build_filter_clause(filters: Dict[str, Any]) -> Tuple[str, List[Any]]:
    """Build a WHERE clause + params from the shared filter semantics.

    Supports equality filters (_FILTER_FIELDS), since/until timestamp
    bounds, and data_accessed partial match. Returns ("", []) if no
    filters are set.
    """
    conditions: List[str] = []
    params: List[Any] = []

    for field in _FILTER_FIELDS:
        if filters.get(field) is not None:
            conditions.append(f"{field} = ?")
            params.append(filters[field])

    if filters.get("since") is not None:
        conditions.append("timestamp >= ?")
        params.append(filters["since"])
    if filters.get("until") is not None:
        conditions.append("timestamp <= ?")
        params.append(filters["until"])
    if filters.get("data_accessed") is not None:
        conditions.append("data_accessed LIKE ?")
        params.append(f"%{filters['data_accessed']}%")

    where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    return where_clause, params


def _ensure_schema(db: "AuditDB") -> None:
    """Create tables and indices if they don't exist; migrate if needed.

    Migration path:
      v0 → v2 (fresh DB): CREATE_EVENTS already includes call_id column;
                           correlation index created after standard indices.
      v1 → v2 (existing DB without call_id): ALTER TABLE to add call_id,
                           backfill from action JSON, then create its index.
      v2 → v3: add prev_hash/event_hash columns to events (nullable — the
                           hash chain starts at the migration boundary, never
                           retroactively), plus chain_meta.
      v3 → v4: drop the legacy call_id uniqueness constraint. call_id is a
                           correlation key; every distinct event is retained.
    """
    conn = db._get_conn()
    try:
        # Schema changes and the chain boundary must be observed atomically by
        # every process opening the same database.
        conn.execute("BEGIN IMMEDIATE")
        conn.execute(CREATE_SCHEMA_VERSION)

        # Reject a newer database before interpreting or mutating its event
        # schema. In particular, do not try to create today's indexes against
        # a future events table whose columns may have changed.
        cur = conn.execute("SELECT MAX(version) FROM schema_version")
        row = cur.fetchone()
        current = row[0] if row and row[0] is not None else 0
        if current > SCHEMA_VERSION:
            raise UnsupportedSchemaVersionError(
                f"Database schema version {current} is newer than supported "
                f"version {SCHEMA_VERSION}; refusing to open it"
            )

        conn.execute(CREATE_EVENTS)
        for idx_sql in CREATE_INDICES:
            conn.execute(idx_sql)

        if current < 2:
            # ── v1 → v2: add call_id column if missing ────────────────────
            col_names = {r[1] for r in conn.execute("PRAGMA table_info(events)")}
            if "call_id" not in col_names:
                conn.execute("ALTER TABLE events ADD COLUMN call_id TEXT DEFAULT ''")

                # Backfill only true provider/host call IDs. A target is a
                # resource, not an idempotency key: repeated legitimate calls
                # may act on the same file, URL, or database.
                conn.execute("""
                    UPDATE events
                    SET call_id = COALESCE(
                        NULLIF(json_extract(action, '$.call_id'), ''), ''
                    )
                    WHERE event_type IN ('tool_call', 'tool_result')
                """)

            # call_id supports correlation queries, never event suppression.
            conn.execute(CREATE_CALL_ID_INDEX)

        if current < 3:
            # ── v2 → v3: hash-chain columns on events ─────────────────────
            col_names = {r[1] for r in conn.execute("PRAGMA table_info(events)")}
            if "prev_hash" not in col_names:
                conn.execute("ALTER TABLE events ADD COLUMN prev_hash TEXT")
            if "event_hash" not in col_names:
                conn.execute("ALTER TABLE events ADD COLUMN event_hash TEXT")

        # Remove the obsolete uniqueness constraint before correcting legacy
        # call IDs: multiple target-derived keys can legitimately converge on
        # one explicit provider call ID.
        conn.execute(DROP_DEDUP_INDEX)

        # Old v2 builds inferred call_id from action.target. Correct only
        # unchained legacy rows; chained rows must never be rewritten.
        conn.execute("""
            UPDATE events
            SET call_id = COALESCE(
                NULLIF(json_extract(action, '$.call_id'), ''), ''
            )
            WHERE event_hash IS NULL
              AND event_type IN ('tool_call', 'tool_result')
        """)

        # The non-unique correlation index is an invariant, not a one-shot
        # migration side effect.
        conn.execute(CREATE_CALL_ID_INDEX)

        # v3 hash-chain metadata (idempotent; also covers fresh DBs)
        conn.execute(CREATE_CHAIN_META)

        # Establish the boundary at migration/open time, not at some later
        # first insert. Existing rows remain explicitly outside chain coverage.
        chain_meta = _read_chain_meta(conn)
        if chain_meta:
            _checkpoint_from_meta(chain_meta)
        else:
            _initialize_chain(conn)

        if current < SCHEMA_VERSION:
            conn.execute(
                "INSERT INTO schema_version (version) VALUES (?)",
                (SCHEMA_VERSION,),
            )
        conn.commit()
    finally:
        db._put_conn(conn)


# ── AuditDB ───────────────────────────────────────────────────────────────────

class AuditDB:
    """Thread-safe SQLite storage for the canonical Panoptes audit trail."""

    # Columns returned by SELECT * (order matters for _row_to_event)
    _EVENT_COLUMNS = [
        "event_id", "timestamp", "agent_type", "session_id", "run_id",
        "event_type", "tool_name", "data_accessed", "call_id",
        "agent", "user_info", "action", "outcome", "context", "cost",
        "raw_request", "raw_response",
    ]

    def __init__(self, db_path: str = "~/.panoptes/audit.db"):
        self._db_path = os.path.expanduser(db_path)
        self._is_memory = self._db_path == ":memory:"
        self._connect_path = (
            f"file:panoptes-{secrets.token_hex(16)}?mode=memory&cache=shared"
            if self._is_memory else self._db_path
        )
        _prepare_database_path(self._db_path)

        # Connections are scoped to one database operation. ThreadingHTTPServer
        # creates short-lived request threads, so retaining a thread-local
        # connection would leak one connection per completed request.
        self._all_conns: set = set()
        self._conns_lock = threading.Lock()
        self._keeper_conn: Optional[sqlite3.Connection] = None

        try:
            # A named shared-memory database exists only while at least one
            # connection remains open. Keep one private connection alive so
            # operation-scoped connections all observe the same schema/data.
            if self._is_memory:
                self._keeper_conn = sqlite3.connect(
                    self._connect_path,
                    timeout=5.0,
                    check_same_thread=False,
                    uri=True,
                )
                self._keeper_conn.row_factory = sqlite3.Row
                self._keeper_conn.execute("PRAGMA foreign_keys=ON")
                self._keeper_conn.execute("PRAGMA busy_timeout=5000")

            # WAL is a persistent database property — set it once here. SQLite
            # keeps its in-memory journal mode for the shared-memory variant.
            conn = self._get_conn()
            try:
                conn.execute("PRAGMA journal_mode=WAL")
                conn.execute("PRAGMA foreign_keys=ON")
                conn.commit()
                _restrict_database_files(self._db_path)
            finally:
                self._put_conn(conn)

            # Run migrations / create tables
            _ensure_schema(self)
        except Exception:
            self.close()
            raise

    # ── Thread-safe connection management ─────────────────────────────────

    def _get_conn(self) -> sqlite3.Connection:
        """Open a connection owned by the current database operation."""
        if not self._is_memory:
            _reject_symlink(self._db_path)
            _reject_symlink(f"{self._db_path}-wal", "WAL")
            _reject_symlink(f"{self._db_path}-shm", "SHM")
        conn = sqlite3.connect(
            self._connect_path,
            timeout=5.0,
            check_same_thread=False,
            uri=self._is_memory,
        )
        try:
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute("PRAGMA busy_timeout=5000")
            if not self._is_memory:
                _restrict_database_files(self._db_path)
        except Exception:
            conn.close()
            raise
        with self._conns_lock:
            self._all_conns.add(conn)
        return conn

    def _put_conn(self, conn: sqlite3.Connection) -> None:
        """Close and forget an operation-scoped connection."""
        with self._conns_lock:
            self._all_conns.discard(conn)
        conn.close()

    def close(self) -> None:
        """Close all connections opened by this AuditDB, across all threads."""
        with self._conns_lock:
            conns, self._all_conns = self._all_conns, set()
            keeper, self._keeper_conn = self._keeper_conn, None
        for conn in conns:
            try:
                conn.close()
            except sqlite3.Error:
                pass
        if keeper is not None:
            try:
                keeper.close()
            except sqlite3.Error:
                pass

    # ── Insert ────────────────────────────────────────────────────────────

    def insert_events(self, events: List[Dict[str, Any]]) -> List[str]:
        """Validate, normalize, and insert a batch of events in one transaction.

        Returns a list of event_ids in the same order as *events*.

        Idempotency is intentionally limited to an identical canonical payload
        with the same stable event_id. Raw inputs changed by redaction cannot be
        proven identical to an existing redacted row and therefore conflict on
        retry; a canonical row returned by AuditDB remains replayable. call_id is
        correlation metadata, so repeated deliveries/executions with distinct
        event_ids are all stored.

        On any exception the whole batch is rolled back and the exception
        re-raised.  ValidationError from an individual event aborts the batch
        before any DB writes occur.

        A caller-supplied event_id also requires a caller-supplied timestamp.
        Otherwise normalization would generate a different timestamp on retry,
        making canonical idempotency ambiguous.
        """
        # Step 1: validate + normalize ALL events before touching the DB.
        # A ValidationError here means no DB state has changed yet.
        prepared: List[tuple] = []  # (normalized, flat, input_requires_redaction)
        for event in events:
            warnings = validate_event(event)  # raises ValidationError if invalid
            if event.get("event_id") and not event.get("timestamp"):
                raise ValidationError(
                    "timestamp is required when event_id is provided; "
                    "stable event replay requires a stable canonical timestamp"
                )
            if warnings:
                log.debug(
                    "Event validation warnings (event_id=%s): %s",
                    event.get("event_id"), warnings,
                )
            normalized = normalize_event(event)
            # Normalization is part of the trust boundary too. Revalidate its
            # output so a classifier/defaulting regression cannot smuggle a
            # non-schema or non-JSON value into the immutable audit trail.
            validate_event(normalized)
            flat = extract_index_fields(normalized)
            prepared.append((normalized, flat, _input_requires_redaction(event)))

        # Step 2: serialize writers with BEGIN IMMEDIATE. Reading and updating
        # the chain head must be one transaction across threads and processes;
        # otherwise concurrent writers can create a fork.
        conn = self._get_conn()
        try:
            if not prepared:
                return []

            conn.execute("BEGIN IMMEDIATE")
            event_ids: List[str] = []
            checkpoint: Optional[Dict[str, Any]] = None
            payload_columns = ", ".join(_EVENT_PAYLOAD_COLUMNS)

            for normalized, flat, input_requires_redaction in prepared:
                # Defense in depth while schema adapters transition away from
                # legacy target-based call IDs: only preserve an explicit
                # provider/host call ID as correlation metadata.
                action = normalized.get("action", {}) or {}
                flat["call_id"] = action.get("call_id") or ""

                values = _build_params(normalized, flat)
                payload = _canonical_payload_from_values(values)
                event_id = values[0]

                # event_id replay is idempotent only when every canonical
                # persisted field matches. A different payload is evidence of
                # an upstream collision or attempted history rewrite.
                existing = conn.execute(
                    f"SELECT {payload_columns} FROM events WHERE event_id = ?",
                    (event_id,),
                ).fetchone()
                if existing is not None:
                    if input_requires_redaction:
                        raise EventConflictError(
                            f"event_id {event_id!r} already exists and the "
                            "incoming raw payload contains redacted material; "
                            "secret-bearing retries cannot be proven identical"
                        )
                    if (
                        _canonical_json(_canonical_payload_from_row(existing))
                        != _canonical_json(payload)
                    ):
                        raise EventConflictError(
                            f"event_id {event_id!r} already exists with a "
                            "different canonical payload"
                        )
                    event_ids.append(existing["event_id"])
                    continue

                if checkpoint is None:
                    checkpoint = _load_chain_for_append(conn)

                prev_hash = checkpoint["head"]
                digest = _event_hash(prev_hash, payload)
                conn.execute(_INSERT_SQL, values + (prev_hash, digest))

                checkpoint["head"] = digest
                checkpoint["event_count"] += 1
                if checkpoint["first_event_id"] is None:
                    checkpoint["first_event_id"] = event_id
                checkpoint["last_event_id"] = event_id
                event_ids.append(event_id)

            if checkpoint is not None:
                _persist_chain_checkpoint(conn, checkpoint)
            conn.commit()
            return event_ids

        except Exception:
            conn.rollback()
            raise
        finally:
            self._put_conn(conn)

    def insert_event(self, event: Dict[str, Any]) -> str:
        """Validate, normalize, and insert a single event. Returns the event_id.

        Delegates to insert_events for a single-element batch so that both
        methods share the same code path (validation, normalization, conflict,
        rollback on error).

        Raises ValidationError if required fields are missing or invalid.
        """
        return self.insert_events([event])[0]

    # ── Tamper-evidence hash chain ────────────────────────────────────────

    def get_chain_checkpoint(self) -> Dict[str, Any]:
        """Return the current chain head and its honest coverage boundary.

        This checkpoint is internal to the same mutable SQLite database. It
        detects partial/accidental tampering, but a privileged attacker able to
        rewrite both events and chain_meta can forge a replacement history.
        Persist ``head`` and ``event_count`` in an external signed/WORM system
        when the checkpoint must survive full local-database compromise.
        """
        conn = self._get_conn()
        try:
            conn.execute("BEGIN")
            meta = _read_chain_meta(conn)
            if meta:
                checkpoint = _checkpoint_from_meta(meta)
            else:
                legacy_count = conn.execute(
                    "SELECT COUNT(*) FROM events "
                    "WHERE prev_hash IS NULL AND event_hash IS NULL"
                ).fetchone()[0]
                hashed_count = conn.execute(
                    "SELECT COUNT(*) FROM events "
                    "WHERE prev_hash IS NOT NULL OR event_hash IS NOT NULL"
                ).fetchone()[0]
                if hashed_count:
                    raise ChainIntegrityError(
                        "Hashed events exist but hash-chain metadata is missing"
                    )
                checkpoint = {
                    "initialized": False,
                    "format_version": _CHAIN_FORMAT_VERSION,
                    "algorithm": _CHAIN_ALGORITHM,
                    "anchor": None,
                    "head": None,
                    "event_count": 0,
                    "legacy_event_count": legacy_count,
                    "started_at": None,
                    "first_event_id": None,
                    "last_event_id": None,
                    "coverage": "none",
                    "checkpoint_scope": "database_internal",
                    "external_anchor_required": True,
                }
            conn.commit()
            return checkpoint
        except Exception:
            conn.rollback()
            raise
        finally:
            self._put_conn(conn)

    def verify_chain(self) -> Dict[str, Any]:
        """Verify links, canonical event hashes, head, count, and boundary.

        Returns a structured result instead of raising for detected tampering,
        so callers can report the first broken event. Operational SQLite errors
        still propagate.
        """
        conn = self._get_conn()
        try:
            conn.execute("BEGIN")
            meta = _read_chain_meta(conn)
            total = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            partial_count = conn.execute(
                """
                SELECT COUNT(*) FROM events
                WHERE (prev_hash IS NULL AND event_hash IS NOT NULL)
                   OR (prev_hash IS NOT NULL AND event_hash IS NULL)
                """
            ).fetchone()[0]
            chained_count = conn.execute(
                "SELECT COUNT(*) FROM events "
                "WHERE prev_hash IS NOT NULL AND event_hash IS NOT NULL"
            ).fetchone()[0]
            legacy_count = total - chained_count - partial_count

            if not meta:
                result = {
                    "valid": not (partial_count or chained_count),
                    "initialized": False,
                    "format_version": _CHAIN_FORMAT_VERSION,
                    "algorithm": _CHAIN_ALGORITHM,
                    "anchor": None,
                    "head": None,
                    "event_count": 0,
                    "legacy_event_count": legacy_count,
                    "started_at": None,
                    "first_event_id": None,
                    "last_event_id": None,
                    "coverage": "none",
                    "checkpoint_scope": "database_internal",
                    "external_anchor_required": True,
                    "checked_events": 0,
                    "broken_event_id": None,
                    "error": (
                        "Hashed events exist without hash-chain metadata"
                        if partial_count or chained_count else None
                    ),
                }
                conn.commit()
                return result

            try:
                checkpoint = _checkpoint_from_meta(meta)
            except ChainIntegrityError as exc:
                conn.commit()
                return {
                    "valid": False,
                    "initialized": True,
                    "checked_events": 0,
                    "broken_event_id": None,
                    "error": str(exc),
                }

            result = {
                **checkpoint,
                "valid": False,
                "checked_events": 0,
                "broken_event_id": None,
                "error": None,
            }

            def fail(message: str, event_id: Optional[str] = None) -> Dict[str, Any]:
                result["error"] = message
                result["broken_event_id"] = event_id
                return result

            if (
                checkpoint["format_version"] != _CHAIN_FORMAT_VERSION
                or checkpoint["algorithm"] != _CHAIN_ALGORITHM
            ):
                conn.commit()
                return fail("Unsupported hash-chain format or algorithm")
            if partial_count:
                conn.commit()
                return fail("Found events with only one hash-chain field")
            if chained_count != checkpoint["event_count"]:
                conn.commit()
                return fail("Hash-chain event count does not match metadata")
            if legacy_count != checkpoint["legacy_event_count"]:
                conn.commit()
                return fail("Unchained event count changed after chain start")

            columns = ", ".join(_EVENT_PAYLOAD_COLUMNS)
            rows = conn.execute(
                f"SELECT {columns}, prev_hash, event_hash FROM events "
                "WHERE prev_hash IS NOT NULL AND event_hash IS NOT NULL"
            ).fetchall()
            by_prev: Dict[str, sqlite3.Row] = {}
            for row in rows:
                prev_hash = row["prev_hash"]
                if prev_hash in by_prev:
                    conn.commit()
                    return fail(
                        "Hash-chain fork: multiple events share one predecessor",
                        row["event_id"],
                    )
                by_prev[prev_hash] = row

            current = checkpoint["anchor"]
            first_event_id: Optional[str] = None
            last_event_id: Optional[str] = None
            visited: set = set()
            for _ in range(checkpoint["event_count"]):
                row = by_prev.get(current)
                if row is None:
                    conn.commit()
                    return fail("Hash-chain link is missing")
                event_id = row["event_id"]
                try:
                    expected = _event_hash(
                        current, _canonical_payload_from_row(row)
                    )
                except Exception as exc:
                    conn.commit()
                    return fail(
                        f"Stored event cannot be canonicalized: {exc}",
                        event_id,
                    )
                if row["event_hash"] != expected:
                    conn.commit()
                    return fail("Canonical event hash mismatch", event_id)
                if row["event_hash"] in visited:
                    conn.commit()
                    return fail("Hash-chain cycle detected", event_id)
                visited.add(row["event_hash"])
                first_event_id = first_event_id or event_id
                last_event_id = event_id
                current = row["event_hash"]
                result["checked_events"] += 1

            if len(visited) != len(rows):
                conn.commit()
                return fail("Hash-chain contains unreachable events")
            if current != checkpoint["head"]:
                conn.commit()
                return fail("Computed hash-chain head does not match metadata")
            if first_event_id != checkpoint["first_event_id"]:
                conn.commit()
                return fail("First chained event does not match metadata")
            if last_event_id != checkpoint["last_event_id"]:
                conn.commit()
                return fail("Last chained event does not match metadata")

            result["valid"] = True
            conn.commit()
            return result
        except sqlite3.Error:
            conn.rollback()
            raise
        finally:
            self._put_conn(conn)

    def verify_checkpoint(self, checkpoint: Dict[str, Any]) -> Dict[str, Any]:
        """Prove that an external checkpoint is an exact prefix of this chain.

        The current chain is fully verified first. The external checkpoint
        must identify the same format, algorithm, random anchor, and legacy
        migration boundary. Its head must then equal the chain hash at exactly
        ``event_count`` links from the anchor.

        Returns ``valid``, ``exact`` (checkpoint equals the current head), and
        ``appended_events`` (events added since a valid older checkpoint).
        Invalid checkpoints return ``appended_events`` as ``None``.
        """
        base_result: Dict[str, Any] = {
            "valid": False,
            "exact": False,
            "appended_events": None,
            "checkpoint_event_count": None,
            "current_event_count": None,
            "current_head": None,
            "error": None,
        }

        def fail(message: str, **details: Any) -> Dict[str, Any]:
            return {**base_result, **details, "error": message}

        if not isinstance(checkpoint, dict):
            return fail("Checkpoint must be a JSON object")

        required = {
            "format_version",
            "algorithm",
            "anchor",
            "head",
            "event_count",
            "legacy_event_count",
        }
        missing = required - set(checkpoint)
        if missing:
            return fail(
                f"Checkpoint is missing required fields: {sorted(missing)}"
            )

        external_count = checkpoint["event_count"]
        external_legacy_count = checkpoint["legacy_event_count"]
        if (
            not isinstance(external_count, int)
            or isinstance(external_count, bool)
            or external_count < 0
        ):
            return fail("Checkpoint event_count must be a non-negative integer")
        if (
            not isinstance(external_legacy_count, int)
            or isinstance(external_legacy_count, bool)
            or external_legacy_count < 0
        ):
            return fail(
                "Checkpoint legacy_event_count must be a non-negative integer",
                checkpoint_event_count=external_count,
            )
        for field in ("format_version", "algorithm", "anchor", "head"):
            if not isinstance(checkpoint[field], str) or not checkpoint[field]:
                return fail(
                    f"Checkpoint {field} must be a non-empty string",
                    checkpoint_event_count=external_count,
                )

        # Retry if an ordinary writer appends between full verification and
        # opening the comparison snapshot. Each successful comparison is made
        # against metadata identical to the fully verified snapshot.
        for _ in range(3):
            verification = self.verify_chain()
            current_count = verification.get("event_count")
            current_head = verification.get("head")
            details = {
                "checkpoint_event_count": external_count,
                "current_event_count": current_count,
                "current_head": current_head,
            }
            if not verification.get("valid"):
                error = verification.get("error") or "unknown integrity error"
                return fail(
                    f"Current hash chain is invalid: {error}",
                    **details,
                )

            conn = self._get_conn()
            try:
                conn.execute("BEGIN")
                meta = _read_chain_meta(conn)
                current = _checkpoint_from_meta(meta)
                snapshot_identity = (
                    current["format_version"],
                    current["algorithm"],
                    current["anchor"],
                    current["head"],
                    current["event_count"],
                    current["legacy_event_count"],
                )
                verified_identity = (
                    verification["format_version"],
                    verification["algorithm"],
                    verification["anchor"],
                    verification["head"],
                    verification["event_count"],
                    verification["legacy_event_count"],
                )
                if snapshot_identity != verified_identity:
                    conn.commit()
                    continue

                details = {
                    "checkpoint_event_count": external_count,
                    "current_event_count": current["event_count"],
                    "current_head": current["head"],
                }
                identity_fields = (
                    "format_version",
                    "algorithm",
                    "anchor",
                    "legacy_event_count",
                )
                for field in identity_fields:
                    if checkpoint[field] != current[field]:
                        conn.commit()
                        return fail(
                            f"Checkpoint {field} does not match this chain",
                            **details,
                        )

                if external_count > current["event_count"]:
                    conn.commit()
                    return fail(
                        "Checkpoint is ahead of the current chain",
                        **details,
                    )

                rows = conn.execute(
                    """
                    SELECT event_id, prev_hash, event_hash
                    FROM events
                    WHERE prev_hash IS NOT NULL AND event_hash IS NOT NULL
                    """
                ).fetchall()
                by_prev: Dict[str, sqlite3.Row] = {}
                for row in rows:
                    if row["prev_hash"] in by_prev:
                        conn.commit()
                        return fail(
                            "Current hash chain forked during checkpoint comparison",
                            **details,
                        )
                    by_prev[row["prev_hash"]] = row

                prefix_head = current["anchor"]
                prefix_first_event_id: Optional[str] = None
                prefix_last_event_id: Optional[str] = None
                for _ in range(external_count):
                    row = by_prev.get(prefix_head)
                    if row is None:
                        conn.commit()
                        return fail(
                            "Current hash chain changed during checkpoint comparison",
                            **details,
                        )
                    prefix_first_event_id = (
                        prefix_first_event_id or row["event_id"]
                    )
                    prefix_last_event_id = row["event_id"]
                    prefix_head = row["event_hash"]

                if checkpoint["head"] != prefix_head:
                    conn.commit()
                    return fail(
                        "Checkpoint head is not the chain prefix at event_count",
                        **details,
                    )
                optional_boundaries = {
                    "first_event_id": prefix_first_event_id,
                    "last_event_id": prefix_last_event_id,
                }
                for field, expected in optional_boundaries.items():
                    if field in checkpoint and checkpoint[field] != expected:
                        conn.commit()
                        return fail(
                            f"Checkpoint {field} does not match its chain prefix",
                            **details,
                        )

                appended = current["event_count"] - external_count
                conn.commit()
                return {
                    **base_result,
                    **details,
                    "valid": True,
                    "exact": appended == 0,
                    "appended_events": appended,
                    "error": None,
                }
            except sqlite3.Error:
                conn.rollback()
                raise
            finally:
                self._put_conn(conn)

        return fail(
            "Hash chain changed repeatedly during checkpoint verification; retry",
            checkpoint_event_count=external_count,
        )

    # ── Query ─────────────────────────────────────────────────────────────

    def query(self, **filters: Any) -> List[Dict[str, Any]]:
        """Query events with optional filters.

        Supported filters:
            agent_type, session_id, run_id, event_type, tool_name,
            since, until (ISO8601 timestamps), data_accessed (partial match),
            limit (default 100), offset (default 0)
        """
        where_clause, params = _build_filter_clause(filters)

        # Pagination
        limit = _validate_page_value(
            filters.get("limit", 100),
            "limit",
            minimum=1,
            maximum=MAX_QUERY_LIMIT,
        )
        offset = _validate_page_value(
            filters.get("offset", 0),
            "offset",
            minimum=0,
            maximum=MAX_QUERY_OFFSET,
        )

        columns_str = ", ".join(self._EVENT_COLUMNS)
        # rowid is the transactional ingestion order for this append-only table
        # and makes pagination deterministic when events share a timestamp.
        sql = (
            f"SELECT {columns_str} FROM events {where_clause} "
            "ORDER BY timestamp DESC, rowid DESC LIMIT ? OFFSET ?"
        )
        params.extend([limit, offset])

        conn = self._get_conn()
        try:
            cur = conn.execute(sql, params)
            rows = cur.fetchall()
        finally:
            self._put_conn(conn)

        return [_row_to_event(r) for r in rows]

    # ── Aggregation ───────────────────────────────────────────────────────

    # Whitelisted GROUP BY dimensions → SQL expressions. Callers pass names,
    # never SQL, so user-supplied strings can't reach the query text.
    _AGG_DIMENSIONS = {
        "agent_type": "agent_type",
        "session_id": "session_id",
        "run_id": "run_id",
        "event_type": "event_type",
        "tool_name": "tool_name",
        "data_accessed": "data_accessed",
        "day": "substr(timestamp, 1, 10)",
        "hour": "substr(timestamp, 1, 13)",
    }

    # Whitelisted metrics → SQL aggregate expressions.
    _AGG_METRICS = {
        "count": "COUNT(*)",
        "distinct_sessions": "COUNT(DISTINCT session_id)",
        "distinct_tools": "COUNT(DISTINCT tool_name)",
        "tokens_in": "COALESCE(SUM(json_extract(cost, '$.tokens_in')), 0)",
        "tokens_out": "COALESCE(SUM(json_extract(cost, '$.tokens_out')), 0)",
        "estimated_usd": "COALESCE(SUM(json_extract(cost, '$.estimated_usd')), 0)",
        "error_count": "COALESCE(SUM(json_extract(outcome, '$.status') = 'error'), 0)",
        "blocked_count": "COALESCE(SUM(json_extract(outcome, '$.status') = 'blocked'), 0)",
        "first_seen": "MIN(timestamp)",
        "last_seen": "MAX(timestamp)",
    }

    def aggregate(
        self,
        group_by: List[str],
        metrics: Optional[List[str]] = None,
        order_by: Optional[str] = None,
        descending: bool = True,
        limit: int = 1000,
        **filters: Any,
    ) -> List[Dict[str, Any]]:
        """Grouped aggregate query over events.

        Args:
            group_by: dimension names (see _AGG_DIMENSIONS; may be empty for
                      whole-table totals). "day"/"hour" bucket the ISO8601
                      timestamp by prefix.
            metrics:  metric names (see _AGG_METRICS). Defaults to ["count"].
            order_by: a selected dimension or metric name to sort on.
                      Defaults to the first metric.
            filters:  agent_type, session_id, run_id, event_type, tool_name,
                      since, until, data_accessed — same semantics as query().

        Returns one dict per group with dimension and metric names as keys.
        Raises ValueError for unknown dimension/metric/order_by names.
        """
        metrics = metrics or ["count"]
        limit = _validate_page_value(
            limit,
            "limit",
            minimum=1,
            maximum=MAX_QUERY_LIMIT,
        )

        bad_dims = [d for d in group_by if d not in self._AGG_DIMENSIONS]
        if bad_dims:
            raise ValueError(
                f"Unknown group_by dimension(s) {bad_dims}. "
                f"Allowed: {sorted(self._AGG_DIMENSIONS)}"
            )
        bad_metrics = [m for m in metrics if m not in self._AGG_METRICS]
        if bad_metrics:
            raise ValueError(
                f"Unknown metric(s) {bad_metrics}. "
                f"Allowed: {sorted(self._AGG_METRICS)}"
            )

        order_by = order_by or metrics[0]
        if order_by not in list(group_by) + metrics:
            raise ValueError(
                f"order_by '{order_by}' must be one of the selected "
                f"dimensions or metrics: {list(group_by) + metrics}"
            )

        select_parts = [
            f'{self._AGG_DIMENSIONS[d]} AS "{d}"' for d in group_by
        ] + [
            f'{self._AGG_METRICS[m]} AS "{m}"' for m in metrics
        ]

        # WHERE clause — same filter semantics as query()
        where_clause, params = _build_filter_clause(filters)
        group_clause = (
            "GROUP BY " + ", ".join(self._AGG_DIMENSIONS[d] for d in group_by)
            if group_by else ""
        )
        direction = "DESC" if descending else "ASC"

        sql = (
            f"SELECT {', '.join(select_parts)} FROM events "
            f"{where_clause} {group_clause} "
            f'ORDER BY "{order_by}" {direction} LIMIT ?'
        )
        params.append(limit)

        conn = self._get_conn()
        try:
            rows = conn.execute(sql, params).fetchall()
        finally:
            self._put_conn(conn)

        return [dict(r) for r in rows]

    # ── Session access ────────────────────────────────────────────────────

    def get_session(self, session_id: str) -> List[Dict[str, Any]]:
        """Return up to 10,000 session events in chronological order."""
        events = self.query(session_id=session_id, limit=10000)
        events.reverse()  # query() returns newest-first; a timeline reads oldest-first
        return events

    # ── Evidence chain ────────────────────────────────────────────────────

    def get_evidence_chain(self, event_id: str) -> List[Dict[str, Any]]:
        """Return the full decision path for a given event.

        For tool_call / tool_result events that have a non-empty call_id,
        the chain is built by unioning:
          • all events sharing that call_id (the paired call/result)
          • all events sharing the anchor's run_id (surrounding exchange —
            model_request / model_response in the same turn)
        run_id being NULL is handled gracefully (only call_id branch used).

        For other events, falls back to:
          • turn-number ±1 within the same session, or
          • a ±1-minute temporal window if turn_number is absent.

        Results are ordered chronologically.
        """
        conn = self._get_conn()
        try:
            # 1. Get the anchor event
            cur = conn.execute(
                f"SELECT {', '.join(self._EVENT_COLUMNS)} FROM events WHERE event_id = ?",
                (event_id,),
            )
            row = cur.fetchone()
            if row is None:
                return []

            anchor = _row_to_event(row)

            session_id = anchor["agent"]["session_id"]
            event_type = anchor.get("event_type", "")
            call_id = row["call_id"] or ""
            run_id = row["run_id"] or ""

            # 2. Build the chain
            if call_id and event_type in ("tool_call", "tool_result"):
                # Primary path: use call_id + run_id for a precise exchange chain
                if run_id:
                    cur = conn.execute(
                        f"""
                        SELECT {', '.join(self._EVENT_COLUMNS)}
                        FROM events
                        WHERE session_id = ?
                          AND (call_id = ? OR run_id = ?)
                        ORDER BY timestamp ASC, rowid ASC
                        """,
                        (session_id, call_id, run_id),
                    )
                else:
                    cur = conn.execute(
                        f"""
                        SELECT {', '.join(self._EVENT_COLUMNS)}
                        FROM events
                        WHERE session_id = ?
                          AND call_id = ?
                        ORDER BY timestamp ASC, rowid ASC
                        """,
                        (session_id, call_id),
                    )
            else:
                # Fallback: turn-number ±1, or temporal ±1-minute window
                turn = anchor["context"].get("turn_number")
                if turn is not None:
                    turn_low = max(0, turn - 1)
                    turn_high = turn + 1
                    cur = conn.execute(
                        f"""
                        SELECT {', '.join(self._EVENT_COLUMNS)}
                        FROM events
                        WHERE session_id = ?
                          AND json_extract(context, '$.turn_number') IS NOT NULL
                          AND CAST(json_extract(context, '$.turn_number') AS INTEGER)
                              BETWEEN ? AND ?
                        ORDER BY timestamp ASC, rowid ASC
                        """,
                        (session_id, turn_low, turn_high),
                    )
                else:
                    cur = conn.execute(
                        f"""
                        SELECT {', '.join(self._EVENT_COLUMNS)}
                        FROM events
                        WHERE session_id = ?
                          AND julianday(timestamp)
                              BETWEEN julianday(?) - (1.0 / 1440.0)
                                  AND julianday(?) + (1.0 / 1440.0)
                        ORDER BY timestamp ASC, rowid ASC
                        """,
                        (session_id, anchor["timestamp"], anchor["timestamp"]),
                    )

            rows = cur.fetchall()
        finally:
            self._put_conn(conn)

        return [_row_to_event(r) for r in rows]

    # ── Session listing ───────────────────────────────────────────────────

    def list_sessions(
        self, agent_type: Optional[str] = None, limit: int = 50
    ) -> List[Dict[str, Any]]:
        """List distinct sessions, optionally filtered by agent_type.

        Returns sessions ordered by most recent activity first, each with:
            session_id, agent_type, first_seen, last_seen, event_count
        """
        limit = _validate_page_value(
            limit,
            "limit",
            minimum=1,
            maximum=MAX_QUERY_LIMIT,
        )
        where_clause = "WHERE agent_type = ?" if agent_type else ""
        params: tuple = (agent_type, limit) if agent_type else (limit,)

        conn = self._get_conn()
        try:
            cur = conn.execute(
                f"""
                SELECT session_id, agent_type,
                       MIN(timestamp) AS first_seen,
                       MAX(timestamp) AS last_seen,
                       COUNT(*) AS event_count
                FROM events
                {where_clause}
                GROUP BY session_id, agent_type
                ORDER BY last_seen DESC
                LIMIT ?
                """,
                params,
            )
            rows = cur.fetchall()
        finally:
            self._put_conn(conn)

        return [dict(r) for r in rows]

    # ── Statistics ────────────────────────────────────────────────────────

    def get_stats(self) -> Dict[str, Any]:
        """Return aggregate statistics about stored events."""
        conn = self._get_conn()
        try:
            total = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]

            by_agent = {
                row["agent_type"]: row["cnt"]
                for row in conn.execute(
                    "SELECT agent_type, COUNT(*) AS cnt FROM events GROUP BY agent_type"
                )
            }
            by_type = {
                row["event_type"]: row["cnt"]
                for row in conn.execute(
                    "SELECT event_type, COUNT(*) AS cnt FROM events GROUP BY event_type"
                )
            }

            # Schema version
            ver_row = conn.execute(
                "SELECT MAX(version) FROM schema_version"
            ).fetchone()
            schema_version = ver_row[0] if ver_row and ver_row[0] is not None else 0
        finally:
            self._put_conn(conn)

        return {
            "total_events": total,
            "events_by_agent": by_agent,
            "events_by_type": by_type,
            "schema_version": schema_version,
        }
