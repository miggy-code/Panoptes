"""
SQLite-backed storage for universal panoptes events.

Provides the AuditDB class with full CRUD, querying, evidence-chain
reconstruction, and statistics — all on Python stdlib sqlite3.
"""

import json
import logging
import os
import sqlite3
import threading
from typing import Any, Dict, List, Optional, Tuple

from .schema import (
    SCHEMA_VERSION,
    ValidationError,
    extract_index_fields,
    normalize_event,
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

    -- Tamper-evidence hash chain (v3; populated by the compliance layer)
    prev_hash       TEXT,
    event_hash      TEXT
)
"""

# ── v3 tables: hash-chain anchor, trust baselines/ledger, alerts ──────────────

CREATE_CHAIN_META = """
CREATE TABLE IF NOT EXISTS chain_meta (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
)
"""

CREATE_BASELINES = """
CREATE TABLE IF NOT EXISTS baselines (
    baseline_key   TEXT PRIMARY KEY,
    state          TEXT NOT NULL DEFAULT 'learning',
    session_count  INTEGER NOT NULL DEFAULT 0,
    first_seen     TEXT NOT NULL,
    updated_at     TEXT NOT NULL,
    metrics        TEXT NOT NULL DEFAULT '{}',
    known_pairs    TEXT NOT NULL DEFAULT '[]'
)
"""

CREATE_TRUST_EVENTS = """
CREATE TABLE IF NOT EXISTS trust_events (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id     TEXT NOT NULL,
    event_id       TEXT,
    timestamp      TEXT NOT NULL,
    delta          REAL NOT NULL,
    reason         TEXT NOT NULL,
    score_after    REAL NOT NULL
)
"""

CREATE_ALERTS = """
CREATE TABLE IF NOT EXISTS alerts (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp      TEXT NOT NULL,
    severity       TEXT NOT NULL,
    kind           TEXT NOT NULL,
    session_id     TEXT,
    payload        TEXT NOT NULL DEFAULT '{}',
    acknowledged   INTEGER NOT NULL DEFAULT 0,
    delivered      TEXT NOT NULL DEFAULT '{}'
)
"""

CREATE_V3_INDICES = [
    "CREATE INDEX IF NOT EXISTS idx_trust_events_session ON trust_events(session_id)",
    "CREATE INDEX IF NOT EXISTS idx_alerts_timestamp     ON alerts(timestamp)",
    "CREATE INDEX IF NOT EXISTS idx_alerts_severity      ON alerts(severity)",
]

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
    # Note: idx_events_call_id and idx_events_dedup are created in the v2
    # migration block (after ensuring the call_id column exists).
]

CREATE_CALL_ID_INDEX = (
    "CREATE INDEX IF NOT EXISTS idx_events_call_id ON events(call_id)"
)

# Unique partial index for deduplicating replayed tool_call/tool_result events.
# Only applies when call_id is non-empty (i.e. we have a stable identifier from
# the provider). Created separately so migrations can add the column + dedupe
# existing rows before attempting to create this constraint.
CREATE_DEDUP_INDEX = """
CREATE UNIQUE INDEX IF NOT EXISTS idx_events_dedup
ON events(session_id, event_type, call_id)
WHERE call_id != '' AND (event_type = 'tool_call' OR event_type = 'tool_result')
"""

# Shared INSERT statement used by both insert_event and insert_events.
_INSERT_SQL = """
INSERT OR IGNORE INTO events (
    event_id, timestamp, agent_type, session_id, run_id,
    event_type, tool_name, data_accessed, call_id,
    agent, user_info, action, outcome, context, cost,
    raw_request, raw_response
) VALUES (
    ?, ?, ?, ?, ?,
    ?, ?, ?, ?,
    ?, ?, ?, ?, ?, ?,
    ?, ?
)
"""

# ── Helpers ───────────────────────────────────────────────────────────────────

def _serialize(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, default=str)


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


def _build_params(normalized: Dict[str, Any], flat: Dict[str, Any]) -> tuple:
    """Build the SQL parameters tuple for one event INSERT."""
    return (
        normalized["event_id"],
        normalized["timestamp"],
        flat["agent_type"],
        flat["session_id"],
        flat["run_id"],
        normalized["event_type"],
        flat["tool_name"],
        flat["data_accessed"],
        flat["call_id"],
        _serialize(normalized["agent"]),
        _serialize(normalized["user"]),
        _serialize(normalized["action"]),
        _serialize(normalized["outcome"]),
        _serialize(normalized["context"]),
        _serialize(normalized["cost"]),
        normalized.get("raw_request"),
        normalized.get("raw_response"),
    )


_FILTER_FIELDS = ("agent_type", "session_id", "run_id", "event_type", "tool_name")


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
                           dedup index created after standard indices.
      v1 → v2 (existing DB without call_id): ALTER TABLE to add call_id,
                           backfill from action JSON, deduplicate existing rows,
                           then create the dedup index.
      v2 → v3: add prev_hash/event_hash columns to events (nullable — the
                           hash chain starts at the migration boundary, never
                           retroactively), plus chain_meta, baselines,
                           trust_events, and alerts tables.
    """
    conn = db._get_conn()
    try:
        conn.execute(CREATE_SCHEMA_VERSION)
        conn.execute(CREATE_EVENTS)
        for idx_sql in CREATE_INDICES:
            conn.execute(idx_sql)

        # Check current schema version
        cur = conn.execute("SELECT MAX(version) FROM schema_version")
        row = cur.fetchone()
        current = row[0] if row and row[0] is not None else 0

        if current < 2:
            # ── v1 → v2: add call_id column if missing ────────────────────
            col_names = {r[1] for r in conn.execute("PRAGMA table_info(events)")}
            if "call_id" not in col_names:
                conn.execute("ALTER TABLE events ADD COLUMN call_id TEXT DEFAULT ''")

                # Backfill call_id for tool_call/tool_result rows:
                # prefer action.call_id, fall back to action.target
                conn.execute("""
                    UPDATE events
                    SET call_id = COALESCE(
                        NULLIF(json_extract(action, '$.call_id'), ''),
                        NULLIF(json_extract(action, '$.target'), ''),
                        ''
                    )
                    WHERE event_type IN ('tool_call', 'tool_result')
                """)

                # Deduplicate: for any (session_id, event_type, call_id) group
                # that has more than one row, keep only the earliest timestamp.
                conn.execute("""
                    DELETE FROM events
                    WHERE event_id IN (
                        SELECT e.event_id
                        FROM events e
                        INNER JOIN (
                            SELECT session_id, event_type, call_id,
                                   MIN(timestamp) AS min_ts
                            FROM events
                            WHERE call_id != ''
                              AND event_type IN ('tool_call', 'tool_result')
                            GROUP BY session_id, event_type, call_id
                            HAVING COUNT(*) > 1
                        ) d ON  e.session_id  = d.session_id
                            AND e.event_type  = d.event_type
                            AND e.call_id     = d.call_id
                            AND e.timestamp  != d.min_ts
                    )
                """)

            # Create the call_id regular index and unique dedup index (idempotent)
            conn.execute(CREATE_CALL_ID_INDEX)
            conn.execute(CREATE_DEDUP_INDEX)

        if current < 3:
            # ── v2 → v3: hash-chain columns on events ─────────────────────
            col_names = {r[1] for r in conn.execute("PRAGMA table_info(events)")}
            if "prev_hash" not in col_names:
                conn.execute("ALTER TABLE events ADD COLUMN prev_hash TEXT")
            if "event_hash" not in col_names:
                conn.execute("ALTER TABLE events ADD COLUMN event_hash TEXT")

        # v3 auxiliary tables and indices (idempotent; also covers fresh DBs)
        conn.execute(CREATE_CHAIN_META)
        conn.execute(CREATE_BASELINES)
        conn.execute(CREATE_TRUST_EVENTS)
        conn.execute(CREATE_ALERTS)
        for idx_sql in CREATE_V3_INDICES:
            conn.execute(idx_sql)

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
    """Thread-safe SQLite storage for the universal panoptes trail."""

    # Columns returned by SELECT * (order matters for _row_to_event)
    _EVENT_COLUMNS = [
        "event_id", "timestamp", "agent_type", "session_id", "run_id",
        "event_type", "tool_name", "data_accessed", "call_id",
        "agent", "user_info", "action", "outcome", "context", "cost",
        "raw_request", "raw_response",
    ]

    def __init__(self, db_path: str = "~/.panoptes/audit.db"):
        self._db_path = os.path.expanduser(db_path)
        os.makedirs(os.path.dirname(self._db_path), exist_ok=True)

        # Thread-local connections, plus a registry of every open connection
        # so close() can release them all (e.g. handler-thread connections in
        # the proxy's ThreadingHTTPServer).
        self._local = threading.local()
        self._all_conns: set = set()
        self._conns_lock = threading.Lock()

        # WAL is a persistent database property — set it once here.
        conn = self._get_conn()
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA foreign_keys=ON")
            conn.commit()
        finally:
            self._put_conn(conn)

        # Run migrations / create tables
        _ensure_schema(self)

    # ── Thread-safe connection management ─────────────────────────────────

    def _get_conn(self) -> sqlite3.Connection:
        """Get or create a thread-local connection."""
        if getattr(self._local, "conn", None) is None:
            # check_same_thread=False so close() can close connections owned
            # by other threads; each connection is still used by one thread
            # only (it stays thread-local).
            conn = sqlite3.connect(self._db_path, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            self._local.conn = conn
            with self._conns_lock:
                self._all_conns.add(conn)
        return self._local.conn

    def _put_conn(self, conn: sqlite3.Connection) -> None:
        """Release the connection (no-op; we keep it open per thread)."""
        pass

    def close(self) -> None:
        """Close all connections opened by this AuditDB, across all threads."""
        with self._conns_lock:
            conns, self._all_conns = self._all_conns, set()
        for conn in conns:
            try:
                conn.close()
            except sqlite3.Error:
                pass
        self._local.conn = None

    # ── Insert ────────────────────────────────────────────────────────────

    def insert_events(self, events: List[Dict[str, Any]]) -> List[str]:
        """Validate, normalize, and insert a batch of events in one transaction.

        Returns a list of event_ids in the same order as *events*.

        Dedup semantics are preserved: for tool_call/tool_result events with a
        non-empty call_id that collide on the unique partial index, the
        event_id of the pre-existing (or first-in-batch) row is returned for
        the duplicate(s).

        On any exception the whole batch is rolled back and the exception
        re-raised.  ValidationError from an individual event aborts the batch
        before any DB writes occur.
        """
        # Step 1: validate + normalize ALL events before touching the DB.
        # A ValidationError here means no DB state has changed yet.
        prepared: List[tuple] = []  # (normalized, flat)
        for event in events:
            warnings = validate_event(event)  # raises ValidationError if invalid
            if warnings:
                log.debug(
                    "Event validation warnings (event_id=%s): %s",
                    event.get("event_id"), warnings,
                )
            normalized = normalize_event(event)
            flat = extract_index_fields(normalized)
            prepared.append((normalized, flat))

        # Step 2: insert everything in one transaction.
        conn = self._get_conn()
        try:
            event_ids: List[Optional[str]] = []
            ignored_indices: List[int] = []

            for i, (normalized, flat) in enumerate(prepared):
                cursor = conn.execute(_INSERT_SQL, _build_params(normalized, flat))
                if cursor.rowcount == 0:
                    # INSERT was silently ignored by the dedup unique index.
                    # We'll look up the surviving event_id after the commit.
                    ignored_indices.append(i)
                    event_ids.append(None)          # placeholder
                else:
                    event_ids.append(normalized["event_id"])

            conn.commit()

            # Step 3: resolve event_ids for ignored rows (post-commit lookup).
            for i in ignored_indices:
                normalized, flat = prepared[i]
                call_id = flat.get("call_id", "")
                if call_id:
                    existing = conn.execute(
                        "SELECT event_id FROM events "
                        "WHERE session_id = ? AND event_type = ? AND call_id = ?",
                        (flat["session_id"], normalized["event_type"], call_id),
                    ).fetchone()
                    if existing:
                        event_ids[i] = existing["event_id"]
                if event_ids[i] is None:
                    event_ids[i] = normalized["event_id"]

            return event_ids  # type: ignore[return-value]

        except Exception:
            conn.rollback()
            raise
        finally:
            self._put_conn(conn)

    def insert_event(self, event: Dict[str, Any]) -> str:
        """Validate, normalize, and insert a single event. Returns the event_id.

        Delegates to insert_events for a single-element batch so that both
        methods share the same code path (validation, normalization, dedup,
        rollback on error).

        Raises ValidationError if required fields are missing or invalid.
        """
        return self.insert_events([event])[0]

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
        limit = filters.get("limit", 100)
        offset = filters.get("offset", 0)

        columns_str = ", ".join(self._EVENT_COLUMNS)
        sql = f"SELECT {columns_str} FROM events {where_clause} ORDER BY timestamp DESC LIMIT ? OFFSET ?"
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
        """Return all events for a given session, in chronological order."""
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
                        ORDER BY timestamp ASC
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
                        ORDER BY timestamp ASC
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
                        ORDER BY timestamp ASC
                        """,
                        (session_id, turn_low, turn_high),
                    )
                else:
                    cur = conn.execute(
                        f"""
                        SELECT {', '.join(self._EVENT_COLUMNS)}
                        FROM events
                        WHERE session_id = ?
                          AND timestamp >= datetime(?, '-1 minute')
                          AND timestamp <= datetime(?, '+1 minute')
                        ORDER BY timestamp ASC
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
                GROUP BY session_id
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

    # ── Maintenance ───────────────────────────────────────────────────────

    def vacuum(self) -> None:
        """Reclaim storage space."""
        conn = self._get_conn()
        try:
            conn.execute("VACUUM")
        finally:
            self._put_conn(conn)
