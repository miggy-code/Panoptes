"""
SQLite-backed storage for universal panoptes events.

Provides the AuditDB class with full CRUD, querying, evidence-chain
reconstruction, and statistics — all on Python stdlib sqlite3.
"""

import json
import os
import sqlite3
import threading
from typing import Any, Dict, List, Optional

from .schema import (
    SCHEMA_VERSION,
    ValidationError,
    extract_index_fields,
    normalize_event,
    validate_event,
)

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

    -- JSON columns (stored as TEXT)
    agent           TEXT    NOT NULL,
    user_info       TEXT    NOT NULL,
    action          TEXT    NOT NULL,
    outcome         TEXT    NOT NULL,
    context         TEXT    NOT NULL,
    cost            TEXT    NOT NULL,
    raw_request     TEXT,
    raw_response    TEXT
)
"""

CREATE_INDICES = [
    "CREATE INDEX IF NOT EXISTS idx_events_agent_type   ON events(agent_type)",
    "CREATE INDEX IF NOT EXISTS idx_events_session_id   ON events(session_id)",
    "CREATE INDEX IF NOT EXISTS idx_events_event_type   ON events(event_type)",
    "CREATE INDEX IF NOT EXISTS idx_events_timestamp    ON events(timestamp)",
    "CREATE INDEX IF NOT EXISTS idx_events_tool_name    ON events(tool_name)",
    "CREATE INDEX IF NOT EXISTS idx_events_run_id       ON events(run_id)",
    "CREATE INDEX IF NOT EXISTS idx_events_data_accessed ON events(data_accessed)",
]

# ── Helpers ───────────────────────────────────────────────────────────────────

def _serialize(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, default=str)


def _deserialize(raw: Optional[str]) -> Optional[Dict[str, Any]]:
    if raw is None:
        return None
    return json.loads(raw)


def _row_to_event(row: tuple, columns: List[str]) -> Dict[str, Any]:
    """Convert a SQLite row tuple to the canonical event dict."""
    d = dict(zip(columns, row))
    return {
        "event_id": d["event_id"],
        "timestamp": d["timestamp"],
        "agent": _deserialize(d["agent"]),
        "user": _deserialize(d["user_info"]),
        "event_type": d["event_type"],
        "action": _deserialize(d["action"]),
        "outcome": _deserialize(d["outcome"]),
        "context": _deserialize(d["context"]),
        "cost": _deserialize(d["cost"]),
        "raw_request": d.get("raw_request"),
        "raw_response": d.get("raw_response"),
    }


def _ensure_schema(db: "AuditDB") -> None:
    """Create tables and indices if they don't exist; migrate if needed."""
    conn = db._get_conn()
    try:
        conn.execute(CREATE_SCHEMA_VERSION)
        conn.execute(CREATE_EVENTS)
        for idx_sql in CREATE_INDICES:
            conn.execute(idx_sql)

        # Check / bump schema version
        cur = conn.execute("SELECT MAX(version) FROM schema_version")
        row = cur.fetchone()
        current = row[0] if row and row[0] is not None else 0

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
        "event_type", "tool_name", "data_accessed",
        "agent", "user_info", "action", "outcome", "context", "cost",
        "raw_request", "raw_response",
    ]

    def __init__(self, db_path: str = "~/.panoptes/audit.db"):
        self._db_path = os.path.expanduser(db_path)
        os.makedirs(os.path.dirname(self._db_path), exist_ok=True)

        # Thread-local connection pool
        self._local = threading.local()

        # Ensure WAL mode on first connection
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
        if not hasattr(self._local, "conn") or self._local.conn is None:
            conn = sqlite3.connect(self._db_path)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            self._local.conn = conn
        return self._local.conn

    def _put_conn(self, conn: sqlite3.Connection) -> None:
        """Release the connection (no-op; we keep it open per thread)."""
        pass

    def close(self) -> None:
        """Close the thread-local connection if open."""
        if hasattr(self._local, "conn") and self._local.conn is not None:
            self._local.conn.close()
            self._local.conn = None

    # ── Insert ────────────────────────────────────────────────────────────

    def insert_event(self, event: Dict[str, Any]) -> str:
        """Validate, normalize, and insert an event. Returns the event_id.

        Raises ValidationError if required fields are missing or invalid.
        """
        # Validate first
        warnings = validate_event(event)
        if warnings:
            # Log warnings? For now, silent — they're non-fatal
            pass

        # Normalize
        normalized = normalize_event(event)
        flat = extract_index_fields(normalized)

        conn = self._get_conn()
        try:
            conn.execute(
                """
                INSERT INTO events (
                    event_id, timestamp, agent_type, session_id, run_id,
                    event_type, tool_name, data_accessed,
                    agent, user_info, action, outcome, context, cost,
                    raw_request, raw_response
                ) VALUES (
                    ?, ?, ?, ?, ?,
                    ?, ?, ?,
                    ?, ?, ?, ?, ?, ?,
                    ?, ?
                )
                """,
                (
                    normalized["event_id"],
                    normalized["timestamp"],
                    flat["agent_type"],
                    flat["session_id"],
                    flat["run_id"],
                    normalized["event_type"],
                    flat["tool_name"],
                    flat["data_accessed"],
                    _serialize(normalized["agent"]),
                    _serialize(normalized["user"]),
                    _serialize(normalized["action"]),
                    _serialize(normalized["outcome"]),
                    _serialize(normalized["context"]),
                    _serialize(normalized["cost"]),
                    normalized.get("raw_request"),
                    normalized.get("raw_response"),
                ),
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            self._put_conn(conn)

        return normalized["event_id"]

    # ── Query ─────────────────────────────────────────────────────────────

    def query(self, **filters: Any) -> List[Dict[str, Any]]:
        """Query events with optional filters.

        Supported filters:
            agent_type, session_id, run_id, event_type, tool_name,
            since, until (ISO8601 timestamps), data_accessed (partial match),
            limit (default 100), offset (default 0)
        """
        conditions: List[str] = []
        params: List[Any] = []

        # Equality filters
        for field in ("agent_type", "session_id", "run_id", "event_type", "tool_name"):
            if field in filters and filters[field] is not None:
                conditions.append(f"{field} = ?")
                params.append(filters[field])

        # Time range
        if "since" in filters and filters["since"] is not None:
            conditions.append("timestamp >= ?")
            params.append(filters["since"])
        if "until" in filters and filters["until"] is not None:
            conditions.append("timestamp <= ?")
            params.append(filters["until"])

        # data_accessed (partial match on comma-separated field)
        if "data_accessed" in filters and filters["data_accessed"] is not None:
            conditions.append("data_accessed LIKE ?")
            params.append(f"%{filters['data_accessed']}%")

        # Pagination
        limit = filters.get("limit", 100)
        offset = filters.get("offset", 0)

        where_clause = ""
        if conditions:
            where_clause = "WHERE " + " AND ".join(conditions)

        columns_str = ", ".join(self._EVENT_COLUMNS)
        sql = f"SELECT {columns_str} FROM events {where_clause} ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        conn = self._get_conn()
        try:
            cur = conn.execute(sql, params)
            rows = cur.fetchall()
        finally:
            self._put_conn(conn)

        return [_row_to_event(tuple(r), self._EVENT_COLUMNS) for r in rows]

    # ── Session access ────────────────────────────────────────────────────

    def get_session(self, session_id: str) -> List[Dict[str, Any]]:
        """Return all events for a given session, ordered by timestamp."""
        return self.query(session_id=session_id, limit=10000)

    # ── Evidence chain ────────────────────────────────────────────────────

    def get_evidence_chain(self, event_id: str) -> List[Dict[str, Any]]:
        """Return the full decision path for a given event.

        The evidence chain reconstructs what happened around a tool call:
        1. The user message that triggered the turn
        2. The model request that decided to call the tool
        3. The tool call + parameters
        4. The tool result
        5. Any subsequent model response incorporating the result

        This aligns with what compliance auditors need: "show me exactly
        what happened and why."
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
            anchor = _row_to_event(tuple(row), self._EVENT_COLUMNS)

            session_id = anchor["agent"]["session_id"]
            turn = anchor["context"].get("turn_number")

            # 2. Build the chain: all events in the same session, ±1 turn of anchor
            #    ordered by timestamp ascending so it reads chronologically
            if turn is not None:
                turn_low = max(0, turn - 1)
                turn_high = turn + 1
                cur = conn.execute(
                    f"""
                    SELECT {', '.join(self._EVENT_COLUMNS)}
                    FROM events
                    WHERE session_id = ?
                      AND json_extract(context, '$.turn_number') IS NOT NULL
                      AND CAST(json_extract(context, '$.turn_number') AS INTEGER) BETWEEN ? AND ?
                    ORDER BY timestamp ASC
                    """,
                    (session_id, turn_low, turn_high),
                )
            else:
                # Fallback: just grab the event and its immediate temporal neighbors
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

        return [_row_to_event(tuple(r), self._EVENT_COLUMNS) for r in rows]

    # ── Session listing ───────────────────────────────────────────────────

    def list_sessions(
        self, agent_type: Optional[str] = None, limit: int = 50
    ) -> List[Dict[str, Any]]:
        """List distinct sessions, optionally filtered by agent_type.

        Returns sessions ordered by most recent activity first, each with:
            session_id, agent_type, first_seen, last_seen, event_count
        """
        conn = self._get_conn()
        try:
            if agent_type:
                cur = conn.execute(
                    """
                    SELECT session_id, agent_type,
                           MIN(timestamp) AS first_seen,
                           MAX(timestamp) AS last_seen,
                           COUNT(*) AS event_count
                    FROM events
                    WHERE agent_type = ?
                    GROUP BY session_id
                    ORDER BY last_seen DESC
                    LIMIT ?
                    """,
                    (agent_type, limit),
                )
            else:
                cur = conn.execute(
                    """
                    SELECT session_id, agent_type,
                           MIN(timestamp) AS first_seen,
                           MAX(timestamp) AS last_seen,
                           COUNT(*) AS event_count
                    FROM events
                    GROUP BY session_id
                    ORDER BY last_seen DESC
                    LIMIT ?
                    """,
                    (limit,),
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

            by_agent = {}
            for row in conn.execute(
                "SELECT agent_type, COUNT(*) AS cnt FROM events GROUP BY agent_type"
            ):
                by_agent[row["agent_type"]] = row["cnt"]

            by_type = {}
            for row in conn.execute(
                "SELECT event_type, COUNT(*) AS cnt FROM events GROUP BY event_type"
            ):
                by_type[row["event_type"]] = row["cnt"]

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
