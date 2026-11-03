"""Hermes Agent plugin for panoptes.

Hooks into the Hermes agent lifecycle (agent:start, agent:step, agent:end)
and writes structured audit events to the SQLite database.

Installation:
  Run `python -m panoptes.install_hermes_plugin` or drop the
  generated files into ~/.hermes/plugins/panoptes/

Plugin structure (written by install_hermes_plugin.py):
  ~/.hermes/plugins/panoptes/
  ├── manifest.json    — plugin metadata + hook declarations
  └── plugin.py        — hook handlers registering with Hermes context
"""

import logging
import os
import threading
import uuid

from panoptes.capture import HERMES_CAPABILITIES
from panoptes.db import AuditDB
from panoptes.schema import (
    redact_secrets,
    utcnow_iso as _utcnow_iso,
    validate_identifier,
)

DB_PATH = os.path.expanduser("~/.panoptes/audit.db")
DEFAULT_MAX_ACTIVE_SESSIONS = 1024

log = logging.getLogger("panoptes.hermes")


def _safe_identifier(value, fallback: str) -> str:
    try:
        validate_identifier(value)
    except Exception:
        return fallback
    return value


def _safe_text(value, limit: int) -> str:
    if value is None:
        return ""
    text = value if isinstance(value, str) else str(value)
    redacted = redact_secrets(text)
    return redacted[:limit]


class AuditPlugin:
    """Hermes plugin that writes agent lifecycle events to the audit DB."""

    def __init__(
        self,
        db_path: str = None,
        max_active_sessions: int = DEFAULT_MAX_ACTIVE_SESSIONS,
    ):
        if (
            isinstance(max_active_sessions, bool)
            or not isinstance(max_active_sessions, int)
            or max_active_sessions < 1
        ):
            raise ValueError("max_active_sessions must be a positive integer")
        self.db = AuditDB(db_path or DB_PATH)
        self._sessions: dict[str, dict] = {}
        self._sessions_lock = threading.RLock()
        self.max_active_sessions = max_active_sessions

    def _store_session_locked(self, state: dict) -> dict:
        """Track a session while enforcing a strict upper memory bound."""
        session_id = state["session_id"]
        existing = self._sessions.get(session_id)
        if existing is not None and existing is not state:
            log.warning("Ignoring duplicate Hermes session start for %r", session_id)
            return existing

        if (
            session_id not in self._sessions
            and len(self._sessions) >= self.max_active_sessions
        ):
            evicted_id = next(iter(self._sessions))
            self._sessions.pop(evicted_id, None)
            log.warning(
                "Hermes active-session limit reached; evicted session %r "
                "while tracking %r",
                evicted_id,
                session_id,
            )
        self._sessions[session_id] = state
        return state

    def _new_session_state(
        self,
        context: dict,
        session_id: str,
    ) -> dict:
        requested_run_id = context.get("run_id")
        run_fallback = uuid.uuid4().hex
        run_id = _safe_identifier(requested_run_id, run_fallback)
        requested_user_id = context.get("user_id", "unknown")
        user_id = _safe_identifier(requested_user_id, "unknown")
        state = {
            "session_id": session_id,
            "run_id": run_id,
            "user_id": user_id,
            "turn": 0,
        }
        if (
            requested_run_id is not None
            and run_id != requested_run_id
        ) or user_id != requested_user_id:
            log.warning("Replaced malformed Hermes lifecycle identity")
        return state

    def _resolve_session(self, context: dict, *, create: bool = False) -> dict:
        """Resolve state without ever merging two concurrent Hermes sessions."""
        raw_requested_id = context.get("session_id")
        requested_id = (
            _safe_identifier(raw_requested_id, uuid.uuid4().hex)
            if raw_requested_id is not None
            else None
        )
        invalid_requested_id = (
            raw_requested_id is not None and requested_id != raw_requested_id
        )
        with self._sessions_lock:
            if requested_id and requested_id in self._sessions:
                return self._sessions[requested_id]

            if requested_id and create:
                state = self._new_session_state(context, requested_id)
                if invalid_requested_id:
                    log.warning("Replaced malformed Hermes lifecycle session_id")
                return self._store_session_locked(state)

            # Backward compatibility for hosts that omit session_id only when
            # there is exactly one unambiguous active session.
            if not requested_id and len(self._sessions) == 1:
                return next(iter(self._sessions.values()))

            # Never attribute an ambiguous event to another session.
            isolated_id = requested_id or uuid.uuid4().hex
            state = self._new_session_state(context, isolated_id)
            if invalid_requested_id:
                log.warning("Replaced malformed Hermes lifecycle session_id")
            if create:
                return self._store_session_locked(state)
            return state

    def _persist_lifecycle_event(self, event: dict) -> bool:
        """Best-effort persistence for observation-only lifecycle hooks.

        Lifecycle callbacks do not form a mandatory enforcement boundary, so
        an audit outage must not accidentally become one. Session state still
        follows the host-reported callback sequence; operators must monitor the
        logged write failure and any resulting gap in turn numbers.
        """
        try:
            self.db.insert_event(event)
            return True
        except Exception:
            log.exception("Failed to persist Hermes lifecycle event")
            return False

    def register(self, ctx):
        """Register hook handlers with the Hermes plugin context."""

        @ctx.on("agent:start")
        def on_agent_start(context):
            raw_session_id = context.get("session_id")
            session_id = _safe_identifier(
                raw_session_id,
                uuid.uuid4().hex,
            )
            with self._sessions_lock:
                state = self._sessions.get(session_id)
                duplicate_start = state is not None
                if duplicate_start:
                    log.warning(
                        "Duplicate Hermes agent:start for an active session; "
                        "retained its established run and user attribution"
                    )
                else:
                    state = self._new_session_state(context, session_id)
                    if (
                        raw_session_id is not None
                        and session_id != raw_session_id
                    ):
                        log.warning(
                            "Replaced malformed Hermes lifecycle session_id"
                        )
                    state = self._store_session_locked(state)
                turn_number = state["turn"]
            run_id = state["run_id"]
            user_id = state["user_id"]

            self._persist_lifecycle_event(
                {
                    "event_id": uuid.uuid4().hex,
                    "timestamp": _utcnow_iso(),
                    "agent": {
                        "type": "hermes",
                        "session_id": session_id,
                        "run_id": run_id,
                    },
                    "user": {
                        "id": user_id,
                        "auth_method": "cli",
                    },
                    "event_type": "agent_start",
                    "action": {
                        "tool_name": None,
                        "parameters": {},
                        "target": None,
                    },
                    "outcome": {
                        "status": "warned" if duplicate_start else "success",
                        "summary": (
                            "Duplicate agent start observed; existing session "
                            "attribution retained"
                            if duplicate_start
                            else "Agent started processing"
                        ),
                    },
                    "context": {
                        "turn_number": turn_number,
                        "user_message": _safe_text(context.get("message"), 500),
                        "capture": HERMES_CAPABILITIES.as_context(),
                    },
                    "cost": {
                        "tokens_in": context.get("tokens_in", 0),
                        "tokens_out": context.get("tokens_out", 0),
                    },
                }
            )

        @ctx.on("agent:step")
        def on_agent_step(context):
            state = self._resolve_session(context, create=True)
            with self._sessions_lock:
                state["turn"] += 1
                turn_number = state["turn"]
            tool_names = context.get("tool_names", [])
            if isinstance(tool_names, str):
                tool_names = [tool_names]
            elif not isinstance(tool_names, (list, tuple)):
                log.warning(
                    "Ignoring malformed Hermes tool_names value of type %s",
                    type(tool_names).__name__,
                )
                tool_names = []
            iteration = context.get("iteration", turn_number)

            valid_tool_names = []
            for tool_name in tool_names:
                try:
                    validate_identifier(tool_name, "tool_name")
                except Exception:
                    log.warning("Ignoring malformed Hermes tool name")
                    continue
                valid_tool_names.append(tool_name)

            self._persist_lifecycle_event(
                {
                    "event_id": uuid.uuid4().hex,
                    "timestamp": _utcnow_iso(),
                    "agent": {
                        "type": "hermes",
                        "session_id": state["session_id"],
                        "run_id": state["run_id"],
                    },
                    "event_type": "agent_step",
                    "action": {
                        "tool_name": (
                            valid_tool_names[0]
                            if len(valid_tool_names) == 1
                            else None
                        ),
                        "tool_names": valid_tool_names,
                        "parameters": context.get("tool_input", {}) or {},
                        "target": context.get("target"),
                    },
                    "outcome": {
                        "status": context.get("outcome_status", "pending"),
                        "summary": _safe_text(
                            context.get(
                                "outcome_summary",
                                "Hermes lifecycle step reported "
                                f"{len(valid_tool_names)} tool(s)",
                            ),
                            500,
                        ),
                    },
                    "context": {
                        "turn_number": turn_number,
                        "iteration": iteration,
                        "platform": context.get("platform", "cli"),
                        "capture": HERMES_CAPABILITIES.as_context(),
                    },
                    "cost": {
                        "tokens_in": context.get("tokens_in", 0),
                        "tokens_out": context.get("tokens_out", 0),
                    },
                }
            )

        @ctx.on("agent:end")
        def on_agent_end(context):
            state = self._resolve_session(context)
            try:
                self._persist_lifecycle_event({
                    "event_id": uuid.uuid4().hex,
                    "timestamp": _utcnow_iso(),
                    "agent": {
                        "type": "hermes",
                        "session_id": state["session_id"],
                        "run_id": state["run_id"],
                    },
                    "event_type": "agent_end",
                    "action": {
                        "tool_name": None,
                        "parameters": {},
                        "target": None,
                    },
                    "outcome": {
                        "status": context.get("outcome_status", "success"),
                        "summary": _safe_text(context.get("response"), 200),
                    },
                    "context": {
                        "turn_number": state.get("turn", 0),
                        "total_turns": context.get("total_turns"),
                        "capture": HERMES_CAPABILITIES.as_context(),
                    },
                    "cost": {
                        "tokens_in": context.get("tokens_in", 0),
                        "tokens_out": context.get("tokens_out", 0),
                        "estimated_usd": context.get(
                            "estimated_usd", context.get("total_cost")
                        ),
                    },
                })
            finally:
                with self._sessions_lock:
                    if self._sessions.get(state["session_id"]) is state:
                        self._sessions.pop(state["session_id"], None)


# Default plugin instance, created lazily via PEP 562 module __getattr__ so
# that merely importing this module doesn't create ~/.panoptes/ or open the
# audit database. `from panoptes.hermes_plugin import plugin` still works.
_plugin = None


def get_plugin() -> AuditPlugin:
    """Return the shared default AuditPlugin, creating it on first use."""
    global _plugin
    if _plugin is None:
        _plugin = AuditPlugin()
    return _plugin


def __getattr__(name: str):
    if name == "plugin":
        return get_plugin()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
