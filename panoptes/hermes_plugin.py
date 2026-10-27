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

import copy
import logging
import os
import threading
import uuid

from panoptes.capture import (
    AuthorizationDecision,
    HERMES_AUTHORIZER_CAPABILITIES,
    HERMES_CAPABILITIES,
)
from panoptes.db import AuditDB
from panoptes.policy import (
    DEFAULT_POLICIES_DIR,
    POLICY_FAILURE_MODES,
    PolicyEngine,
    PolicyResult,
)
from panoptes.schema import (
    normalize_event,
    redact_secrets,
    utcnow_iso as _utcnow_iso,
    validate_event,
    validate_identifier,
)

DB_PATH = os.path.expanduser("~/.panoptes/audit.db")
DEFAULT_MAX_ACTIVE_SESSIONS = 1024
POLICY_FAILURE_MODE_ENV = "PANOPTES_POLICY_FAILURE_MODE"
log = logging.getLogger("panoptes.hermes")


def _block_message(result: PolicyResult) -> str:
    blocking_items = [
        item
        for item in result.violated_policies
        if item.get("action") == "block"
    ]
    if not blocking_items and result.action == "block":
        # Compatibility with host-supplied PolicyResult objects that predate
        # per-match action metadata. Never use explicit warn entries here.
        blocking_items = [
            item
            for item in result.violated_policies
            if item.get("action") in (None, "block")
        ]
    messages = [
        item.get("message", "Tool call blocked by policy")
        for item in blocking_items
    ]
    return "; ".join(messages) or "Tool call blocked by policy"


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
        policies_dir: str = DEFAULT_POLICIES_DIR,
        policy_failure_mode: str = "fail_open",
        max_active_sessions: int = DEFAULT_MAX_ACTIVE_SESSIONS,
    ):
        if policy_failure_mode not in POLICY_FAILURE_MODES:
            allowed = ", ".join(sorted(POLICY_FAILURE_MODES))
            raise ValueError(f"policy_failure_mode must be one of: {allowed}")
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
        self.policy_failure_mode = policy_failure_mode
        self.policy_engine = (
            PolicyEngine(
                policies_dir=policies_dir,
                db=self.db,
                failure_mode=policy_failure_mode,
            )
            if policies_dir
            else None
        )

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

    def _persist_decision(self, event: dict, result: PolicyResult) -> bool:
        """Persist an authorization decision and report whether evidence was durable."""
        decision = copy.deepcopy(event)
        decision["event_id"] = uuid.uuid4().hex
        decision["timestamp"] = _utcnow_iso()
        decision["event_type"] = "decision_point"
        decision["context"]["decision_kind"] = "tool_authorization"
        decision["context"]["source_event_id"] = event["event_id"]
        decision["context"]["source_event_type"] = event["event_type"]
        decision["context"]["policy"] = {
            "action": result.action,
            "matched_policies": result.matched_policies,
            "violated_policies": result.violated_policies,
            "evaluation_errors": result.evaluation_errors,
            "snapshot_id": result.policy_snapshot_id,
            "semantics_version": result.policy_engine_semantics_version,
        }
        if result.action == "block":
            message = _block_message(result)
            decision["outcome"] = {"status": "blocked", "summary": message}
        elif result.action == "warn" or result.evaluation_errors:
            decision["outcome"] = {
                "status": "warned",
                "summary": (
                    "Tool call authorized under fail-open after a policy "
                    "evaluation failure"
                    if result.evaluation_errors
                    else "Tool call authorized with policy warning"
                ),
            }
        else:
            decision["outcome"] = {
                "status": "success",
                "summary": "Tool call authorized before execution",
            }
        try:
            violations: list[dict] = []
            if self.policy_engine is not None:
                builder = getattr(
                    self.policy_engine,
                    "build_violation_event",
                    None,
                )
                if callable(builder):
                    for violation in result.violated_policies:
                        policy_action = violation.get("action", "block")
                        if policy_action not in ("warn", "block"):
                            continue
                        built = builder(
                            event,
                            violation.get("policy_name", "unknown"),
                            violation.get("message", "Policy matched"),
                            policy_action=policy_action,
                            policy_snapshot_id=result.policy_snapshot_id,
                            policy_engine_semantics_version=(
                                result.policy_engine_semantics_version
                            ),
                        )
                        if built is not None:
                            violations.append(built)
            insert_events = getattr(self.db, "insert_events", None)
            if callable(insert_events):
                # Preserve both the exact pre-execution request and its derived
                # decision, plus policy violations, in one audit transaction.
                # A decision_point alone would otherwise erase the fact that
                # the adapter observed a distinct tool_call request.
                insert_events([event, decision, *violations])
            else:
                # Compatibility for lightweight injected DB implementations.
                self.db.insert_event(event)
                self.db.insert_event(decision)
                for violation in violations:
                    self.db.insert_event(violation)
            return True
        except Exception:
            # A deny must never turn into an exception that a permissive host
            # could interpret as permission to execute.
            log.exception("Failed to persist Hermes authorization decision")
            return False

    def authorize_tool_call(self, context: dict) -> AuthorizationDecision:
        """Authorize a tool immediately before a host executes it.

        Hermes' shipped ``agent:*`` lifecycle hooks are observation-only. A
        Hermes host integration that supports a pre-execution tool hook should
        call this method and decline execution when ``allowed`` is false.
        Blocked calls are persisted here because no subsequent lifecycle step
        will exist for a tool that was correctly denied.
        """
        if not isinstance(context, dict):
            return AuthorizationDecision(
                allowed=False,
                action="block",
                message="Invalid tool authorization context",
            )

        state = self._resolve_session(context)
        # Once an agent:start callback establishes lifecycle identity, later
        # authorizer claims cannot rewrite that session's run attribution.
        session_id = state["session_id"]
        run_id = state["run_id"]
        user_id = state["user_id"]
        tool_name = context.get("tool_name") or context.get("name") or "unknown"
        with self._sessions_lock:
            turn_number = state.get("turn", 0)
        event = {
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
            "event_type": "tool_call",
            "action": {
                "tool_name": tool_name,
                "parameters": context.get("tool_input", context.get("parameters", {})),
                "target": context.get("target"),
                "call_id": context.get("call_id"),
            },
            "outcome": {
                "status": "pending",
                "summary": "Tool authorization requested before execution",
            },
            "context": {
                "turn_number": turn_number,
                "capture": HERMES_AUTHORIZER_CAPABILITIES.as_context(
                    authorization_check="pre_execution"
                ),
            },
            "cost": {},
        }

        try:
            event = normalize_event(event)
            validate_event(event)
        except Exception as exc:
            log.exception("Failed to normalize Hermes authorization event")
            errors = [f"Authorization event normalization failed: {exc}"]
            result = (
                self.policy_engine.input_failure_result(errors)
                if self.policy_engine
                else PolicyEngine.make_failure_result(
                    self.policy_failure_mode, errors
                )
            )
            fallback_session_id = _safe_identifier(
                session_id, uuid.uuid4().hex
            )
            fallback_run_id = _safe_identifier(run_id, uuid.uuid4().hex)
            fallback_tool_name = _safe_identifier(tool_name, "unknown")
            fallback = normalize_event({
                "event_id": uuid.uuid4().hex,
                "timestamp": _utcnow_iso(),
                "agent": {
                    "type": "hermes",
                    "session_id": fallback_session_id,
                    "run_id": fallback_run_id,
                },
                "user": {
                    "id": _safe_identifier(user_id, "unknown"),
                    "auth_method": "cli",
                },
                "event_type": "tool_call",
                "action": {
                    "tool_name": fallback_tool_name,
                    "parameters": {},
                    "target": None,
                    "call_id": None,
                },
                "outcome": {
                    "status": "pending",
                    "summary": "Invalid tool authorization event received",
                },
                "context": {
                    "turn_number": turn_number,
                    "capture": HERMES_AUTHORIZER_CAPABILITIES.as_context(
                        authorization_check="pre_execution",
                        input_validation="failed",
                    ),
                },
                "cost": {},
            })
            self._persist_decision(fallback, result)
            if result.action == "block":
                return AuthorizationDecision(
                    allowed=False,
                    action="block",
                    message=_block_message(result),
                )
            return AuthorizationDecision(
                allowed=True,
                action="allow",
                message=result.evaluation_errors[0],
            )

        if not self.policy_engine:
            result = PolicyEngine.make_failure_result(
                self.policy_failure_mode,
                ["No policy engine is configured for tool authorization"],
            )
        else:
            # Persistence is owned by _persist_decision so the source request,
            # derived decision, and policy violations share one transaction.
            result = self.policy_engine.evaluate(event)

        persisted = self._persist_decision(event, result)
        if result.action != "block":
            if not persisted and self.policy_failure_mode == "fail_closed":
                return AuthorizationDecision(
                    allowed=False,
                    action="block",
                    message="Authorization evidence could not be persisted",
                )
            return AuthorizationDecision(
                allowed=True,
                action=result.action,
                message=(result.warnings[0] if result.warnings else None),
            )

        message = _block_message(result)
        return AuthorizationDecision(allowed=False, action="block", message=message)

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


def _configured_failure_mode() -> str:
    """Read the installed plugin's failure mode from the environment.

    An unrecognized value means the operator asked for something other than
    the default, so it resolves to the stricter mode rather than fail-open.
    """
    value = os.environ.get(POLICY_FAILURE_MODE_ENV)
    if value is None or value == "":
        return "fail_open"
    if value in POLICY_FAILURE_MODES:
        return value
    log.error(
        "Unrecognized %s=%r; using fail_closed", POLICY_FAILURE_MODE_ENV, value
    )
    return "fail_closed"


def get_plugin() -> AuditPlugin:
    """Return the shared default AuditPlugin, creating it on first use."""
    global _plugin
    if _plugin is None:
        _plugin = AuditPlugin(policy_failure_mode=_configured_failure_mode())
    return _plugin


def __getattr__(name: str):
    if name == "plugin":
        return get_plugin()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
