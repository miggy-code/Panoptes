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

import os
import uuid

from panoptes.db import AuditDB
from panoptes.schema import utcnow_iso as _utcnow_iso

DB_PATH = os.path.expanduser("~/.panoptes/audit.db")


class AuditPlugin:
    """Hermes plugin that writes agent lifecycle events to the audit DB."""

    def __init__(self, db_path: str = None):
        self.db = AuditDB(db_path or DB_PATH)
        self._session_state = {}

    def register(self, ctx):
        """Register hook handlers with the Hermes plugin context."""

        @ctx.on("agent:start")
        def on_agent_start(context):
            session_id = context.get("session_id") or str(uuid.uuid4())
            run_id = context.get("run_id") or str(uuid.uuid4())
            user_id = context.get("user_id", "unknown")
            self._session_state = {
                "session_id": session_id,
                "run_id": run_id,
                "user_id": user_id,
                "turn": 0,
            }

            self.db.insert_event(
                {
                    "event_id": str(uuid.uuid4()),
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
                    "event_type": "model_request",
                    "action": {
                        "tool_name": None,
                        "parameters": {},
                        "target": None,
                    },
                    "outcome": {
                        "status": "success",
                        "summary": "Agent started processing",
                    },
                    "context": {
                        "turn_number": 0,
                        "user_message": context.get("message", "")[:500],
                    },
                    "cost": {
                        "tokens_in": context.get("tokens_in", 0),
                        "tokens_out": context.get("tokens_out", 0),
                    },
                }
            )

        @ctx.on("agent:step")
        def on_agent_step(context):
            self._session_state["turn"] += 1
            tool_names = context.get("tool_names", [])
            iteration = context.get("iteration", self._session_state["turn"])

            for tool_name in tool_names:
                self.db.insert_event(
                    {
                        "event_id": str(uuid.uuid4()),
                        "timestamp": _utcnow_iso(),
                        "agent": {
                            "type": "hermes",
                            "session_id": self._session_state["session_id"],
                            "run_id": self._session_state.get("run_id"),
                        },
                        "event_type": "tool_call",
                        "action": {
                            "tool_name": tool_name,
                            "parameters": context.get("tool_input", {}),
                            "target": context.get("target"),
                        },
                        "outcome": {
                            "status": context.get("outcome_status", "success"),
                            "summary": context.get(
                                "outcome_summary", f"Called {tool_name}"
                            ),
                        },
                        "context": {
                            "turn_number": self._session_state["turn"],
                            "iteration": iteration,
                            "platform": context.get("platform", "cli"),
                        },
                        "cost": {
                            "tokens_in": context.get("tokens_in", 0),
                            "tokens_out": context.get("tokens_out", 0),
                        },
                    }
                )

        @ctx.on("agent:end")
        def on_agent_end(context):
            self.db.insert_event(
                {
                    "event_id": str(uuid.uuid4()),
                    "timestamp": _utcnow_iso(),
                    "agent": {
                        "type": "hermes",
                        "session_id": self._session_state.get("session_id"),
                        "run_id": self._session_state.get("run_id"),
                    },
                    "event_type": "model_response",
                    "action": {
                        "tool_name": None,
                        "parameters": {},
                        "target": None,
                    },
                    "outcome": {
                        "status": context.get("outcome_status", "success"),
                        "summary": context.get("response", "")[:200],
                    },
                    "context": {
                        "turn_number": self._session_state.get("turn", 0),
                        "total_turns": context.get("total_turns"),
                    },
                    "cost": {
                        "tokens_in": context.get("tokens_in", 0),
                        "tokens_out": context.get("tokens_out", 0),
                        "total_cost": context.get("total_cost"),
                    },
                }
            )


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
