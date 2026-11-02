"""Write tests/fixtures/panoptes_v4.db with a schema-v4 Panoptes.

Run against the code at commit 7fc2704 (the last schema-v4 writer), never a
newer checkout: the point of the fixture is a database a v4 build wrote and a
v5 build must still read and verify.

    git archive 7fc2704 | tar -x -C /tmp/panoptes-v4
    PYTHONPATH=/tmp/panoptes-v4 python tests/fixtures/make_panoptes_v4.py OUT.db
"""

import sys

from panoptes.db import AuditDB
from panoptes.schema import SCHEMA_VERSION

assert SCHEMA_VERSION == 4, "run this against a schema-v4 Panoptes"

CAPTURE = {
    "adapter": "proxy",
    "provenance": "adapter_asserted",
    "authenticated": False,
    "client_correlation_id": "corr-fixture-1",
}


def event(n, event_type, **extra):
    base = {
        "event_id": f"v4-fixture-{n:02d}",
        "timestamp": f"2026-10-01T09:00:{n:02d}.000Z",
        "event_type": event_type,
        "agent": {"type": "hermes", "session_id": "sess-1", "run_id": "run-1"},
        "action": {},
        "outcome": {"status": "success"},
        "context": {"schema_version": 4},
    }
    base.update(extra)
    return base


events = [
    event(1, "agent_start"),
    event(
        2, "model_request",
        action={"parameters": {"model": "m"}, "target": "https://api.example/v1"},
        context={"schema_version": 4, "turn_number": 1, "capture": CAPTURE},
        raw_request={"messages": [{"role": "user", "content": "hi"}]},
    ),
    event(
        3, "model_response",
        cost={"tokens_in": 10, "tokens_out": 5, "estimated_usd": 0.0012},
        context={"schema_version": 4, "turn_number": 1, "capture": CAPTURE},
    ),
    event(
        4, "tool_call",
        action={
            "tool_name": "bash", "call_id": "call-1",
            "parameters": {"command": "ls", "api_key": "sk-fake-fixture-secret-0123456789"},
        },
        outcome={"status": "pending"},
    ),
    event(
        5, "tool_result",
        action={"tool_name": "bash", "call_id": "call-1", "parameters": {}},
    ),
    event(6, "agent_step", action={"tool_names": ["bash", "read"]}),
    event(
        7, "policy_violation",
        outcome={"status": "blocked", "summary": "no prod"},
        user={"id": "alice", "auth_method": "api_key"},
    ),
    event(
        8, "decision_point",
        agent={"type": "agentgate", "session_id": "sess-2", "run_id": "run-2"},
    ),
    event(9, "agent_end"),
]

db = AuditDB(sys.argv[1])
db.insert_events(events)
assert db.verify_chain()["valid"]
db.close()
