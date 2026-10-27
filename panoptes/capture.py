"""Capture capability assertions made by Panoptes adapters.

An event can be perfectly normalized yet still be only an observation of a
model response rather than proof that a local tool ran.  Adapters attach this
metadata to every event so users and policy authors can distinguish those
guarantees.  The metadata is an adapter assertion, not authenticated
provenance or cryptographic proof of the reported identity or execution.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any, Tuple

from .schema import ALLOWED_EVENT_TYPES


CAPTURE_PROVENANCE = "adapter_asserted"
CAPTURE_PROVENANCE_AUTHENTICATED = False
_RESERVED_CAPTURE_FIELDS = frozenset({
    "adapter",
    "fidelity",
    "observed_events",
    "observation_boundary",
    "identity_assurance",
    "execution_observed",
    "enforcement_mandatory",
    "enforcement_points",
    "notes",
    "provenance",
    "authenticated",
})


@dataclass(frozen=True)
class CaptureCapabilities:
    """Observation and enforcement capabilities asserted by one adapter."""

    adapter: str
    fidelity: str
    observed_events: Tuple[str, ...]
    observation_boundary: str
    identity_assurance: str = "unverified"
    execution_observed: bool = False
    enforcement_mandatory: bool = False
    enforcement_points: Tuple[str, ...] = ()
    notes: str = ""

    def __post_init__(self) -> None:
        string_fields = {
            "adapter": self.adapter,
            "fidelity": self.fidelity,
            "observation_boundary": self.observation_boundary,
            "identity_assurance": self.identity_assurance,
        }
        for field, value in string_fields.items():
            if not isinstance(value, str) or not value:
                raise ValueError(f"{field} must be a non-empty string")
        if not isinstance(self.execution_observed, bool):
            raise ValueError("execution_observed must be a bool")
        if not isinstance(self.enforcement_mandatory, bool):
            raise ValueError("enforcement_mandatory must be a bool")
        if not isinstance(self.observed_events, tuple) or not all(
            isinstance(event_type, str) and event_type
            for event_type in self.observed_events
        ):
            raise ValueError("observed_events must be a tuple of event type names")
        unknown_events = set(self.observed_events) - ALLOWED_EVENT_TYPES
        if unknown_events:
            raise ValueError(
                "observed_events contains event types outside the audit schema: "
                f"{sorted(unknown_events)}"
            )
        if not isinstance(self.enforcement_points, tuple) or not all(
            isinstance(point, str) and point
            for point in self.enforcement_points
        ):
            raise ValueError(
                "enforcement_points must be a tuple of non-empty strings"
            )
        if not isinstance(self.notes, str):
            raise ValueError("notes must be a string")

    def as_context(self, **extra: Any) -> dict[str, Any]:
        """Return metadata suitable for ``event.context.capture``.

        Extra adapter details may supplement the assertion, but they cannot
        replace a reserved capability field.
        """
        conflicts = _RESERVED_CAPTURE_FIELDS.intersection(extra)
        if conflicts:
            raise ValueError(
                "capture extras cannot override reserved fields: "
                f"{sorted(conflicts)}"
            )
        capture = {
            "adapter": self.adapter,
            "fidelity": self.fidelity,
            "observed_events": list(self.observed_events),
            "observation_boundary": self.observation_boundary,
            "identity_assurance": self.identity_assurance,
            "execution_observed": self.execution_observed,
            "enforcement_mandatory": self.enforcement_mandatory,
            "enforcement_points": list(self.enforcement_points),
            "provenance": CAPTURE_PROVENANCE,
            "authenticated": CAPTURE_PROVENANCE_AUTHENTICATED,
        }
        if self.notes:
            capture["notes"] = self.notes
        capture.update({key: value for key, value in extra.items() if value is not None})
        return capture


PROXY_CAPABILITIES = CaptureCapabilities(
    adapter="http_proxy",
    fidelity="model_api",
    observation_boundary="model_api",
    identity_assurance="client_asserted",
    execution_observed=False,
    enforcement_mandatory=False,
    observed_events=(
        "model_request",
        "model_response",
        "tool_call",
        "tool_result",
    ),
    enforcement_points=(
        "model_request_preflight",
        "buffered_model_response",
    ),
    notes=(
        "Observes model API traffic and model-issued tool instructions; it does not "
        "observe or intercept arbitrary local tool execution."
    ),
)


# Credential-injection mode: agent type and session come from a Panoptes
# session token the proxy issued and resolved, not from client headers.
PROXY_TOKEN_CAPABILITIES = replace(
    PROXY_CAPABILITIES,
    identity_assurance="panoptes_session_token",
)


HERMES_CAPABILITIES = CaptureCapabilities(
    adapter="hermes_plugin",
    fidelity="agent_lifecycle",
    observation_boundary="hermes_lifecycle_hooks",
    identity_assurance="host_asserted",
    execution_observed=False,
    enforcement_mandatory=False,
    observed_events=("agent_start", "agent_step", "agent_end"),
    enforcement_points=("optional_pre_execution_authorizer",),
    notes=(
        "The installed lifecycle hooks are observational. A host integration must call "
        "AuditPlugin.authorize_tool_call() before execution to enforce a policy."
    ),
)

HERMES_AUTHORIZER_CAPABILITIES = CaptureCapabilities(
    adapter="hermes_authorizer",
    fidelity="host_pre_execution_authorization",
    observation_boundary="hermes_host_authorizer",
    identity_assurance="host_asserted",
    execution_observed=False,
    enforcement_mandatory=False,
    observed_events=("tool_call", "decision_point"),
    enforcement_points=("synchronous_pre_execution_authorizer",),
    notes=(
        "Records a host-supplied tool request before execution. Enforcement is "
        "effective only when the host calls the authorizer synchronously and honors "
        "allowed=False for the exact requested action."
    ),
)


@dataclass(frozen=True)
class AuthorizationDecision:
    """The result a host receives from a pre-execution authorization check."""

    allowed: bool
    action: str
    message: str | None = None
