"""Adapter-based agent observations, local audit trails, and policy gates.

Panoptes normalizes events emitted by supported adapters into a canonical
schema and stores them in SQLite. Capture metadata is an unauthenticated
adapter assertion describing whether an event was observed, host-reported, or
synchronously authorized; schema conformance does not prove identity or local
execution.
"""

from .capture import (
    AuthorizationDecision,
    CaptureCapabilities,
    HERMES_AUTHORIZER_CAPABILITIES,
    HERMES_CAPABILITIES,
    PROXY_CAPABILITIES,
)
from .db import (
    AuditDB,
    ChainIntegrityError,
    EventConflictError,
    UnsupportedSchemaVersionError,
)
from .policy import (
    POLICY_ENGINE_SEMANTICS_VERSION,
    Policy,
    PolicyEngine,
    PolicyResult,
)
from .schema import (
    SCHEMA_VERSION,
    ValidationError,
    normalize_event,
    redact_secrets,
    validate_event,
    validate_identifier,
)

__all__ = [
    "AuditDB",
    "AuthorizationDecision",
    "CaptureCapabilities",
    "ChainIntegrityError",
    "EventConflictError",
    "HERMES_AUTHORIZER_CAPABILITIES",
    "HERMES_CAPABILITIES",
    "POLICY_ENGINE_SEMANTICS_VERSION",
    "Policy",
    "PolicyEngine",
    "PolicyResult",
    "PROXY_CAPABILITIES",
    "SCHEMA_VERSION",
    "UnsupportedSchemaVersionError",
    "ValidationError",
    "normalize_event",
    "redact_secrets",
    "validate_event",
    "validate_identifier",
]
