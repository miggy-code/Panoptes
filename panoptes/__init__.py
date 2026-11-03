"""Adapter-based agent observations, local audit trails, and policy gates.

Panoptes normalizes events emitted by supported adapters into a canonical
schema and stores them in SQLite. Capture metadata is an unauthenticated
adapter assertion describing whether an event was observed, host-reported, or
synchronously authorized; schema conformance does not prove identity or local
execution.
"""

from importlib.metadata import PackageNotFoundError, version

from .capture import (
    CaptureCapabilities,
    HERMES_CAPABILITIES,
    PROXY_CAPABILITIES,
)
from .db import (
    AuditDB,
    ChainIntegrityError,
    EventConflictError,
    NotAnAuditDatabaseError,
    UnsupportedSchemaVersionError,
)
from .schema import (
    KNOWN_AGENT_TYPES,
    SCHEMA_VERSION,
    IdentifierRewriteError,
    ValidationError,
    normalize_event,
    redact_secrets,
    validate_event,
    validate_identifier,
)

# The policy engine pulls in PyYAML; load it only when it is asked for, so
# ``from panoptes import AuditDB`` stays light.
_LAZY_POLICY_EXPORTS = frozenset({
    "POLICY_ENGINE_SEMANTICS_VERSION",
    "Policy",
    "PolicyEngine",
    "PolicyResult",
})


def __getattr__(name: str):
    if name in _LAZY_POLICY_EXPORTS:
        from . import policy

        value = getattr(policy, name)
        globals()[name] = value
        return value
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return sorted(set(globals()) | _LAZY_POLICY_EXPORTS)


try:
    __version__ = version("panoptes-observe")
except PackageNotFoundError:
    __version__ = "0+unknown"

__all__ = [
    "AuditDB",
    "CaptureCapabilities",
    "ChainIntegrityError",
    "EventConflictError",
    "HERMES_CAPABILITIES",
    "IdentifierRewriteError",
    "KNOWN_AGENT_TYPES",
    "NotAnAuditDatabaseError",
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
    "__version__",
]
