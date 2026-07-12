"""
panoptes — Universal panoptes trail system.

Normalizes events from any agent (Claude Code, Codex, Hermes, etc.)
into a canonical schema and stores them in SQLite with a rich query API.
"""

from .config import ConfigError, load_config
from .db import AuditDB
from .policy import (
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
)

__all__ = [
    "AuditDB",
    "ConfigError",
    "load_config",
    "Policy",
    "PolicyEngine",
    "PolicyResult",
    "SCHEMA_VERSION",
    "ValidationError",
    "normalize_event",
    "redact_secrets",
    "validate_event",
]
