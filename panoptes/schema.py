"""
Universal audit schema — constants, validation, normalization, and secret redaction.

Every captured event from every agent gets normalized to the canonical schema
before being stored. This module provides the schema definition, validation logic,
and the normalization engine.
"""

import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

# ── Schema version ────────────────────────────────────────────────────────────
SCHEMA_VERSION = 1

# ── Allowed values ────────────────────────────────────────────────────────────
ALLOWED_AGENT_TYPES = frozenset({
    "claude_code", "codex", "hermes", "antigravity", "unknown",
})

ALLOWED_EVENT_TYPES = frozenset({
    "model_request", "model_response", "tool_call", "tool_result",
    "decision_point", "policy_violation",
})

ALLOWED_OUTCOME_STATUSES = frozenset({
    "success", "error", "blocked", "timeout",
})

ALLOWED_AUTH_METHODS = frozenset({
    "api_key", "oauth", "cli",
})

# ── Secret redaction ───────────────────────────────────────────────────────────

# Keys whose values should always be redacted regardless of content
_SENSITIVE_KEYS: frozenset = frozenset({
    "password", "passwd", "pwd", "secret", "token", "api_key", "apikey",
    "api_secret", "auth", "authorization", "private_key", "access_key",
    "access_token", "refresh_token", "credential", "credentials",
})

# Patterns for detecting secrets inside string values
_CONTENT_PATTERNS: List[Tuple[re.Pattern, str]] = [
    # Bearer tokens in Authorization header values
    (re.compile(r'^Bearer\s+(\S{16,})$', re.IGNORECASE),
     'Bearer [REDACTED]'),
    (re.compile(r'Bearer\s+([A-Za-z0-9_\-\.=]{16,})', re.IGNORECASE),
     r'Bearer [REDACTED]'),
    # Basic auth
    (re.compile(r'Basic\s+([A-Za-z0-9+/=]{8,})', re.IGNORECASE),
     r'Basic [REDACTED]'),
    # Private keys (PEM)
    (re.compile(r'-----BEGIN (?:RSA|EC|DSA|OPENSSH|ENCRYPTED)?\s*PRIVATE KEY-----.*?-----END (?:RSA|EC|DSA|OPENSSH|ENCRYPTED)?\s*PRIVATE KEY-----', re.DOTALL),
     '[REDACTED PRIVATE KEY]'),
    # AWS-like key IDs
    (re.compile(r'AKIA[0-9A-Z]{16}'), '[REDACTED AWS KEY ID]'),
    # GitHub tokens
    (re.compile(r'(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}'), '[REDACTED GITHUB TOKEN]'),
    # Generic API keys (sk-..., key=... patterns) inside string values
    (re.compile(r'(?:sk|api[_-]?key|apikey)\s*[:=]\s*["\']?([A-Za-z0-9_\-\.]{16,})["\']?', re.IGNORECASE),
     lambda m: m.group(0).replace(m.group(1), '[REDACTED]')),
]

_REDACT_REPLACEMENT = "[REDACTED]"


def _is_sensitive_key(key: str) -> bool:
    """Check if a key name indicates a sensitive value."""
    key_lower = key.lower().replace("-", "_").replace(" ", "_")
    # Direct match
    if key_lower in _SENSITIVE_KEYS:
        return True
    # Substring match (e.g. "db_password", "aws_secret_key")
    for sensitive in _SENSITIVE_KEYS:
        if sensitive in key_lower:
            return True
    return False


def _redact_string(value: str) -> str:
    """Apply content-based patterns to redact secrets from a string."""
    result = value
    for pattern, replacement in _CONTENT_PATTERNS:
        if callable(replacement):
            result = pattern.sub(replacement, result)
        else:
            result = pattern.sub(replacement, result)
    return result


def redact_secrets(value: Any) -> Any:
    """Recursively redact secrets from strings, dicts, and lists.

    Two strategies:
    1. Key-based: if a dict key looks sensitive (password, token, etc.),
       the value is replaced with [REDACTED] regardless of content.
    2. Content-based: string values are scanned for patterns like
       Bearer tokens, private keys, API keys, etc.
    """
    if value is None:
        return None
    if isinstance(value, str):
        return _redact_string(value)
    if isinstance(value, dict):
        redacted: Dict[str, Any] = {}
        for k, v in value.items():
            if isinstance(k, str) and _is_sensitive_key(k):
                redacted[k] = _REDACT_REPLACEMENT
            else:
                redacted[k] = redact_secrets(v)
        return redacted
    if isinstance(value, list):
        return [redact_secrets(item) for item in value]
    return value


# ── Validation ────────────────────────────────────────────────────────────────

class ValidationError(Exception):
    """Raised when an event fails schema validation."""
    pass


def _validate_required_fields(event: Dict[str, Any]) -> None:
    required_top = {"event_type", "agent", "action", "outcome", "context"}
    missing_top = required_top - set(event.keys())
    if missing_top:
        raise ValidationError(f"Missing top-level fields: {missing_top}")

    # agent sub-fields
    agent = event.get("agent", {})
    if not isinstance(agent, dict):
        raise ValidationError("'agent' must be a dict")
    missing_agent = {"type", "session_id", "run_id"} - set(agent.keys())
    if missing_agent:
        raise ValidationError(f"Missing agent fields: {missing_agent}")

    if agent.get("type") not in ALLOWED_AGENT_TYPES:
        raise ValidationError(
            f"Invalid agent type '{agent.get('type')}'. "
            f"Allowed: {sorted(ALLOWED_AGENT_TYPES)}"
        )

    # event_type
    if event.get("event_type") not in ALLOWED_EVENT_TYPES:
        raise ValidationError(
            f"Invalid event_type '{event.get('event_type')}'. "
            f"Allowed: {sorted(ALLOWED_EVENT_TYPES)}"
        )

    # outcome
    outcome = event.get("outcome", {})
    if not isinstance(outcome, dict):
        raise ValidationError("'outcome' must be a dict")
    if outcome.get("status") not in ALLOWED_OUTCOME_STATUSES:
        raise ValidationError(
            f"Invalid outcome status '{outcome.get('status')}'. "
            f"Allowed: {sorted(ALLOWED_OUTCOME_STATUSES)}"
        )

    # action
    action = event.get("action", {})
    if not isinstance(action, dict):
        raise ValidationError("'action' must be a dict")

    # context
    context = event.get("context", {})
    if not isinstance(context, dict):
        raise ValidationError("'context' must be a dict")


def validate_event(event: Dict[str, Any]) -> List[str]:
    """Validate an event against the universal schema.

    Returns a list of warnings (non-fatal issues). Raises ValidationError
    for fatal issues (missing required fields, invalid values).
    """
    warnings: List[str] = []
    _validate_required_fields(event)

    # Validate user if present
    user = event.get("user", {})
    if user:
        if user.get("auth_method") not in ALLOWED_AUTH_METHODS:
            warnings.append(
                f"Unknown auth_method '{user.get('auth_method')}'. "
                f"Allowed: {sorted(ALLOWED_AUTH_METHODS)}"
            )

    # Validate cost if present
    cost = event.get("cost", {})
    if cost and not isinstance(cost, dict):
        warnings.append("'cost' must be a dict, ignoring")

    # Check that tool_name matches event_type
    et = event.get("event_type", "")
    action = event.get("action", {})
    if et in ("tool_call", "tool_result") and not action.get("tool_name"):
        warnings.append(
            f"event_type '{et}' should have a non-empty action.tool_name"
        )

    # Warn about missing event_id (will be generated)
    if not event.get("event_id"):
        warnings.append("No event_id provided; will be auto-generated")

    # Warn about missing timestamp (will be generated)
    if not event.get("timestamp"):
        warnings.append("No timestamp provided; will be set to now")

    return warnings


# ── Normalization ─────────────────────────────────────────────────────────────

def normalize_event(raw_event: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize a raw event dict into the canonical schema.

    This fills in defaults, generates missing fields, redacts secrets,
    and truncates long fields. Returns a fully normalized event dict ready
    for storage.
    """
    event: Dict[str, Any] = {}

    # --- event_id ---
    event["event_id"] = raw_event.get("event_id") or uuid.uuid4().hex

    # --- timestamp ---
    ts = raw_event.get("timestamp")
    if ts is None:
        event["timestamp"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    elif isinstance(ts, datetime):
        event["timestamp"] = ts.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    else:
        event["timestamp"] = str(ts)

    # --- agent ---
    agent = raw_event.get("agent", {})
    event["agent"] = {
        "type": agent.get("type", "unknown"),
        "version": agent.get("version"),
        "session_id": agent.get("session_id", uuid.uuid4().hex),
        "run_id": agent.get("run_id", uuid.uuid4().hex),
    }

    # --- user ---
    user = raw_event.get("user", {}) or {}
    event["user"] = {
        "id": user.get("id", "local_user"),
        "auth_method": user.get("auth_method", "cli"),
    }

    # --- event_type ---
    event["event_type"] = raw_event.get("event_type", "unknown")

    # --- action (with secret redaction) ---
    action = raw_event.get("action", {}) or {}
    parameters = redact_secrets(action.get("parameters", {}) or {})
    event["action"] = {
        "tool_name": action.get("tool_name"),
        "parameters": parameters,
        "target": action.get("target"),
        "data_accessed": action.get("data_accessed", []),
    }

    # --- outcome ---
    outcome = raw_event.get("outcome", {}) or {}
    event["outcome"] = {
        "status": outcome.get("status", "success"),
        "summary": outcome.get("summary"),
        "error": outcome.get("error"),
    }

    # --- context (truncate user_message to 500 chars) ---
    context = raw_event.get("context", {}) or {}
    user_msg = context.get("user_message")
    if user_msg and isinstance(user_msg, str) and len(user_msg) > 500:
        user_msg = user_msg[:497] + "..."
    event["context"] = {
        **context,  # preserve all extra keys (policy_name, policy_message, etc.)
        "turn_number": context.get("turn_number"),
        "user_message": user_msg,
        "reasoning": context.get("reasoning"),
    }

    # --- cost ---
    cost = raw_event.get("cost", {}) or {}
    event["cost"] = {
        "tokens_in": cost.get("tokens_in"),
        "tokens_out": cost.get("tokens_out"),
        "estimated_usd": cost.get("estimated_usd"),
    }

    # --- raw payloads (optional, for debugging) ---
    event["raw_request"] = raw_event.get("raw_request")
    event["raw_response"] = raw_event.get("raw_response")

    return event


# ── Helper: extract flattened fields for SQLite indexing ──────────────────────

def extract_index_fields(event: Dict[str, Any]) -> Dict[str, Any]:
    """Extract flattened fields from a normalized event for SQLite storage.

    SQLite stores nested dicts as JSON TEXT, but we also extract key fields
    into dedicated columns for indexing and fast filtering.
    """
    agent = event.get("agent", {})
    action = event.get("action", {})
    return {
        "agent_type": agent.get("type"),
        "session_id": agent.get("session_id"),
        "run_id": agent.get("run_id"),
        "tool_name": action.get("tool_name"),
        "data_accessed": ",".join(action.get("data_accessed", []) or []),
    }
