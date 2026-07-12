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
SCHEMA_VERSION = 3

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

# Compiled regex for camelCase splitting (used in key tokenization)
_CAMEL_SPLIT_RE = re.compile(r'([a-z])([A-Z])')
_DELIMITER_SPLIT_RE = re.compile(r'[_\-\s]+')


def _tokenize_key(key: str) -> List[str]:
    """Tokenize a key name into lower-case word parts.

    Handles snake_case, kebab-case, space-separated, and camelCase names.
    Examples:
        "author"            → ["author"]
        "authorization"     → ["authorization"]
        "db_password"       → ["db", "password"]
        "apiKey"            → ["api", "key"]
        "AWS-SECRET-KEY"    → ["aws", "secret", "key"]
    """
    # Split camelCase boundaries before lowercasing
    camel_split = _CAMEL_SPLIT_RE.sub(r'\1_\2', key)
    parts = _DELIMITER_SPLIT_RE.split(camel_split)
    return [p.lower() for p in parts if p]


def _is_sensitive_key(key: str) -> bool:
    """Check if a key name indicates a sensitive value.

    Uses token-based matching to avoid false positives like 'author' matching
    'auth'. Checks:
      1. Full normalized key direct match (fast path).
      2. Any single token in the set.
      3. Any adjacent token pair joined by '_' in the set.
    """
    key_lower = key.lower().replace("-", "_").replace(" ", "_")
    # Direct match on full normalized key
    if key_lower in _SENSITIVE_KEYS:
        return True

    # Token-based matching — avoids "auth" matching "author"
    tokens = _tokenize_key(key)
    for token in tokens:
        if token in _SENSITIVE_KEYS:
            return True
    # Adjacent token-pair matching — catches "api_key", "private_key", etc.
    for i in range(len(tokens) - 1):
        pair = tokens[i] + "_" + tokens[i + 1]
        if pair in _SENSITIVE_KEYS:
            return True
    return False


def _redact_string(value: str) -> str:
    """Apply content-based patterns to redact secrets from a string."""
    result = value
    for pattern, replacement in _CONTENT_PATTERNS:
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


# ── Data access classifiers ────────────────────────────────────────────────────
# Each entry is (compiled_regex, tag). During normalize_event, when
# action.data_accessed is empty on a tool_call/tool_result, all string values
# inside action.parameters (recursively) and action.target are scanned against
# these patterns. Matching tags are collected into data_accessed as a sorted,
# deduped list. Keep strings > _CLASSIFIER_STRING_MAX_LEN unscanned for perf.
#
# This table is intentionally module-level so users can extend it at import time:
#   from panoptes.schema import DATA_ACCESS_CLASSIFIERS
#   DATA_ACCESS_CLASSIFIERS.append((re.compile(r'\bstaging\b'), 'staging'))

DATA_ACCESS_CLASSIFIERS: List[Tuple[re.Pattern, str]] = [
    # prod: production paths, namespaces, hostnames, or env names
    (re.compile(r'\bprod(?:uction)?\b', re.IGNORECASE), 'prod'),
    # secrets: credential files, private keys, secret-named paths/vars
    (re.compile(
        r'\.env\b|id_rsa|\.pem\b|\.key\b|/etc/passwd|/etc/shadow'
        r'|credential|AWS_SECRET|/vault/',
        re.IGNORECASE
    ), 'secrets'),
    # infra: infrastructure orchestration CLI tools
    (re.compile(r'\b(?:kubectl|helm|terraform|gcloud)\b', re.IGNORECASE), 'infra'),
    # database: database clients and connection-string env vars
    (re.compile(r'\b(?:psql|mysql|mongosh?|redis-cli)\b|DATABASE_URL', re.IGNORECASE), 'database'),
    # network: HTTP transfer tools and URLs
    (re.compile(r'\b(?:curl|wget)\b|https?://', re.IGNORECASE), 'network'),
]

_CLASSIFIER_STRING_MAX_LEN = 10_000


def _collect_string_values(
    obj: Any,
    max_len: int = _CLASSIFIER_STRING_MAX_LEN,
    _out: Optional[List[str]] = None,
) -> List[str]:
    """Recursively collect string values from a nested dict/list/str.

    Uses a shared accumulator to avoid building intermediate lists at
    every level of the recursion.
    """
    out: List[str] = [] if _out is None else _out
    if isinstance(obj, str):
        if len(obj) <= max_len:
            out.append(obj)
    elif isinstance(obj, dict):
        for v in obj.values():
            _collect_string_values(v, max_len, out)
    elif isinstance(obj, list):
        for item in obj:
            _collect_string_values(item, max_len, out)
    return out


def _derive_data_accessed(action: Dict[str, Any], event_type: str) -> List[str]:
    """Scan action parameters and target for data-access tags.

    Only called when action.data_accessed is empty and event_type is
    'tool_call' or 'tool_result'. Returns a sorted deduplicated list of tags.
    """
    if event_type not in ("tool_call", "tool_result"):
        return []

    strings_to_scan = _collect_string_values(action.get("parameters") or {})
    target = action.get("target")
    if target and isinstance(target, str) and len(target) <= _CLASSIFIER_STRING_MAX_LEN:
        strings_to_scan.append(target)

    tags: set = set()
    for s in strings_to_scan:
        for pattern, tag in DATA_ACCESS_CLASSIFIERS:
            if tag not in tags and pattern.search(s):
                tags.add(tag)

    return sorted(tags)


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

def _format_utc(dt: datetime) -> str:
    """Format a datetime as ISO8601 UTC with millisecond precision and Z suffix."""
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def utcnow_iso() -> str:
    """Current UTC time in the canonical event timestamp format.

    All event producers (proxy, policy engine, agent plugins) should use this
    so stored timestamps sort consistently.
    """
    return _format_utc(datetime.now(timezone.utc))


def _normalize_timestamp(ts: Any) -> str:
    """Normalize a timestamp to a Z-suffixed ISO8601 UTC string.

    Events are ordered by string comparison of this column, so all sources
    must agree on one suffix: '+00:00' sorts before 'Z' at the same instant,
    which would interleave events from different producers incorrectly.
    """
    if ts is None:
        return _format_utc(datetime.now(timezone.utc))
    if isinstance(ts, datetime):
        return _format_utc(ts)
    s = str(ts)
    if s.endswith("+00:00"):
        return s[:-6] + "Z"
    return s


def normalize_event(raw_event: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize a raw event dict into the canonical schema.

    This fills in defaults, generates missing fields, redacts secrets,
    truncates long fields, and derives data_accessed tags when empty.
    Returns a fully normalized event dict ready for storage.
    """
    event: Dict[str, Any] = {}

    # --- event_id ---
    event["event_id"] = raw_event.get("event_id") or uuid.uuid4().hex

    # --- timestamp ---
    event["timestamp"] = _normalize_timestamp(raw_event.get("timestamp"))

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
    event_type = raw_event.get("event_type", "unknown")
    event["event_type"] = event_type

    # --- action (with secret redaction) ---
    action = raw_event.get("action", {}) or {}
    parameters = redact_secrets(action.get("parameters", {}) or {})
    data_accessed = list(action.get("data_accessed", []) or [])

    event["action"] = {
        "tool_name": action.get("tool_name"),
        "parameters": parameters,
        "target": action.get("target"),
        "call_id": action.get("call_id"),  # preserve explicit call_id for dedup
        "data_accessed": data_accessed,
    }

    # --- derive data_accessed tags when not explicitly set ---
    if not data_accessed and event_type in ("tool_call", "tool_result"):
        derived = _derive_data_accessed(event["action"], event_type)
        if derived:
            event["action"]["data_accessed"] = derived

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

    call_id is used for deduplication of replayed tool_call/tool_result events:
      - prefer action.call_id (set by proxy from provider call id)
      - fall back to action.target (legacy behavior)
      - empty string if neither
    """
    agent = event.get("agent", {})
    action = event.get("action", {})
    call_id = action.get("call_id") or action.get("target") or ""
    return {
        "agent_type": agent.get("type"),
        "session_id": agent.get("session_id"),
        "run_id": agent.get("run_id"),
        "tool_name": action.get("tool_name"),
        "data_accessed": ",".join(action.get("data_accessed", []) or []),
        "call_id": call_id,
    }
