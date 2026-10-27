"""Audit event validation, normalization, classification, and secret redaction.

Supported adapters normalize their observations to this canonical schema before
storage. Schema conformance alone does not establish execution or identity
assurance; those guarantees come from adapter provenance.
"""

import math
import re
import unicodedata
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

# ── Schema version ────────────────────────────────────────────────────────────
SCHEMA_VERSION = 4

# ── Allowed values ────────────────────────────────────────────────────────────
ALLOWED_AGENT_TYPES = frozenset({
    "claude_code", "codex", "hermes", "antigravity", "cursor",
    "gemini_cli", "agentgate", "unknown",
})

ALLOWED_EVENT_TYPES = frozenset({
    "model_request", "model_response", "tool_call", "tool_result",
    "decision_point", "policy_violation",
    "agent_start", "agent_step", "agent_end",
})

ALLOWED_OUTCOME_STATUSES = frozenset({
    "success", "error", "blocked", "timeout", "pending", "warned",
})

ALLOWED_AUTH_METHODS = frozenset({
    "api_key", "oauth", "cli",
})
_LEGACY_EVENT_TYPES = frozenset({
    "model_request", "model_response", "tool_call", "tool_result",
    "decision_point", "policy_violation",
})
_LEGACY_OUTCOME_STATUSES = frozenset({
    "success", "error", "blocked", "timeout",
})
_LEGACY_AGENT_TYPES = frozenset({
    "claude_code", "codex", "hermes", "antigravity", "unknown",
})
_EVENT_TYPES_BY_SCHEMA_VERSION = {
    1: _LEGACY_EVENT_TYPES,
    2: _LEGACY_EVENT_TYPES,
    3: _LEGACY_EVENT_TYPES,
    4: ALLOWED_EVENT_TYPES,
}
_OUTCOME_STATUSES_BY_SCHEMA_VERSION = {
    1: _LEGACY_OUTCOME_STATUSES,
    2: _LEGACY_OUTCOME_STATUSES,
    3: _LEGACY_OUTCOME_STATUSES,
    4: ALLOWED_OUTCOME_STATUSES,
}
_AGENT_TYPES_BY_SCHEMA_VERSION = {
    1: _LEGACY_AGENT_TYPES,
    2: _LEGACY_AGENT_TYPES,
    3: _LEGACY_AGENT_TYPES,
    4: ALLOWED_AGENT_TYPES,
}
MAX_IDENTIFIER_LENGTH = 256
MAX_JSON_DEPTH = 64
MAX_JSON_NODES = 100_000
MAX_EVENT_TEXT_CHARS = 8 * 1024 * 1024
MAX_JSON_INTEGER_BITS = 4096
MAX_COST_INTEGER = 2**53
_CONTROL_CHARACTER_RE = re.compile(r"[\x00-\x1f\x7f]")

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
    # OpenAI-style keys are commonly logged as bare values rather than key=value.
    (re.compile(r'\bsk-(?:proj-)?[A-Za-z0-9_\-]{16,}\b'),
     '[REDACTED API KEY]'),
    # Panoptes session tokens are live bearer credentials for injected keys.
    (re.compile(r'\bpnpt_[A-Za-z0-9_\-]{20,}'), '[REDACTED PANOPTES TOKEN]'),
    # Credentials embedded in database and other authority-bearing URLs.
    (re.compile(
        r'(?P<scheme>[a-z][a-z0-9+\-.]*://)'
        r'(?P<userinfo>[^/\s:@]+(?::[^/\s@]*)?@)',
        re.IGNORECASE,
    ), lambda m: f"{m.group('scheme')}[REDACTED]@"),
    # Signed URLs and API credentials in query strings.
    (re.compile(
        r'(?P<prefix>[?&](?:api[_-]?key|key|token|access[_-]?token|'
        r'signature|sig|x-amz-signature|x-goog-signature)=)'
        r'[^&#\s]+',
        re.IGNORECASE,
    ), lambda m: f"{m.group('prefix')}[REDACTED]"),
]

_REDACT_REPLACEMENT = "[REDACTED]"
_NON_SECRET_METADATA_KEYS = frozenset({
    # This records how the caller authenticated; it is not itself a credential.
    "auth_method",
})
_SAFE_CAPTURE_METADATA_VALUES = {
    # This fixed capability label is not an HTTP Authorization header. Only
    # known values receive that exception; arbitrary values under a
    # credential-shaped key must still be redacted.
    "authorization_check": frozenset({"pre_execution"}),
}
_CAPTURE_PROVENANCE = "adapter_asserted"

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
    if key_lower in _NON_SECRET_METADATA_KEYS:
        return False
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
            redacted_key = _redact_string(k) if isinstance(k, str) else k
            if redacted_key in redacted:
                # Redacting two distinct secret-bearing keys must not silently
                # discard one value. The suffix reveals only insertion order.
                base = str(redacted_key)
                index = 2
                while f"{base} #{index}" in redacted:
                    index += 1
                redacted_key = f"{base} #{index}"
            if isinstance(k, str) and _is_sensitive_key(k):
                redacted[redacted_key] = _REDACT_REPLACEMENT
            else:
                redacted[redacted_key] = redact_secrets(v)
        return redacted
    if isinstance(value, list):
        return [redact_secrets(item) for item in value]
    return value


def _redact_capture_metadata(value: Any) -> Any:
    """Apply key-aware redaction to an adapter's capture assertion.

    ``authorization_check`` is a known-safe capability label, so its value is
    inspected recursively without treating the label itself as a credential
    field. Every other key uses the normal key- and content-aware rules.
    """
    if not isinstance(value, dict):
        return redact_secrets(value)

    redacted: Dict[Any, Any] = {}
    for key, item in value.items():
        redacted_key = _redact_string(key) if isinstance(key, str) else key
        if redacted_key in redacted:
            base = str(redacted_key)
            index = 2
            while f"{base} #{index}" in redacted:
                index += 1
            redacted_key = f"{base} #{index}"
        if (
            isinstance(key, str)
            and key in _SAFE_CAPTURE_METADATA_VALUES
            and item in _SAFE_CAPTURE_METADATA_VALUES[key]
        ):
            redacted[redacted_key] = redact_secrets(item)
        elif isinstance(key, str) and _is_sensitive_key(key):
            redacted[redacted_key] = _REDACT_REPLACEMENT
        else:
            redacted[redacted_key] = redact_secrets(item)
    # Even sparse legacy assertions become explicit when normalized.
    redacted.setdefault("provenance", _CAPTURE_PROVENANCE)
    redacted.setdefault("authenticated", False)
    return redacted


# ── Data access classifiers ────────────────────────────────────────────────────
# Each entry is (compiled_regex, tag). During normalize_event, when
# action.data_accessed is supplied on a tool_call/tool_result, all strings in
# the action are still scanned against these patterns. Adapter-declared tags are
# untrusted hints; server-derived tags are authoritative and the two sets are
# unioned during normalization.
#
# This table is intentionally module-level so users can extend it at import time:
#   from panoptes.schema import DATA_ACCESS_CLASSIFIERS
#   DATA_ACCESS_CLASSIFIERS.append((re.compile(r'\bstaging\b'), 'staging'))

DATA_ACCESS_CLASSIFIERS: List[Tuple[re.Pattern, str]] = [
    # prod: production paths, namespaces, hostnames, or env names
    (re.compile(
        r'(?<![A-Za-z0-9])prod(?:uction)?(?![A-Za-z0-9])',
        re.IGNORECASE,
    ), 'prod'),
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

def _collect_string_values(
    obj: Any,
    _out: Optional[List[str]] = None,
    _seen: Optional[set[int]] = None,
) -> List[str]:
    """Recursively collect all string keys and values from JSON-like input.

    Uses a shared accumulator to avoid building intermediate lists at
    every level of the recursion. Container identities are tracked so a
    malformed cyclic Python object cannot recurse forever.
    """
    out: List[str] = [] if _out is None else _out
    seen: set[int] = set() if _seen is None else _seen
    if isinstance(obj, str):
        out.append(obj)
    elif isinstance(obj, dict):
        identity = id(obj)
        if identity in seen:
            return out
        seen.add(identity)
        for key, value in obj.items():
            if isinstance(key, str):
                out.append(key)
            _collect_string_values(value, out, seen)
    elif isinstance(obj, (list, tuple, set)):
        identity = id(obj)
        if identity in seen:
            return out
        seen.add(identity)
        for item in obj:
            _collect_string_values(item, out, seen)
    return out


def _derive_data_accessed(action: Dict[str, Any], event_type: str) -> List[str]:
    """Scan action parameters and target for data-access tags.

    Returns a sorted deduplicated list of server-derived tags.
    """
    if event_type not in (
        "tool_call",
        "tool_result",
        "decision_point",
        "policy_violation",
        "agent_step",
    ):
        return []

    scan_action = {
        key: value
        for key, value in action.items()
        if key not in {
            "call_id",
            "data_accessed",
            "declared_data_accessed",
            "derived_data_accessed",
        }
    }
    strings_to_scan = _collect_string_values(scan_action)

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


def validate_identifier(value: Any, field: str = "identifier") -> None:
    """Validate an identifier used for event, session, run, tool, or call IDs."""
    if not isinstance(value, str) or not value.strip():
        raise ValidationError(f"{field} must be a non-empty string")
    if len(value) > MAX_IDENTIFIER_LENGTH:
        raise ValidationError(
            f"{field} must be at most {MAX_IDENTIFIER_LENGTH} characters"
        )
    if _CONTROL_CHARACTER_RE.search(value) or any(
        unicodedata.category(character).startswith("C")
        for character in value
    ):
        raise ValidationError(f"{field} must not contain control characters")
    if "[REDACTED" in value or _redact_string(value) != value:
        raise ValidationError(f"{field} must not contain secret material")


def _validate_capture_metadata(
    capture: Any,
    *,
    require_assertion_marker: bool = False,
) -> None:
    """Validate the core shape of an unauthenticated adapter assertion."""
    if not isinstance(capture, dict):
        raise ValidationError("context.capture must be a dict")

    core_string_fields = (
        "adapter",
        "fidelity",
        "observation_boundary",
        "identity_assurance",
        "provenance",
    )
    for field in core_string_fields:
        if field not in capture:
            continue
        value = capture[field]
        if not isinstance(value, str) or not value:
            raise ValidationError(
                f"context.capture.{field} must be a non-empty string"
            )
    if (
        "provenance" in capture
        and capture["provenance"] != _CAPTURE_PROVENANCE
    ):
        raise ValidationError(
            "context.capture.provenance must declare an adapter assertion"
        )
    if require_assertion_marker and "provenance" not in capture:
        raise ValidationError(
            "context.capture.provenance must declare an adapter assertion"
        )

    for field in (
        "execution_observed",
        "enforcement_mandatory",
        "authenticated",
    ):
        if field in capture and not isinstance(capture[field], bool):
            raise ValidationError(f"context.capture.{field} must be a bool")
    if "authenticated" in capture and capture["authenticated"] is not False:
        raise ValidationError(
            "context.capture cannot claim authenticated provenance"
        )
    if require_assertion_marker and "authenticated" not in capture:
        raise ValidationError(
            "context.capture must explicitly disclaim authenticated provenance"
        )

    observed_events = capture.get("observed_events")
    if observed_events is not None:
        if not isinstance(observed_events, list) or not all(
            isinstance(event_type, str) and event_type
            for event_type in observed_events
        ):
            raise ValidationError(
                "context.capture.observed_events must be a list of event types"
            )
        unknown_event_types = set(observed_events) - ALLOWED_EVENT_TYPES
        if unknown_event_types:
            raise ValidationError(
                "context.capture.observed_events contains unknown event types: "
                f"{sorted(unknown_event_types)}"
            )

    enforcement_points = capture.get("enforcement_points")
    if enforcement_points is not None:
        if not isinstance(enforcement_points, list) or not all(
            isinstance(point, str) and point
            for point in enforcement_points
        ):
            raise ValidationError(
                "context.capture.enforcement_points must be a list of strings"
            )
    notes = capture.get("notes")
    if notes is not None and not isinstance(notes, str):
        raise ValidationError("context.capture.notes must be a string")
    for field, allowed_values in _SAFE_CAPTURE_METADATA_VALUES.items():
        if field in capture and (
            not isinstance(capture[field], str)
            or capture[field] not in allowed_values
        ):
            raise ValidationError(
                f"context.capture.{field} must be one of "
                f"{sorted(allowed_values)}"
            )


def _reject_unencodable(text: str, path: str) -> None:
    """Reject strings UTF-8 cannot encode, such as lone UTF-16 surrogates.

    JSON's ``\\ud800`` escapes decode to such strings; storage and hashing
    encode UTF-8, so accepting one would lose the event after validation.
    """
    try:
        text.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValidationError(f"{path} contains text that is not valid Unicode") from exc


def _validate_json_value(
    value: Any,
    path: str,
    *,
    depth: int = 0,
    seen: Optional[set[int]] = None,
    budget: Optional[Dict[str, int]] = None,
) -> None:
    """Reject cyclic, non-JSON, non-finite, or pathologically deep content."""
    budget = {"nodes": 0, "text_chars": 0} if budget is None else budget
    budget["nodes"] += 1
    if budget["nodes"] > MAX_JSON_NODES:
        raise ValidationError(
            f"{path} exceeds the maximum JSON node count of {MAX_JSON_NODES}"
        )
    if depth > MAX_JSON_DEPTH:
        raise ValidationError(
            f"{path} exceeds the maximum JSON depth of {MAX_JSON_DEPTH}"
        )
    if isinstance(value, str):
        _reject_unencodable(value, path)
        budget["text_chars"] += len(value)
        if budget["text_chars"] > MAX_EVENT_TEXT_CHARS:
            raise ValidationError(
                "event text exceeds the maximum of "
                f"{MAX_EVENT_TEXT_CHARS} characters"
            )
        return
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, int):
        if value.bit_length() > MAX_JSON_INTEGER_BITS:
            raise ValidationError(
                f"{path} contains an integer larger than "
                f"{MAX_JSON_INTEGER_BITS} bits"
            )
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValidationError(f"{path} contains a non-finite number")
        return

    seen = set() if seen is None else seen
    if isinstance(value, dict):
        identity = id(value)
        if identity in seen:
            raise ValidationError(f"{path} contains a cyclic mapping")
        seen.add(identity)
        try:
            for key, item in value.items():
                if not isinstance(key, str):
                    raise ValidationError(f"{path} contains a non-string key")
                _reject_unencodable(key, f"{path} key")
                budget["text_chars"] += len(key)
                if budget["text_chars"] > MAX_EVENT_TEXT_CHARS:
                    raise ValidationError(
                        "event text exceeds the maximum of "
                        f"{MAX_EVENT_TEXT_CHARS} characters"
                    )
                _validate_json_value(
                    item,
                    f"{path}.{key}",
                    depth=depth + 1,
                    seen=seen,
                    budget=budget,
                )
        finally:
            seen.remove(identity)
        return
    if isinstance(value, list):
        identity = id(value)
        if identity in seen:
            raise ValidationError(f"{path} contains a cyclic list")
        seen.add(identity)
        try:
            for index, item in enumerate(value):
                _validate_json_value(
                    item,
                    f"{path}[{index}]",
                    depth=depth + 1,
                    seen=seen,
                    budget=budget,
                )
        finally:
            seen.remove(identity)
        return
    raise ValidationError(
        f"{path} contains a non-JSON value of type {type(value).__name__}"
    )


def _validate_required_fields(event: Dict[str, Any]) -> None:
    if not isinstance(event, dict):
        raise ValidationError("event must be a dict")

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

    context = event.get("context", {})
    if not isinstance(context, dict):
        raise ValidationError("'context' must be a dict")
    capture = context.get("capture")
    if capture is not None:
        _validate_capture_metadata(capture, require_assertion_marker=True)
    schema_version = context.get("schema_version", SCHEMA_VERSION)
    if (
        isinstance(schema_version, bool)
        or not isinstance(schema_version, int)
        or schema_version < 1
        or schema_version > SCHEMA_VERSION
    ):
        raise ValidationError(
            f"context.schema_version must be between 1 and {SCHEMA_VERSION}"
        )

    allowed_agent_types = _AGENT_TYPES_BY_SCHEMA_VERSION[schema_version]
    if agent.get("type") not in allowed_agent_types:
        raise ValidationError(
            f"Invalid agent type '{agent.get('type')}' for event schema "
            f"version {schema_version}. Allowed: {sorted(allowed_agent_types)}"
        )
    for field in ("session_id", "run_id"):
        validate_identifier(agent.get(field), f"agent.{field}")

    event_id = event.get("event_id")
    if event_id is not None:
        validate_identifier(event_id, "event_id")

    timestamp = event.get("timestamp")
    if timestamp is not None:
        if isinstance(timestamp, datetime):
            if timestamp.tzinfo is None:
                raise ValidationError("timestamp datetime must include a timezone")
            parsed = timestamp
        elif not isinstance(timestamp, str) or not timestamp.strip():
            raise ValidationError("timestamp must be a non-empty ISO8601 string")
        else:
            try:
                parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            except ValueError as exc:
                raise ValidationError("timestamp must be valid ISO8601") from exc
            if parsed.tzinfo is None:
                raise ValidationError("timestamp must include a timezone")
        # Normalization stores UTC; an offset that pushes the instant outside
        # datetime's range must be a validation error, not a later crash.
        try:
            parsed.astimezone(timezone.utc)
        except OverflowError as exc:
            raise ValidationError("timestamp is outside the representable range") from exc

    # event_type
    allowed_event_types = _EVENT_TYPES_BY_SCHEMA_VERSION[schema_version]
    if event.get("event_type") not in allowed_event_types:
        raise ValidationError(
            f"Invalid event_type '{event.get('event_type')}' for event schema "
            f"version {schema_version}. Allowed: {sorted(allowed_event_types)}"
        )

    # outcome
    outcome = event.get("outcome", {})
    if not isinstance(outcome, dict):
        raise ValidationError("'outcome' must be a dict")
    allowed_outcome_statuses = _OUTCOME_STATUSES_BY_SCHEMA_VERSION[schema_version]
    if outcome.get("status") not in allowed_outcome_statuses:
        raise ValidationError(
            f"Invalid outcome status '{outcome.get('status')}' for event schema "
            f"version {schema_version}. Allowed: "
            f"{sorted(allowed_outcome_statuses)}"
        )

    # action
    action = event.get("action", {})
    if not isinstance(action, dict):
        raise ValidationError("'action' must be a dict")
    parameters = action.get("parameters")
    if parameters is not None and not isinstance(parameters, dict):
        raise ValidationError("action.parameters must be a dict")
    data_accessed = action.get("data_accessed")
    if data_accessed is not None and (
        not isinstance(data_accessed, list)
        or not all(isinstance(tag, str) and tag for tag in data_accessed)
    ):
        raise ValidationError("action.data_accessed must be a list of non-empty strings")
    for field in ("declared_data_accessed", "derived_data_accessed"):
        tags = action.get(field)
        if tags is not None and (
            not isinstance(tags, list)
            or not all(isinstance(tag, str) and tag for tag in tags)
        ):
            raise ValidationError(
                f"action.{field} must be a list of non-empty strings"
            )
    call_id = action.get("call_id")
    if call_id is not None:
        validate_identifier(call_id, "action.call_id")

    # context
    turn_number = context.get("turn_number")
    if turn_number is not None and (
        not isinstance(turn_number, int)
        or isinstance(turn_number, bool)
        or turn_number < 0
    ):
        raise ValidationError("context.turn_number must be a non-negative integer")


def validate_event(event: Dict[str, Any]) -> List[str]:
    """Validate an event against the universal schema.

    Returns a list of warnings (non-fatal issues). Raises ValidationError
    for fatal issues (missing required fields, invalid values).
    """
    warnings: List[str] = []
    _validate_required_fields(event)

    # Validate user if present
    user = event.get("user", {})
    if user is not None and not isinstance(user, dict):
        raise ValidationError("'user' must be a dict")
    if user:
        user_id = user.get("id")
        if user_id is not None:
            validate_identifier(user_id, "user.id")
        if user.get("auth_method") not in ALLOWED_AUTH_METHODS:
            raise ValidationError(
                f"Unknown auth_method '{user.get('auth_method')}'. "
                f"Allowed: {sorted(ALLOWED_AUTH_METHODS)}"
            )

    # Validate cost if present
    cost = event.get("cost", {})
    if cost is not None and not isinstance(cost, dict):
        raise ValidationError("'cost' must be a dict")
    if isinstance(cost, dict):
        for field in ("tokens_in", "tokens_out", "estimated_usd"):
            value = cost.get(field)
            if value is None:
                continue
            invalid = (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or value < 0
            )
            # Integers are finite by definition. Converting a valid, bounded
            # JSON integer to float can itself raise OverflowError and turn a
            # policy input into a fail-open parser error.
            if isinstance(value, float) and not math.isfinite(value):
                invalid = True
            # SQLite sums INTEGER columns in 64 bits and raises on overflow.
            if isinstance(value, int) and value > MAX_COST_INTEGER:
                invalid = True
            if invalid:
                raise ValidationError(
                    f"cost.{field} must be a finite non-negative number "
                    f"no larger than {MAX_COST_INTEGER}"
                )

    # Tool events require an explicit, usable tool identity.
    et = event.get("event_type", "")
    action = event.get("action", {})
    tool_name = action.get("tool_name")
    if tool_name is not None:
        validate_identifier(tool_name, "action.tool_name")
    if et in ("tool_call", "tool_result"):
        validate_identifier(tool_name, "action.tool_name")
    if et == "agent_step":
        tool_names = action.get("tool_names")
        if not isinstance(tool_names, list) or not all(
            isinstance(tool_name, str) and tool_name
            for tool_name in tool_names
        ):
            raise ValidationError(
                "agent_step action.tool_names must be a list of tool identifiers"
            )
        for tool_name in tool_names:
            validate_identifier(tool_name, "action.tool_names[]")

    # SQLite stores these sections as JSON. Reject values that would otherwise
    # be silently stringified or recurse forever during redaction/serialization.
    json_budget = {"nodes": 0, "text_chars": 0}
    for field in (
        "agent",
        "user",
        "action",
        "outcome",
        "context",
        "cost",
        "raw_request",
        "raw_response",
    ):
        if field in event and event[field] is not None:
            _validate_json_value(event[field], field, budget=json_budget)

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
    # Validation guarantees an aware ISO8601 value before database storage.
    # Parse every offset so lexicographic ordering remains chronological.
    parsed = datetime.fromisoformat(s.replace("Z", "+00:00"))
    return _format_utc(parsed)


def normalize_event(raw_event: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize a raw event dict into the canonical schema.

    This fills in defaults, generates missing fields, redacts secrets,
    truncates long fields, and derives data_accessed tags when empty.
    Returns a fully normalized event dict ready for storage.
    """
    if not isinstance(raw_event, dict):
        raise ValidationError("event must be a dict")

    # Reject malformed/cyclic or unreasonably large adapter input before
    # recursive redaction and classification touch it. This is intentionally
    # repeated by validate_event() after normalization because defaults and
    # derived fields also count toward the stored-event limit.
    json_budget = {"nodes": 0, "text_chars": 0}
    for field in (
        "agent",
        "user",
        "action",
        "outcome",
        "context",
        "cost",
        "raw_request",
        "raw_response",
    ):
        value = raw_event.get(field)
        if value is not None:
            _validate_json_value(value, field, budget=json_budget)
    for field in ("agent", "user", "action", "outcome", "context", "cost"):
        value = raw_event.get(field)
        if value is not None and not isinstance(value, dict):
            raise ValidationError(f"'{field}' must be a dict")

    # Validate correlation and identity fields before any content redaction.
    # Replacing two secret-shaped identifiers with the same redaction marker
    # would create an apparent identity collision in the audit trail.
    raw_event_id = raw_event.get("event_id")
    event_id = raw_event_id if raw_event_id is not None else uuid.uuid4().hex
    validate_identifier(event_id, "event_id")

    agent = raw_event.get("agent", {}) or {}
    session_id = (
        agent["session_id"]
        if "session_id" in agent
        else uuid.uuid4().hex
    )
    run_id = agent["run_id"] if "run_id" in agent else uuid.uuid4().hex
    validate_identifier(session_id, "agent.session_id")
    validate_identifier(run_id, "agent.run_id")

    user = raw_event.get("user", {}) or {}
    user_id = user["id"] if "id" in user else "local_user"
    validate_identifier(user_id, "user.id")
    auth_method = user.get("auth_method", "cli")
    if auth_method not in ALLOWED_AUTH_METHODS:
        raise ValidationError(
            f"Unknown auth_method '{auth_method}'. "
            f"Allowed: {sorted(ALLOWED_AUTH_METHODS)}"
        )

    action = raw_event.get("action", {}) or {}
    parameters = action.get("parameters")
    if parameters is not None and not isinstance(parameters, dict):
        raise ValidationError("action.parameters must be a dict")
    for field in ("data_accessed", "declared_data_accessed"):
        tags = action.get(field)
        if tags is not None and (
            not isinstance(tags, list)
            or not all(isinstance(tag, str) and tag for tag in tags)
        ):
            raise ValidationError(
                f"action.{field} must be a list of non-empty strings"
            )
    tool_name = action.get("tool_name")
    if tool_name is not None:
        validate_identifier(tool_name, "action.tool_name")
    call_id = action.get("call_id")
    if call_id is not None:
        validate_identifier(call_id, "action.call_id")
    tool_names = action.get("tool_names")
    if tool_names is not None:
        if not isinstance(tool_names, list):
            raise ValidationError("action.tool_names must be a list")
        for item in tool_names:
            validate_identifier(item, "action.tool_names[]")

    raw_context = raw_event.get("context", {}) or {}
    if raw_context.get("capture") is not None:
        _validate_capture_metadata(raw_context["capture"])

    event: Dict[str, Any] = {}

    # --- event_id ---
    event["event_id"] = event_id

    # --- timestamp ---
    event["timestamp"] = _normalize_timestamp(raw_event.get("timestamp"))

    # --- agent ---
    redacted_agent = redact_secrets({
        **agent,
        "type": agent.get("type", "unknown"),
        "version": agent.get("version"),
        "session_id": session_id,
        "run_id": run_id,
    })
    # These validated structural values are deliberately not content-redacted.
    redacted_agent["session_id"] = session_id
    redacted_agent["run_id"] = run_id
    event["agent"] = redacted_agent

    # --- user ---
    redacted_user = redact_secrets({
        **user,
        "id": user_id,
        "auth_method": auth_method,
    })
    redacted_user["id"] = user_id
    event["user"] = redacted_user

    # --- event_type ---
    event_type = raw_event.get("event_type", "unknown")
    event["event_type"] = event_type

    # --- action (with secret redaction) ---
    declared_source = (
        action.get("declared_data_accessed")
        if "declared_data_accessed" in action
        else action.get("data_accessed", [])
    )
    declared_data_accessed = sorted(set(declared_source or []))
    event["action"] = {
        **action,
        "tool_name": tool_name,
        "parameters": parameters or {},
        "target": action.get("target"),
        "call_id": call_id,  # preserve explicit correlation ID
        "data_accessed": declared_data_accessed,
        "declared_data_accessed": declared_data_accessed,
    }

    # --- always derive authoritative tags and union adapter-declared hints ---
    derived: List[str] = []
    if event_type in (
        "tool_call",
        "tool_result",
        "decision_point",
        "policy_violation",
        "agent_step",
    ):
        derived = _derive_data_accessed(event["action"], event_type)
    # Never trust a caller-supplied ``derived_data_accessed`` value. Canonical
    # replay remains idempotent because the classifier deterministically
    # recomputes this field from the action itself.
    event["action"]["derived_data_accessed"] = sorted(set(derived))
    event["action"]["data_accessed"] = sorted(
        set(declared_data_accessed).union(
            event["action"]["derived_data_accessed"]
        )
    )
    event["action"] = redact_secrets(event["action"])
    event["action"]["tool_name"] = tool_name
    event["action"]["call_id"] = call_id
    if tool_names is not None:
        event["action"]["tool_names"] = tool_names

    # --- outcome ---
    outcome = raw_event.get("outcome", {}) or {}
    event["outcome"] = redact_secrets({
        **outcome,
        "status": outcome.get("status", "success"),
        "summary": outcome.get("summary"),
        "error": outcome.get("error"),
    })

    # --- context (truncate user_message to 500 chars) ---
    context = raw_context
    user_msg = context.get("user_message")
    normalized_context = {
        **context,  # preserve all extra keys (policy_name, policy_message, etc.)
        "turn_number": context.get("turn_number"),
        "user_message": user_msg,
        "reasoning": context.get("reasoning"),
        # Preserve the schema under which an already-canonical event was
        # produced so replaying it after an upgrade remains idempotent.
        "schema_version": context.get("schema_version", SCHEMA_VERSION),
    }
    capture_metadata = normalized_context.pop("capture", None)
    event["context"] = redact_secrets(normalized_context)
    redacted_user_msg = event["context"].get("user_message")
    if (
        redacted_user_msg
        and isinstance(redacted_user_msg, str)
        and len(redacted_user_msg) > 500
    ):
        event["context"]["user_message"] = redacted_user_msg[:497] + "..."
    if capture_metadata is not None:
        event["context"]["capture"] = _redact_capture_metadata(capture_metadata)

    # --- cost ---
    cost = raw_event.get("cost", {}) or {}
    event["cost"] = redact_secrets({
        **cost,
        "tokens_in": cost.get("tokens_in"),
        "tokens_out": cost.get("tokens_out"),
        "estimated_usd": cost.get("estimated_usd"),
    })

    # --- raw payloads (optional, for debugging) ---
    event["raw_request"] = redact_secrets(raw_event.get("raw_request"))
    event["raw_response"] = redact_secrets(raw_event.get("raw_response"))

    return event


# ── Helper: extract flattened fields for SQLite indexing ──────────────────────

def extract_index_fields(event: Dict[str, Any]) -> Dict[str, Any]:
    """Extract flattened fields from a normalized event for SQLite storage.

    SQLite stores nested dicts as JSON TEXT, but we also extract key fields
    into dedicated columns for indexing and fast filtering.

    call_id is a provider/host correlation identifier. It is never inferred
    from a resource target: two legitimate calls may act on the same file or
    URL, and repeated deliveries remain distinct audit events.
    """
    agent = event.get("agent", {})
    action = event.get("action", {})
    call_id = action.get("call_id") or ""
    return {
        "agent_type": agent.get("type"),
        "session_id": agent.get("session_id"),
        "run_id": agent.get("run_id"),
        "tool_name": action.get("tool_name"),
        "data_accessed": ",".join(action.get("data_accessed", []) or []),
        "call_id": call_id,
    }
