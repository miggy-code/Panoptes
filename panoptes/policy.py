"""
Policy engine for panoptes.

Loads YAML policy definitions, evaluates events against rules, and enforces
allow/warn/block decisions. Supports condition matching, scope filtering, and
policy violation recording.

Policies live in ~/.panoptes/policies/ as individual .yaml files.
"""

from __future__ import annotations

import copy
import hashlib
import json
import logging
import os
import re
import uuid
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from typing import Any, Callable, Dict, List, Optional, Tuple

import yaml

from panoptes.schema import (
    ALLOWED_AGENT_TYPES,
    ALLOWED_EVENT_TYPES,
    normalize_event,
    redact_secrets,
    utcnow_iso,
    validate_event,
)

log = logging.getLogger("panoptes.policy")

# ── Default policies directory ───────────────────────────────────────────────

DEFAULT_POLICIES_DIR = "~/.panoptes/policies/"
POLICY_ENGINE_SEMANTICS_VERSION = 1
POLICY_FAILURE_MODES = frozenset({"fail_open", "fail_closed"})
CONDITION_OPERATORS = frozenset({
    "==", "!=", "contains", "in", "matches", "gt", "lt", "gte", "lte",
})
MAX_MATCH_PATTERN_LENGTH = 256
MAX_POLICY_REASON_LENGTH = 2048
_POLICY_FIELD_PATHS = frozenset({
    "event_id",
    "timestamp",
    "event_type",
    "agent.type",
    "agent.version",
    "agent.session_id",
    "agent.run_id",
    "user.id",
    "user.auth_method",
    "action.tool_name",
    "action.tool_names",
    "action.parameters",
    "action.target",
    "action.call_id",
    "action.data_accessed",
    "action.declared_data_accessed",
    "action.derived_data_accessed",
    "action.requested_tools",
    "action.client_side_tools",
    "action.server_side_tools",
    "action.unknown_tool_types",
    "action.requested_tool_targets",
    "action.execution_scope",
    "action.provider_item_type",
    "action.status",
    "action.server_result_type",
    "action.server_result_complete",
    "action.result",
    "action.result_complete",
    "action.method",
    "action.path",
    "action.model",
    "action.messages_count",
    "action.tools_count",
    "action.streaming",
    "action.status_code",
    "action.duration_ms",
    "outcome.status",
    "outcome.summary",
    "outcome.error",
    "context.turn_number",
    "context.reasoning",
    "context.schema_version",
    "context.capture",
    "context.iteration",
    "context.platform",
    "context.total_turns",
    "context.decision_kind",
    "context.policy",
    "context.policy_name",
    "context.policy_message",
    "context.policy_action",
    "context.policy_snapshot_id",
    "context.policy_engine_semantics_version",
    "context.source_event_id",
    "context.source_event_type",
    "context.source_schema_version",
    "context.source_capture",
    "cost.tokens_in",
    "cost.tokens_out",
    "cost.estimated_usd",
})
_OPEN_POLICY_FIELD_PREFIXES = (
    "action.parameters.",
    "action.result.",
    "context.capture.",
    "context.policy.",
    "context.source_capture.",
)
_LOSSY_POLICY_FIELD_ROOTS = frozenset({
    "raw_request",
    "raw_response",
    "context.user_message",
    "action.server_result_summary",
})
_POLICY_FIELDS = frozenset({
    "name", "description", "enabled", "scope", "rule", "action", "message",
})
_SCOPE_FIELDS = frozenset({"agents", "sessions"})
_RULE_FIELDS = frozenset({"event_type", "conditions", "logic"})
_CONDITION_FIELDS = frozenset({"field", "operator", "value"})
_POLICY_ENGINE_CAPTURE = {
    "adapter": "policy_engine",
    "fidelity": "derived_policy_record",
    "observation_boundary": "policy_evaluation",
    "identity_assurance": "inherited_unverified",
    "provenance": "adapter_asserted",
    "execution_observed": False,
    "enforcement_mandatory": False,
    "authenticated": False,
    "observed_events": ["policy_violation"],
}


class _UniqueKeySafeLoader(yaml.SafeLoader):
    """Safe YAML loader that rejects duplicate mapping keys."""


def _construct_unique_mapping(
    loader: yaml.SafeLoader,
    node: yaml.nodes.MappingNode,
    deep: bool = False,
) -> dict:
    mapping: dict = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in mapping
        except TypeError as exc:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                "found an unhashable mapping key",
                key_node.start_mark,
            ) from exc
        if duplicate:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"found duplicate key {key!r}",
                key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueKeySafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def _strict_json_loads(payload: str) -> Any:
    """Parse JSON without duplicate keys or non-finite numeric extensions."""
    def unique_object(pairs: list[tuple[str, Any]]) -> dict:
        result: dict = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key {key!r}")
            result[key] = value
        return result

    def reject_constant(value: str) -> None:
        raise ValueError(f"non-finite JSON number {value!r}")

    return json.loads(
        payload,
        object_pairs_hook=unique_object,
        parse_constant=reject_constant,
    )


# ── PolicyResult ─────────────────────────────────────────────────────────────


@dataclass
class PolicyResult:
    """Result of evaluating one or more policies against an event."""

    action: str  # "allow", "warn", "block"
    violated_policies: list[dict] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    evaluation_errors: list[str] = field(default_factory=list)
    matched_policies: list[dict] = field(default_factory=list)
    policy_snapshot_id: str | None = None
    policy_engine_semantics_version: int = POLICY_ENGINE_SEMANTICS_VERSION


def _sanitize_reason(reason: str) -> str:
    """Redact and bound untrusted values embedded in diagnostic reasons."""
    redacted = redact_secrets(reason)
    text = redacted if isinstance(redacted, str) else str(redacted)
    if len(text) <= MAX_POLICY_REASON_LENGTH:
        return text
    return text[: MAX_POLICY_REASON_LENGTH - 3] + "..."


def _validate_policy_field_path(field_path: str, prefix: str) -> None:
    """Allow only complete canonical fields and explicitly open namespaces."""
    field_parts = field_path.split(".")
    if any(not part for part in field_parts):
        raise ValueError(
            f"{prefix}.field must not contain empty path components"
        )
    if any(
        field_path == lossy_root
        or field_path.startswith(lossy_root + ".")
        for lossy_root in _LOSSY_POLICY_FIELD_ROOTS
    ):
        raise ValueError(
            f"{prefix}.field cannot target lossy presentation field "
            f"{field_path!r}"
        )
    if (
        field_path in _POLICY_FIELD_PATHS
        or any(
            field_path.startswith(open_prefix)
            for open_prefix in _OPEN_POLICY_FIELD_PREFIXES
        )
    ):
        return
    raise ValueError(
        f"{prefix}.field is not a canonical enforceable field: "
        f"{field_path!r}"
    )


def _validate_safe_match_pattern(pattern: str, prefix: str) -> None:
    """Validate the deliberately small, predictable ``matches`` subset.

    Python's backtracking regex engine can consume unbounded CPU on nested or
    ambiguous patterns. Policy patterns therefore allow character classes,
    anchors, escapes, literals, ``.``, and at most one unescaped ``*``, ``+``
    or ``?`` quantifier. A quantified pattern must be start-anchored. Groups,
    alternation, and brace quantifiers are not part of the policy language.
    """
    if len(pattern) > MAX_MATCH_PATTERN_LENGTH:
        raise ValueError(
            f"{prefix}.value exceeds the maximum regex length of "
            f"{MAX_MATCH_PATTERN_LENGTH}"
        )

    escaped = False
    in_character_class = False
    quantifier_count = 0
    for character in pattern:
        if escaped:
            escaped = False
            continue
        if character == "\\":
            escaped = True
            continue
        if character == "[" and not in_character_class:
            in_character_class = True
            continue
        if character == "]" and in_character_class:
            in_character_class = False
            continue
        if in_character_class:
            continue
        if character in "()|{}":
            raise ValueError(
                f"{prefix}.value uses unsupported regex syntax {character!r}"
            )
        if character in "*+?":
            quantifier_count += 1
            if quantifier_count > 1:
                raise ValueError(
                    f"{prefix}.value may contain at most one unescaped "
                    "regex quantifier"
                )
    if quantifier_count and not pattern.startswith("^"):
        raise ValueError(
            f"{prefix}.value regex quantifiers require a leading '^' anchor"
        )

    try:
        re.compile(pattern)
    except re.error as exc:
        raise ValueError(f"{prefix}.value is an invalid regex: {exc}") from exc


# ── Pre-compiled condition helpers ────────────────────────────────────────────


def _diagnostic_repr(value: Any, limit: int = 768) -> str:
    """Render a value only after structured, key-aware secret redaction."""
    try:
        rendered = repr(redact_secrets(value))
    except Exception:
        rendered = f"<{type(value).__name__}>"
    if len(rendered) <= limit:
        return rendered
    return rendered[: limit - 3] + "..."


def _coerce_finite_decimal(value: Any) -> Optional[Decimal]:
    """Convert supported numeric values without float overflow or bool coercion."""
    if value is None or isinstance(value, bool):
        return None
    if not isinstance(value, (int, float, str)):
        return None
    try:
        converted = Decimal(str(value))
    except (InvalidOperation, ValueError, OverflowError):
        return None
    return converted if converted.is_finite() else None


def _compile_condition_fn(
    field_path: str, operator: str, expected: Any
) -> Callable[[Any], Tuple[bool, str]]:
    """Return a callable(actual_value) -> (matched, reason) for one condition.

    All expensive work (regex compilation, numeric conversion) is done here
    once at Policy construction time.  The returned callable is called once
    per event.
    """
    if operator == "==":
        def run(actual: Any) -> Tuple[bool, str]:
            return (
                actual == expected,
                f"{field_path} == {_diagnostic_repr(expected)} -> "
                f"{_diagnostic_repr(actual)}",
            )

    elif operator == "!=":
        def run(actual: Any) -> Tuple[bool, str]:
            return (
                actual != expected,
                f"{field_path} != {_diagnostic_repr(expected)} -> "
                f"{_diagnostic_repr(actual)}",
            )

    elif operator == "contains":
        def run(actual: Any) -> Tuple[bool, str]:
            if isinstance(actual, list):
                matched = expected in actual if expected is not None else False
                return (
                    matched,
                    f"{field_path} contains {_diagnostic_repr(expected)} -> "
                    f"{_diagnostic_repr(actual)}",
                )
            elif isinstance(actual, str):
                matched = str(expected) in actual if expected is not None else False
                return (
                    matched,
                    f"{field_path} contains {_diagnostic_repr(expected)} -> "
                    f"{_diagnostic_repr(actual)}",
                )
            else:
                return (
                    False,
                    f"{field_path} is not a string or list ({type(actual).__name__})",
                )

    elif operator == "in":
        if isinstance(expected, list):
            def run(actual: Any) -> Tuple[bool, str]:
                return (
                    actual in expected,
                    f"{field_path} in {_diagnostic_repr(expected)} -> "
                    f"{_diagnostic_repr(actual)}",
                )
        else:
            def run(actual: Any) -> Tuple[bool, str]:
                return (
                    False,
                    f"{field_path} in {_diagnostic_repr(expected)} -> "
                    f"{_diagnostic_repr(actual)}",
                )

    elif operator == "matches":
        if not isinstance(expected, str):
            def run(actual: Any) -> Tuple[bool, str]:
                return False, f"{field_path} not a string or pattern not a string"
        else:
            try:
                _pattern = re.compile(expected)
                def run(actual: Any) -> Tuple[bool, str]:
                    if isinstance(actual, str):
                        matched = bool(_pattern.search(actual))
                        return (
                            matched,
                            f"{field_path} matches "
                            f"{_diagnostic_repr(expected)} -> "
                            f"{_diagnostic_repr(actual)}",
                        )
                    return False, f"{field_path} not a string or pattern not a string"
            except re.error as exc:
                log.warning(
                    "Invalid regex %r in policy condition (will never match): %s",
                    expected,
                    exc,
                )
                _reason = f"regex error: {exc}"
                def run(actual: Any) -> Tuple[bool, str]:  # type: ignore[misc]
                    return False, _reason

    elif operator in ("gt", "lt", "gte", "lte"):
        _expected_num = _coerce_finite_decimal(expected)

        if _expected_num is None:
            def run(actual: Any) -> Tuple[bool, str]:
                return False, f"{field_path} missing value"
        else:
            # Capture operator and expected_num in local names so the closure
            # is self-contained even if the caller's local variables change.
            _op = operator
            _exp = _expected_num

            def run(actual: Any) -> Tuple[bool, str]:
                actual_num = _coerce_finite_decimal(actual)
                if actual_num is None:
                    return (
                        False,
                        f"{field_path} not a finite numeric value "
                        f"(got {_diagnostic_repr(actual)})",
                    )
                if _op == "gt":
                    matched = actual_num > _exp
                elif _op == "lt":
                    matched = actual_num < _exp
                elif _op == "gte":
                    matched = actual_num >= _exp
                else:  # lte
                    matched = actual_num <= _exp
                return matched, f"{field_path} {_op} {_exp} -> {actual_num}"

    else:
        _unknown_reason = f"unknown operator: {operator}"

        def run(actual: Any) -> Tuple[bool, str]:
            return False, _unknown_reason

    return run


class _CompiledCondition:
    """A policy condition pre-compiled for efficient per-event evaluation."""

    __slots__ = ("_field_keys", "_run")

    def __init__(self, cond: dict) -> None:
        field_path: str = cond.get("field", "")
        self._field_keys: List[str] = field_path.split(".") if field_path else []
        self._run: Callable[[Any], Tuple[bool, str]] = _compile_condition_fn(
            field_path,
            cond.get("operator", "=="),
            cond.get("value"),
        )

    def evaluate(self, event: dict) -> Tuple[bool, str]:
        # Walk the nested dict using the pre-split key list.
        current: Any = event
        for key in self._field_keys:
            if isinstance(current, dict):
                current = current.get(key)
            else:
                current = None
                break
        return self._run(current)


# ── Policy ───────────────────────────────────────────────────────────────────


class Policy:
    """A single policy rule loaded from a YAML file."""

    def __init__(self, raw: dict, source_file: str = ""):
        self._validate_definition(raw)
        self.name: str = raw.get("name", "unnamed")
        self.description: str = raw.get("description", "")
        self.enabled: bool = raw.get("enabled", True)
        self.action: str = raw.get("action", "warn")  # allow, warn, block
        self.message: str = raw.get("message", "")
        self.scope: dict = raw.get("scope", {})
        self.rule: dict = raw.get("rule", {})
        self.source_file: str = source_file

        # Pre-compile conditions at construction time so per-event evaluation
        # is pure callable dispatch with no repeated string parsing.
        conditions_raw = self.rule.get("conditions", []) if self.rule else []
        self._compiled_conditions: List[_CompiledCondition] = [
            _CompiledCondition(c)
            for c in conditions_raw
            if isinstance(c, dict)
        ]

    @staticmethod
    def _validate_definition(raw: dict) -> None:
        """Reject definitions whose typos could silently weaken enforcement."""
        unknown_policy_fields = set(raw) - _POLICY_FIELDS
        if unknown_policy_fields:
            raise ValueError(
                "policy has unknown fields: "
                + ", ".join(sorted(str(key) for key in unknown_policy_fields))
            )
        name = raw.get("name")
        if not isinstance(name, str) or not name.strip():
            raise ValueError("policy.name must be a non-empty string")
        if "action" not in raw:
            raise ValueError("policy.action is required")
        if "rule" not in raw:
            raise ValueError("policy.rule is required")
        if "enabled" in raw and not isinstance(raw["enabled"], bool):
            raise ValueError("policy.enabled must be a boolean")
        if raw.get("action", "warn") not in ("allow", "warn", "block"):
            raise ValueError("policy.action must be allow, warn, or block")
        for key in ("description", "message"):
            if key in raw and not isinstance(raw[key], str):
                raise ValueError(f"policy.{key} must be a string")

        scope = raw.get("scope", {})
        if not isinstance(scope, dict):
            raise ValueError("policy.scope must be a mapping")
        unknown_scope_fields = set(scope) - _SCOPE_FIELDS
        if unknown_scope_fields:
            raise ValueError(
                "policy.scope has unknown fields: "
                + ", ".join(sorted(str(key) for key in unknown_scope_fields))
            )
        for key in ("agents", "sessions"):
            if key in scope and not isinstance(scope[key], list):
                raise ValueError(f"policy.scope.{key} must be a list")
            if key in scope and not all(
                isinstance(item, str) and item for item in scope[key]
            ):
                raise ValueError(
                    f"policy.scope.{key} must contain non-empty strings"
                )
        invalid_agents = set(scope.get("agents", [])) - (
            set(ALLOWED_AGENT_TYPES) | {"*"}
        )
        if invalid_agents:
            raise ValueError(
                "policy.scope.agents contains unknown agents: "
                + ", ".join(sorted(invalid_agents))
            )
        if "*" in scope.get("agents", []) and scope.get("agents") != ["*"]:
            raise ValueError(
                "policy.scope.agents wildcard '*' must be the only entry"
            )

        rule = raw.get("rule", {})
        if not isinstance(rule, dict):
            raise ValueError("policy.rule must be a mapping")
        unknown_rule_fields = set(rule) - _RULE_FIELDS
        if unknown_rule_fields:
            raise ValueError(
                "policy.rule has unknown fields: "
                + ", ".join(sorted(str(key) for key in unknown_rule_fields))
            )
        if not rule:
            raise ValueError(
                "policy.rule must explicitly define event_type or conditions"
            )
        event_type = rule.get("event_type")
        if event_type is not None and event_type not in ALLOWED_EVENT_TYPES:
            raise ValueError(
                f"policy.rule.event_type is unknown: {event_type!r}"
            )
        conditions = rule.get("conditions", [])
        if not isinstance(conditions, list):
            raise ValueError("policy.rule.conditions must be a list")
        logic = str(rule.get("logic", "AND")).upper()
        if logic not in ("AND", "OR"):
            raise ValueError("policy.rule.logic must be AND or OR")

        for index, condition in enumerate(conditions):
            prefix = f"policy.rule.conditions[{index}]"
            if not isinstance(condition, dict):
                raise ValueError(f"{prefix} must be a mapping")
            unknown_condition_fields = set(condition) - _CONDITION_FIELDS
            if unknown_condition_fields:
                raise ValueError(
                    f"{prefix} has unknown fields: "
                    + ", ".join(
                        sorted(str(key) for key in unknown_condition_fields)
                    )
                )
            field_path = condition.get("field")
            if not isinstance(field_path, str) or not field_path:
                raise ValueError(f"{prefix}.field must be a non-empty string")
            _validate_policy_field_path(field_path, prefix)
            operator = condition.get("operator", "==")
            if operator not in CONDITION_OPERATORS:
                raise ValueError(f"{prefix}.operator is unknown: {operator!r}")
            expected = condition.get("value")
            if operator == "in" and not isinstance(expected, list):
                raise ValueError(f"{prefix}.value must be a list for 'in'")
            if operator == "matches":
                if not isinstance(expected, str):
                    raise ValueError(f"{prefix}.value must be a string for 'matches'")
                _validate_safe_match_pattern(expected, prefix)
            if operator in ("gt", "lt", "gte", "lte"):
                if isinstance(expected, bool):
                    raise ValueError(
                        f"{prefix}.value must be numeric for {operator!r}"
                    )
                expected_number = _coerce_finite_decimal(expected)
                if expected_number is None:
                    raise ValueError(
                        f"{prefix}.value must be finite numeric for {operator!r}"
                    )

    def matches_scope(self, event: dict) -> bool:
        """Check whether this policy applies to the given event's agent."""
        if not self.scope:
            return True  # No scope = applies to all

        agent_type = _get_nested(event, "agent.type", "")

        # Check agent whitelist
        agents = self.scope.get("agents", [])
        if agents and agents != ["*"]:
            if agent_type not in agents:
                return False

        # Check session filter
        sessions = self.scope.get("sessions", [])
        if sessions:
            session_id = _get_nested(event, "agent.session_id", "")
            if session_id not in sessions:
                return False

        return True

    def evaluate_conditions(self, event: dict) -> Tuple[bool, str]:
        """Evaluate this policy's conditions against an event.

        Returns (matched, reason).
        """
        rule = self.rule
        if not rule:
            return False, "no rule defined"

        # Check event_type filter in rule
        rule_event_type = rule.get("event_type")
        if rule_event_type and event.get("event_type") != rule_event_type:
            return False, f"event_type {event.get('event_type')} != {rule_event_type}"

        if not self._compiled_conditions:
            return True, "no conditions — always matches"

        logic = rule.get("logic", "AND").upper()
        results: List[bool] = []
        reasons: List[str] = []

        for cc in self._compiled_conditions:
            matched, reason = cc.evaluate(event)
            results.append(matched)
            reasons.append(reason)

        if logic == "OR":
            overall = any(results)
        else:  # AND (default)
            overall = all(results)

        reason_text = _sanitize_reason("; ".join(reasons))
        return overall, reason_text


# ── PolicyEngine ─────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class _PolicySnapshot:
    """A fully validated set of policies loaded together."""

    policies: Tuple[Policy, ...]
    snapshot_id: str


class PolicyEngine:
    """Load one policy set and evaluate events against it.

    Policy files are read at startup or when ``load_policies()`` is called
    explicitly. Keeping filesystem polling out of the enforcement path makes
    each decision deterministic and cheap.
    """

    def __init__(
        self,
        policies_dir: str = DEFAULT_POLICIES_DIR,
        db: Any = None,
        failure_mode: str = "fail_open",
    ):
        if failure_mode not in POLICY_FAILURE_MODES:
            allowed = ", ".join(sorted(POLICY_FAILURE_MODES))
            raise ValueError(f"failure_mode must be one of: {allowed}")
        self._policies_dir = os.path.expanduser(policies_dir)
        self._db = db
        # Enforcement reads an immutable snapshot. ``policies`` is a detached
        # list for CLI display and compatibility with the public alpha API.
        self.policies: List[Policy] = []
        self._snapshot: Optional[_PolicySnapshot] = None
        self.failure_mode = failure_mode
        self.load_errors: List[str] = []

        self.load_policies()

    # ── Policy loading ───────────────────────────────────────────────────

    def load_policies(self) -> List[Policy]:
        """Load all .yaml policy files from the policies directory.

        A complete candidate generation is built without mutating live state.
        It is published only when every policy file is valid and at least one
        valid policy exists. A failed explicit reload retains the active set.
        """
        candidate, errors = self._build_policy_snapshot()
        self.load_errors = list(errors)
        if candidate is None:
            for error in errors:
                log.warning(error)
            return self.policies

        self._snapshot = candidate
        self.policies = [copy.deepcopy(policy) for policy in candidate.policies]
        self.load_errors = []
        for policy in candidate.policies:
            log.debug(
                "Loaded policy '%s' from %s",
                policy.name,
                os.path.basename(policy.source_file),
            )
        return self.policies

    def _build_policy_snapshot(
        self,
    ) -> Tuple[Optional[_PolicySnapshot], List[str]]:
        """Build a candidate snapshot without touching active enforcement state."""
        errors: List[str] = []
        policies: List[Policy] = []
        snapshot_hasher = hashlib.sha256()
        snapshot_hasher.update(b"panoptes-policy-engine-semantics\0")
        snapshot_hasher.update(
            str(POLICY_ENGINE_SEMANTICS_VERSION).encode("ascii")
        )
        snapshot_hasher.update(b"\0")

        if not os.path.isdir(self._policies_dir):
            return None, [
                f"Policies directory is missing or not a directory: {self._policies_dir}"
            ]

        try:
            entries = sorted(os.listdir(self._policies_dir))
        except OSError as exc:
            return None, [
                f"Cannot read policies directory {self._policies_dir}: {exc}"
            ]

        policy_filenames = [
            filename
            for filename in entries
            if filename.endswith((".yaml", ".yml"))
        ]
        if not policy_filenames:
            return None, [
                f"No policy files found in policies directory: {self._policies_dir}"
            ]

        for filename in policy_filenames:
            filepath = os.path.join(self._policies_dir, filename)

            try:
                with open(filepath, "r", encoding="utf-8") as fh:
                    contents = fh.read()
                raw = yaml.load(contents, Loader=_UniqueKeySafeLoader)
            except yaml.YAMLError as exc:
                errors.append(f"Malformed YAML in policy file {filename}: {exc}")
                continue
            except OSError as exc:
                errors.append(f"Cannot read policy file {filename}: {exc}")
                continue

            if not isinstance(raw, dict):
                errors.append(f"Policy file {filename} is not a mapping")
                continue

            try:
                policy = Policy(raw, source_file=filepath)
            except Exception as exc:
                errors.append(f"Failed to parse policy {filename}: {exc}")
                continue

            policies.append(policy)
            snapshot_hasher.update(filename.encode("utf-8"))
            snapshot_hasher.update(b"\0")
            snapshot_hasher.update(contents.encode("utf-8"))
            snapshot_hasher.update(b"\0")

        if errors:
            return None, errors
        if not policies:
            return None, [
                f"No valid policies loaded from directory: {self._policies_dir}"
            ]

        return (
            _PolicySnapshot(
                policies=tuple(policies),
                snapshot_id=snapshot_hasher.hexdigest(),
            ),
            [],
        )

    def _active_policies(
        self,
    ) -> Tuple[Tuple[Policy, ...], bool, Optional[str]]:
        """Return one policy generation, availability, and its stable ID."""
        if not hasattr(self, "_snapshot"):
            # Compatibility for tests and callers that construct via __new__.
            return tuple(getattr(self, "policies", [])), True, None
        snapshot = self._snapshot
        if snapshot is None:
            return (), False, None
        return snapshot.policies, True, snapshot.snapshot_id

    # ── Snapshot access ───────────────────────────────────────────────────────

    @property
    def has_blocking_policies(self) -> bool:
        """Whether an enabled policy can deny an event."""
        policies, _, _ = self._active_policies()
        return any(
            policy.enabled and policy.action == "block"
            for policy in policies
        )

    @property
    def policy_snapshot_id(self) -> Optional[str]:
        """Stable digest of the immutable snapshot used for decisions."""
        _, available, snapshot_id = self._active_policies()
        return snapshot_id if available else None

    @staticmethod
    def make_failure_result(failure_mode: str, errors: list[str]) -> "PolicyResult":
        """Build a PolicyResult for a policy evaluation failure.

        This is the canonical fail-closed/fail-open decision point.  All
        callers — the engine's own evaluate(), _policy_failure_result(), and
        proxy.py's exception handler — delegate here so the semantics stay in
        one place.
        """
        errors = [
            _sanitize_reason(str(error))
            for error in (list(errors) or ["Unknown policy evaluation failure"])
        ]
        if failure_mode == "fail_closed":
            message = "Policy evaluation failed; denied by fail-closed mode"
            violations = [
                {
                    "policy_name": "policy_engine_error",
                    "message": message,
                    "reason": error,
                    "action": "block",
                }
                for error in errors
            ]
            return PolicyResult(
                action="block",
                violated_policies=violations,
                warnings=[message],
                evaluation_errors=errors,
                matched_policies=list(violations),
            )
        return PolicyResult(
            action="allow",
            warnings=errors,
            evaluation_errors=errors,
        )

    def _policy_failure_result(self, errors: List[str]) -> PolicyResult:
        """Apply the configured safety posture when policy processing fails."""
        result = self.make_failure_result(
            getattr(self, "failure_mode", "fail_open"), errors
        )
        result.policy_snapshot_id = self.policy_snapshot_id
        return result

    # ── Evaluation ───────────────────────────────────────────────────────

    def evaluate(self, event: dict) -> PolicyResult:
        """Evaluate a single event against all loaded policies.

        Returns a PolicyResult. The most severe action wins:
        block > warn > allow.

        The input is normalized, redacted, classified, and validated before
        scope or condition evaluation.
        """
        result, _ = self._evaluate_with_normalized_source(event)
        return result

    def _evaluate_with_normalized_source(
        self, event: dict
    ) -> Tuple[PolicyResult, Optional[dict]]:
        """Evaluate one input and retain its canonical form for provenance."""
        normalized: Optional[dict] = None
        try:
            normalized = normalize_event(event)
            validate_event(normalized)
            return self._evaluate_event(normalized), normalized
        except Exception as exc:
            error = _sanitize_reason(
                f"Unexpected policy engine failure: {exc}"
            )
            log.exception(error)
            return self._policy_failure_result([error]), normalized

    def _evaluate_event(self, event: dict) -> PolicyResult:
        """Internal evaluation path wrapped by canonical failure handling."""
        policies, snapshot_available, snapshot_id = self._active_policies()
        load_errors = getattr(self, "load_errors", [])
        if not snapshot_available:
            errors = list(load_errors) or [
                f"No valid policy snapshot is available from {self._policies_dir}"
            ]
            return self._policy_failure_result(errors)

        violated: list[dict] = []
        matched_policies: list[dict] = []
        warnings: list[str] = [
            f"Policy load failed; using active snapshot: {error}"
            for error in load_errors
        ]
        evaluation_errors: list[str] = list(load_errors)
        runtime_errors: list[str] = []
        final_action = "allow"

        for policy in policies:
            try:
                if not policy.enabled:
                    continue
                if not policy.matches_scope(event):
                    continue

                matched, reason = policy.evaluate_conditions(event)
                if not matched:
                    continue

            except Exception as exc:
                error = _sanitize_reason(
                    f"Error evaluating policy '{policy.name}': {exc}"
                )
                log.exception(error)
                runtime_errors.append(error)
                continue

            default_message = (
                f"Policy '{policy.name}' matched"
                if policy.action == "allow"
                else f"Policy '{policy.name}' violated"
            )
            msg = policy.message or default_message
            match = {
                "policy_name": policy.name,
                "message": msg,
                "reason": reason,
                "action": policy.action,
            }
            matched_policies.append(match)

            if policy.action in ("warn", "block"):
                violated.append(match)
                warnings.append(msg)

            # Escalate action: block > warn > allow
            if policy.action == "block":
                final_action = "block"
            elif policy.action == "warn" and final_action != "block":
                final_action = "warn"

        if runtime_errors:
            evaluation_errors.extend(runtime_errors)
            failed = self._policy_failure_result(evaluation_errors)
            if failed.action == "block":
                failed.violated_policies = (
                    violated + failed.violated_policies
                )
                failed.matched_policies = (
                    matched_policies + failed.matched_policies
                )
                failed.warnings = warnings + failed.warnings
                failed.policy_snapshot_id = snapshot_id
                return failed
            # Load errors are already represented by the warning above.
            warnings.extend(runtime_errors)

        return PolicyResult(
            action=final_action,
            violated_policies=violated,
            warnings=warnings,
            evaluation_errors=evaluation_errors,
            matched_policies=matched_policies,
            policy_snapshot_id=snapshot_id,
        )

    def check_event(self, event: dict) -> PolicyResult:
        """Evaluate an event and record violations if any.

        This is the main entry point for real-time policy checking.
        After evaluating, any violations are recorded as policy_violation
        events in the database.
        """
        result, normalized_event = self._evaluate_with_normalized_source(event)

        # Record violations to DB
        persistence_errors: list[str] = []
        if result.violated_policies and self._db and normalized_event is not None:
            for vp in result.violated_policies:
                policy_action = vp.get("action", "block")
                if policy_action not in ("warn", "block"):
                    continue
                try:
                    self.record_violation(
                        normalized_event,
                        vp["policy_name"],
                        vp["message"],
                        policy_action=policy_action,
                        policy_snapshot_id=result.policy_snapshot_id,
                        policy_engine_semantics_version=(
                            result.policy_engine_semantics_version
                        ),
                    )
                except Exception as exc:
                    log.exception("Failed to record policy violation")
                    persistence_errors.append(
                        _sanitize_reason(
                            "Policy violation evidence could not be persisted: "
                            f"{exc}"
                        )
                    )

        if persistence_errors:
            result.evaluation_errors.extend(persistence_errors)
            result.warnings.extend(persistence_errors)
            if getattr(self, "failure_mode", "fail_open") == "fail_closed":
                result.action = "block"
                result.violated_policies.extend({
                    "policy_name": "policy_evidence_write_error",
                    "message": (
                        "Policy evidence write failed; denied by fail-closed mode"
                    ),
                    "reason": error,
                    "action": "block",
                } for error in persistence_errors)

        return result

    def record_violation(
        self,
        event: dict,
        policy_name: str,
        message: str,
        policy_action: str = "block",
        policy_snapshot_id: Optional[str] = None,
        policy_engine_semantics_version: int = POLICY_ENGINE_SEMANTICS_VERSION,
    ) -> None:
        """Insert a policy_violation event into the database."""
        if not self._db:
            return
        violation_event = self.build_violation_event(
            event,
            policy_name,
            message,
            policy_action=policy_action,
            policy_snapshot_id=policy_snapshot_id,
            policy_engine_semantics_version=policy_engine_semantics_version,
        )
        if violation_event is not None:
            self._db.insert_event(violation_event)

    def build_violation_event(
        self,
        event: dict,
        policy_name: str,
        message: str,
        policy_action: str = "block",
        policy_snapshot_id: Optional[str] = None,
        policy_engine_semantics_version: int = POLICY_ENGINE_SEMANTICS_VERSION,
    ) -> Optional[dict]:
        """Build durable violation evidence without performing an I/O side effect.

        Enforcement adapters use this form so source observations, decisions,
        and violations can be inserted in one database transaction.
        """
        if policy_action == "allow":
            return None
        if policy_action not in ("warn", "block"):
            raise ValueError("policy_action must be allow, warn, or block")

        source_event = normalize_event(event)
        validate_event(source_event)
        agent_info = source_event.get("agent", {})
        action_info = source_event.get("action", {})
        outcome_status = "warned" if policy_action == "warn" else "blocked"

        violation_context = {
            "policy_name": policy_name,
            "policy_message": message,
            "policy_action": policy_action,
            "policy_snapshot_id": policy_snapshot_id,
            "policy_engine_semantics_version": policy_engine_semantics_version,
            "source_event_id": source_event.get("event_id"),
            "source_event_type": source_event.get("event_type"),
            "source_schema_version": (
                (source_event.get("context", {}) or {}).get("schema_version")
            ),
            "capture": copy.deepcopy(_POLICY_ENGINE_CAPTURE),
        }
        source_capture = (
            (source_event.get("context", {}) or {}).get("capture")
        )
        if source_capture is not None:
            violation_context["source_capture"] = copy.deepcopy(source_capture)

        violation_event = {
            "event_id": uuid.uuid4().hex,
            "timestamp": utcnow_iso(),
            "agent": {
                "type": agent_info.get("type", "unknown"),
                "session_id": agent_info.get("session_id", ""),
                "run_id": agent_info.get("run_id", ""),
            },
            "user": copy.deepcopy(source_event.get("user", {})),
            "event_type": "policy_violation",
            # Preserve the normalized, redacted source action. call_id,
            # parameters, and declared_data_accessed are needed to recompute
            # classification and correlate this decision later.
            "action": copy.deepcopy(action_info),
            "outcome": {
                "status": outcome_status,
                "summary": f"Policy '{policy_name}': {message}",
            },
            "context": violation_context,
            "cost": {},
        }
        normalized_violation = normalize_event(violation_event)
        validate_event(normalized_violation)
        return normalized_violation


    # ── Testing helpers ──────────────────────────────────────────────────

    @staticmethod
    def test_policy(policy_path: str, event_json: str) -> PolicyResult:
        """Test a single policy file against a JSON event string.

        Static — needs no engine state, so it can be called as
        PolicyEngine.test_policy(...) without constructing an engine.
        Useful for CLI `policy test` command and ad-hoc testing.
        """
        try:
            event = _strict_json_loads(event_json)
        except (json.JSONDecodeError, ValueError) as exc:
            raise ValueError(f"Invalid event JSON: {exc}") from exc

        try:
            with open(os.path.expanduser(policy_path), "r") as fh:
                raw = yaml.load(fh, Loader=_UniqueKeySafeLoader)
        except yaml.YAMLError as exc:
            raise ValueError(f"Invalid policy YAML: {exc}") from exc
        except OSError as exc:
            raise ValueError(f"Cannot read policy file: {exc}") from exc

        if not isinstance(raw, dict):
            raise ValueError("Policy file is not a valid YAML dict")

        policy = Policy(raw, source_file=policy_path)
        try:
            normalized_event = normalize_event(event)
            validate_event(normalized_event)
        except Exception as exc:
            raise ValueError(f"Invalid event: {exc}") from exc

        # Use the live decision path so enabled, scope, and conditions cannot
        # drift from enforcement semantics.
        engine = PolicyEngine.__new__(PolicyEngine)
        engine._policies_dir = os.path.dirname(os.path.expanduser(policy_path))
        engine._db = None
        engine.failure_mode = "fail_open"
        engine.load_errors = []
        engine.policies = [policy]
        return engine._evaluate_event(normalized_event)


# ── Condition evaluation helpers ─────────────────────────────────────────────


def _get_nested(data: dict, path: str, default: Any = None) -> Any:
    """Access a nested dict value using dot notation.

    Examples:
        _get_nested(event, "action.tool_name")
        _get_nested(event, "agent.type")
    """
    keys = path.split(".")
    current: Any = data
    for key in keys:
        if isinstance(current, dict):
            current = current.get(key, default)
        else:
            return default
    return current
