"""
Policy engine for panoptes.

Loads YAML policy definitions, evaluates events against rules, and enforces
allow/warn/block decisions. Supports condition matching, rate limiting,
scope filtering, and policy violation recording.

Policies live in ~/.panoptes/policies/ as individual .yaml files.
"""

from __future__ import annotations

import logging
import os
import re
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

import yaml

log = logging.getLogger("panoptes.policy")

# ── Default policies directory ───────────────────────────────────────────────

DEFAULT_POLICIES_DIR = "~/.panoptes/policies/"

# ── PolicyResult ─────────────────────────────────────────────────────────────


@dataclass
class PolicyResult:
    """Result of evaluating one or more policies against an event."""

    action: str  # "allow", "warn", "block"
    violated_policies: list[dict] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


# ── Policy ───────────────────────────────────────────────────────────────────


class Policy:
    """A single policy rule loaded from a YAML file."""

    def __init__(self, raw: dict, source_file: str = ""):
        self.name: str = raw.get("name", "unnamed")
        self.description: str = raw.get("description", "")
        self.enabled: bool = raw.get("enabled", True)
        self.action: str = raw.get("action", "warn")  # allow, warn, block
        self.message: str = raw.get("message", "")
        self.scope: dict = raw.get("scope", {})
        self.rule: dict = raw.get("rule", {})
        self.source_file: str = source_file

        # Validate action
        if self.action not in ("allow", "warn", "block"):
            log.warning(
                "Policy '%s': invalid action '%s', defaulting to 'warn'",
                self.name,
                self.action,
            )
            self.action = "warn"

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

        conditions = rule.get("conditions", [])
        if not conditions:
            return True, "no conditions — always matches"

        logic = rule.get("logic", "AND").upper()
        results = []
        reasons = []

        for cond in conditions:
            matched, reason = _evaluate_condition(cond, event)
            results.append(matched)
            reasons.append(reason)

        if logic == "OR":
            matched = any(results)
        else:  # AND (default)
            matched = all(results)

        reason_text = "; ".join(reasons)
        return matched, reason_text


# ── PolicyEngine ─────────────────────────────────────────────────────────────


class PolicyEngine:
    """Loads, evaluates, and enforces policies."""

    def __init__(
        self,
        policies_dir: str = DEFAULT_POLICIES_DIR,
        db: Any = None,
    ):
        self._policies_dir = os.path.expanduser(policies_dir)
        self._db = db
        self.policies: List[Policy] = []

        # Rate-limit tracking: session_id -> {key -> count}
        self._rate_limits: Dict[str, Dict[str, int]] = {}
        self._rate_lock = threading.Lock()

        self.load_policies()

    # ── Policy loading ───────────────────────────────────────────────────

    def load_policies(self) -> List[Policy]:
        """Load all .yaml policy files from the policies directory.

        Returns the list of loaded policies. Malformed files are skipped
        with a warning. Missing directory = no policies.
        """
        self.policies = []

        if not os.path.isdir(self._policies_dir):
            log.debug("Policies directory not found: %s", self._policies_dir)
            return self.policies

        try:
            entries = sorted(os.listdir(self._policies_dir))
        except OSError:
            log.warning("Cannot read policies directory: %s", self._policies_dir)
            return self.policies

        for filename in entries:
            if not filename.endswith((".yaml", ".yml")):
                continue

            filepath = os.path.join(self._policies_dir, filename)
            try:
                with open(filepath, "r") as fh:
                    raw = yaml.safe_load(fh)
            except yaml.YAMLError as exc:
                log.warning("Malformed YAML in policy file %s: %s", filename, exc)
                continue
            except OSError as exc:
                log.warning("Cannot read policy file %s: %s", filename, exc)
                continue

            if not isinstance(raw, dict):
                log.warning("Policy file %s is not a dict, skipping", filename)
                continue

            try:
                policy = Policy(raw, source_file=filepath)
            except Exception as exc:
                log.warning("Failed to parse policy %s: %s", filename, exc)
                continue

            self.policies.append(policy)
            log.debug("Loaded policy '%s' from %s", policy.name, filename)

        return self.policies

    # ── Evaluation ───────────────────────────────────────────────────────

    def evaluate(self, event: dict) -> PolicyResult:
        """Evaluate a single event against all loaded policies.

        Returns a PolicyResult. The most severe action wins:
        block > warn > allow.
        """
        violated: list[dict] = []
        warnings: list[str] = []
        final_action = "allow"

        for policy in self.policies:
            if not policy.enabled:
                continue

            if not policy.matches_scope(event):
                continue

            try:
                matched, reason = policy.evaluate_conditions(event)
            except Exception:
                log.exception(
                    "Error evaluating policy '%s' — skipping (fail-open)", policy.name
                )
                continue

            if not matched:
                continue

            # Check rate limits if defined
            rate_limit = policy.rule.get("rate_limit") if policy.rule else None
            if rate_limit:
                exceeded = self._check_rate_limit(event, policy, rate_limit)
                if not exceeded:
                    continue  # Within limit — skip this policy

            # Policy matched — record the violation
            msg = policy.message or f"Policy '{policy.name}' violated"
            violated.append({
                "policy_name": policy.name,
                "message": msg,
                "reason": reason,
            })

            if policy.action == "warn":
                warnings.append(msg)
            elif policy.action == "block":
                warnings.append(msg)

            # Escalate action
            if policy.action == "block":
                final_action = "block"
            elif policy.action == "warn" and final_action != "block":
                final_action = "warn"

        return PolicyResult(
            action=final_action,
            violated_policies=violated,
            warnings=warnings,
        )

    def check_event(self, event: dict) -> PolicyResult:
        """Evaluate an event and record violations if any.

        This is the main entry point for real-time policy checking.
        After evaluating, any violations are recorded as policy_violation
        events in the database.
        """
        result = self.evaluate(event)

        # Record violations to DB
        if result.violated_policies and self._db:
            for vp in result.violated_policies:
                try:
                    self.record_violation(event, vp["policy_name"], vp["message"])
                except Exception:
                    log.exception("Failed to record policy violation")

        return result

    def record_violation(
        self,
        event: dict,
        policy_name: str,
        message: str,
    ) -> None:
        """Insert a policy_violation event into the database."""
        if not self._db:
            return

        import uuid
        from datetime import datetime, timezone

        agent_info = event.get("agent", {})
        action_info = event.get("action", {})

        violation_event = {
            "event_id": uuid.uuid4().hex,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "agent": {
                "type": agent_info.get("type", "unknown"),
                "session_id": agent_info.get("session_id", ""),
                "run_id": agent_info.get("run_id", ""),
            },
            "event_type": "policy_violation",
            "action": {
                "tool_name": action_info.get("tool_name"),
                "parameters": {},
                "target": action_info.get("target"),
                "data_accessed": action_info.get("data_accessed", []),
            },
            "outcome": {
                "status": "blocked",
                "summary": f"Policy '{policy_name}': {message}",
            },
            "context": {
                "policy_name": policy_name,
                "policy_message": message,
            },
            "cost": {},
        }
        self._db.insert_event(violation_event)

    # ── Rate limiting ────────────────────────────────────────────────────

    def _check_rate_limit(
        self, event: dict, policy: Policy, rate_limit: dict
    ) -> bool:
        """Check if a rate limit has been exceeded. Returns True if exceeded.

        Rate limit config:
            count: max allowed
            window: "session" (only supported window for v1)
        """
        max_count = rate_limit.get("count")
        if not max_count:
            return False

        session_id = _get_nested(event, "agent.session_id", "unknown")
        tool_name = _get_nested(event, "action.tool_name", "")

        # Build a key: session_id + tool_name (if applicable)
        if tool_name:
            key = f"{session_id}:{tool_name}"
        else:
            key = session_id

        with self._rate_lock:
            if session_id not in self._rate_limits:
                self._rate_limits[session_id] = {}
            current = self._rate_limits[session_id].get(key, 0) + 1
            self._rate_limits[session_id][key] = current

        return current > max_count

    # ── Testing helpers ──────────────────────────────────────────────────

    def test_policy(self, policy_path: str, event_json: str) -> PolicyResult:
        """Test a single policy file against a JSON event string.

        Useful for CLI `policy test` command and ad-hoc testing.
        """
        import json

        try:
            event = json.loads(event_json)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid event JSON: {exc}") from exc

        try:
            with open(os.path.expanduser(policy_path), "r") as fh:
                raw = yaml.safe_load(fh)
        except yaml.YAMLError as exc:
            raise ValueError(f"Invalid policy YAML: {exc}") from exc
        except OSError as exc:
            raise ValueError(f"Cannot read policy file: {exc}") from exc

        if not isinstance(raw, dict):
            raise ValueError("Policy file is not a valid YAML dict")

        policy = Policy(raw, source_file=policy_path)
        matched, reason = policy.evaluate_conditions(event)

        if matched:
            return PolicyResult(
                action=policy.action,
                violated_policies=[{
                    "policy_name": policy.name,
                    "message": policy.message or f"Policy '{policy.name}' matched",
                    "reason": reason,
                }],
                warnings=[policy.message] if policy.message else [],
            )
        else:
            return PolicyResult(
                action="allow",
                violated_policies=[],
                warnings=[],
            )


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


def _evaluate_condition(cond: dict, event: dict) -> Tuple[bool, str]:
    """Evaluate a single condition against an event.

    Returns (matched, reason_string).
    """
    field_path = cond.get("field", "")
    operator = cond.get("operator", "==")
    expected = cond.get("value")

    actual = _get_nested(event, field_path)

    # ── == operator ──
    if operator == "==":
        matched = actual == expected
        reason = f"{field_path} == {expected!r} -> {actual!r}"

    # ── != operator ──
    elif operator == "!=":
        matched = actual != expected
        reason = f"{field_path} != {expected!r} -> {actual!r}"

    # ── contains operator ──
    elif operator == "contains":
        if isinstance(actual, list):
            # For lists, check if expected value is IN the list
            matched = expected in actual if expected is not None else False
            reason = f"{field_path} contains {expected!r} -> {actual!r}"
        elif isinstance(actual, str):
            matched = str(expected) in actual if expected is not None else False
            reason = f"{field_path} contains {expected!r} -> {actual!r}"
        else:
            matched = False
            reason = f"{field_path} is not a string or list ({type(actual).__name__})"

    # ── in operator ──
    elif operator == "in":
        if isinstance(expected, list):
            matched = actual in expected
        else:
            matched = False
        reason = f"{field_path} in {expected!r} -> {actual!r}"

    # ── matches (regex) operator ──
    elif operator == "matches":
        if isinstance(actual, str) and isinstance(expected, str):
            try:
                matched = bool(re.search(expected, actual))
                reason = f"{field_path} matches /{expected}/ -> {actual!r}"
            except re.error as exc:
                matched = False
                reason = f"regex error: {exc}"
        else:
            matched = False
            reason = f"{field_path} not a string or pattern not a string"

    # ── Numeric comparisons ──
    elif operator in ("gt", "lt", "gte", "lte"):
        try:
            actual_num = float(actual) if actual is not None else None
            expected_num = float(expected) if expected is not None else None
        except (TypeError, ValueError):
            matched = False
            reason = f"{field_path} not numeric (got {actual!r})"
        else:
            if actual_num is None or expected_num is None:
                matched = False
                reason = f"{field_path} missing value"
            elif operator == "gt":
                matched = actual_num > expected_num
            elif operator == "lt":
                matched = actual_num < expected_num
            elif operator == "gte":
                matched = actual_num >= expected_num
            else:  # lte
                matched = actual_num <= expected_num
            reason = f"{field_path} {operator} {expected_num} -> {actual_num}"

    else:
        matched = False
        reason = f"unknown operator: {operator}"

    return matched, reason
