"""
Policy engine for panoptes.

Loads YAML policy definitions, evaluates events against rules, and enforces
allow/warn/block decisions. Supports condition matching, rate limiting,
scope filtering, and policy violation recording.

Policies live in ~/.panoptes/policies/ as individual .yaml files.
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
import threading
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

import yaml

from panoptes.schema import utcnow_iso

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


# ── Pre-compiled condition helpers ────────────────────────────────────────────


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
            return actual == expected, f"{field_path} == {expected!r} -> {actual!r}"

    elif operator == "!=":
        def run(actual: Any) -> Tuple[bool, str]:
            return actual != expected, f"{field_path} != {expected!r} -> {actual!r}"

    elif operator == "contains":
        def run(actual: Any) -> Tuple[bool, str]:
            if isinstance(actual, list):
                matched = expected in actual if expected is not None else False
                return matched, f"{field_path} contains {expected!r} -> {actual!r}"
            elif isinstance(actual, str):
                matched = str(expected) in actual if expected is not None else False
                return matched, f"{field_path} contains {expected!r} -> {actual!r}"
            else:
                return (
                    False,
                    f"{field_path} is not a string or list ({type(actual).__name__})",
                )

    elif operator == "in":
        if isinstance(expected, list):
            def run(actual: Any) -> Tuple[bool, str]:
                return actual in expected, f"{field_path} in {expected!r} -> {actual!r}"
        else:
            def run(actual: Any) -> Tuple[bool, str]:
                return False, f"{field_path} in {expected!r} -> {actual!r}"

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
                        return matched, f"{field_path} matches /{expected}/ -> {actual!r}"
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
        try:
            _expected_num: Optional[float] = (
                float(expected) if expected is not None else None
            )
        except (TypeError, ValueError):
            _expected_num = None

        if _expected_num is None:
            def run(actual: Any) -> Tuple[bool, str]:
                return False, f"{field_path} missing value"
        else:
            # Capture operator and expected_num in local names so the closure
            # is self-contained even if the caller's local variables change.
            _op = operator
            _exp = _expected_num

            def run(actual: Any) -> Tuple[bool, str]:
                try:
                    actual_num: Optional[float] = (
                        float(actual) if actual is not None else None
                    )
                except (TypeError, ValueError):
                    return False, f"{field_path} not numeric (got {actual!r})"
                if actual_num is None:
                    return False, f"{field_path} missing value"
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

        # Pre-compile conditions at construction time so per-event evaluation
        # is pure callable dispatch with no repeated string parsing.
        conditions_raw = self.rule.get("conditions", []) if self.rule else []
        self._compiled_conditions: List[_CompiledCondition] = [
            _CompiledCondition(c)
            for c in conditions_raw
            if isinstance(c, dict)
        ]

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

        reason_text = "; ".join(reasons)
        return overall, reason_text


# ── PolicyEngine ─────────────────────────────────────────────────────────────


class PolicyEngine:
    """Loads, evaluates, and enforces policies.

    Supports mtime-based hot-reload: the policies directory and each policy
    file's mtime are recorded at load time.  evaluate() (via _maybe_reload())
    stats the directory at most once every *reload_interval* seconds (using
    the monotonic clock) and reloads if the directory or any file has changed.

    Rate-limit counters (self._rate_limits) are stored on the engine instance
    and survive reloads.
    """

    def __init__(
        self,
        policies_dir: str = DEFAULT_POLICIES_DIR,
        db: Any = None,
        reload_interval: float = 2.0,
    ):
        self._policies_dir = os.path.expanduser(policies_dir)
        self._db = db
        self.policies: List[Policy] = []

        # Rate-limit tracking: session_id -> {"last_seen": monotonic,
        # "counts": {"session_id[:tool_name]" -> count}}. Idle sessions are
        # evicted so a long-running engine doesn't accumulate counters forever.
        self._rate_limits: Dict[str, Dict[str, Any]] = {}
        self._rate_lock = threading.Lock()
        self._rate_last_evict: float = 0.0

        # Hot-reload state
        self._reload_interval: float = reload_interval
        self._last_check_time: float = 0.0       # monotonic clock
        self._dir_mtime: Optional[float] = None
        self._file_mtimes: Dict[str, float] = {}
        self._reload_lock = threading.Lock()

        self.load_policies()

    # ── Policy loading ───────────────────────────────────────────────────

    def load_policies(self) -> List[Policy]:
        """Load all .yaml policy files from the policies directory.

        Returns the list of loaded policies. Malformed files are skipped
        with a warning. Missing directory = no policies.

        Also records directory and per-file mtimes for hot-reload detection.
        """
        self.policies = []
        new_file_mtimes: Dict[str, float] = {}

        if not os.path.isdir(self._policies_dir):
            log.debug("Policies directory not found: %s", self._policies_dir)
            self._dir_mtime = None
            self._file_mtimes = {}
            return self.policies

        # Record directory mtime
        try:
            self._dir_mtime = os.stat(self._policies_dir).st_mtime
        except OSError:
            self._dir_mtime = None

        try:
            entries = sorted(os.listdir(self._policies_dir))
        except OSError:
            log.warning("Cannot read policies directory: %s", self._policies_dir)
            self._file_mtimes = {}
            return self.policies

        for filename in entries:
            if not filename.endswith((".yaml", ".yml")):
                continue

            filepath = os.path.join(self._policies_dir, filename)

            # Record file mtime before reading
            try:
                new_file_mtimes[filepath] = os.stat(filepath).st_mtime
            except OSError:
                pass

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

        self._file_mtimes = new_file_mtimes
        return self.policies

    # ── Hot-reload ───────────────────────────────────────────────────────

    def _policies_changed(self) -> bool:
        """Return True if the policies directory or any tracked file has changed."""
        if not os.path.isdir(self._policies_dir):
            return False

        try:
            dir_mtime = os.stat(self._policies_dir).st_mtime
        except OSError:
            return False

        # A new or deleted file changes the directory mtime on Unix.
        if dir_mtime != self._dir_mtime:
            return True

        # A file edit only changes the file's own mtime.
        for filepath, recorded_mtime in self._file_mtimes.items():
            try:
                if os.stat(filepath).st_mtime != recorded_mtime:
                    return True
            except OSError:
                return True  # file disappeared — reload to reconcile

        return False

    def _maybe_reload(self) -> None:
        """Reload policies if the directory has changed, throttled by reload_interval.

        Thread-safe: the check-and-reload is serialised under _reload_lock so
        only one thread reloads at a time; other threads proceed with the
        (briefly stale) current policy list during the reload.

        This method is a no-op when the engine was created via __new__ without
        calling __init__ (as done by some test helpers).
        """
        if not hasattr(self, "_reload_lock"):
            return

        now = time.monotonic()
        # Fast path: still within the throttle window — no stat needed.
        if now - self._last_check_time < self._reload_interval:
            return

        with self._reload_lock:
            # Double-check under lock: another thread may have just reloaded.
            if now - self._last_check_time < self._reload_interval:
                return
            self._last_check_time = now

            if self._policies_changed():
                log.debug(
                    "Policies directory changed — reloading from %s",
                    self._policies_dir,
                )
                self.load_policies()

    # ── Evaluation ───────────────────────────────────────────────────────

    def evaluate(self, event: dict) -> PolicyResult:
        """Evaluate a single event against all loaded policies.

        Returns a PolicyResult. The most severe action wins:
        block > warn > allow.

        Checks for policy file changes before evaluation (mtime-based, throttled).
        """
        self._maybe_reload()

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

            if policy.action in ("warn", "block"):
                warnings.append(msg)

            # Escalate action: block > warn > allow
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

        agent_info = event.get("agent", {})
        action_info = event.get("action", {})

        violation_event = {
            "event_id": uuid.uuid4().hex,
            "timestamp": utcnow_iso(),
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

    # Sessions with no rate-limited activity for this long are forgotten.
    RATE_LIMIT_SESSION_TTL = 3600.0
    # How often (at most) to scan for stale sessions.
    _RATE_EVICT_INTERVAL = 60.0

    def _evict_stale_sessions(self, now: float) -> None:
        """Drop counters for idle sessions. Must be called under _rate_lock."""
        if now - getattr(self, "_rate_last_evict", 0.0) < self._RATE_EVICT_INTERVAL:
            return
        self._rate_last_evict = now
        stale = [
            sid for sid, entry in self._rate_limits.items()
            if now - entry["last_seen"] > self.RATE_LIMIT_SESSION_TTL
        ]
        for sid in stale:
            del self._rate_limits[sid]

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
        key = f"{session_id}:{tool_name}" if tool_name else session_id

        now = time.monotonic()
        with self._rate_lock:
            self._evict_stale_sessions(now)
            entry = self._rate_limits.setdefault(
                session_id, {"last_seen": now, "counts": {}}
            )
            entry["last_seen"] = now
            current = entry["counts"].get(key, 0) + 1
            entry["counts"][key] = current

        return current > max_count

    # ── Testing helpers ──────────────────────────────────────────────────

    @staticmethod
    def test_policy(policy_path: str, event_json: str) -> PolicyResult:
        """Test a single policy file against a JSON event string.

        Static — needs no engine state, so it can be called as
        PolicyEngine.test_policy(...) without constructing an engine.
        Useful for CLI `policy test` command and ad-hoc testing.
        """
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
