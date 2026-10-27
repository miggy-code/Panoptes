"""
proxy.py — local HTTP reverse proxy for agent LLM API traffic.

Intercepts agent LLM API requests/responses and writes normalized audit events
to a SQLite database via the storage module.

Supports OpenAI, Anthropic, and Google (Gemini) API formats.

Reverse-proxy mode (recommended — works with HTTPS):
    Point your agent's base URL at the proxy:
        ANTHROPIC_BASE_URL=http://127.0.0.1:8081
        OPENAI_BASE_URL=http://127.0.0.1:8081/v1
    The proxy auto-routes to the correct upstream based on path patterns.
    Override upstreams via env vars:
        PANOPTES_UPSTREAM_ANTHROPIC=https://api.anthropic.com
        PANOPTES_UPSTREAM_OPENAI=https://api.openai.com
        PANOPTES_UPSTREAM_GEMINI=https://generativelanguage.googleapis.com

Credential injection (``--inject-credentials``):
    Provider API keys live only in the proxy process. Agents present a Panoptes
    session token where their SDK sends an API key; the proxy resolves it to an
    authenticated agent type and session, strips every client credential, and
    adds the real key for the routed upstream. Missing, unknown, expired, or
    revoked tokens get HTTP 401 and are never forwarded.

Streaming policy behavior:
    When an enabled blocking policy is loaded, streaming responses are buffered
    until response-side policy checks complete. This protects the model-response
    boundary but adds time-to-first-byte latency. Without a blocking policy,
    streams are relayed immediately and are audit-only after the request check.

Usage:
    panoptes proxy --port 8081 --db-path ./audit.db
"""

from __future__ import annotations

import http.server
import ipaddress
import json
import logging
import os
import tempfile
import threading
import time
import uuid
from typing import Any
from urllib.parse import unquote_plus, urlparse

import httpx

from panoptes.capture import PROXY_CAPABILITIES, PROXY_TOKEN_CAPABILITIES
from panoptes.credentials import (
    SessionIdentity,
    SessionTokenStore,
    TokenRejected,
)
from panoptes.db import AuditDB
from panoptes.policy import PolicyEngine, PolicyResult
from panoptes.schema import (
    ALLOWED_AGENT_TYPES,
    ValidationError,
    normalize_event,
    redact_secrets,
    utcnow_iso,
    validate_event,
)

import panoptes.providers as _providers
from panoptes.providers.base import (
    SSEParseError,
    _parse_sse_events,  # noqa: F401 — re-exported for callers
    _strict_json_loads,
)

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

log = logging.getLogger("panoptes")

# ---------------------------------------------------------------------------
# Raw-payload helpers
# ---------------------------------------------------------------------------

_RAW_MAX = 64 * 1024  # 64 KB cap on stored raw payloads

# Transport limits protect the proxy process itself. Enforcement-buffered
# responses are never truncated and released: exceeding the limit is a hard
# denial. Audit-only passthrough streams may continue to the client, but their
# local capture is bounded and explicitly marked incomplete.
DEFAULT_MAX_REQUEST_BODY_BYTES = 8 * 1024 * 1024
DEFAULT_MAX_BUFFERED_RESPONSE_BYTES = 32 * 1024 * 1024
DEFAULT_MAX_AUDIT_STREAM_BYTES = 8 * 1024 * 1024
DEFAULT_MAX_TOOL_EVENTS_PER_EXCHANGE = 256
DEFAULT_CLIENT_SOCKET_TIMEOUT_SECONDS = 30.0
DEFAULT_MAX_CONCURRENT_REQUESTS = 64

def _is_loopback_bind_host(host: str) -> bool:
    """Return whether ``host`` is an explicit loopback bind target."""
    normalized = host.strip().strip("[]").rstrip(".").lower()
    if normalized == "localhost":
        return True
    try:
        return ipaddress.ip_address(normalized).is_loopback
    except ValueError:
        # Do not resolve arbitrary hostnames here. DNS resolution can change,
        # so only explicit loopback literals and localhost are safe defaults.
        return False


def _cap_raw(body: dict | None) -> str | None:
    """Serialize body to JSON, redact secrets, cap at 64 KB."""
    if body is None:
        return None
    try:
        redacted = redact_secrets(body)
        s = json.dumps(redacted, ensure_ascii=False, default=str)
        if len(s) > _RAW_MAX:
            return s[:_RAW_MAX] + "...[truncated]"
        return s
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Agent detection
# ---------------------------------------------------------------------------

_AGENT_UA_PATTERNS: list[tuple[str, str]] = [
    ("claude-code", "claude_code"),
    ("codex", "codex"),
    ("openai-codex", "codex"),
    ("hermes", "hermes"),
    ("antigravity", "antigravity"),
    ("google-code-assist", "antigravity"),
]

def _lower_keys(headers: dict[str, str]) -> dict[str, str]:
    """Lowercase header names so lookups are case-insensitive."""
    return {k.lower(): v for k, v in headers.items()}


def detect_agent_type(
    path: str,
    headers: dict[str, str],
    req_body: dict | None,
) -> str:
    lowered_headers = _lower_keys(headers)
    declared_agent = lowered_headers.get("x-panoptes-agent", "")
    if declared_agent in ALLOWED_AGENT_TYPES:
        return declared_agent

    user_agent = lowered_headers.get("user-agent", "")
    if user_agent:
        ua_lower = user_agent.lower()
        for pattern, agent_type in _AGENT_UA_PATTERNS:
            if pattern in ua_lower:
                return agent_type

    # A provider endpoint or payload format identifies an API protocol, not the
    # calling agent. Without an adapter declaration or recognizable user-agent,
    # preserve the uncertainty instead of corrupting audit attribution.
    return "unknown"


# ---------------------------------------------------------------------------
# SSE parsing and reassembly
# ---------------------------------------------------------------------------


def _parse_sse_response(
    raw: bytes,
    req_format: str,
    *,
    path: str | None = None,
) -> dict | None:
    """Parse accumulated SSE bytes into a response dict for auditing."""
    if not raw:
        return None
    for provider in _providers.REGISTRY:
        if provider.name == req_format:
            return provider.reassemble_sse(raw, path=path)
    # Unknown format: try SSE then raw JSON
    events = _parse_sse_events(raw)
    if events:
        return events[-1]
    try:
        return _strict_json_loads(raw)
    except (json.JSONDecodeError, ValueError):
        return None


def _parse_provider_response(
    raw: bytes,
    resp_headers: dict[str, str],
    exchange_ctx: dict,
) -> dict:
    """Parse a complete provider response or raise ``ResponseInspectionError``."""
    if not raw or not raw.strip():
        raise ResponseInspectionError("successful upstream response body was empty")

    req_format = exchange_ctx.get("req_format", "unknown")
    path = exchange_ctx.get("path")
    streaming = bool(exchange_ctx.get("req_info", {}).get("stream"))
    content_type = _lower_keys(resp_headers).get("content-type", "").lower()
    stripped = raw.lstrip()
    looks_like_sse = (
        "text/event-stream" in content_type
        or stripped.startswith((b"data:", b"event:", b":"))
    )

    try:
        if streaming and looks_like_sse:
            parsed = _parse_sse_response(raw, req_format, path=path)
        else:
            decoded = _strict_json_loads(raw)
            if isinstance(decoded, dict):
                parsed = decoded
            elif streaming and req_format == "gemini" and isinstance(decoded, list):
                # Gemini's streaming endpoint may return a JSON array unless
                # ``alt=sse`` was requested. Its provider reassembler validates
                # and combines that representation.
                parsed = _parse_sse_response(raw, req_format, path=path)
            else:
                raise ResponseInspectionError(
                    "provider response must contain a JSON object"
                )
    except SSEParseError as exc:
        raise ResponseInspectionError(f"SSE parse failed: {exc}") from exc
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
        if "duplicate JSON object key" in str(exc):
            raise AmbiguousResponseError(
                f"JSON parse rejected an ambiguous object: {exc}"
            ) from exc
        raise ResponseInspectionError(f"JSON parse failed: {exc}") from exc

    if not isinstance(parsed, dict) or not parsed:
        raise ResponseInspectionError("provider response produced no inspectable object")
    return parsed


def _response_requires_inspection(
    writer: "AuditEventWriter | None",
    method: str,
    resp_status: int,
) -> bool:
    """Whether a response must be understood before any bytes are released."""
    if not writer:
        return False
    requires_buffering = getattr(
        writer,
        "requires_stream_buffering",
        getattr(writer, "policy_failure_mode", "fail_open") == "fail_closed",
    )
    return bool(
        requires_buffering
        and method != "HEAD"
        and 200 <= resp_status < 300
        and resp_status not in (204, 205)
    )


def _mark_inspection_failure(
    events: list[dict],
    message: str,
    *,
    blocked: bool,
    truncated: bool = False,
) -> None:
    """Attach an explicit response-inspection failure to model response events."""
    for event in events:
        if event.get("event_type") != "model_response":
            continue
        event["outcome"] = {
            "status": "blocked" if blocked else "error",
            "summary": message,
        }
        capture = event.setdefault("context", {}).setdefault("capture", {})
        capture["inspection_status"] = "blocked" if blocked else "incomplete"
        capture["inspection_error"] = message
        if blocked:
            capture["response_delivered"] = False
            capture["delivery_status"] = "withheld"
        if truncated:
            capture["audit_body_truncated"] = True


def _mark_preflight_blocked(events: list[dict]) -> None:
    """Record that a denied model request never crossed the upstream boundary."""
    for event in events:
        if event.get("event_type") != "model_request":
            continue
        event["outcome"] = {
            "status": "blocked",
            "summary": "Request blocked before upstream forwarding",
        }
        capture = event.setdefault("context", {}).setdefault("capture", {})
        capture["upstream_forwarded"] = False
        capture["delivery_status"] = "blocked_before_upstream"


def _mark_postflight_blocked(events: list[dict]) -> None:
    """Record that a buffered response and its tool proposals were withheld."""
    for event in events:
        event_type = event.get("event_type")
        if event_type == "model_response":
            event["outcome"] = {
                "status": "blocked",
                "summary": "Upstream response withheld by postflight policy",
            }
        elif event_type == "tool_call":
            event["outcome"] = {
                "status": "blocked",
                "summary": (
                    "Model proposed this tool call, but its containing response "
                    "was withheld; local execution was not observed"
                ),
            }
        else:
            continue
        capture = event.setdefault("context", {}).setdefault("capture", {})
        capture["response_delivered"] = False
        capture["delivery_status"] = "withheld"


def _apply_unknown_tool_posture(
    event: dict,
    result: PolicyResult,
    *,
    failure_mode: str,
) -> PolicyResult:
    """Never silently allow an unrecognized provider execution surface."""
    unknown_types = (event.get("action", {}) or {}).get(
        "unknown_tool_types",
        [],
    )
    if not unknown_types:
        return result

    synthetic_action = "block" if failure_mode == "fail_closed" else "warn"
    message = (
        "Unknown requested tool types were denied by fail-closed mode"
        if synthetic_action == "block"
        else "Unknown requested tool types were allowed with a fail-open warning"
    )
    synthetic = {
        "policy_name": "unknown_requested_tool_type",
        "message": message,
        "reason": "action.unknown_tool_types is non-empty",
        "action": synthetic_action,
    }
    if result.action == "block" or synthetic_action == "block":
        final_action = "block"
    else:
        final_action = "warn"
    return PolicyResult(
        action=final_action,
        violated_policies=[*result.violated_policies, synthetic],
        warnings=[*result.warnings, message],
        evaluation_errors=list(
            getattr(result, "evaluation_errors", [])
        ),
        matched_policies=[
            *getattr(result, "matched_policies", []),
            synthetic,
        ],
        policy_snapshot_id=getattr(result, "policy_snapshot_id", None),
        policy_engine_semantics_version=getattr(
            result,
            "policy_engine_semantics_version",
            1,
        ),
    )


# ---------------------------------------------------------------------------
# AuditEventWriter
# ---------------------------------------------------------------------------


class AuditEventWriter:
    """Build audit events and enforce policy at the model API boundary.

    The proxy observes requests, responses, and model-issued tool instructions.
    It does not observe arbitrary local tool execution after an agent receives a
    model response; its capture metadata makes that boundary explicit.
    """

    def __init__(
        self,
        db: Any,
        policies_dir: str | None = None,
        policy_failure_mode: str = "fail_open",
        max_tool_events_per_exchange: int = DEFAULT_MAX_TOOL_EVENTS_PER_EXCHANGE,
    ) -> None:
        if max_tool_events_per_exchange <= 0:
            raise ValueError("max_tool_events_per_exchange must be positive")
        self.db = db
        self._session_id: str | None = None
        self.policy_engine: Any = None
        self.policy_failure_mode = policy_failure_mode
        self.max_tool_events_per_exchange = max_tool_events_per_exchange
        self.policy_initialization_error: str | None = None
        if policies_dir:
            try:
                self.policy_engine = PolicyEngine(
                    policies_dir=policies_dir,
                    db=db,
                    failure_mode=policy_failure_mode,
                )
                log.debug("Policy engine initialized with %d policies", len(self.policy_engine.policies))
            except Exception as exc:
                self.policy_initialization_error = str(exc)
                log.exception("Failed to initialize policy engine — policies disabled")

    @property
    def session_id(self) -> str:
        if self._session_id is None:
            self._session_id = uuid.uuid4().hex[:16]
        return self._session_id

    def set_session_id(self, sid: str) -> None:
        self._session_id = sid

    # ------------------------------------------------------------------
    # Build helpers
    # ------------------------------------------------------------------

    @property
    def requires_stream_buffering(self) -> bool:
        """True when a streamed model response must be checked before delivery."""
        if not self.policy_engine:
            return self.policy_failure_mode == "fail_closed"
        return bool(
            getattr(self.policy_engine, "has_blocking_policies", False)
            or self.policy_failure_mode == "fail_closed"
        )

    def _capture_metadata(self, streaming: bool, token_identity: bool = False) -> dict:
        stream_delivery = None
        if streaming:
            stream_delivery = (
                "buffered_for_enforcement"
                if self.requires_stream_buffering
                else "passthrough_audit_only"
            )
        if token_identity:
            return PROXY_TOKEN_CAPABILITIES.as_context(
                stream_delivery=stream_delivery,
                identity_source="panoptes_token",
            )
        return PROXY_CAPABILITIES.as_context(stream_delivery=stream_delivery)

    def _make_base_event(
        self,
        event_type: str,
        *,
        run_id: str,
        session_id: str,
        agent_type: str,
        turn_number: int,
        streaming: bool,
        token_identity: bool = False,
    ) -> dict:
        return {
            "event_id": uuid.uuid4().hex,
            "timestamp": utcnow_iso(),
            "agent": {"type": agent_type, "session_id": session_id, "run_id": run_id},
            "event_type": event_type,
            "action": {},
            "outcome": {},
            "context": {
                "turn_number": turn_number,
                "capture": self._capture_metadata(streaming, token_identity),
            },
            "cost": {},
        }

    def build_request_events(
        self,
        *,
        path: str,
        method: str,
        req_headers: dict[str, str],
        req_body: dict | None,
        run_id: str | None = None,
        identity: SessionIdentity | None = None,
    ) -> tuple[list[dict], dict]:
        """Build request-side audit events (model_request + tool_result).

        Returns (events, exchange_ctx). Pass exchange_ctx to build_response_events
        to share run_id, session_id, agent_type, req_format, and turn_number.
        A token-resolved ``identity`` replaces the client's identity headers.
        """
        if run_id is None:
            run_id = uuid.uuid4().hex

        provider = _providers.detect(path, req_body)
        req_format = provider.name
        agent_type = (
            identity.agent_type
            if identity is not None
            else detect_agent_type(path, req_headers, req_body)
        )
        req_info = provider.extract_request_info(req_body)
        requested_tools = (
            provider.extract_requested_tools(req_body)
            if isinstance(req_body, dict)
            else {
                "requested_tools": [],
                "client_side_tools": [],
                "server_side_tools": [],
                "unknown_tool_types": [],
                "requested_tool_targets": [],
            }
        )
        for field, values in requested_tools.items():
            if not isinstance(values, list) or not all(
                isinstance(value, str) and value for value in values
            ):
                raise ValidationError(
                    f"provider {provider.name} returned invalid {field}"
                )
            if len(values) > self.max_tool_events_per_exchange:
                raise ValidationError(
                    f"request {field} exceeds the per-exchange limit of "
                    f"{self.max_tool_events_per_exchange}"
                )
        # Streaming can be signalled by the path (Gemini), not just the body.
        req_info["stream"] = provider.is_streaming(path, req_body)
        turn_number = provider.estimate_turn_number(req_body)
        # Without an explicit adapter session identifier, isolate each exchange.
        # Merging unrelated clients into one process-wide session corrupts
        # timelines and evidence chains; continuity requires the documented
        # x-panoptes-session header.
        session_id = (
            identity.session_id
            if identity is not None
            else _lower_keys(req_headers).get("x-panoptes-session")
            or self._session_id
            or run_id
        )
        token_identity = identity is not None

        exchange_ctx = {
            "run_id": run_id,
            "session_id": session_id,
            "agent_type": agent_type,
            "path": path,
            "req_format": req_format,
            "req_info": req_info,
            "turn_number": turn_number,
            "token_identity": token_identity,
        }

        def _base(event_type: str) -> dict:
            return self._make_base_event(
                event_type, run_id=run_id, session_id=session_id,
                agent_type=agent_type, turn_number=turn_number,
                streaming=req_info["stream"], token_identity=token_identity,
            )

        events: list[dict] = []

        # model_request event
        req_event = _base("model_request")
        req_event["action"] = {
            "method": method,
            "path": path,
            "model": req_info["model"],
            "messages_count": req_info["messages_count"],
            "tools_count": req_info["tools_count"],
            "streaming": req_info["stream"],
            **requested_tools,
        }
        req_event["outcome"] = {"status": "success"}
        req_event["raw_request"] = _cap_raw(req_body)
        if (
            isinstance(req_event["raw_request"], str)
            and req_event["raw_request"].endswith("...[truncated]")
        ):
            req_event["context"]["capture"]["raw_request_truncated"] = True
        events.append(req_event)

        # tool_result events (from request body)
        if isinstance(req_body, dict):
            tool_results = provider.extract_tool_results(req_body)
            if len(tool_results) > self.max_tool_events_per_exchange:
                raise ValidationError(
                    "tool result count exceeds the per-exchange limit of "
                    f"{self.max_tool_events_per_exchange}"
                )
            for tr in tool_results:
                tr_event = _base("tool_result")
                call_id = tr.get("call_id") or None
                redacted_result = redact_secrets(tr.get("result", ""))
                tr_event["action"] = {
                    "tool_name": tr.get("tool_name", "unknown"),
                    "target": call_id,
                    "call_id": call_id,
                    "result": redacted_result,
                    "result_complete": True,
                }
                if isinstance(redacted_result, str):
                    result_str = redacted_result
                else:
                    result_str = json.dumps(
                        redacted_result, ensure_ascii=False, default=str
                    )
                result_status = (
                    "error" if tr.get("is_error") is True else "success"
                )
                tr_event["outcome"] = {
                    "status": result_status,
                    "summary": result_str[:500],
                }
                events.append(tr_event)

        normalized_events = [normalize_event(event) for event in events]
        for event in normalized_events:
            validate_event(event)
        return normalized_events, exchange_ctx

    def build_response_events(
        self,
        *,
        path: str,
        req_body: dict | None,
        resp_status: int,
        resp_headers: dict[str, str],
        resp_body: dict | None,
        duration_ms: int,
        exchange_ctx: dict,
    ) -> list[dict]:
        """Build response-side audit events (model_response + tool_call)."""
        run_id = exchange_ctx.get("run_id") or uuid.uuid4().hex
        session_id = exchange_ctx.get("session_id") or self.session_id
        agent_type = exchange_ctx.get("agent_type", "unknown")
        turn_number = exchange_ctx.get("turn_number", 0)

        # Resolve provider for tool extraction (re-detect only if ctx is missing it)
        req_format = exchange_ctx.get("req_format")
        if req_format is None:
            provider = _providers.detect(path, req_body)
        else:
            provider = next(
                (p for p in _providers.REGISTRY if p.name == req_format),
                _providers._UNKNOWN,
            )
        req_info = exchange_ctx.get("req_info")
        if req_info is None:
            req_info = provider.extract_request_info(req_body)
            # Streaming can be signalled by the path (Gemini), not just the body;
            # always re-derive it here to match the logic in build_request_events.
            req_info["stream"] = provider.is_streaming(path, req_body)

        def _base(event_type: str) -> dict:
            return self._make_base_event(
                event_type, run_id=run_id, session_id=session_id,
                agent_type=agent_type, turn_number=turn_number,
                streaming=bool(req_info.get("stream", False)),
                token_identity=bool(exchange_ctx.get("token_identity")),
            )

        events: list[dict] = []

        # model_response event
        resp_event = _base("model_response")
        resp_event["action"] = {
            "model": req_info["model"],
            "status_code": resp_status,
            "duration_ms": duration_ms,
        }
        if resp_status < 400:
            resp_event["outcome"] = {"status": "success", "summary": f"HTTP {resp_status}"}
        elif resp_status < 500:
            resp_event["outcome"] = {"status": "error", "summary": f"Client error HTTP {resp_status}"}
        else:
            resp_event["outcome"] = {"status": "error", "summary": f"Server error HTTP {resp_status}"}

        if isinstance(resp_body, dict):
            resp_event["cost"] = provider.extract_usage(resp_body)

        resp_event["raw_response"] = _cap_raw(resp_body)
        if (
            isinstance(resp_event["raw_response"], str)
            and resp_event["raw_response"].endswith("...[truncated]")
        ):
            resp_event["context"]["capture"]["raw_response_truncated"] = True
        events.append(resp_event)

        # tool_call events (from response body)
        if isinstance(resp_body, dict):
            tool_calls = provider.extract_tool_calls(resp_body, path=path)
            if len(tool_calls) > self.max_tool_events_per_exchange:
                raise ValidationError(
                    "tool call count exceeds the per-exchange limit of "
                    f"{self.max_tool_events_per_exchange}"
                )
            for tc in tool_calls:
                tc_event = _base("tool_call")
                call_id = tc.get("call_id") or None
                tc_event["action"] = {
                    "tool_name": tc["tool_name"],
                    "parameters": tc.get("parameters", {}),
                    "target": call_id,
                    "call_id": call_id,
                }
                for field in (
                    "execution_scope",
                    "provider_item_type",
                    "status",
                    "server_result_type",
                ):
                    if tc.get(field) is not None:
                        tc_event["action"][field] = tc[field]
                if "result" in tc:
                    tc_event["action"]["result"] = redact_secrets(tc["result"])
                    tc_event["action"]["result_complete"] = True
                if tc.get("server_result") is not None:
                    redacted_server_result = redact_secrets(tc["server_result"])
                    if isinstance(redacted_server_result, str):
                        server_result_text = redacted_server_result
                    else:
                        server_result_text = json.dumps(
                            redacted_server_result,
                            ensure_ascii=False,
                            default=str,
                        )
                    tc_event["action"]["server_result_summary"] = (
                        server_result_text[:500]
                    )
                    tc_event["action"]["server_result_complete"] = (
                        len(server_result_text) <= 500
                    )

                provider_status = tc.get("status")
                outcome_status = tc.get("outcome_status")
                execution_scope = tc.get("execution_scope")
                if outcome_status not in {
                    "success",
                    "error",
                    "blocked",
                    "timeout",
                    "pending",
                    "warned",
                }:
                    if tc.get("is_error") is True or provider_status in {
                        "failed",
                        "error",
                        "cancelled",
                    }:
                        outcome_status = "error"
                    elif (
                        execution_scope in {"provider", "server"}
                        and (
                            "result" in tc
                            or provider_status
                            in {"completed", "success", "succeeded"}
                        )
                    ):
                        outcome_status = "success"
                    else:
                        outcome_status = "pending"

                if execution_scope in {"provider", "server"}:
                    if outcome_status == "success":
                        summary = (
                            "Provider-hosted action completed upstream; "
                            "local execution was not involved"
                        )
                    elif outcome_status == "error":
                        summary = (
                            "Provider-hosted action failed upstream; "
                            "local execution was not involved"
                        )
                    else:
                        summary = (
                            "Provider-hosted action is pending or deferred upstream"
                        )
                else:
                    summary = (
                        "Model proposed this tool call; local execution was not observed"
                    )
                tc_event["outcome"] = {
                    "status": outcome_status,
                    "summary": summary,
                }
                events.append(tc_event)

        normalized_events = [normalize_event(event) for event in events]
        for event in normalized_events:
            validate_event(event)
        return normalized_events

    # ------------------------------------------------------------------
    # Write and policy helpers
    # ------------------------------------------------------------------

    def write(self, events: list[dict]) -> None:
        """Persist every event or raise ``AuditWriteError``.

        A batch failure falls back to per-event inserts. Swallowing a fallback
        failure would make fail-closed enforcement claim evidence exists when it
        does not, so callers must be able to react to incomplete durability.
        """
        if not events:
            return
        if hasattr(self.db, "insert_events"):
            try:
                self.db.insert_events(events)
                return
            except Exception:
                log.exception("Batch write failed — falling back to per-event writes")
        failures: list[Exception] = []
        for event in events:
            try:
                self.db.insert_event(event)
            except Exception as exc:
                failures.append(exc)
                log.exception("Failed to write audit event")
        if failures:
            raise AuditWriteError(
                f"Failed to persist {len(failures)} of {len(events)} audit events"
            ) from failures[0]

    def write_events(
        self,
        *,
        path: str,
        method: str,
        req_headers: dict[str, str],
        req_body: dict | None,
        resp_status: int,
        resp_headers: dict[str, str],
        resp_body: dict | None,
        duration_ms: int,
    ) -> list[dict]:
        """Build all events for an exchange and write them.

        Backward-compatible wrapper — generates a fresh run_id per call.
        """
        run_id = uuid.uuid4().hex
        req_events, exchange_ctx = self.build_request_events(
            path=path, method=method, req_headers=req_headers,
            req_body=req_body, run_id=run_id,
        )
        resp_events = self.build_response_events(
            path=path, req_body=req_body, resp_status=resp_status,
            resp_headers=resp_headers, resp_body=resp_body,
            duration_ms=duration_ms, exchange_ctx=exchange_ctx,
        )
        all_events = req_events + resp_events
        self.write(all_events)
        return all_events

    def check_policies(self, events: list[dict]) -> Any:
        """Check events against loaded policies.

        Returns a PolicyResult (action="allow" if no policy engine).
        """
        if not self.policy_engine:
            if self.policy_failure_mode == "fail_closed":
                message = "Policy engine unavailable; denied by fail-closed mode"
                reason = (
                    self.policy_initialization_error
                    or "no policy engine was configured"
                )
                result = PolicyResult(
                    action="block",
                    violated_policies=[{
                        "policy_name": "policy_engine_error",
                        "message": message,
                        "reason": reason,
                    }],
                    warnings=[message],
                    evaluation_errors=[reason],
                )
            else:
                result = PolicyResult(
                    action="allow", violated_policies=[], warnings=[]
                )
            aggregate_result = result
            for event in events:
                event_result = _apply_unknown_tool_posture(
                    event,
                    result,
                    failure_mode=self.policy_failure_mode,
                )
                self._attach_policy_result(event, event_result)
                if event_result is not result:
                    aggregate_result = event_result
            return aggregate_result

        all_violated: list[dict] = []
        all_matched: list[dict] = []
        all_warnings: list[str] = []
        all_errors: list[str] = []
        snapshot_ids: set[str] = set()
        final_action = "allow"

        source_events = list(events)
        evaluate = getattr(self.policy_engine, "evaluate", None)
        if evaluate is None:
            evaluate = self.policy_engine.check_event
        build_violation = getattr(
            self.policy_engine,
            "build_violation_event",
            None,
        )

        for event in source_events:
            # PolicyEngine.evaluate() is pure with respect to audit storage.
            # Violation records are appended to this same batch so a database
            # supporting insert_events() commits source and decision evidence
            # atomically.
            result = _apply_unknown_tool_posture(
                event,
                evaluate(event),
                failure_mode=self.policy_failure_mode,
            )
            all_violated.extend(result.violated_policies)
            all_matched.extend(getattr(result, "matched_policies", []))
            all_warnings.extend(result.warnings)
            all_errors.extend(getattr(result, "evaluation_errors", []))
            snapshot_id = getattr(result, "policy_snapshot_id", None)
            if snapshot_id:
                snapshot_ids.add(snapshot_id)
            self._attach_policy_result(event, result)
            if build_violation is not None:
                for violation in result.violated_policies:
                    policy_action = violation.get("action")
                    if policy_action not in ("warn", "block"):
                        policy_action = (
                            result.action
                            if result.action in ("warn", "block")
                            else "block"
                        )
                    violation_event = build_violation(
                        event,
                        violation["policy_name"],
                        violation["message"],
                        policy_action=policy_action,
                        policy_snapshot_id=snapshot_id,
                        policy_engine_semantics_version=getattr(
                            result,
                            "policy_engine_semantics_version",
                            1,
                        ),
                    )
                    if violation_event is not None:
                        events.append(violation_event)
            if result.action == "block":
                final_action = "block"
            elif result.action == "warn" and final_action != "block":
                final_action = "warn"

        if len(snapshot_ids) > 1:
            snapshot_error = (
                "Policy snapshot changed while one proxy event batch was evaluated"
            )
            all_errors.append(snapshot_error)
            all_warnings.append(snapshot_error)
            if self.policy_failure_mode == "fail_closed":
                final_action = "block"
                all_violated.append({
                    "policy_name": "policy_snapshot_changed",
                    "message": snapshot_error,
                    "reason": snapshot_error,
                    "action": "block",
                })
                if build_violation is not None and source_events:
                    snapshot_violation = build_violation(
                        source_events[0],
                        "policy_snapshot_changed",
                        snapshot_error,
                        policy_action="block",
                        policy_snapshot_id=None,
                    )
                    if snapshot_violation is not None:
                        events.append(snapshot_violation)

        return PolicyResult(
            action=final_action,
            violated_policies=all_violated,
            warnings=all_warnings,
            evaluation_errors=all_errors,
            matched_policies=all_matched,
            policy_snapshot_id=(
                next(iter(snapshot_ids)) if len(snapshot_ids) == 1 else None
            ),
        )

    @staticmethod
    def _attach_policy_result(event: dict, result: PolicyResult) -> None:
        """Persist the exact decision provenance alongside the checked event."""
        event.setdefault("context", {})["policy"] = {
            "action": result.action,
            "matched_policies": list(getattr(result, "matched_policies", [])),
            "violated_policies": list(result.violated_policies),
            "evaluation_errors": list(
                getattr(result, "evaluation_errors", [])
            ),
            "snapshot_id": getattr(result, "policy_snapshot_id", None),
            "engine_semantics_version": getattr(
                result,
                "policy_engine_semantics_version",
                None,
            ),
        }


# ---------------------------------------------------------------------------
# Upstream routing (reverse-proxy mode)
# ---------------------------------------------------------------------------

_ENV_ANTHROPIC = "PANOPTES_UPSTREAM_ANTHROPIC"
_ENV_OPENAI = "PANOPTES_UPSTREAM_OPENAI"
_ENV_GEMINI = "PANOPTES_UPSTREAM_GEMINI"

_PROVIDER_ENV: dict[str, str] = {
    "anthropic": _ENV_ANTHROPIC,
    "openai": _ENV_OPENAI,
    "gemini": _ENV_GEMINI,
}


class ProxyRequestError(ValueError):
    """A client-visible proxy request error."""

    status_code = 400


class NoUpstreamError(ProxyRequestError):
    """Raised when no upstream can be determined for a reverse-proxy path."""

    status_code = 502


class RequestFramingError(ProxyRequestError):
    """Raised when request-body framing is unsupported or ambiguous."""

    status_code = 400


class RequestBodyTooLarge(ProxyRequestError):
    """Raised before an oversized client body is read."""

    status_code = 413


class UpstreamBodyTooLarge(RuntimeError):
    """Raised when a buffered upstream response exceeds its hard limit."""

    def __init__(
        self,
        limit: int,
        *,
        upstream_status: int | None = None,
        upstream_headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(f"upstream response exceeded {limit} bytes")
        self.limit = limit
        self.upstream_status = upstream_status
        self.upstream_headers = upstream_headers or {}


class ResponseInspectionError(RuntimeError):
    """Raised when a response cannot be proven safe before delivery."""


class AmbiguousResponseError(ResponseInspectionError):
    """Raised when response JSON has parser-differential ambiguity."""


class AuditWriteError(RuntimeError):
    """Raised when one or more required audit events could not be persisted."""


def _parse_upstream_url(url: str, default_scheme: str = "https") -> tuple[str, str, int]:
    """Parse and validate a configured upstream URL.

    Only HTTP(S) upstreams without embedded credentials, query strings, or
    fragments are accepted. A bare hostname remains supported for compatibility.
    """
    candidate = url.strip()
    if "://" not in candidate:
        candidate = f"{default_scheme}://{candidate}"
    p = urlparse(candidate)
    scheme = p.scheme.lower()
    if scheme not in ("http", "https"):
        raise NoUpstreamError(f"Unsupported upstream URL scheme: {scheme or '<missing>'}")
    if p.username is not None or p.password is not None:
        raise NoUpstreamError("Upstream URLs must not contain credentials")
    if p.query or p.fragment:
        raise NoUpstreamError("Upstream base URLs must not contain a query or fragment")
    if p.path not in ("", "/"):
        raise NoUpstreamError("Upstream base URLs must not contain a path")
    host = (p.hostname or "").rstrip(".").lower()
    if not host:
        raise NoUpstreamError("Upstream URL is missing a hostname")
    try:
        port = p.port or (443 if scheme == "https" else 80)
    except ValueError as exc:
        raise NoUpstreamError(f"Invalid upstream port: {exc}") from exc
    return scheme, host, port


# ---------------------------------------------------------------------------
# HTTP proxy handler
# ---------------------------------------------------------------------------

HOP_BY_HOP = frozenset({
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "proxy-connection", "te", "trailer", "trailers", "transfer-encoding",
    "upgrade",
})
PANOPTES_INTERNAL_HEADERS = frozenset({
    "x-panoptes-agent",
    "x-panoptes-session",
})

# Credential injection: every client credential is stripped, and only the
# routed provider's key is added. Clients present their Panoptes token in the
# slot their provider SDK already uses for an API key.
CLIENT_CREDENTIAL_HEADERS = frozenset({
    "authorization",
    "x-api-key",
    "x-goog-api-key",
})
_CLIENT_TOKEN_SLOTS: dict[str, tuple[str, ...]] = {
    "anthropic": ("x-api-key", "authorization"),
    "openai": ("authorization",),
    "gemini": ("x-goog-api-key", "query:key"),
}
_PROVIDER_KEY_HEADERS: dict[str, tuple[str, str]] = {
    "anthropic": ("x-api-key", "{key}"),
    "openai": ("Authorization", "Bearer {key}"),
    "gemini": ("x-goog-api-key", "{key}"),
}


def _strip_query_credentials(path: str) -> tuple[str, list[str]]:
    """Remove every ``key`` query parameter, returning the path and its values.

    Other parameters keep their original encoding and order.
    """
    base, sep, query = path.partition("?")
    if not sep:
        return path, []
    query, hash_sep, fragment = query.partition("#")
    kept: list[str] = []
    values: list[str] = []
    for part in query.split("&"):
        name, _, value = part.partition("=")
        if unquote_plus(name) == "key":
            values.append(unquote_plus(value))
        else:
            kept.append(part)
    stripped = base + ("?" + "&".join(kept) if kept else "")
    return stripped + (hash_sep + fragment if hash_sep else ""), values


def _with_upstream_credential(
    fwd_headers: dict[str, str],
    upstream_credential: tuple[str, str] | None,
) -> dict[str, str]:
    """Replace every client credential with the provider key, if injecting.

    Applied after hop-by-hop filtering so a client ``Connection`` header cannot
    nominate the injected credential for removal.
    """
    if upstream_credential is None:
        return fwd_headers
    swapped = {
        key: value
        for key, value in fwd_headers.items()
        if key.lower() not in CLIENT_CREDENTIAL_HEADERS
    }
    swapped[upstream_credential[0]] = upstream_credential[1]
    return swapped


def _presented_token(
    provider: str,
    headers: Any,
    query_values: list[str],
) -> str | None:
    """Return the one credential the client presented for ``provider``.

    Several differing credentials are ambiguous and rejected rather than
    letting one slot win silently.
    """
    presented: list[str] = []
    for slot in _CLIENT_TOKEN_SLOTS.get(provider, ()):
        if slot == "query:key":
            presented.extend(query_values)
            continue
        for value in _header_values(headers, slot):
            value = value.strip()
            if slot == "authorization":
                scheme, _, credential = value.partition(" ")
                value = (
                    credential.strip() if scheme.lower() == "bearer" else value
                )
            presented.append(value)
    distinct = {value for value in presented if value}
    if len(distinct) > 1:
        raise TokenRejected("ambiguous")
    return next(iter(distinct), None)


def _filter_headers(headers: dict[str, str]) -> dict[str, str]:
    connection_nominated: set[str] = set()
    for key, value in headers.items():
        if key.lower() != "connection":
            continue
        connection_nominated.update(
            token.strip().lower()
            for token in str(value).split(",")
            if token.strip()
        )
    blocked = HOP_BY_HOP | connection_nominated
    return {k: v for k, v in headers.items() if k.lower() not in blocked}


def _decoded_body_headers(
    headers: dict[str, str],
    *,
    streaming: bool,
) -> dict[str, str]:
    """Headers safe to forward after ``httpx.iter_bytes`` decoded the body."""
    filtered = _filter_headers(headers)
    return {
        key: value
        for key, value in filtered.items()
        if key.lower() != "content-encoding"
        and (not streaming or key.lower() != "content-length")
    }


def _header_values(headers: Any, name: str) -> list[str]:
    """Return all values for a header from HTTPMessage-like or mapping objects."""
    get_all = getattr(headers, "get_all", None)
    if callable(get_all):
        values = get_all(name)
        return [str(value) for value in (values or [])]
    get_list = getattr(headers, "get_list", None)
    if callable(get_list):
        values = get_list(name)
        return [str(value) for value in (values or [])]
    return [
        str(value)
        for key, value in getattr(headers, "items", lambda: [])()
        if str(key).lower() == name.lower()
    ]


def _upstream_url(scheme: str, host: str, port: int, path: str) -> str:
    """Build an upstream URL, preserving IPv6 literal authority syntax."""
    authority_host = f"[{host}]" if ":" in host and not host.startswith("[") else host
    return f"{scheme}://{authority_host}:{port}{path}"


def _safe_upstream_label(scheme: str, host: str, port: int, path: str) -> str:
    """Return a log label that cannot expose query-string credentials."""
    return _upstream_url(scheme, host, port, urlparse(path).path or "/")


def _block_payload(policy_result: PolicyResult) -> tuple[str, dict]:
    """Build the (message, extra-fields) pair for a policy-block response."""
    messages = [
        vp.get("message", "Blocked by policy")
        for vp in policy_result.violated_policies
    ]
    block_msg = "; ".join(messages) or "Blocked by policy"
    extra = {
        "violated_policies": [
            vp.get("policy_name", "") for vp in policy_result.violated_policies
        ],
        "matched_policies": [
            match.get("policy_name", "")
            for match in getattr(policy_result, "matched_policies", [])
        ],
        "policy_snapshot_id": getattr(
            policy_result, "policy_snapshot_id", None
        ),
    }
    return block_msg, extra


def _log_policy_warnings(policy_result: PolicyResult) -> None:
    if policy_result.action == "warn":
        for w in policy_result.warnings:
            log.warning("Policy warning: %s", w)


def _policy_exception_payload(
    writer: AuditEventWriter | None,
    phase: str,
    exc: Exception,
) -> tuple[str, dict] | None:
    """Return a denial payload when policy errors must fail closed.

    Delegates to PolicyEngine.make_failure_result() so the fail-closed
    semantics are defined in exactly one place.
    """
    failure_mode = writer.policy_failure_mode if writer else "fail_open"
    result = PolicyEngine.make_failure_result(failure_mode, [str(exc)])
    if result.action == "block":
        log.exception("%s policy processing failed — denying traffic", phase)
        return (
            result.violated_policies[0]["message"] if result.violated_policies
            else "Policy processing failed; denied by fail-closed mode",
            {"policy_error": True, "phase": phase},
        )
    log.exception("%s policy processing failed — allowing traffic", phase)
    return None


def _mark_policy_processing_failure(
    events: list[dict],
    writer: AuditEventWriter,
    phase: str,
    exc: Exception,
) -> None:
    """Record fail-open/fail-closed policy errors on every affected event."""
    action = (
        "block"
        if writer.policy_failure_mode == "fail_closed"
        else "allow"
    )
    snapshot_id = getattr(
        getattr(writer, "policy_engine", None), "policy_snapshot_id", None
    )
    for event in events:
        event.setdefault("context", {})["policy"] = {
            "action": action,
            "matched_policies": [],
            "violated_policies": [],
            "evaluation_errors": [f"{phase}: {exc}"],
            "snapshot_id": snapshot_id,
        }


def _unpersisted_exchange_events(
    req_events: list[dict],
    resp_events: list[dict],
    exchange_ctx: dict,
) -> list[dict]:
    """Avoid duplicating request events already made durable pre-forward."""
    if exchange_ctx.get("_request_events_persisted"):
        return resp_events
    return req_events + resp_events


class ProxyHandler(http.server.BaseHTTPRequestHandler):
    """HTTP reverse-proxy request handler."""

    writer: AuditEventWriter | None = None
    http_client: httpx.Client | None = None  # shared per-server instance
    upstream_timeout: float = 120.0
    max_request_body_bytes: int = DEFAULT_MAX_REQUEST_BODY_BYTES
    max_buffered_response_bytes: int = DEFAULT_MAX_BUFFERED_RESPONSE_BYTES
    max_audit_stream_bytes: int = DEFAULT_MAX_AUDIT_STREAM_BYTES
    # Credential-injection mode is on when provider_keys is not None.
    provider_keys: dict[str, str] | None = None
    token_store: SessionTokenStore | None = None

    def log_message(self, fmt: str, *args: Any) -> None:
        safe_args = list(args)
        request_line = getattr(self, "requestline", "")
        if safe_args and request_line and safe_args[0] == request_line:
            safe_path = urlparse(getattr(self, "path", "")).path or "/"
            safe_args[0] = (
                f"{getattr(self, 'command', '')} {safe_path} "
                f"{getattr(self, 'request_version', '')}"
            ).strip()
        raw_path = getattr(self, "path", "")
        safe_path = urlparse(raw_path).path or "/"
        if raw_path and raw_path != safe_path:
            safe_args = [
                value.replace(raw_path, safe_path)
                if isinstance(value, str)
                else value
                for value in safe_args
            ]
        log.info(fmt % tuple(safe_args))

    # ------------------------------------------------------------------
    # Target parsing
    # ------------------------------------------------------------------

    def _parse_target(self) -> tuple[str, str, int, str]:
        """Parse the request line into (scheme, host, port, path).

        Requests use origin-form paths and are routed by provider pattern.
        """
        parsed = urlparse(self.path)

        if parsed.scheme or parsed.netloc:
            raise ProxyRequestError(
                "Absolute-form targets are not supported; configure the client "
                "to use Panoptes as its API base URL"
            )

        # Reverse-proxy mode — relative path; consult provider registry
        path = self.path
        if not path.startswith("/"):
            raise ProxyRequestError("Reverse-proxy targets must use origin-form paths")

        for provider in _providers.REGISTRY:
            if provider.matches_path(path):
                env_var = _PROVIDER_ENV.get(provider.name)
                env_val = os.environ.get(env_var) if env_var else None
                if env_val:
                    s, h, p = _parse_upstream_url(env_val)
                else:
                    s, h, p = _parse_upstream_url(provider.default_upstream)
                return s, h, p, path

        safe_path = urlparse(path).path or "/"
        raise NoUpstreamError(
            f"No supported provider route for path '{safe_path}'"
        )

    # ------------------------------------------------------------------
    # Request body
    # ------------------------------------------------------------------

    def _read_body(self) -> bytes:
        transfer_encoding = _header_values(self.headers, "Transfer-Encoding")
        content_lengths = _header_values(self.headers, "Content-Length")

        if transfer_encoding and content_lengths:
            raise RequestFramingError(
                "Ambiguous request framing: both Transfer-Encoding and Content-Length"
            )
        if transfer_encoding:
            # BaseHTTPRequestHandler does not decode request transfer codings.
            # Treating a chunked body as empty would let opaque bytes reach the
            # next request and can bypass policy inspection.
            raise RequestFramingError(
                "Transfer-Encoding request bodies are not supported"
            )
        if len(content_lengths) > 1:
            raise RequestFramingError("Multiple Content-Length headers are not allowed")
        if not content_lengths:
            return b""

        raw_length = content_lengths[0].strip()
        if not raw_length or "," in raw_length:
            raise RequestFramingError("Ambiguous Content-Length header")
        try:
            content_length = int(raw_length, 10)
        except ValueError as exc:
            raise RequestFramingError("Invalid Content-Length header") from exc
        if content_length < 0:
            raise RequestFramingError("Content-Length must not be negative")

        limit = getattr(
            self, "max_request_body_bytes", DEFAULT_MAX_REQUEST_BODY_BYTES
        )
        if content_length > limit:
            raise RequestBodyTooLarge(
                f"Request body exceeds the {limit}-byte limit"
            )
        if content_length == 0:
            return b""

        try:
            body = self.rfile.read(content_length)
        except OSError as exc:
            raise RequestFramingError("Failed to read the complete request body") from exc
        if len(body) != content_length:
            raise RequestFramingError(
                "Request body ended before the declared Content-Length"
            )
        return body

    # ------------------------------------------------------------------
    # Upstream forwarding
    # ------------------------------------------------------------------

    def _build_fwd_headers(self, headers: dict[str, str]) -> dict[str, str]:
        fwd = {
            key: value
            for key, value in _filter_headers(dict(headers)).items()
            if key.lower() not in PANOPTES_INTERNAL_HEADERS and key.lower() != "host"
        }
        fwd["Accept-Encoding"] = "identity"
        return fwd

    def _get_client(self) -> tuple[httpx.Client, bool]:
        """Return (client, owned). If owned=True, caller must close it."""
        if self.http_client is not None:
            return self.http_client, False
        return (
            httpx.Client(
                timeout=self.upstream_timeout,
                follow_redirects=False,
                trust_env=False,
            ),
            True,
        )

    def _forward_request(
        self,
        method: str,
        scheme: str,
        host: str,
        port: int,
        path: str,
        headers: dict[str, str],
        body: bytes,
        upstream_credential: tuple[str, str] | None = None,
    ) -> tuple[int, dict[str, str], bytes]:
        """Buffered forward: return (status, headers, body_bytes)."""
        upstream_url = _upstream_url(scheme, host, port, path)
        safe_label = _safe_upstream_label(scheme, host, port, path)
        fwd_headers = _with_upstream_credential(
            self._build_fwd_headers(headers), upstream_credential
        )
        client, owned = self._get_client()
        limit = getattr(
            self,
            "max_buffered_response_bytes",
            DEFAULT_MAX_BUFFERED_RESPONSE_BYTES,
        )
        try:
            with client.stream(
                method, upstream_url, headers=fwd_headers, content=body
            ) as resp:
                response_headers = dict(resp.headers)
                content_lengths = _header_values(resp.headers, "Content-Length")
                transfer_encodings = _header_values(
                    resp.headers, "Transfer-Encoding"
                )
                if content_lengths and transfer_encodings:
                    raise ResponseInspectionError(
                        "Ambiguous upstream response framing"
                    )
                if len(content_lengths) > 1:
                    raise ResponseInspectionError(
                        "Multiple upstream Content-Length headers"
                    )
                if content_lengths:
                    raw_length = content_lengths[0].strip()
                    if not raw_length or "," in raw_length:
                        raise ResponseInspectionError(
                            "Ambiguous upstream Content-Length header"
                        )
                    try:
                        declared_length = int(raw_length, 10)
                    except ValueError as exc:
                        raise ResponseInspectionError(
                            "Invalid upstream Content-Length header"
                        ) from exc
                    if declared_length < 0:
                        raise ResponseInspectionError(
                            "Negative upstream Content-Length header"
                        )
                    if declared_length > limit:
                        raise UpstreamBodyTooLarge(
                            limit,
                            upstream_status=resp.status_code,
                            upstream_headers=response_headers,
                        )

                accumulated = bytearray()
                for chunk in resp.iter_bytes():
                    if not chunk:
                        continue
                    if len(accumulated) + len(chunk) > limit:
                        raise UpstreamBodyTooLarge(
                            limit,
                            upstream_status=resp.status_code,
                            upstream_headers=response_headers,
                        )
                    accumulated.extend(chunk)
                return (
                    resp.status_code,
                    _decoded_body_headers(response_headers, streaming=False),
                    bytes(accumulated),
                )
        except UpstreamBodyTooLarge:
            raise
        except ResponseInspectionError:
            log.exception("Unsafe upstream response framing from %s", safe_label)
            return (
                502,
                {"content-type": "application/json"},
                json.dumps({"error": "Unsafe upstream response framing"}).encode(),
            )
        except httpx.TimeoutException:
            log.error("Upstream timeout: %s %s", method, safe_label)
            return 504, {"content-type": "application/json"}, json.dumps({"error": "Gateway Timeout"}).encode()
        except httpx.ConnectError:
            log.error("Upstream connect error: %s %s", method, safe_label)
            return 502, {"content-type": "application/json"}, json.dumps({"error": "Bad Gateway"}).encode()
        except Exception:
            log.exception("Upstream error: %s %s", method, safe_label)
            return 502, {"content-type": "application/json"}, json.dumps({"error": "Bad Gateway"}).encode()
        finally:
            if owned:
                client.close()

    def _forward_streaming(
        self,
        method: str,
        scheme: str,
        host: str,
        port: int,
        path: str,
        headers: dict[str, str],
        body: bytes,
        upstream_credential: tuple[str, str] | None = None,
    ) -> tuple[int, dict[str, str], bytes, bool]:
        """Relay a stream while keeping a bounded audit capture.

        Sends HTTP status + headers to the client, then streams the body.
        Returns ``(status, headers, accumulated_bytes, audit_truncated)``.
        Truncated bytes are never used for response-side enforcement: any
        enforcement-capable stream takes the bounded pre-delivery path instead.
        """
        upstream_url = _upstream_url(scheme, host, port, path)
        safe_label = _safe_upstream_label(scheme, host, port, path)
        fwd_headers = _with_upstream_credential(
            self._build_fwd_headers(headers), upstream_credential
        )
        accumulated = bytearray()
        audit_truncated = False
        audit_limit = getattr(
            self, "max_audit_stream_bytes", DEFAULT_MAX_AUDIT_STREAM_BYTES
        )
        client, owned = self._get_client()
        response_started = False

        try:
            with client.stream(method, upstream_url, headers=fwd_headers, content=body) as resp:
                # Send status and headers to client (strip Content-Length — unknown)
                resp_headers = _decoded_body_headers(
                    dict(resp.headers), streaming=True
                )
                self.send_response(resp.status_code)
                for k, v in resp_headers.items():
                    self.send_header(k, v)
                self.end_headers()
                response_started = True

                # Stream body
                try:
                    for chunk in resp.iter_bytes():
                        if chunk:
                            if not audit_truncated:
                                remaining = audit_limit - len(accumulated)
                                if remaining > 0:
                                    accumulated.extend(chunk[:remaining])
                                if len(chunk) > remaining:
                                    audit_truncated = True
                            self.wfile.write(chunk)
                    self.wfile.flush()
                except Exception:
                    audit_truncated = True
                    log.exception("Error mid-stream from %s", safe_label)

                return (
                    resp.status_code,
                    resp_headers,
                    bytes(accumulated),
                    audit_truncated,
                )

        except httpx.TimeoutException:
            log.error("Upstream timeout (streaming): %s %s", method, safe_label)
            if not response_started:
                self._send_json_error(504, "Gateway Timeout")
            return 504, {"content-type": "application/json"}, b"", True
        except httpx.ConnectError:
            log.error("Upstream connect error (streaming): %s %s", method, safe_label)
            if not response_started:
                self._send_json_error(502, "Bad Gateway")
            return 502, {"content-type": "application/json"}, b"", True
        except Exception:
            log.exception("Upstream streaming error: %s %s", method, safe_label)
            if not response_started:
                self._send_json_error(502, "Bad Gateway")
            return 502, {"content-type": "application/json"}, b"", True
        finally:
            if owned:
                client.close()

    # ------------------------------------------------------------------
    # Response helpers
    # ------------------------------------------------------------------

    def _send_json_error(self, status: int, message: str, extra: dict | None = None) -> None:
        body: dict[str, Any] = {"error": message}
        if extra:
            body.update(extra)
        body_bytes = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body_bytes)))
        self.end_headers()
        self.wfile.write(body_bytes)

    # ------------------------------------------------------------------
    # Main request handler
    # ------------------------------------------------------------------

    def _handle_request(self, method: str) -> None:
        """Handle a proxied request: parse → pre-flight → forward → post-flight → respond."""
        t0 = time.monotonic()

        # Credential mode: a query-string token must never reach routing,
        # audit records, logs, or the upstream URL.
        provider_keys = getattr(self, "provider_keys", None)
        query_credentials: list[str] = []
        if provider_keys is not None:
            self.path, query_credentials = _strip_query_credentials(self.path)

        # 1. Parse target and read body
        try:
            scheme, host, port, path = self._parse_target()
            req_headers = dict(self.headers.items())
            body = self._read_body()
        except ProxyRequestError as exc:
            self._send_json_error(exc.status_code, str(exc))
            return
        except Exception:
            log.exception("Failed to parse proxy request")
            self.send_error(400, "Bad Request")
            return

        # 1b. Swap the client's Panoptes token for the provider key (fail closed)
        identity: SessionIdentity | None = None
        upstream_credential: tuple[str, str] | None = None
        if provider_keys is not None:
            provider = next(
                p.name for p in _providers.REGISTRY if p.matches_path(path)
            )
            token_store = getattr(self, "token_store", None)
            try:
                if token_store is None:
                    raise TokenRejected("unknown")
                identity = token_store.resolve(
                    _presented_token(provider, self.headers, query_credentials)
                )
            except TokenRejected as exc:
                self._deny_before_upstream(
                    method, path, req_headers, body,
                    status=401,
                    message="A valid Panoptes session token is required",
                    reason=exc.reason,
                )
                return
            provider_key = provider_keys.get(provider)
            if provider_key is None:
                self._deny_before_upstream(
                    method, path, req_headers, body,
                    status=503,
                    message=f"No {provider} provider key is configured in Panoptes",
                    reason="no_provider_key",
                    identity=identity,
                )
                return
            header_name, template = _PROVIDER_KEY_HEADERS[provider]
            upstream_credential = (header_name, template.format(key=provider_key))

        # 2. Parse request body
        req_body: dict | None = None
        if body:
            try:
                req_body = _strict_json_loads(body)
            except (json.JSONDecodeError, ValueError):
                self._send_json_error(
                    400,
                    "Supported provider requests must be unambiguous valid JSON",
                )
                return
            if not isinstance(req_body, dict):
                self._send_json_error(
                    400, "Supported provider requests must contain a JSON object"
                )
                return

        # 3. Build request events and run pre-flight policy check
        writer = self.writer
        req_events: list[dict] = []
        exchange_ctx: dict = {}

        if writer:
            try:
                req_events, exchange_ctx = writer.build_request_events(
                    path=path, method=method, req_headers=req_headers,
                    req_body=req_body, identity=identity,
                )
            except (ValidationError, SSEParseError, ValueError) as exc:
                log.warning("Rejected invalid proxy audit context: %s", exc)
                self._send_json_error(
                    400, "Request metadata cannot be represented safely"
                )
                return
            except Exception as exc:
                failure = _policy_exception_payload(
                    writer, "preflight event construction", exc
                )
                if failure:
                    message, extra = failure
                    self._send_json_error(503, message, extra)
                    return
            if req_events:
                try:
                    policy_result = writer.check_policies(req_events)
                except Exception as exc:
                    _mark_policy_processing_failure(
                        req_events, writer, "preflight", exc
                    )
                    failure = _policy_exception_payload(
                        writer, "preflight", exc
                    )
                    if failure:
                        _mark_preflight_blocked(req_events)
                        try:
                            writer.write(req_events)
                        except AuditWriteError:
                            log.exception(
                                "Fail-closed preflight error audit was not durable"
                            )
                        message, extra = failure
                        self._send_json_error(503, message, extra)
                        return
                else:
                    if policy_result.action == "block":
                        block_msg, extra = _block_payload(policy_result)
                        _mark_preflight_blocked(req_events)
                        try:
                            writer.write(req_events)
                            extra["audit_persisted"] = True
                        except AuditWriteError:
                            log.exception(
                                "Policy block audit was not durable; request remains blocked"
                            )
                            extra["audit_persisted"] = False
                        log.warning("Policy PRE-FLIGHT BLOCK: %s", block_msg)
                        self._send_json_error(403, block_msg, extra)
                        return
                    _log_policy_warnings(policy_result)

                # Make the request intent durable before it leaves the process.
                # Fail-open may continue after a storage outage; fail-closed may not.
                try:
                    writer.write(req_events)
                    exchange_ctx["_request_events_persisted"] = True
                except AuditWriteError:
                    log.exception("Request-intent audit could not be persisted")
                    if writer.policy_failure_mode == "fail_closed":
                        self._send_json_error(
                            503,
                            "Request denied because its audit record could not be persisted",
                            {"audit_error": True},
                        )
                        return

        # 4. Forward to upstream (streaming decided by the provider — body
        #    flag for OpenAI/Anthropic, URL path for Gemini)
        handler = (
            self._handle_streaming
            if _providers.detect(path, req_body).is_streaming(path, req_body)
            else self._handle_buffered
        )
        handler(
            method=method, scheme=scheme, host=host, port=port, path=path,
            req_headers=req_headers, body=body, req_body=req_body,
            req_events=req_events, exchange_ctx=exchange_ctx, t0=t0,
            upstream_credential=upstream_credential,
        )

    def _deny_before_upstream(
        self,
        method: str,
        path: str,
        req_headers: dict[str, str],
        body: bytes,
        *,
        status: int,
        message: str,
        reason: str,
        identity: SessionIdentity | None = None,
    ) -> None:
        """Record and refuse a request that failed credential checks.

        Without a resolved token, identity headers are ignored so an
        unauthenticated caller cannot write into another session's timeline.
        """
        writer = self.writer
        audit_persisted = False
        if writer:
            headers = {
                key: value
                for key, value in req_headers.items()
                if key.lower() not in PANOPTES_INTERNAL_HEADERS
            }
            try:
                req_body = _strict_json_loads(body) if body else None
            except (json.JSONDecodeError, ValueError):
                req_body = None
            if not isinstance(req_body, dict):
                req_body = None
            try:
                try:
                    events, _ = writer.build_request_events(
                        path=path, method=method, req_headers=headers,
                        req_body=req_body, identity=identity,
                    )
                except (ValidationError, SSEParseError, ValueError):
                    events, _ = writer.build_request_events(
                        path=path, method=method, req_headers=headers,
                        req_body=None, identity=identity,
                    )
                events = [
                    event for event in events
                    if event.get("event_type") == "model_request"
                ]
                _mark_preflight_blocked(events)
                for event in events:
                    event["outcome"]["summary"] = f"{message} ({reason})"
                    event["context"]["capture"]["identity_check"] = reason
                writer.write(events)
                audit_persisted = True
            except Exception:
                log.exception("Credential denial audit was not durable")
        log.warning("Denied proxy request before upstream: %s (%s)", message, reason)
        self._send_json_error(
            status, message, {"reason": reason, "audit_persisted": audit_persisted}
        )

    def _handle_streaming(
        self,
        *,
        method: str,
        scheme: str,
        host: str,
        port: int,
        path: str,
        req_headers: dict[str, str],
        body: bytes,
        req_body: dict | None,
        req_events: list[dict],
        exchange_ctx: dict,
        t0: float,
        upstream_credential: tuple[str, str] | None = None,
    ) -> None:
        """Handle a streamed model response.

        Enforcement-enabled streams are buffered so a policy can deny a
        model-issued tool instruction before the agent receives it. Otherwise
        this retains low-latency pass-through streaming and audits post-hoc.
        """
        writer = self.writer
        if writer and writer.requires_stream_buffering:
            # _handle_buffered preserves the upstream SSE content type and
            # payload but intentionally delays delivery until policy checking
            # completes. It is the only safe proxy-level enforcement posture
            # for streamed tool instructions.
            self._handle_buffered(
                method=method, scheme=scheme, host=host, port=port, path=path,
                req_headers=req_headers, body=body, req_body=req_body,
                req_events=req_events, exchange_ctx=exchange_ctx, t0=t0,
                upstream_credential=upstream_credential,
            )
            return

        resp_status, resp_headers_raw, accumulated, audit_truncated = (
            self._forward_streaming(
            method, scheme, host, port, path, req_headers, body,
            upstream_credential,
            )
        )
        duration_ms = int((time.monotonic() - t0) * 1000)

        if not writer:
            return

        resp_body: dict | None = None
        inspection_error: str | None = None
        if audit_truncated:
            inspection_error = (
                "Audit capture limit reached during pass-through streaming; "
                "response was not fully inspected"
            )
        elif accumulated:
            try:
                resp_body = _parse_provider_response(
                    accumulated, resp_headers_raw, exchange_ctx
                )
            except ResponseInspectionError as exc:
                inspection_error = str(exc)

        resp_events: list[dict] = []
        try:
            resp_events = writer.build_response_events(
                path=path, req_body=req_body, resp_status=resp_status,
                resp_headers=resp_headers_raw, resp_body=resp_body,
                duration_ms=duration_ms, exchange_ctx=exchange_ctx,
            )
            if inspection_error:
                _mark_inspection_failure(
                    resp_events,
                    inspection_error,
                    blocked=False,
                    truncated=audit_truncated,
                )
            # Post-flight policy is audit-only here because bytes already left
            # the proxy. Blocking-policy configurations take the buffered path
            # above instead.
            policy_result = writer.check_policies(resp_events)
            writer.write(
                _unpersisted_exchange_events(
                    req_events, resp_events, exchange_ctx
                )
            )
            if policy_result.action == "block":
                log.warning(
                    "Policy BLOCK after pass-through streaming response — bytes already sent; "
                    "violation was recorded but cannot be retroactively enforced."
                )
            else:
                _log_policy_warnings(policy_result)
        except ValidationError as exc:
            message = (
                "Pass-through response produced invalid audit events after delivery"
            )
            log.warning("%s: %s", message, exc)
            try:
                fallback_events = writer.build_response_events(
                    path=path,
                    req_body=req_body,
                    resp_status=resp_status,
                    resp_headers=resp_headers_raw,
                    resp_body=None,
                    duration_ms=duration_ms,
                    exchange_ctx=exchange_ctx,
                )
                _mark_inspection_failure(
                    fallback_events, f"{message}: {exc}", blocked=False
                )
                writer.write(
                    _unpersisted_exchange_events(
                        req_events, fallback_events, exchange_ctx
                    )
                )
            except Exception:
                log.exception("Failed to persist streaming audit fallback")
        except AuditWriteError:
            log.exception(
                "Pass-through response audit was not durable after delivery"
            )
        except Exception as exc:
            if resp_events:
                _mark_policy_processing_failure(
                    resp_events, writer, "streaming postflight", exc
                )
                try:
                    writer.write(
                        _unpersisted_exchange_events(
                            req_events, resp_events, exchange_ctx
                        )
                    )
                except AuditWriteError:
                    log.exception(
                        "Streaming policy-failure audit was not durable"
                    )
            log.exception("Failed to process streaming audit events — continuing")

    def _handle_buffered(
        self,
        *,
        method: str,
        scheme: str,
        host: str,
        port: int,
        path: str,
        req_headers: dict[str, str],
        body: bytes,
        req_body: dict | None,
        req_events: list[dict],
        exchange_ctx: dict,
        t0: float,
        upstream_credential: tuple[str, str] | None = None,
    ) -> None:
        """Buffered path: forward, audit, optionally replace a blocked response."""
        writer = self.writer
        try:
            resp_status, resp_headers_raw, resp_body_bytes = self._forward_request(
                method, scheme, host, port, path, req_headers, body,
                upstream_credential,
            )
        except UpstreamBodyTooLarge as exc:
            duration_ms = int((time.monotonic() - t0) * 1000)
            message = (
                "Upstream response denied because it exceeded the "
                f"{exc.limit}-byte inspection limit"
            )
            if writer:
                resp_events = writer.build_response_events(
                    path=path,
                    req_body=req_body,
                    resp_status=exc.upstream_status or 502,
                    resp_headers=exc.upstream_headers,
                    resp_body=None,
                    duration_ms=duration_ms,
                    exchange_ctx=exchange_ctx,
                )
                _mark_inspection_failure(
                    resp_events, message, blocked=True, truncated=True
                )
                try:
                    writer.write(
                        _unpersisted_exchange_events(
                            req_events, resp_events, exchange_ctx
                        )
                    )
                except AuditWriteError:
                    log.exception(
                        "Oversized-response denial audit was not durable"
                    )
            self._send_json_error(
                502,
                message,
                {"inspection_error": True, "response_too_large": True},
            )
            return

        duration_ms = int((time.monotonic() - t0) * 1000)

        resp_body_parsed: dict | None = None
        inspection_error: str | None = None
        ambiguous_response = False
        if resp_body_bytes:
            try:
                resp_body_parsed = _parse_provider_response(
                    resp_body_bytes, resp_headers_raw, exchange_ctx
                )
            except AmbiguousResponseError as exc:
                inspection_error = str(exc)
                ambiguous_response = True
            except ResponseInspectionError as exc:
                inspection_error = str(exc)

        inspection_required = _response_requires_inspection(
            writer, method, resp_status
        )
        if inspection_required and exchange_ctx.get("req_format") == "unknown":
            inspection_error = (
                "Response format is unsupported and cannot be checked for tool calls"
            )
        if inspection_required and not resp_body_bytes:
            inspection_error = "Successful upstream response body was empty"

        if inspection_error and (inspection_required or ambiguous_response):
            message = (
                "Upstream response denied because it could not be safely inspected"
            )
            resp_events = writer.build_response_events(  # type: ignore[union-attr]
                path=path,
                req_body=req_body,
                resp_status=resp_status,
                resp_headers=resp_headers_raw,
                resp_body=None,
                duration_ms=duration_ms,
                exchange_ctx=exchange_ctx,
            )
            _mark_inspection_failure(
                resp_events,
                f"{message}: {inspection_error}",
                blocked=True,
            )
            resp_status = 502
            resp_body_bytes = json.dumps({
                "error": message,
                "inspection_error": True,
            }).encode()
            resp_headers_raw = {
                "content-type": "application/json",
                "x-panoptes-inspection-blocked": "true",
            }
            try:
                writer.write(  # type: ignore[union-attr]
                    _unpersisted_exchange_events(
                        req_events, resp_events, exchange_ctx
                    )
                )
            except AuditWriteError:
                log.exception(
                    "Uninspectable-response denial audit was not durable"
                )
            inspection_error = None  # denial has already been persisted
            writer = None  # do not run response policies on an opaque body

        if writer:
            resp_events: list[dict] = []
            try:
                resp_events = writer.build_response_events(
                    path=path, req_body=req_body, resp_status=resp_status,
                    resp_headers=resp_headers_raw, resp_body=resp_body_parsed,
                    duration_ms=duration_ms, exchange_ctx=exchange_ctx,
                )
                if inspection_error:
                    _mark_inspection_failure(
                        resp_events, inspection_error, blocked=False
                    )
                # Post-flight policy check — response events only; request
                # events were already checked (and violations recorded)
                # pre-flight, so re-checking them would double-count.
                policy_result = writer.check_policies(resp_events)
                if policy_result.action == "block":
                    block_msg, extra = _block_payload(policy_result)
                    _mark_postflight_blocked(resp_events)
                    log.warning("Policy POST-FLIGHT BLOCK: %s", block_msg)
                    resp_status = 403
                    resp_headers_raw = {
                        "content-type": "application/json",
                        "x-policy-blocked": "true",
                    }
                else:
                    _log_policy_warnings(policy_result)
                try:
                    writer.write(
                        _unpersisted_exchange_events(
                            req_events, resp_events, exchange_ctx
                        )
                    )
                    if policy_result.action == "block":
                        extra["audit_persisted"] = True
                except AuditWriteError:
                    log.exception("Response audit could not be persisted")
                    if policy_result.action == "block":
                        # A storage outage must never turn a block into an allow.
                        extra["audit_persisted"] = False
                    elif writer.policy_failure_mode == "fail_closed":
                        resp_status = 503
                        resp_headers_raw = {
                            "content-type": "application/json",
                            "x-audit-error": "true",
                        }
                        resp_body_bytes = json.dumps({
                            "error": (
                                "Response denied because its audit record "
                                "could not be persisted"
                            ),
                            "audit_error": True,
                        }).encode()
                if policy_result.action == "block":
                    resp_body_bytes = json.dumps({
                        "error": block_msg,
                        **extra,
                    }).encode()
            except ValidationError as exc:
                message = (
                    "Upstream response denied because its audit events were invalid"
                )
                log.warning("%s: %s", message, exc)
                try:
                    fallback_events = writer.build_response_events(
                        path=path,
                        req_body=req_body,
                        resp_status=resp_status,
                        resp_headers=resp_headers_raw,
                        resp_body=None,
                        duration_ms=duration_ms,
                        exchange_ctx=exchange_ctx,
                    )
                    _mark_inspection_failure(
                        fallback_events,
                        f"{message}: {exc}",
                        blocked=True,
                    )
                    writer.write(
                        _unpersisted_exchange_events(
                            req_events, fallback_events, exchange_ctx
                        )
                    )
                except Exception:
                    log.exception(
                        "Failed to persist invalid response audit fallback"
                    )
                resp_status = 502
                resp_body_bytes = json.dumps({
                    "error": message,
                    "inspection_error": True,
                }).encode()
                resp_headers_raw = {
                    "content-type": "application/json",
                    "x-panoptes-inspection-blocked": "true",
                }
            except Exception as exc:
                event_construction_failed = not resp_events
                if event_construction_failed:
                    log.exception(
                        "Response event construction failed; recording an "
                        "explicit incomplete fallback"
                    )
                    failure = (
                        (
                            "Response processing failed; denied by fail-closed mode",
                            {
                                "inspection_error": True,
                                "policy_error": True,
                                "phase": "response_event_construction",
                            },
                        )
                        if writer.policy_failure_mode == "fail_closed"
                        else None
                    )
                    try:
                        resp_events = writer.build_response_events(
                            path=path,
                            req_body=req_body,
                            resp_status=resp_status,
                            resp_headers=resp_headers_raw,
                            resp_body=None,
                            duration_ms=duration_ms,
                            exchange_ctx=exchange_ctx,
                        )
                        _mark_inspection_failure(
                            resp_events,
                            f"Response event construction failed: {exc}",
                            blocked=failure is not None,
                        )
                    except Exception:
                        resp_events = []
                        log.exception(
                            "Failed to build the incomplete response fallback"
                        )
                else:
                    failure = _policy_exception_payload(
                        writer, "postflight", exc
                    )
                if resp_events:
                    _mark_policy_processing_failure(
                        resp_events, writer, "postflight", exc
                    )
                    if failure and not event_construction_failed:
                        _mark_postflight_blocked(resp_events)
                    try:
                        writer.write(
                            _unpersisted_exchange_events(
                                req_events, resp_events, exchange_ctx
                            )
                        )
                    except AuditWriteError:
                        log.exception(
                            "Postflight policy-failure audit was not durable"
                        )
                if failure:
                    message, extra = failure
                    resp_status = 503
                    resp_body_bytes = json.dumps({"error": message, **extra}).encode()
                    resp_headers_raw = {
                        "content-type": "application/json",
                        "x-policy-error": "true",
                    }

        # Send response to client
        self.send_response(resp_status)
        filtered_headers = _decoded_body_headers(
            dict(resp_headers_raw), streaming=False
        )
        filtered_headers = {
            key: value
            for key, value in filtered_headers.items()
            if key.lower() != "content-length"
        }
        for key, val in filtered_headers.items():
            self.send_header(key, val)
        self.send_header("Content-Length", str(len(resp_body_bytes)))
        self.end_headers()
        if method != "HEAD":
            self.wfile.write(resp_body_bytes)

    def do_GET(self) -> None:
        self._handle_request("GET")

    def do_POST(self) -> None:
        self._handle_request("POST")

# ---------------------------------------------------------------------------
# ProxyServer
# ---------------------------------------------------------------------------


class _BoundedThreadingHTTPServer(http.server.ThreadingHTTPServer):
    """Threaded HTTP server with bounded workers and per-client I/O timeout."""

    daemon_threads = True

    def __init__(
        self,
        server_address: tuple[str, int],
        request_handler: type[http.server.BaseHTTPRequestHandler],
        *,
        client_socket_timeout_seconds: float,
        max_concurrent_requests: int,
    ) -> None:
        self.client_socket_timeout_seconds = client_socket_timeout_seconds
        self._request_slots = threading.BoundedSemaphore(max_concurrent_requests)
        super().__init__(server_address, request_handler)

    def get_request(self):
        request, client_address = super().get_request()
        request.settimeout(self.client_socket_timeout_seconds)
        return request, client_address

    def process_request(self, request, client_address) -> None:
        if not self._request_slots.acquire(blocking=False):
            try:
                request.sendall(
                    b"HTTP/1.1 503 Service Unavailable\r\n"
                    b"Connection: close\r\n"
                    b"Content-Type: text/plain\r\n"
                    b"Content-Length: 30\r\n\r\n"
                    b"Proxy request capacity reached"
                )
            except OSError:
                pass
            finally:
                self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._request_slots.release()
            raise

    def process_request_thread(self, request, client_address) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._request_slots.release()


class ProxyServer:
    """Runs a local HTTP proxy server in a background thread."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8081,
        db_path: str = ":memory:",
        policies_dir: str | None = None,
        policy_failure_mode: str = "fail_open",
        max_request_body_bytes: int = DEFAULT_MAX_REQUEST_BODY_BYTES,
        max_buffered_response_bytes: int = DEFAULT_MAX_BUFFERED_RESPONSE_BYTES,
        max_audit_stream_bytes: int = DEFAULT_MAX_AUDIT_STREAM_BYTES,
        max_tool_events_per_exchange: int = DEFAULT_MAX_TOOL_EVENTS_PER_EXCHANGE,
        client_socket_timeout_seconds: float = DEFAULT_CLIENT_SOCKET_TIMEOUT_SECONDS,
        max_concurrent_requests: int = DEFAULT_MAX_CONCURRENT_REQUESTS,
        provider_keys: dict[str, str] | None = None,
    ) -> None:
        if not _is_loopback_bind_host(host):
            raise ValueError(
                f"Refusing non-loopback proxy bind host {host!r}"
            )
        self.host = host
        self.port = port
        self.db_path = db_path
        self.policies_dir = policies_dir
        self.policy_failure_mode = policy_failure_mode
        for value, name in (
            (max_request_body_bytes, "max_request_body_bytes"),
            (max_buffered_response_bytes, "max_buffered_response_bytes"),
            (max_audit_stream_bytes, "max_audit_stream_bytes"),
            (max_tool_events_per_exchange, "max_tool_events_per_exchange"),
            (client_socket_timeout_seconds, "client_socket_timeout_seconds"),
            (max_concurrent_requests, "max_concurrent_requests"),
        ):
            if value <= 0:
                raise ValueError(f"{name} must be positive")
        self.max_request_body_bytes = max_request_body_bytes
        self.max_buffered_response_bytes = max_buffered_response_bytes
        self.max_audit_stream_bytes = max_audit_stream_bytes
        self.max_tool_events_per_exchange = max_tool_events_per_exchange
        self.client_socket_timeout_seconds = client_socket_timeout_seconds
        self.max_concurrent_requests = max_concurrent_requests
        self.provider_keys = dict(provider_keys) if provider_keys is not None else None
        self.token_store: SessionTokenStore | None = None
        self._server: http.server.HTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._db: AuditDB | None = None
        self._http_client: httpx.Client | None = None
        self._tmp_db_path: str | None = None  # set when db_path == ":memory:"
        self.writer: AuditEventWriter | None = None

    def start(self) -> int:
        """Start the proxy in a background thread. Returns the listening port."""
        # ProxyServer maps its ``:memory:`` convenience mode to a disposable
        # file. This is a proxy lifecycle choice; AuditDB itself also supports
        # shared in-memory databases.
        if self.db_path == ":memory:":
            fd, self._tmp_db_path = tempfile.mkstemp(suffix=".panoptes.db")
            os.close(fd)
            actual_db_path = self._tmp_db_path
            log.debug("Using temporary DB for :memory: mode: %s", actual_db_path)
        else:
            actual_db_path = self.db_path

        try:
            self._db = AuditDB(actual_db_path)
            self._http_client = httpx.Client(
                timeout=120.0,
                follow_redirects=False,
                trust_env=False,
            )
            self.writer = AuditEventWriter(
                self._db,
                policies_dir=self.policies_dir,
                policy_failure_mode=self.policy_failure_mode,
                max_tool_events_per_exchange=self.max_tool_events_per_exchange,
            )
            if self.provider_keys is not None:
                self.token_store = SessionTokenStore(self._db)

            _writer = self.writer
            _http_client = self._http_client
            _max_request_body_bytes = self.max_request_body_bytes
            _max_buffered_response_bytes = self.max_buffered_response_bytes
            _max_audit_stream_bytes = self.max_audit_stream_bytes
            _provider_keys = self.provider_keys
            _token_store = self.token_store

            class _ConfiguredHandler(ProxyHandler):
                writer = _writer
                http_client = _http_client
                max_request_body_bytes = _max_request_body_bytes
                max_buffered_response_bytes = _max_buffered_response_bytes
                max_audit_stream_bytes = _max_audit_stream_bytes
                provider_keys = _provider_keys
                token_store = _token_store

            self._server = _BoundedThreadingHTTPServer(
                (self.host, self.port),
                _ConfiguredHandler,
                client_socket_timeout_seconds=self.client_socket_timeout_seconds,
                max_concurrent_requests=self.max_concurrent_requests,
            )
            self.port = self._server.server_address[1]

            self._thread = threading.Thread(
                target=self._server.serve_forever,
                name="panoptes-proxy",
                daemon=True,
            )
            self._thread.start()
        except Exception:
            self._cleanup_resources(start_failed=True)
            raise

        log.info("Panoptes proxy listening on %s:%d", self.host, self.port)
        if self.provider_keys is not None:
            log.info(
                "Credential injection enabled for: %s",
                ", ".join(sorted(self.provider_keys)),
            )
        log.info("Reverse-proxy mode: ANTHROPIC_BASE_URL=http://%s:%d", self.host, self.port)
        log.info("Reverse-proxy mode: OPENAI_BASE_URL=http://%s:%d/v1", self.host, self.port)
        return self.port

    def stop(self) -> None:
        """Stop the proxy server and release resources."""
        self._cleanup_resources(start_failed=False)
        log.info("Panoptes proxy stopped")

    def _cleanup_resources(self, *, start_failed: bool) -> None:
        """Release partially or fully initialized server resources."""
        if self._server is not None:
            if (
                not start_failed
                and self._thread is not None
                and self._thread.is_alive()
            ):
                self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None
        if self._http_client is not None:
            self._http_client.close()
            self._http_client = None
        if self._db is not None:
            self._db.close()
            self._db = None
        self.writer = None
        self.token_store = None
        if self._tmp_db_path is not None:
            try:
                os.unlink(self._tmp_db_path)
            except OSError:
                pass
            self._tmp_db_path = None

    @property
    def events(self) -> list[dict]:
        if self._db is not None:
            return self._db.query()
        return []


# ---------------------------------------------------------------------------
# Public start function (called from panoptes.cli)
# ---------------------------------------------------------------------------


def start_proxy(
    port: int = 8081,
    host: str = "127.0.0.1",
    db_path: str = "~/.panoptes/audit.db",
    policies_dir: str | None = None,
    log_level: str = "INFO",
    policy_failure_mode: str = "fail_open",
    max_request_body_bytes: int = DEFAULT_MAX_REQUEST_BODY_BYTES,
    max_buffered_response_bytes: int = DEFAULT_MAX_BUFFERED_RESPONSE_BYTES,
    max_audit_stream_bytes: int = DEFAULT_MAX_AUDIT_STREAM_BYTES,
    max_tool_events_per_exchange: int = DEFAULT_MAX_TOOL_EVENTS_PER_EXCHANGE,
    client_socket_timeout_seconds: float = DEFAULT_CLIENT_SOCKET_TIMEOUT_SECONDS,
    max_concurrent_requests: int = DEFAULT_MAX_CONCURRENT_REQUESTS,
    provider_keys: dict[str, str] | None = None,
) -> None:
    """Start the audit proxy server (called from panoptes.cli)."""
    logging.basicConfig(
        level=getattr(logging, log_level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    db_path_expanded = os.path.expanduser(db_path)
    # port 0 (or None) lets the OS pick a free port; ProxyServer.start()
    # reads the actual bound port back from the socket.
    port = port or 0

    server = ProxyServer(
        host=host, port=port, db_path=db_path_expanded,
        policies_dir=policies_dir,
        policy_failure_mode=policy_failure_mode,
        max_request_body_bytes=max_request_body_bytes,
        max_buffered_response_bytes=max_buffered_response_bytes,
        max_audit_stream_bytes=max_audit_stream_bytes,
        max_tool_events_per_exchange=max_tool_events_per_exchange,
        client_socket_timeout_seconds=client_socket_timeout_seconds,
        max_concurrent_requests=max_concurrent_requests,
        provider_keys=provider_keys,
    )
    actual_port = server.start()

    print(f"Panoptes proxy running on http://{host}:{actual_port}")
    print(f"Database: {db_path_expanded}")
    if policies_dir:
        print(f"Policies: {policies_dir}")
        print(f"Policy failure mode: {policy_failure_mode}")
    print()
    print("Reverse-proxy mode (recommended — captures HTTPS traffic):")
    print(f"  export ANTHROPIC_BASE_URL=http://{host}:{actual_port}")
    print(f"  export OPENAI_BASE_URL=http://{host}:{actual_port}/v1")
    print()
    if provider_keys is not None:
        print(
            "Credential injection: on for "
            f"{', '.join(sorted(provider_keys))}. Give agents a Panoptes token, "
            "not a provider key:"
        )
        print(
            "  export ANTHROPIC_API_KEY=$(panoptes token issue "
            "--agent claude_code --session <id>)"
        )
        print()
    print("Press Ctrl+C to stop")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        server.stop()
