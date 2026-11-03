"""Event construction and persistence for the reverse proxy.

Private to the proxy: how a request and its response become audit events, and
how a provider reply is parsed for them. Nothing here talks to a network.
"""

from __future__ import annotations

import json
import logging
import uuid
from typing import Any

import panoptes.providers as _providers
from panoptes.capture import PROXY_CAPABILITIES
from panoptes.hooks import Identity
from panoptes.providers.base import (
    SSEParseError,
    _parse_sse_events,
    _strict_json_loads,
)
from panoptes.schema import (
    KNOWN_AGENT_TYPES,
    ValidationError,
    normalize_event,
    redact_secrets,
    utcnow_iso,
    validate_event,
    validate_identifier,
)

log = logging.getLogger("panoptes")

DEFAULT_MAX_TOOL_EVENTS_PER_EXCHANGE = 256
_RAW_MAX = 64 * 1024  # 64 KB cap on stored raw payloads


_USAGE_KEYS = ("usage", "usageMetadata", "usage_metadata")


def provider_reported_usage(resp_body: Any) -> bool:
    """Whether a parsed response carries a usage object of the provider's own."""
    return isinstance(resp_body, dict) and any(
        isinstance(resp_body.get(key), dict) and resp_body.get(key)
        for key in _USAGE_KEYS
    )


class AuditWriteError(RuntimeError):
    """Raised when one or more required audit events could not be persisted."""


class ResponseInspectionError(RuntimeError):
    """Raised when a response cannot be proven safe before delivery."""


class AmbiguousResponseError(ResponseInspectionError):
    """Raised when response JSON has parser-differential ambiguity."""




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
    if declared_agent in KNOWN_AGENT_TYPES:
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


# ---------------------------------------------------------------------------
# AuditEventWriter
# ---------------------------------------------------------------------------


class AuditEventWriter:
    """Build audit events at the model API boundary.

    The proxy observes requests, responses, and model-issued tool instructions.
    It does not observe arbitrary local tool execution after an agent receives a
    model response; its capture metadata makes that boundary explicit.
    """

    def __init__(
        self,
        db: Any,
        max_tool_events_per_exchange: int = DEFAULT_MAX_TOOL_EVENTS_PER_EXCHANGE,
        pricing: Any = None,
    ) -> None:
        if max_tool_events_per_exchange <= 0:
            raise ValueError("max_tool_events_per_exchange must be positive")
        self.db = db
        self.pricing = pricing
        self._session_id: str | None = None
        self.max_tool_events_per_exchange = max_tool_events_per_exchange

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

    def _capture_metadata(self, streaming: bool) -> dict:
        stream_delivery = "passthrough_audit_only" if streaming else None
        return PROXY_CAPABILITIES.as_context(stream_delivery=stream_delivery)

    def _make_base_event(
        self,
        event_type: str,
        *,
        run_id: str | None,
        session_id: str,
        agent_type: str,
        turn_number: int,
        streaming: bool,
        correlation_id: str | None = None,
        correlation_source: str | None = None,
        exchange_id: str | None = None,
        parent_run_id: str | None = None,
        user: dict | None = None,
        identity_attr: dict | None = None,
        identity_assured: bool = False,
    ) -> dict:
        capture = self._capture_metadata(streaming)
        if identity_assured:
            # An embedder asserted this identity; Panoptes cannot know how it
            # was established.
            capture["identity_assurance"] = "hook_asserted"
        if correlation_id is not None and correlation_source == "client":
            # A client assertion for joining this exchange to an external journal;
            # it never changes agent type, session, or identity assurance.
            capture["client_correlation_id"] = correlation_id
        event = {
            "event_id": uuid.uuid4().hex,
            "timestamp": utcnow_iso(),
            "agent": {"type": agent_type, "session_id": session_id},
            "event_type": event_type,
            "action": {},
            "outcome": {},
            "context": {
                "turn_number": turn_number,
                "capture": capture,
            },
            "cost": {},
        }
        if run_id is not None:
            event["agent"]["run_id"] = run_id
        if parent_run_id is not None:
            event["agent"]["parent_run_id"] = parent_run_id
        if user:
            event["user"] = dict(user)
        if correlation_id is not None:
            # First-class since schema v5. The capture copy above is kept for
            # readers of earlier events.
            event["correlation_id"] = correlation_id
        if exchange_id is not None:
            # A client may reuse a correlation id across requests; the exchange
            # id is unique to this one and is what joins its events exactly.
            event["attributes"] = {
                "exchange_id": exchange_id,
                "correlation_source": correlation_source,
            }
            if identity_attr is not None:
                event["attributes"]["identity"] = dict(identity_attr)
        return event

    @staticmethod
    def _base_kwargs(exchange_ctx: dict) -> dict:
        """Event-identity arguments carried by an exchange context."""
        return {
            "run_id": exchange_ctx["run_id"],
            "session_id": exchange_ctx["session_id"],
            "agent_type": exchange_ctx["agent_type"],
            "turn_number": exchange_ctx.get("turn_number", 0),
            "correlation_id": exchange_ctx.get("correlation_id"),
            "correlation_source": exchange_ctx.get("correlation_source"),
            "exchange_id": exchange_ctx.get("exchange_id"),
            "parent_run_id": exchange_ctx.get("parent_run_id"),
            "user": exchange_ctx.get("user"),
            "identity_attr": exchange_ctx.get("identity_attr"),
            "identity_assured": bool(exchange_ctx.get("identity_assured")),
        }

    def build_hook_error_event(self, exchange_ctx: dict, exc: BaseException) -> dict:
        """The ``panoptes.hook_error`` event for an ``after_exchange`` failure."""
        event = self._make_base_event(
            "panoptes.hook_error",
            streaming=False,
            **self._base_kwargs(exchange_ctx),
        )
        event["outcome"] = {"status": "error", "summary": "after_exchange raised"}
        event["attributes"].update({
            "hook": "after_exchange",
            "error_type": type(exc).__name__,
            "error": str(redact_secrets(str(exc)))[:500],
        })
        event = normalize_event(event)
        validate_event(event)
        return event

    def build_request_events(
        self,
        *,
        path: str,
        method: str,
        req_headers: dict[str, str],
        req_body: dict | None,
        run_id: str | None = None,
        hook_mode: bool = False,
        hook_identity: Identity | None = None,
        exchange_id: str | None = None,
    ) -> tuple[list[dict], dict]:
        """Build request-side audit events (model_request + tool_result).

        Returns (events, exchange_ctx). Pass exchange_ctx to build_response_events
        to share run_id, session_id, agent_type, req_format, and turn_number.

        ``hook_mode`` records how the identity was established; a
        ``hook_identity`` replaces the seeded one wholesale and its ``run_id``
        is never invented. ``exchange_id`` lets a rebuild keep the join key.
        """
        if run_id is None:
            run_id = uuid.uuid4().hex

        provider = _providers.detect(path, req_body)
        req_format = provider.name
        agent_type = detect_agent_type(path, req_headers, req_body)
        req_info = provider.extract_request_info(req_body, path=path)
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
            _lower_keys(req_headers).get("x-panoptes-session")
            or self._session_id
            or run_id
        )
        parent_run_id: str | None = None
        user: dict | None = None
        identity_attr: dict | None = None
        if hook_identity is not None:
            agent_type = hook_identity.agent_type
            session_id = hook_identity.session_id
            run_id = hook_identity.run_id
            parent_run_id = hook_identity.parent_run_id
            if hook_identity.user is not None:
                user = {
                    key: value
                    for key, value in (
                        ("id", hook_identity.user.id),
                        ("auth_method", hook_identity.user.auth_method),
                    )
                    if value is not None
                } or None
        if hook_mode:
            identity_attr = {
                "source": "hook" if hook_identity is not None else "seeded",
                "assurance": (
                    hook_identity.assurance if hook_identity is not None else None
                ),
            }
        if exchange_id is None:
            exchange_id = uuid.uuid4().hex
        correlation_id = _lower_keys(req_headers).get("x-panoptes-correlation-id")
        if correlation_id is not None:
            validate_identifier(correlation_id, "correlation_id")
            correlation_source = "client"
        else:
            # Every exchange has a join key. Without a client-asserted one it is
            # the exchange id.
            correlation_id = exchange_id
            correlation_source = "proxy"

        exchange_ctx = {
            "run_id": run_id,
            "session_id": session_id,
            "agent_type": agent_type,
            "path": path,
            "req_format": req_format,
            "req_info": req_info,
            "turn_number": turn_number,
            "correlation_id": correlation_id,
            "correlation_source": correlation_source,
            "exchange_id": exchange_id,
            "parent_run_id": parent_run_id,
            "user": user,
            "identity_attr": identity_attr,
            "identity_assured": hook_identity is not None,
        }

        def _base(event_type: str) -> dict:
            return self._make_base_event(
                event_type, streaming=req_info["stream"],
                **self._base_kwargs(exchange_ctx),
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
            **provider.request_fingerprint(req_body),
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
        # Fill what a caller-built context may omit; a hook-set identity can
        # legitimately carry no run_id, so only a missing key is defaulted.
        exchange_ctx.setdefault("run_id", uuid.uuid4().hex)
        exchange_ctx["session_id"] = exchange_ctx.get("session_id") or self.session_id
        exchange_ctx.setdefault("agent_type", "unknown")

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
            req_info = provider.extract_request_info(req_body, path=path)
            # Streaming can be signalled by the path (Gemini), not just the body;
            # always re-derive it here to match the logic in build_request_events.
            req_info["stream"] = provider.is_streaming(path, req_body)

        def _base(event_type: str) -> dict:
            return self._make_base_event(
                event_type,
                streaming=bool(req_info.get("stream", False)),
                **self._base_kwargs(exchange_ctx),
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
        if resp_status >= 400:
            # An error response from the provider is not billed.
            exchange_ctx["cost_micros"] = 0
        elif self.pricing is not None and provider_reported_usage(resp_body):
            # No usage object means no token counts to price: unpriced, not free.
            micros = self.pricing.cost_micros(req_info["model"], resp_event["cost"])
            if micros is not None:
                resp_event["cost"]["estimated_usd"] = micros / 1_000_000
                resp_event["cost"]["pricing_version"] = self.pricing.version
                exchange_ctx["cost_micros"] = micros

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

