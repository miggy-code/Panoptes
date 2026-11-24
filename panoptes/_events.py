"""Event construction and persistence for the reverse proxy.

Private to the proxy: how a request and its response become audit events, and
how a provider reply is parsed for them. Nothing here talks to a network.
"""

from __future__ import annotations

import dataclasses
import json
import logging
import uuid
from typing import Any, TypeGuard

import panoptes.providers as _providers
from panoptes.capture import PROXY_CAPABILITIES
from panoptes.hermes_hooks import request_fingerprint as hermes_request_fingerprint
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


def provider_reported_usage(resp_body: Any) -> TypeGuard[dict]:
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


@dataclasses.dataclass(frozen=True)
class ExchangeContext:
    """What every event of one exchange shares: ids, identity, request shape.

    ``AuditEventWriter.build_request_events`` creates it. When a hook assigns
    an identity the writer builds a new context; nothing mutates one.
    """

    exchange_id: str
    run_id: str | None  # a hook-assigned identity may carry none
    session_id: str
    agent_type: str
    provider: str  # the wire protocol, e.g. "anthropic"
    path: str
    model: Any  # as the request named it; client data, not validated
    streaming: bool
    turn_number: int
    correlation_id: str
    correlation_source: str  # "client" (asserted by header) or "proxy"
    parent_run_id: str | None = None
    user: dict[str, str] | None = None
    identity_attr: dict[str, str | None] | None = None  # hook mode only
    identity_assured: bool = False  # a hook asserted the identity


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
    context: ExchangeContext,
) -> dict:
    """Parse a complete provider response or raise ``ResponseInspectionError``."""
    if not raw or not raw.strip():
        raise ResponseInspectionError("successful upstream response body was empty")

    req_format = context.provider
    path = context.path
    streaming = context.streaming
    content_type = _lower_keys(resp_headers).get("content-type", "").lower()
    stripped = raw.lstrip()
    looks_like_sse = "text/event-stream" in content_type or stripped.startswith(
        (b"data:", b"event:", b":")
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
        raise ResponseInspectionError(
            "provider response produced no inspectable object"
        )
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
        self.max_tool_events_per_exchange = max_tool_events_per_exchange

    # ------------------------------------------------------------------
    # Build helpers
    # ------------------------------------------------------------------

    def _capture_metadata(self, streaming: bool) -> dict:
        stream_delivery = "passthrough_audit_only" if streaming else None
        return PROXY_CAPABILITIES.as_context(stream_delivery=stream_delivery)

    def _make_base_event(
        self, event_type: str, context: ExchangeContext, *, streaming: bool
    ) -> dict:
        capture = self._capture_metadata(streaming)
        if context.identity_assured:
            # An embedder asserted this identity; Panoptes cannot know how it
            # was established.
            capture["identity_assurance"] = "hook_asserted"
        if context.correlation_source == "client":
            # A client assertion for joining this exchange to an external journal;
            # it never changes agent type, session, or identity assurance.
            capture["client_correlation_id"] = context.correlation_id
        event: dict[str, Any] = {
            "event_id": uuid.uuid4().hex,
            "timestamp": utcnow_iso(),
            "agent": {"type": context.agent_type, "session_id": context.session_id},
            "event_type": event_type,
            "action": {},
            "outcome": {},
            "context": {
                "turn_number": context.turn_number,
                "capture": capture,
            },
            "cost": {},
            # First-class since schema v5. The capture copy above is kept for
            # readers of earlier events.
            "correlation_id": context.correlation_id,
            # A client may reuse a correlation id across requests; the exchange
            # id is unique to this one and is what joins its events exactly.
            "attributes": {
                "exchange_id": context.exchange_id,
                "correlation_source": context.correlation_source,
            },
        }
        if context.run_id is not None:
            event["agent"]["run_id"] = context.run_id
        if context.parent_run_id is not None:
            event["agent"]["parent_run_id"] = context.parent_run_id
        if context.user:
            event["user"] = dict(context.user)
        if context.identity_attr is not None:
            event["attributes"]["identity"] = dict(context.identity_attr)
        return event

    def build_hook_error_event(
        self, context: ExchangeContext, exc: BaseException
    ) -> dict:
        """The ``panoptes.hook_error`` event for an ``after_exchange`` failure."""
        event = self._make_base_event("panoptes.hook_error", context, streaming=False)
        event["outcome"] = {"status": "error", "summary": "after_exchange raised"}
        event["attributes"].update(
            {
                "hook": "after_exchange",
                "error_type": type(exc).__name__,
                "error": str(redact_secrets(str(exc)))[:500],
            }
        )
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
    ) -> tuple[list[dict], ExchangeContext]:
        """Build request-side audit events (model_request + tool_result).

        Returns the events and the exchange's context. Pass the context to
        ``build_response_events`` so both sides share one identity.

        ``hook_mode`` records how the identity was established; a
        ``hook_identity`` replaces the seeded one wholesale and its ``run_id``
        is never invented. ``exchange_id`` lets a rebuild keep the join key.
        """
        if run_id is None:
            run_id = uuid.uuid4().hex

        provider = _providers.detect(path, req_body)
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
        session_id = _lower_keys(req_headers).get("x-panoptes-session") or run_id
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

        context = ExchangeContext(
            exchange_id=exchange_id,
            run_id=run_id,
            session_id=session_id,
            agent_type=agent_type,
            provider=provider.name,
            path=path,
            model=req_info["model"],
            streaming=req_info["stream"],
            turn_number=turn_number,
            correlation_id=correlation_id,
            correlation_source=correlation_source,
            parent_run_id=parent_run_id,
            user=user,
            identity_attr=identity_attr,
            identity_assured=hook_identity is not None,
        )

        def _base(event_type: str) -> dict:
            return self._make_base_event(
                event_type, context, streaming=context.streaming
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
        messages = req_body.get("messages") if isinstance(req_body, dict) else None
        if (
            path == "/v1/chat/completions"
            and isinstance(messages, list)
            and len(messages) <= 1024
        ):
            req_event["action"]["message_hashes"] = hermes_request_fingerprint(
                {"request_messages": messages}
            )["messages"]
        req_event["outcome"] = {"status": "success"}
        req_event["raw_request"] = _cap_raw(req_body)
        if isinstance(req_event["raw_request"], str) and req_event[
            "raw_request"
        ].endswith("...[truncated]"):
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
                result_status = "error" if tr.get("is_error") is True else "success"
                tr_event["outcome"] = {
                    "status": result_status,
                    "summary": result_str[:500],
                }
                events.append(tr_event)

        normalized_events = [normalize_event(event) for event in events]
        for event in normalized_events:
            validate_event(event)
        return normalized_events, context

    @staticmethod
    def _provider(context: ExchangeContext) -> _providers.Provider:
        return next(
            (p for p in _providers.REGISTRY if p.name == context.provider),
            _providers._UNKNOWN,
        )

    def estimate_cost_micros(
        self, context: ExchangeContext, status: int, body: dict | None
    ) -> int | None:
        """What the response cost in USD micros, or None when unpriced.

        An error reply is not billed. No usage object means no token counts to
        price: unpriced, not free.
        """
        if status >= 400:
            return 0
        if self.pricing is None or not provider_reported_usage(body):
            return None
        usage = self._provider(context).extract_usage(body)
        return self.pricing.cost_micros(context.model, usage)

    def build_response_events(
        self,
        context: ExchangeContext,
        *,
        status: int,
        body: dict | None,
        duration_ms: int,
    ) -> list[dict]:
        """Build response-side audit events (model_response + tool_call)."""
        provider = self._provider(context)

        def _base(event_type: str) -> dict:
            return self._make_base_event(
                event_type, context, streaming=context.streaming
            )

        events: list[dict] = []

        # model_response event
        resp_event = _base("model_response")
        resp_event["action"] = {
            "model": context.model,
            "status_code": status,
            "duration_ms": duration_ms,
        }
        if status < 400:
            resp_event["outcome"] = {
                "status": "success",
                "summary": f"HTTP {status}",
            }
        elif status < 500:
            resp_event["outcome"] = {
                "status": "error",
                "summary": f"Client error HTTP {status}",
            }
        else:
            resp_event["outcome"] = {
                "status": "error",
                "summary": f"Server error HTTP {status}",
            }

        if isinstance(body, dict):
            resp_event["cost"] = provider.extract_usage(body)
        micros = self.estimate_cost_micros(context, status, body)
        if micros is not None and status < 400:
            resp_event["cost"]["estimated_usd"] = micros / 1_000_000
            resp_event["cost"]["pricing_version"] = self.pricing.version

        resp_event["raw_response"] = _cap_raw(body)
        if isinstance(resp_event["raw_response"], str) and resp_event[
            "raw_response"
        ].endswith("...[truncated]"):
            resp_event["context"]["capture"]["raw_response_truncated"] = True
        events.append(resp_event)

        # tool_call events (from response body)
        if isinstance(body, dict):
            tool_calls = provider.extract_tool_calls(body, path=context.path)
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
                    tc_event["action"]["server_result_summary"] = server_result_text[
                        :500
                    ]
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
                    elif execution_scope in {"provider", "server"} and (
                        "result" in tc
                        or provider_status in {"completed", "success", "succeeded"}
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
                    summary = "Model proposed this tool call; local execution was not observed"
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
        req_events, context = self.build_request_events(
            path=path,
            method=method,
            req_headers=req_headers,
            req_body=req_body,
            run_id=run_id,
        )
        resp_events = self.build_response_events(
            context, status=resp_status, body=resp_body, duration_ms=duration_ms
        )
        all_events = req_events + resp_events
        self.write(all_events)
        return all_events
