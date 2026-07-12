"""
proxy.py — HTTP reverse-proxy and forward-proxy for agent LLM API traffic.

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

Forward-proxy mode (HTTP only):
    export HTTP_PROXY=http://127.0.0.1:8081
    (HTTPS CONNECT tunneling not supported — use reverse-proxy mode for HTTPS)

Streaming policy limitation:
    When upstream responds with SSE streaming (content-type: text/event-stream),
    bytes are relayed to the client immediately. If a post-flight policy check
    triggers a BLOCK decision, the response has already been sent and cannot be
    recalled. Panoptes logs a warning and records the violation event but cannot
    retroactively block the streamed response. Pre-flight policy checks (on
    request events) DO block before any bytes are sent.

Usage:
    panoptes proxy --port 8081 --db-path ./audit.db
"""

from __future__ import annotations

import http.server
import json
import logging
import os
import re
import tempfile
import threading
import time
import uuid
from typing import Any
from urllib.parse import urlparse

import httpx

from panoptes.db import AuditDB
from panoptes.policy import PolicyEngine, PolicyResult
from panoptes.schema import redact_secrets, utcnow_iso

import panoptes.providers as _providers
from panoptes.providers.base import _parse_sse_events  # noqa: F401 — re-exported for callers

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

log = logging.getLogger("panoptes")

# ---------------------------------------------------------------------------
# Raw-payload helpers
# ---------------------------------------------------------------------------

_RAW_MAX = 64 * 1024  # 64 KB cap on stored raw payloads


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

_AGENT_PATH_PATTERNS: list[tuple[str, str]] = [
    (r"/v1beta/models/.*:(?:streamGenerateContent|generateContent)", "antigravity"),
    (r"/v1alpha/models/.*:(?:streamGenerateContent|generateContent)", "antigravity"),
    (r"/v1internal", "antigravity"),
]


def _lower_keys(headers: dict[str, str]) -> dict[str, str]:
    """Lowercase header names so lookups are case-insensitive."""
    return {k.lower(): v for k, v in headers.items()}


def detect_agent_type(
    path: str,
    headers: dict[str, str],
    req_body: dict | None,
) -> str:
    user_agent = _lower_keys(headers).get("user-agent", "")
    if user_agent:
        ua_lower = user_agent.lower()
        for pattern, agent_type in _AGENT_UA_PATTERNS:
            if pattern in ua_lower:
                return agent_type

    for pattern, agent_type in _AGENT_PATH_PATTERNS:
        if re.search(pattern, path):
            return agent_type

    if isinstance(req_body, dict):
        provider = _providers.detect(path, req_body)
        model = str(req_body.get("model", "")).lower()

        if provider.name == "anthropic":
            if "hermes" in model:
                return "hermes"
            return "claude_code"

        if provider.name == "openai":
            return "codex"

        if provider.name == "gemini":
            return "antigravity"

    return "unknown"


# ---------------------------------------------------------------------------
# SSE parsing and reassembly
# ---------------------------------------------------------------------------


def _parse_sse_response(raw: bytes, req_format: str) -> dict | None:
    """Parse accumulated SSE bytes into a response dict for auditing."""
    if not raw:
        return None
    for provider in _providers.REGISTRY:
        if provider.name == req_format:
            return provider.reassemble_sse(raw)
    # Unknown format: try SSE then raw JSON
    events = _parse_sse_events(raw)
    if events:
        return events[-1]
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return None


# ---------------------------------------------------------------------------
# AuditEventWriter
# ---------------------------------------------------------------------------


class AuditEventWriter:
    """Normalizes proxy-captured request/response data into universal audit
    events and writes them to the AuditDB storage module. Optionally checks
    events against policy rules before allowing the request through."""

    def __init__(self, db: Any, policies_dir: str | None = None) -> None:
        self.db = db
        self._session_id: str | None = None
        self.policy_engine: Any = None
        if policies_dir:
            try:
                self.policy_engine = PolicyEngine(policies_dir=policies_dir, db=db)
                log.debug("Policy engine initialized with %d policies", len(self.policy_engine.policies))
            except Exception:
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

    def _make_base_event(self, event_type: str, *, run_id: str, session_id: str, agent_type: str, turn_number: int) -> dict:
        return {
            "event_id": uuid.uuid4().hex,
            "timestamp": utcnow_iso(),
            "agent": {"type": agent_type, "session_id": session_id, "run_id": run_id},
            "event_type": event_type,
            "action": {},
            "outcome": {},
            "context": {"turn_number": turn_number},
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
    ) -> tuple[list[dict], dict]:
        """Build request-side audit events (model_request + tool_result).

        Returns (events, exchange_ctx). Pass exchange_ctx to build_response_events
        to share run_id, session_id, agent_type, req_format, and turn_number.
        """
        if run_id is None:
            run_id = uuid.uuid4().hex

        provider = _providers.detect(path, req_body)
        req_format = provider.name
        agent_type = detect_agent_type(path, req_headers, req_body)
        req_info = provider.extract_request_info(req_body)
        # Streaming can be signalled by the path (Gemini), not just the body.
        req_info["stream"] = provider.is_streaming(path, req_body)
        turn_number = provider.estimate_turn_number(req_body)
        session_id = (
            _lower_keys(req_headers).get("x-panoptes-session") or self.session_id
        )

        exchange_ctx = {
            "run_id": run_id,
            "session_id": session_id,
            "agent_type": agent_type,
            "req_format": req_format,
            "req_info": req_info,
            "turn_number": turn_number,
        }

        def _base(event_type: str) -> dict:
            return self._make_base_event(
                event_type, run_id=run_id, session_id=session_id,
                agent_type=agent_type, turn_number=turn_number,
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
        }
        req_event["outcome"] = {"status": "success"}
        req_event["raw_request"] = _cap_raw(req_body)
        events.append(req_event)

        # tool_result events (from request body)
        if isinstance(req_body, dict):
            tool_results = provider.extract_tool_results(req_body)
            for tr in tool_results:
                tr_event = _base("tool_result")
                tr_event["action"] = {
                    "tool_name": tr.get("tool_name", "unknown"),
                    "target": tr.get("call_id", ""),
                    "call_id": tr.get("call_id", ""),
                }
                result_str = str(tr.get("result", ""))
                tr_event["outcome"] = {"status": "success", "summary": result_str[:500]}
                events.append(tr_event)

        return events, exchange_ctx

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

        def _base(event_type: str) -> dict:
            return self._make_base_event(
                event_type, run_id=run_id, session_id=session_id,
                agent_type=agent_type, turn_number=turn_number,
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
        events.append(resp_event)

        # tool_call events (from response body)
        if isinstance(resp_body, dict):
            tool_calls = provider.extract_tool_calls(resp_body)
            for tc in tool_calls:
                tc_event = _base("tool_call")
                tc_event["action"] = {
                    "tool_name": tc["tool_name"],
                    "parameters": tc["parameters"],
                    "target": tc.get("call_id", ""),
                    "call_id": tc.get("call_id", ""),
                }
                tc_event["outcome"] = {"status": "success", "summary": ""}
                events.append(tc_event)

        return events

    # ------------------------------------------------------------------
    # Write and policy helpers
    # ------------------------------------------------------------------

    def write(self, events: list[dict]) -> None:
        """Write a list of audit events to the database."""
        if hasattr(self.db, "insert_events"):
            try:
                self.db.insert_events(events)
                return
            except Exception:
                log.exception("Batch write failed — falling back to per-event writes")
        for event in events:
            try:
                self.db.insert_event(event)
            except Exception:
                log.exception("Failed to write audit event")

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
            return PolicyResult(action="allow", violated_policies=[], warnings=[])

        all_violated: list[dict] = []
        all_warnings: list[str] = []
        final_action = "allow"

        for event in events:
            result = self.policy_engine.check_event(event)
            all_violated.extend(result.violated_policies)
            all_warnings.extend(result.warnings)
            if result.action == "block":
                final_action = "block"
            elif result.action == "warn" and final_action != "block":
                final_action = "warn"

        return PolicyResult(action=final_action, violated_policies=all_violated, warnings=all_warnings)


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


class NoUpstreamError(ValueError):
    """Raised when no upstream can be determined for a reverse-proxy path."""
    pass


def _parse_upstream_url(url: str, default_scheme: str = "https") -> tuple[str, str, int]:
    """Parse a base URL string into (scheme, host, port)."""
    p = urlparse(url)
    scheme = p.scheme or default_scheme
    host = p.hostname or ""
    port = p.port or (443 if scheme == "https" else 80)
    return scheme, host, port


# ---------------------------------------------------------------------------
# HTTP proxy handler
# ---------------------------------------------------------------------------

HOP_BY_HOP = frozenset({
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade",
})


def _filter_headers(headers: dict[str, str]) -> dict[str, str]:
    return {k: v for k, v in headers.items() if k.lower() not in HOP_BY_HOP}


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
    }
    return block_msg, extra


def _log_policy_warnings(policy_result: PolicyResult) -> None:
    if policy_result.action == "warn":
        for w in policy_result.warnings:
            log.warning("Policy warning: %s", w)


class ProxyHandler(http.server.BaseHTTPRequestHandler):
    """HTTP proxy request handler supporting both forward and reverse-proxy modes."""

    writer: AuditEventWriter | None = None
    http_client: httpx.Client | None = None  # shared per-server instance
    upstream_timeout: float = 120.0
    default_upstream: str | None = None  # set by ProxyServer

    def log_message(self, fmt: str, *args: Any) -> None:
        log.info(fmt % args)

    # ------------------------------------------------------------------
    # Target parsing
    # ------------------------------------------------------------------

    def _parse_target(self) -> tuple[str, str, int, str]:
        """Parse the request line into (scheme, host, port, path).

        Forward-proxy mode: self.path is an absolute URL with scheme.
        Reverse-proxy mode: self.path is a relative path; route by pattern.
        """
        parsed = urlparse(self.path)

        # Forward-proxy mode — absolute URL
        if parsed.scheme and parsed.hostname:
            scheme = parsed.scheme
            host = parsed.hostname
            port = parsed.port or (443 if scheme == "https" else 80)
            path = parsed.path or "/"
            if parsed.query:
                path += "?" + parsed.query
            return scheme, host, port, path

        # Reverse-proxy mode — relative path; consult provider registry
        path = self.path

        for provider in _providers.REGISTRY:
            if provider.matches_path(path):
                env_var = _PROVIDER_ENV.get(provider.name)
                env_val = os.environ.get(env_var) if env_var else None
                if env_val:
                    s, h, p = _parse_upstream_url(env_val)
                else:
                    s, h, p = _parse_upstream_url(provider.default_upstream)
                return s, h, p, path

        # Fallback: default_upstream or 502
        default = self.default_upstream
        if not default:
            raise NoUpstreamError(
                f"No upstream route for path '{path}'. "
                f"Set PANOPTES_UPSTREAM_ANTHROPIC / PANOPTES_UPSTREAM_OPENAI / "
                f"PANOPTES_UPSTREAM_GEMINI or use --default-upstream."
            )
        s, h, p = _parse_upstream_url(default)
        return s, h, p, path

    # ------------------------------------------------------------------
    # Request body
    # ------------------------------------------------------------------

    def _read_body(self) -> bytes:
        content_length = self.headers.get("Content-Length")
        if content_length:
            try:
                return self.rfile.read(int(content_length))
            except (ValueError, OSError):
                return b""
        return b""

    # ------------------------------------------------------------------
    # Upstream forwarding
    # ------------------------------------------------------------------

    def _build_fwd_headers(self, headers: dict[str, str]) -> dict[str, str]:
        fwd = _filter_headers(dict(headers))
        fwd.pop("host", None)
        fwd.pop("Host", None)
        fwd["Accept-Encoding"] = "identity"
        return fwd

    def _get_client(self) -> tuple[httpx.Client, bool]:
        """Return (client, owned). If owned=True, caller must close it."""
        if self.http_client is not None:
            return self.http_client, False
        return httpx.Client(timeout=self.upstream_timeout, follow_redirects=False), True

    def _forward_request(
        self,
        method: str,
        scheme: str,
        host: str,
        port: int,
        path: str,
        headers: dict[str, str],
        body: bytes,
    ) -> tuple[int, dict[str, str], bytes]:
        """Buffered forward: return (status, headers, body_bytes)."""
        upstream_url = f"{scheme}://{host}:{port}{path}"
        fwd_headers = self._build_fwd_headers(headers)
        client, owned = self._get_client()
        try:
            resp = client.request(method=method, url=upstream_url, headers=fwd_headers, content=body)
            return resp.status_code, dict(resp.headers), resp.content
        except httpx.TimeoutException:
            log.error("Upstream timeout: %s %s", method, upstream_url)
            return 504, {"content-type": "application/json"}, json.dumps({"error": "Gateway Timeout"}).encode()
        except httpx.ConnectError:
            log.error("Upstream connect error: %s %s", method, upstream_url)
            return 502, {"content-type": "application/json"}, json.dumps({"error": "Bad Gateway"}).encode()
        except Exception:
            log.exception("Upstream error: %s %s", method, upstream_url)
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
    ) -> tuple[int, dict[str, str], bytes]:
        """Streaming forward: relay chunks to client as they arrive, accumulate bytes.

        Sends HTTP status + headers to the client, then streams the body.
        Returns (status, headers, accumulated_bytes) for auditing.
        """
        upstream_url = f"{scheme}://{host}:{port}{path}"
        fwd_headers = self._build_fwd_headers(headers)
        accumulated = bytearray()
        client, owned = self._get_client()

        try:
            with client.stream(method, upstream_url, headers=fwd_headers, content=body) as resp:
                # Send status and headers to client (strip Content-Length — unknown)
                resp_headers = _filter_headers(dict(resp.headers))
                resp_headers.pop("content-length", None)
                self.send_response(resp.status_code)
                for k, v in resp_headers.items():
                    self.send_header(k, v)
                self.end_headers()

                # Stream body
                try:
                    for chunk in resp.iter_bytes():
                        if chunk:
                            accumulated.extend(chunk)
                            self.wfile.write(chunk)
                    self.wfile.flush()
                except Exception:
                    log.exception("Error mid-stream from %s", upstream_url)

                return resp.status_code, dict(resp.headers), bytes(accumulated)

        except httpx.TimeoutException:
            log.error("Upstream timeout (streaming): %s %s", method, upstream_url)
            self._send_json_error(504, "Gateway Timeout")
            return 504, {"content-type": "application/json"}, b""
        except httpx.ConnectError:
            log.error("Upstream connect error (streaming): %s %s", method, upstream_url)
            self._send_json_error(502, "Bad Gateway")
            return 502, {"content-type": "application/json"}, b""
        except Exception:
            log.exception("Upstream streaming error: %s %s", method, upstream_url)
            self._send_json_error(502, "Bad Gateway")
            return 502, {"content-type": "application/json"}, b""
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

        # 1. Parse target and read body
        try:
            scheme, host, port, path = self._parse_target()
            req_headers = dict(self.headers.items())
            body = self._read_body()
        except NoUpstreamError as exc:
            self._send_json_error(502, str(exc))
            return
        except Exception:
            log.exception("Failed to parse proxy request")
            self.send_error(400, "Bad Request")
            return

        # 2. Parse request body
        req_body: dict | None = None
        if body:
            try:
                req_body = json.loads(body)
            except (json.JSONDecodeError, ValueError):
                pass

        # 3. Build request events and run pre-flight policy check
        writer = self.writer
        req_events: list[dict] = []
        exchange_ctx: dict = {}

        if writer:
            try:
                req_events, exchange_ctx = writer.build_request_events(
                    path=path, method=method, req_headers=req_headers,
                    req_body=req_body,
                )
                policy_result = writer.check_policies(req_events)
                if policy_result.action == "block":
                    writer.write(req_events)  # engine already recorded violation
                    block_msg, extra = _block_payload(policy_result)
                    log.warning("Policy PRE-FLIGHT BLOCK: %s", block_msg)
                    self._send_json_error(403, block_msg, extra)
                    return
            except Exception:
                log.exception("Pre-flight policy check failed — allowing request through")

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
    ) -> None:
        """Streaming path: relay chunks to the client, then audit post-hoc.

        The response is sent to the client by _forward_streaming as bytes
        arrive, so post-flight policy can only warn — never block.
        """
        resp_status, resp_headers_raw, accumulated = self._forward_streaming(
            method, scheme, host, port, path, req_headers, body
        )
        duration_ms = int((time.monotonic() - t0) * 1000)

        # Parse accumulated SSE for auditing
        ct = resp_headers_raw.get("content-type", "")
        if "text/event-stream" in ct:
            req_format = exchange_ctx.get("req_format") or _providers.detect(path, req_body).name
            resp_body: dict | None = _parse_sse_response(accumulated, req_format)
        else:
            try:
                resp_body = json.loads(accumulated) if accumulated else None
            except (json.JSONDecodeError, ValueError):
                resp_body = None

        writer = self.writer
        if not writer:
            return
        try:
            resp_events = writer.build_response_events(
                path=path, req_body=req_body, resp_status=resp_status,
                resp_headers=resp_headers_raw, resp_body=resp_body,
                duration_ms=duration_ms, exchange_ctx=exchange_ctx,
            )
            writer.write(req_events + resp_events)

            # Post-flight policy: warn only — bytes already sent
            policy_result = writer.check_policies(resp_events)
            if policy_result.action == "block":
                log.warning(
                    "Policy BLOCK after streaming response — bytes already sent to client; "
                    "violation recorded but cannot be retroactively enforced. "
                    "Use pre-flight request policies to block before forwarding."
                )
            else:
                _log_policy_warnings(policy_result)
        except Exception:
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
    ) -> None:
        """Buffered path: forward, audit, optionally replace a blocked response."""
        resp_status, resp_headers_raw, resp_body_bytes = self._forward_request(
            method, scheme, host, port, path, req_headers, body
        )
        duration_ms = int((time.monotonic() - t0) * 1000)

        resp_body_parsed: dict | None = None
        if resp_body_bytes:
            try:
                resp_body_parsed = json.loads(resp_body_bytes)
            except (json.JSONDecodeError, ValueError):
                pass

        writer = self.writer
        if writer:
            try:
                resp_events = writer.build_response_events(
                    path=path, req_body=req_body, resp_status=resp_status,
                    resp_headers=resp_headers_raw, resp_body=resp_body_parsed,
                    duration_ms=duration_ms, exchange_ctx=exchange_ctx,
                )
                writer.write(req_events + resp_events)

                # Post-flight policy check — response events only; request
                # events were already checked (and violations recorded)
                # pre-flight, so re-checking them would double-count.
                policy_result = writer.check_policies(resp_events)
                if policy_result.action == "block":
                    block_msg, extra = _block_payload(policy_result)
                    log.warning("Policy POST-FLIGHT BLOCK: %s", block_msg)
                    resp_status = 403
                    resp_body_bytes = json.dumps({"error": block_msg, **extra}).encode()
                    resp_headers_raw = {
                        "content-type": "application/json",
                        "x-policy-blocked": "true",
                    }
                else:
                    _log_policy_warnings(policy_result)
            except Exception:
                log.exception("Policy check failed — allowing request through")

        # Send response to client
        self.send_response(resp_status)
        for key, val in _filter_headers(dict(resp_headers_raw)).items():
            self.send_header(key, val)
        self.end_headers()
        self.wfile.write(resp_body_bytes)

    def do_GET(self) -> None:
        self._handle_request("GET")

    def do_POST(self) -> None:
        self._handle_request("POST")

    def do_PUT(self) -> None:
        self._handle_request("PUT")

    def do_DELETE(self) -> None:
        self._handle_request("DELETE")

    def do_PATCH(self) -> None:
        self._handle_request("PATCH")

    def do_HEAD(self) -> None:
        self._handle_request("HEAD")

    def do_OPTIONS(self) -> None:
        self._handle_request("OPTIONS")

    def do_CONNECT(self) -> None:
        """CONNECT tunneling is not supported.

        Use reverse-proxy mode instead — point your agent's base URL at the proxy:
            ANTHROPIC_BASE_URL=http://127.0.0.1:<PORT>
            OPENAI_BASE_URL=http://127.0.0.1:<PORT>/v1
        The proxy forwards over HTTPS to the real upstream without CONNECT tunneling.
        """
        msg = (
            b"CONNECT tunneling not supported. Use reverse-proxy mode:\n"
            b"  ANTHROPIC_BASE_URL=http://127.0.0.1:<PORT>\n"
            b"  OPENAI_BASE_URL=http://127.0.0.1:<PORT>/v1\n"
            b"  GEMINI_API_BASE=http://127.0.0.1:<PORT>\n"
            b"The proxy routes paths to the correct upstream over HTTPS.\n"
        )
        self.send_response(405)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(msg)))
        self.end_headers()
        self.wfile.write(msg)


# ---------------------------------------------------------------------------
# ProxyServer
# ---------------------------------------------------------------------------


class ProxyServer:
    """Runs a local HTTP proxy server in a background thread."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8081,
        db_path: str = ":memory:",
        policies_dir: str | None = None,
        default_upstream: str | None = None,
    ) -> None:
        self.host = host
        self.port = port
        self.db_path = db_path
        self.policies_dir = policies_dir
        self.default_upstream = default_upstream
        self._server: http.server.HTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._db: AuditDB | None = None
        self._http_client: httpx.Client | None = None
        self._tmp_db_path: str | None = None  # set when db_path == ":memory:"
        self.writer: AuditEventWriter | None = None

    def start(self) -> int:
        """Start the proxy in a background thread. Returns the listening port."""
        # Resolve database path — AuditDB cannot use ":memory:" (it calls makedirs)
        if self.db_path == ":memory:":
            fd, self._tmp_db_path = tempfile.mkstemp(suffix=".panoptes.db")
            os.close(fd)
            actual_db_path = self._tmp_db_path
            log.debug("Using temporary DB for :memory: mode: %s", actual_db_path)
        else:
            actual_db_path = self.db_path

        self._db = AuditDB(actual_db_path)
        self._http_client = httpx.Client(timeout=120.0, follow_redirects=False)
        self.writer = AuditEventWriter(self._db, policies_dir=self.policies_dir)

        _writer = self.writer
        _default_upstream = self.default_upstream
        _http_client = self._http_client

        class _ConfiguredHandler(ProxyHandler):
            writer = _writer
            default_upstream = _default_upstream
            http_client = _http_client

        self._server = http.server.ThreadingHTTPServer((self.host, self.port), _ConfiguredHandler)
        self.port = self._server.server_address[1]

        self._thread = threading.Thread(
            target=self._server.serve_forever, name="panoptes-proxy", daemon=True,
        )
        self._thread.start()

        log.info("Panoptes proxy listening on %s:%d", self.host, self.port)
        log.info("Reverse-proxy mode: ANTHROPIC_BASE_URL=http://%s:%d", self.host, self.port)
        log.info("Reverse-proxy mode: OPENAI_BASE_URL=http://%s:%d/v1", self.host, self.port)
        log.info("Forward-proxy mode: HTTP_PROXY=http://%s:%d", self.host, self.port)
        return self.port

    def stop(self) -> None:
        """Stop the proxy server and release resources."""
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None
        if self._http_client is not None:
            self._http_client.close()
            self._http_client = None
        if self._tmp_db_path is not None:
            try:
                os.unlink(self._tmp_db_path)
            except OSError:
                pass
            self._tmp_db_path = None
        log.info("Panoptes proxy stopped")

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
    default_upstream: str | None = None,
    log_level: str = "INFO",
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
        policies_dir=policies_dir, default_upstream=default_upstream,
    )
    actual_port = server.start()

    print(f"Panoptes proxy running on http://{host}:{actual_port}")
    print(f"Database: {db_path_expanded}")
    if policies_dir:
        print(f"Policies: {policies_dir}")
    print()
    print("Reverse-proxy mode (recommended — captures HTTPS traffic):")
    print(f"  export ANTHROPIC_BASE_URL=http://{host}:{actual_port}")
    print(f"  export OPENAI_BASE_URL=http://{host}:{actual_port}/v1")
    print()
    print("Forward-proxy mode (HTTP only):")
    print(f"  export HTTP_PROXY=http://{host}:{actual_port}")
    print(f"  export HTTPS_PROXY=http://{host}:{actual_port}")
    print()
    print("Press Ctrl+C to stop")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        server.stop()
