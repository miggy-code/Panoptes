"""
proxy.py — MITM HTTP forward proxy for agent LLM API traffic.

Intercepts agent LLM API requests/responses and writes normalized audit events
to a SQLite database via the storage module.

Supports OpenAI, Anthropic, and Google (Gemini) API formats.
HTTP-only for v1 (no HTTPS CONNECT tunneling).

Usage:
    panoptes proxy --port 8081 --db-path ./audit.db
"""

from __future__ import annotations

import argparse
import http.server
import json
import logging
import os
import re
import socket
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from http import HTTPStatus
from typing import Any
from urllib.parse import urlparse

import httpx

# ---------------------------------------------------------------------------
# Storage stub — the real AuditDB is built in parallel at panoptes/db.py
# ---------------------------------------------------------------------------

try:
    from panoptes.db import AuditDB
except ImportError:
    AuditDB = None  # type: ignore[assignment,misc]

try:
    from panoptes.policy import PolicyEngine
except ImportError:
    PolicyEngine = None  # type: ignore[assignment,misc]


class _AuditDBStub:
    """In-memory fallback when panoptes.db is not yet available."""

    def __init__(self, _db_path: str = ":memory:") -> None:
        self.events: list[dict] = []

    def insert_event(self, event: dict) -> None:
        self.events.append(event)

    def query(self, _filters: dict | None = None) -> list[dict]:
        return list(self.events)


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

log = logging.getLogger("panoptes")


# ---------------------------------------------------------------------------
# Agent detection
# ---------------------------------------------------------------------------

# Known agent-signalling User-Agent prefixes
_AGENT_UA_PATTERNS: list[tuple[str, str]] = [
    ("claude-code", "claude_code"),
    ("codex", "codex"),
    ("openai-codex", "codex"),
    ("hermes", "hermes"),
    ("antigravity", "antigravity"),
    ("google-code-assist", "antigravity"),
]

# Path-based agent detection
_AGENT_PATH_PATTERNS: list[tuple[str, str]] = [
    (r"/v1beta/models/.*:(?:streamGenerateContent|generateContent)", "antigravity"),
    (r"/v1alpha/models/.*:(?:streamGenerateContent|generateContent)", "antigravity"),
    (r"/v1internal", "antigravity"),
]


def detect_agent_type(
    path: str,
    headers: dict[str, str],
    req_body: dict | None,
) -> str:
    """Detect which agent CLI is making the request.

    Uses a combination of User-Agent header, request path patterns,
    request body format, and model name.
    """
    # 1. User-Agent header (strongest signal)
    user_agent = headers.get("user-agent", headers.get("User-Agent", ""))
    if user_agent:
        ua_lower = user_agent.lower()
        for pattern, agent_type in _AGENT_UA_PATTERNS:
            if pattern in ua_lower:
                return agent_type

    # 2. Path-based detection
    for pattern, agent_type in _AGENT_PATH_PATTERNS:
        if re.search(pattern, path):
            return agent_type

    # 3. Body format + model name detection
    if isinstance(req_body, dict):
        req_format = _detect_format(path, req_body)
        model = str(req_body.get("model", "")).lower()

        if req_format == "anthropic":
            if "hermes" in model:
                return "hermes"
            return "claude_code"

        if req_format == "openai":
            if any(kw in model for kw in ("gpt", "o1", "o3", "o4", "codex")):
                return "codex"
            return "codex"  # default OpenAI-format to codex

        if req_format == "gemini":
            return "antigravity"

    return "unknown"


# ---------------------------------------------------------------------------
# Normalizer: converts provider-specific data to universal audit events
# ---------------------------------------------------------------------------


def _extract_model_request_info(
    req_body: dict | None, req_format: str
) -> dict[str, Any]:
    """Extract model request info from the request body."""
    if not isinstance(req_body, dict):
        return {"messages_count": 0, "tools_count": 0, "stream": False, "model": "unknown"}

    model = req_body.get("model", "unknown")

    # Messages
    messages = req_body.get("messages", [])
    system_prompt = req_body.get("system", req_body.get("system_instruction"))
    if system_prompt:
        messages_count = len(messages) + 1
    else:
        messages_count = len(messages)

    # Tools
    tools = req_body.get("tools", req_body.get("functions"))
    tools_count = len(tools) if isinstance(tools, list) else 0

    # Streaming
    stream = bool(
        req_body.get("stream", False)
        or "streamGenerateContent" in req_format
    )

    return {
        "messages_count": messages_count,
        "tools_count": tools_count,
        "stream": stream,
        "model": model,
    }


def _extract_tool_calls_from_openai(resp_body: dict) -> list[dict]:
    """Extract tool calls from an OpenAI chat completion response."""
    events: list[dict] = []
    choices = resp_body.get("choices", [])
    for choice in choices:
        message = choice.get("message", {})
        tool_calls = message.get("tool_calls", [])
        for tc in tool_calls:
            func = tc.get("function", {})
            events.append({
                "tool_name": func.get("name", "unknown"),
                "parameters": json.loads(func.get("arguments", "{}"))
                if isinstance(func.get("arguments"), str)
                else func.get("arguments", {}),
                "call_id": tc.get("id", ""),
            })
    return events


def _extract_tool_calls_from_anthropic(resp_body: dict) -> list[dict]:
    """Extract tool calls from an Anthropic message response."""
    events: list[dict] = []
    content = resp_body.get("content", [])
    if isinstance(content, str):
        return events
    for block in content:
        if isinstance(block, dict) and block.get("type") == "tool_use":
            events.append({
                "tool_name": block.get("name", "unknown"),
                "parameters": block.get("input", {}),
                "call_id": block.get("id", ""),
            })
    return events


def _extract_tool_results_from_openai(req_body: dict) -> list[dict]:
    """Extract tool results from an OpenAI request's messages array."""
    events: list[dict] = []
    messages = req_body.get("messages", [])
    for msg in messages:
        if msg.get("role") == "tool":
            events.append({
                "tool_name": msg.get("name", "unknown"),
                "result": msg.get("content", ""),
                "call_id": msg.get("tool_call_id", ""),
            })
    return events


def _extract_tool_results_from_anthropic(req_body: dict) -> list[dict]:
    """Extract tool results from an Anthropic request's messages array."""
    events: list[dict] = []
    messages = req_body.get("messages", [])
    for msg in messages:
        content = msg.get("content", [])
        if isinstance(content, list):
            for block in content:
                if isinstance(block, dict) and block.get("type") == "tool_result":
                    events.append({
                        "tool_name": block.get("tool_use_id", "unknown"),
                        "result": block.get("content", ""),
                        "call_id": block.get("tool_use_id", ""),
                    })
    return events


def _extract_usage_openai(resp_body: dict) -> dict:
    """Extract usage from OpenAI response."""
    usage = resp_body.get("usage", {})
    return {
        "tokens_in": usage.get("prompt_tokens", 0),
        "tokens_out": usage.get("completion_tokens", 0),
    }


def _extract_usage_anthropic(resp_body: dict) -> dict:
    """Extract usage from Anthropic response."""
    usage = resp_body.get("usage", {})
    return {
        "tokens_in": usage.get("input_tokens", 0),
        "tokens_out": usage.get("output_tokens", 0),
    }


def _extract_usage_gemini(resp_body: dict) -> dict:
    """Extract usage from Gemini response."""
    usage = resp_body.get("usageMetadata", {})
    return {
        "tokens_in": usage.get("promptTokenCount", 0),
        "tokens_out": usage.get("candidatesTokenCount", 0),
    }


def _detect_format(path: str, req_body: dict | None) -> str:
    """Detect the API format from the request path and body."""
    if not isinstance(req_body, dict):
        # Fall back to path-only detection
        if "/chat/completions" in path:
            return "openai"
        if "/v1/messages" in path:
            return "anthropic"
        if any(p in path for p in ("generateContent", "streamGenerateContent")):
            return "gemini"
        return "unknown"

    # Anthropic: has "system" key at top level OR messages have "content" as list
    if "system" in req_body or (
        isinstance(req_body.get("messages"), list)
        and req_body["messages"]
        and isinstance(req_body["messages"][0].get("content"), list)
    ):
        return "anthropic"

    # OpenAI: messages have "role":"system"/"user" and "content" as string
    if isinstance(req_body.get("messages"), list):
        return "openai"

    # Gemini: has "contents" key
    if "contents" in req_body or "system_instruction" in req_body:
        return "gemini"

    # Path-based fallback
    if "/chat/completions" in path or "/responses" in path:
        return "openai"
    if "/v1/messages" in path:
        return "anthropic"
    if any(p in path for p in ("generateContent", "streamGenerateContent")):
        return "gemini"

    return "unknown"


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

        # Initialize policy engine if policies directory is provided
        self.policy_engine: Any = None
        if policies_dir and PolicyEngine is not None:
            try:
                self.policy_engine = PolicyEngine(policies_dir=policies_dir, db=db)
                log.debug(
                    "Policy engine initialized with %d policies from %s",
                    len(self.policy_engine.policies),
                    policies_dir,
                )
            except Exception:
                log.exception("Failed to initialize policy engine — policies disabled")

    @property
    def session_id(self) -> str:
        if self._session_id is None:
            self._session_id = uuid.uuid4().hex[:16]
        return self._session_id

    def set_session_id(self, sid: str) -> None:
        self._session_id = sid

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
        """Parse request/response, normalize to audit events, and write to DB.

        Returns the list of events written.
        """
        req_format = _detect_format(path, req_body)
        agent_type = detect_agent_type(path, req_headers, req_body)
        req_info = _extract_model_request_info(req_body, req_format)
        events: list[dict] = []

        # Extract session_id from headers if present
        session_id = (
            req_headers.get("x-panoptes-session")
            or req_headers.get("X-Panoptes-Session")
            or self.session_id
        )

        def _base_event(event_type: str) -> dict:
            return {
                "event_id": uuid.uuid4().hex,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "agent": {
                    "type": agent_type,
                    "session_id": session_id,
                    "run_id": uuid.uuid4().hex,
                },
                "event_type": event_type,
                "action": {},
                "outcome": {},
                "context": {},
                "cost": {},
            }

        # --- model_request event ---
        req_event = _base_event("model_request")
        req_event["action"] = {
            "method": method,
            "path": path,
            "model": req_info["model"],
            "messages_count": req_info["messages_count"],
            "tools_count": req_info["tools_count"],
            "streaming": req_info["stream"],
        }
        req_event["outcome"] = {"status": "success"}
        req_event["cost"] = {}
        events.append(req_event)

        # --- model_response event ---
        resp_event = _base_event("model_response")
        resp_event["action"] = {
            "model": req_info["model"],
            "status_code": resp_status,
            "duration_ms": duration_ms,
        }

        # Outcome
        if resp_status < 400:
            resp_event["outcome"] = {"status": "success", "summary": f"HTTP {resp_status}"}
        elif resp_status < 500:
            resp_event["outcome"] = {
                "status": "error",
                "summary": f"Client error HTTP {resp_status}",
            }
        else:
            resp_event["outcome"] = {
                "status": "error",
                "summary": f"Server error HTTP {resp_status}",
            }

        # Cost (tokens)
        if isinstance(resp_body, dict):
            if req_format == "anthropic":
                cost = _extract_usage_anthropic(resp_body)
            elif req_format == "gemini":
                cost = _extract_usage_gemini(resp_body)
            else:
                cost = _extract_usage_openai(resp_body)
            resp_event["cost"] = cost

        events.append(resp_event)

        # --- tool_call events (extracted from response) ---
        if isinstance(resp_body, dict):
            if req_format == "anthropic":
                tool_calls = _extract_tool_calls_from_anthropic(resp_body)
            else:
                tool_calls = _extract_tool_calls_from_openai(resp_body)
            for tc in tool_calls:
                tc_event = _base_event("tool_call")
                tc_event["action"] = {
                    "tool_name": tc["tool_name"],
                    "parameters": tc["parameters"],
                    "target": tc.get("call_id", ""),
                }
                tc_event["outcome"] = {"status": "success", "summary": ""}
                events.append(tc_event)

        # --- tool_result events (extracted from request body) ---
        if isinstance(req_body, dict):
            if req_format == "anthropic":
                tool_results = _extract_tool_results_from_anthropic(req_body)
            else:
                tool_results = _extract_tool_results_from_openai(req_body)
            for tr in tool_results:
                tr_event = _base_event("tool_result")
                tr_event["action"] = {
                    "tool_name": tr.get("tool_name", "unknown"),
                    "target": tr.get("call_id", ""),
                }
                result_str = str(tr.get("result", ""))
                tr_event["outcome"] = {
                    "status": "success",
                    "summary": result_str[:500],
                }
                events.append(tr_event)

        # Write all events to DB
        for event in events:
            try:
                self.db.insert_event(event)
            except Exception:
                log.exception("Failed to write audit event")

        return events

    def check_policies(self, events: list[dict]) -> Any:
        """Check all events against loaded policies.

        Returns a PolicyResult (or stub with action="allow" if no policy engine).
        """
        if not self.policy_engine:
            # No policy engine — allow everything
            return type("_AllowResult", (), {
                "action": "allow",
                "violated_policies": [],
                "warnings": [],
            })()

        # Aggregate results across all events
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

        from panoptes.policy import PolicyResult

        return PolicyResult(
            action=final_action,
            violated_policies=all_violated,
            warnings=all_warnings,
        )


# ---------------------------------------------------------------------------
# HTTP Proxy Handler
# ---------------------------------------------------------------------------

# Hop-by-hop headers we strip when forwarding
HOP_BY_HOP = frozenset({
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
})


def _filter_headers(headers: dict[str, str]) -> dict[str, str]:
    """Remove hop-by-hop headers from a header dict."""
    return {k: v for k, v in headers.items() if k.lower() not in HOP_BY_HOP}


class ProxyHandler(http.server.BaseHTTPRequestHandler):
    """HTTP forward proxy request handler.

    Handles requests from agent CLIs configured to use this proxy
    via HTTP_PROXY / HTTPS_PROXY environment variables.
    """

    # Class-level reference set by ProxyServer
    writer: AuditEventWriter | None = None
    upstream_timeout: float = 120.0

    def log_message(self, fmt: str, *args: Any) -> None:
        log.info(fmt % args)

    def _parse_target(self) -> tuple[str, str, int]:
        """Parse the absolute URL from the proxy request line.

        In forward proxy mode, the request line contains the full URL:
            POST https://api.openai.com/v1/chat/completions HTTP/1.1

        Returns:
            (scheme, host, port, path)
        """
        # self.path is the full URL in proxy mode
        parsed = urlparse(self.path)
        scheme = parsed.scheme or "https"
        host = parsed.hostname or "api.openai.com"
        port = parsed.port or (443 if scheme == "https" else 80)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        return scheme, host, port, path

    def _read_body(self) -> bytes:
        """Read the request body based on Content-Length."""
        content_length = self.headers.get("Content-Length")
        if content_length:
            try:
                length = int(content_length)
                return self.rfile.read(length)
            except (ValueError, OSError):
                return b""
        return b""

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
        """Forward the request to the upstream server using httpx.

        Returns:
            (status_code, response_headers, response_body_bytes)
        """
        upstream_url = f"{scheme}://{host}:{port}{path}"
        fwd_headers = _filter_headers(dict(headers))
        fwd_headers.pop("host", None)
        fwd_headers.pop("Host", None)
        fwd_headers["Accept-Encoding"] = "identity"

        try:
            with httpx.Client(timeout=self.upstream_timeout, follow_redirects=False) as client:
                resp = client.request(
                    method=method,
                    url=upstream_url,
                    headers=fwd_headers,
                    content=body,
                )
                resp_headers = dict(resp.headers)
                resp_body = resp.content
                return resp.status_code, resp_headers, resp_body
        except httpx.TimeoutException:
            log.error(f"Upstream timeout: {method} {upstream_url}")
            return 504, {"content-type": "text/plain"}, b"Gateway Timeout"
        except httpx.ConnectError:
            log.error(f"Upstream connection refused: {method} {upstream_url}")
            return 502, {"content-type": "text/plain"}, b"Bad Gateway"
        except Exception:
            log.exception(f"Upstream error: {method} {upstream_url}")
            return 502, {"content-type": "text/plain"}, b"Bad Gateway"

    def _handle_request(self, method: str) -> None:
        """Handle a single proxied request: parse, forward, capture, respond."""
        t0 = time.monotonic()

        try:
            scheme, host, port, path = self._parse_target()
            req_headers = {k: v for k, v in self.headers.items()}
            body = self._read_body()
        except Exception:
            log.exception("Failed to parse proxy request")
            self.send_error(400, "Bad Request")
            return

        # Parse request body
        req_body: dict | None = None
        if body:
            try:
                req_body = json.loads(body)
            except (json.JSONDecodeError, ValueError):
                req_body = None

        # Forward to upstream
        resp_status, resp_headers, resp_body_bytes = self._forward_request(
            method, scheme, host, port, path, req_headers, body
        )

        duration_ms = int((time.monotonic() - t0) * 1000)

        # Parse response body
        resp_body: dict | None = None
        if resp_body_bytes:
            try:
                resp_body = json.loads(resp_body_bytes)
            except (json.JSONDecodeError, ValueError):
                resp_body = None

        # Write audit events
        events_written: list[dict] = []
        if self.writer:
            try:
                events_written = self.writer.write_events(
                    path=path,
                    method=method,
                    req_headers=req_headers,
                    req_body=req_body,
                    resp_status=resp_status,
                    resp_headers=resp_headers,
                    resp_body=resp_body,
                    duration_ms=duration_ms,
                )
            except Exception:
                log.exception("Failed to write audit events — continuing")

        # Check policies against written events
        if self.writer and events_written:
            try:
                policy_result = self.writer.check_policies(events_written)
                if policy_result.action == "block":
                    # Override response — block the agent from seeing the result
                    messages = [
                        vp.get("message", "Blocked by policy")
                        for vp in policy_result.violated_policies
                    ]
                    block_msg = "; ".join(messages) if messages else "Blocked by policy"
                    log.warning("Policy BLOCK: %s", block_msg)
                    resp_status = 403
                    resp_body_bytes = json.dumps({
                        "error": block_msg,
                        "violated_policies": [
                            vp["policy_name"] for vp in policy_result.violated_policies
                        ],
                    }).encode()
                    resp_headers = {
                        "content-type": "application/json",
                        "x-policy-blocked": "true",
                    }
                elif policy_result.action == "warn":
                    for w in policy_result.warnings:
                        log.warning("Policy warning: %s", w)
            except Exception:
                log.exception("Policy check failed — allowing request through")

        # Send response back to client
        self.send_response(resp_status)
        resp_headers_out = _filter_headers(dict(resp_headers))
        for key, val in resp_headers_out.items():
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
        """CONNECT is not supported in v1 (HTTP-only proxy).

        Return 405 Method Not Allowed so the client falls back.
        """
        self.send_response(405)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"CONNECT tunneling not supported in v1. Use HTTP proxy mode.")


# ---------------------------------------------------------------------------
# ProxyServer
# ---------------------------------------------------------------------------


class ProxyServer:
    """Runs a local HTTP forward proxy server.

    Agent CLIs are configured to route through it via HTTP_PROXY env var.
    The proxy intercepts LLM API requests/responses and writes normalized
    audit events to the SQLite database.
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8081,
        db_path: str = ":memory:",
        policies_dir: str | None = None,
    ) -> None:
        self.host = host
        self.port = port
        self.db_path = db_path
        self.policies_dir = policies_dir
        self._server: http.server.HTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._db: Any = None
        self.writer: AuditEventWriter | None = None

    def start(self) -> int:
        """Start the proxy server in a background thread.

        Returns the actual port the server is listening on.
        """
        # Initialize storage
        if AuditDB is not None:
            self._db = AuditDB(self.db_path)
        else:
            log.warning("panoptes.db not available — using in-memory stub")
            self._db = _AuditDBStub(self.db_path)

        self.writer = AuditEventWriter(self._db, policies_dir=self.policies_dir)

        # Configure the handler class
        class _ConfiguredHandler(ProxyHandler):
            writer = self.writer

        self._server = http.server.ThreadingHTTPServer(
            (self.host, self.port), _ConfiguredHandler
        )
        self.port = self._server.server_address[1]

        self._thread = threading.Thread(
            target=self._server.serve_forever,
            name="panoptes-proxy",
            daemon=True,
        )
        self._thread.start()

        log.info(f"Panoptes proxy listening on {self.host}:{self.port}")
        log.info(f"Configure agents with: export HTTP_PROXY=http://{self.host}:{self.port}")
        log.info(f"                       export HTTPS_PROXY=http://{self.host}:{self.port}")
        return self.port

    def stop(self) -> None:
        """Stop the proxy server."""
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None
        log.info("Panoptes proxy stopped")

    @property
    def events(self) -> list[dict]:
        """Return all captured events (for testing)."""
        if self._db is not None:
            return self._db.query()
        return []


# ---------------------------------------------------------------------------
# CLI (also exported as start_proxy for panoptes.cli integration)
# ---------------------------------------------------------------------------


def start_proxy(
    port: int = 8081,
    db_path: str = "~/.panoptes/audit.db",
    policies_dir: str | None = None,
) -> None:
    """Start the audit proxy server (called from panoptes.cli)."""

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Expand ~ in db_path
    db_path_expanded = os.path.expanduser(db_path)

    port = port if port else _find_free_port()

    server = ProxyServer(
        host="127.0.0.1",
        port=port,
        db_path=db_path_expanded,
        policies_dir=policies_dir,
    )
    actual_port = server.start()

    print(f"Panoptes proxy running on http://127.0.0.1:{actual_port}")
    print(f"Database: {db_path_expanded}")
    if policies_dir:
        print(f"Policies: {policies_dir}")
    print()
    print("Configure your agent to use this proxy:")
    print(f"  export HTTP_PROXY=http://127.0.0.1:{actual_port}")
    print(f"  export HTTPS_PROXY=http://127.0.0.1:{actual_port}")
    print()
    print("Press Ctrl+C to stop")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        server.stop()


def _find_free_port(start: int = 8081, max_attempts: int = 10) -> int:
    """Find a free port starting from `start`."""
    for port in range(start, start + max_attempts):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if s.connect_ex(("127.0.0.1", port)) != 0:
                return port
    return start  # fallback


def main(argv: list[str] | None = None) -> None:
    """CLI entry point for `panoptes proxy`."""

    parser = argparse.ArgumentParser(
        prog="panoptes",
        description="Universal panoptes trail — proxy capture adapter",
    )
    subparsers = parser.add_subparsers(dest="command", help="sub-commands")

    # 'proxy' subcommand
    proxy_parser = subparsers.add_parser("proxy", help="Start the audit proxy server")
    proxy_parser.add_argument(
        "--port",
        type=int,
        default=None,
        help="Port to listen on (default: auto-select from 8081)",
    )
    proxy_parser.add_argument(
        "--host",
        type=str,
        default="127.0.0.1",
        help="Host to bind to (default: 127.0.0.1)",
    )
    proxy_parser.add_argument(
        "--db-path",
        type=str,
        default="audit.db",
        help="Path to SQLite database (default: audit.db)",
    )
    proxy_parser.add_argument(
        "--log-level",
        type=str,
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Log level (default: INFO)",
    )

    args = parser.parse_args(argv)

    if args.command != "proxy":
        parser.print_help()
        sys.exit(1)

    # Configure logging
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Resolve port
    port = args.port if args.port else _find_free_port()

    # Start server
    server = ProxyServer(host=args.host, port=port, db_path=args.db_path)
    actual_port = server.start()

    print(f"Panoptes proxy running on http://{args.host}:{actual_port}")
    print(f"Database: {args.db_path}")
    print()
    print("Configure your agent to use this proxy:")
    print(f"  export HTTP_PROXY=http://{args.host}:{actual_port}")
    print(f"  export HTTPS_PROXY=http://{args.host}:{actual_port}")
    print()
    print("Press Ctrl+C to stop")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        server.stop()


if __name__ == "__main__":
    main()
