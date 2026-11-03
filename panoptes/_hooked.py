"""Hook machinery for the reverse proxy (see docs/hooks.md).

The proxy forwards and records; everything that exists only because a hook may
decide lives here: the per-exchange run state, what the forwarding code
observed, and the handler methods that enter an exchange, run
``before_forward``, and settle it for ``after_exchange``. Private to the proxy.
"""

from __future__ import annotations

import copy
import dataclasses
import logging
import socket
import threading
import time
from typing import Any

import httpx

from panoptes.hooks import (
    STATIC_HOP_BY_HOP,
    Exchange,
    Identity,
    OutboundHeaders,
    RequestHeaders,
    reject_response,
)

log = logging.getLogger("panoptes")


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


class AuditWriteError(RuntimeError):
    """Raised when one or more required audit events could not be persisted."""


def _upstream_url(scheme: str, host: str, port: int, path: str) -> str:
    """Build an upstream URL, preserving IPv6 literal authority syntax."""
    authority_host = f"[{host}]" if ":" in host and not host.startswith("[") else host
    return f"{scheme}://{authority_host}:{port}{path}"


def _may_have_reached_upstream(exc: BaseException) -> bool:
    """False only for failures that happen before any request byte is written."""
    return not isinstance(
        exc,
        (
            httpx.ConnectError,
            httpx.ConnectTimeout,
            httpx.PoolTimeout,
            httpx.UnsupportedProtocol,
            httpx.LocalProtocolError,
            httpx.InvalidURL,
        ),
    )


def _start_drain_timer(resp: Any, seconds: float) -> tuple[threading.Timer, threading.Event]:
    """Cut the upstream read after *seconds*, however silent the upstream is.

    A deadline checked only when a chunk arrives is no bound at all: a stalled
    upstream would hold the request slot until the read timeout.
    """
    expired = threading.Event()
    network_stream = resp.extensions.get("network_stream")
    get_extra = getattr(network_stream, "get_extra_info", None)
    sock = get_extra("socket") if callable(get_extra) else None

    def expire() -> None:
        expired.set()
        try:
            if sock is not None:
                sock.shutdown(socket.SHUT_RDWR)
            else:
                resp.close()
        except Exception:
            pass

    timer = threading.Timer(seconds, expire)
    timer.daemon = True
    timer.start()
    return timer, expired


def _answer_if_client_present(handler: Any, status: int, message: str) -> None:
    """Send an error reply; a client that has left must not change the outcome."""
    try:
        handler._send_json_error(status, message)
    except OSError:
        log.warning("Client disconnected before the %s reply was written", status)


def _report_of(handler: Any) -> "_ForwardReport":
    run = getattr(handler, "_run", None)
    return run.report if run is not None else _ForwardReport()


_USAGE_KEYS = ("usage", "usageMetadata", "usage_metadata")


def _provider_reported_usage(resp_body: Any) -> bool:
    """Whether a parsed response carries a usage object of the provider's own."""
    return isinstance(resp_body, dict) and any(
        isinstance(resp_body.get(key), dict) and resp_body.get(key)
        for key in _USAGE_KEYS
    )


@dataclasses.dataclass
class _ForwardReport:
    """What the forwarding code observed, for ``Exchange`` to report."""

    request_sent: bool = False
    answered: bool = False  # the upstream sent a response head
    upstream_status: int | None = None  # the status the upstream itself sent
    upstream_error: bool = False  # no usable upstream response
    body_bytes: int = 0
    client_gone: bool = False


@dataclasses.dataclass
class _ExchangeRun:
    """Proxy-side state of one exchange that entered ``before_forward``."""

    exchange: Exchange
    t0: float
    client_headers: dict
    req_body: dict | None  # the original, never the copy a hook can edit
    seeded_events: list
    seeded_identity: Identity
    events: list
    ctx: dict
    report: _ForwardReport = dataclasses.field(default_factory=_ForwardReport)
    fwd_headers: dict | None = None
    forward_path: str | None = None
    raw_path: str = ""
    entered: bool = False
    finished: bool = False
    outcome: str | None = None
    status: int | None = None
    complete: bool = False
    response_events: list = dataclasses.field(default_factory=list)
    usage: dict = dataclasses.field(default_factory=dict)
    cost_micros: int | None = None


class HookedExchangeMixin:
    """The hook-handling half of ``ProxyHandler``.

    Expects the handler to provide ``hooks``, ``writer``, ``headers``,
    ``_build_fwd_headers`` and ``_send_json_error``.
    """

    # ------------------------------------------------------------------
    # Hook seam (docs/hooks.md)
    # ------------------------------------------------------------------

    def _enter_exchange(
        self,
        *,
        method: str,
        path: str,
        raw_path: str,
        target: tuple[str, str, int],
        req_headers: dict[str, str],
        body: bytes,
        req_body: dict | None,
        req_events: list[dict],
        exchange_ctx: dict,
        query_credentials: list[str],
        t0: float,
    ) -> _ExchangeRun:
        seeded = Identity(
            agent_type=exchange_ctx["agent_type"],
            session_id=exchange_ctx["session_id"],
            run_id=exchange_ctx["run_id"],
        )
        exchange = Exchange(
            exchange_id=exchange_ctx["exchange_id"],
            correlation_id=exchange_ctx["correlation_id"],
            correlation_source=exchange_ctx["correlation_source"],
            provider=exchange_ctx["req_format"],
            upstream_name=self._upstream_name,
            upstream_url=_upstream_url(*target, ""),
            method=method,
            path=path,
            request_headers=RequestHeaders(list(self.headers.items())),
            query_credentials=tuple(query_credentials),
            request_body=body,
            request_json=copy.deepcopy(req_body),
            request_events=copy.deepcopy(req_events),
            identity=seeded,
            outbound_headers=OutboundHeaders(self._build_fwd_headers(req_headers)),
        )
        run = _ExchangeRun(
            exchange=exchange,
            t0=t0,
            client_headers=req_headers,
            req_body=req_body,
            seeded_events=copy.deepcopy(req_events),
            seeded_identity=seeded,
            events=req_events,
            ctx=exchange_ctx,
            forward_path=path,
            raw_path=raw_path,
        )
        self._run = run
        return run

    def _run_before_forward(self, run: _ExchangeRun) -> bool:
        """Run ``before_forward`` and act on its answer. True means forward."""
        exchange = run.exchange
        writer = self.writer
        run.entered = True  # after_exchange is owed from here
        started = time.monotonic()
        failure: Exception | None = None
        reject: tuple[int, bytes, str] | None = None
        try:
            result = self.hooks.before_forward(exchange)
            if result is not None:
                reject = reject_response(result)
        except Exception as exc:
            failure = exc
            log.exception("before_forward raised")
        finally:
            exchange._freeze_identity()
            self._warn_if_slow("before_forward", started)

        events, ctx, outbound = run.events, run.ctx, None
        if failure is None:
            try:
                if exchange._identity_assigned:
                    events, ctx = writer.build_request_events(
                        path=run.ctx["path"],
                        method=exchange.method,
                        req_headers=run.client_headers,
                        req_body=run.req_body,
                        hook_mode=True,
                        hook_identity=exchange.identity,
                        exchange_id=exchange.exchange_id,
                    )
                if reject is None:
                    outbound = self._final_outbound_headers(run)
            except Exception as exc:
                failure = exc
                log.exception("A hook returned an unusable identity or headers")
        if failure is not None:
            self._hook_failed(run, failure)
            return False

        run.events, run.ctx = events, ctx
        if reject is not None:
            status, encoded, reason = reject
            hook = {"action": "reject", "status": status, "reason": reason}
            self._mark_hook_blocked(events, hook)
            self._write_best_effort(events, "Hook rejection audit was not durable")
            run.outcome, run.status = "rejected", status
            self._send_json_bytes(status, encoded)
            return False

        run.fwd_headers = outbound
        if not exchange._drop_query_credentials:
            run.forward_path = run.raw_path
        # The request intent is durable before it leaves the process.
        try:
            writer.write(events)
            ctx["_request_events_persisted"] = True
        except AuditWriteError:
            log.exception("Request-intent audit could not be persisted")
            run.outcome, run.status = "not_forwarded", 503
            self._send_json_error(
                503,
                "Request denied because its audit record could not be persisted",
                {"audit_error": True},
            )
            return False
        return True

    def _final_outbound_headers(self, run: _ExchangeRun) -> dict[str, str]:
        """The hook's headers plus the invariants Panoptes always re-applies."""
        client = {k.lower(): (k, v) for k, v in run.client_headers.items()}
        headers = {
            name: value
            for name, value in run.exchange.outbound_headers.as_dict().items()
            if name.lower() not in STATIC_HOP_BY_HOP
            and name.lower()
            not in ("host", "content-length", "content-type", "accept-encoding")
        }
        if "content-type" in client:
            name, value = client["content-type"]
            headers[name] = value
        headers["Accept-Encoding"] = "identity"
        return headers

    def _hook_failed(self, run: _ExchangeRun, exc: BaseException) -> None:
        """A failing hook never means "forward anyway"."""
        exchange = run.exchange
        exchange._settle(identity=run.seeded_identity)
        events = copy.deepcopy(run.seeded_events)
        run.events = events
        self._mark_hook_blocked(
            events, {"action": "error", "error_type": type(exc).__name__}
        )
        self._write_best_effort(events, "Hook error audit was not durable")
        run.outcome, run.status = "hook_error", 502
        self._send_json_error(502, "The request could not be processed")

    @staticmethod
    def _mark_hook_blocked(events: list[dict], hook: dict) -> None:
        _mark_preflight_blocked(events)
        for event in events:
            event.setdefault("attributes", {})["hook"] = dict(hook)

    def _write_best_effort(self, events: list[dict], message: str) -> None:
        try:
            self.writer.write(events)
        except AuditWriteError:
            log.exception(message)

    def _send_json_bytes(self, status: int, encoded: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def _warn_if_slow(self, hook: str, started: float) -> None:
        elapsed = time.monotonic() - started
        if elapsed > self.hook_slow_seconds:
            log.warning(
                "%s took %.1fs (hook_slow_seconds=%s); a slow hook holds a "
                "request slot",
                hook, elapsed, self.hook_slow_seconds,
            )

    def _set_outcome(self, outcome: str, status: int | None) -> None:
        run = getattr(self, "_run", None)
        if run is not None:
            run.outcome, run.status = outcome, status

    def _note_response(
        self,
        resp_events: list[dict],
        exchange_ctx: dict,
        resp_body: dict | None,
        *,
        read_in_full: bool,
        inspection_error: str | None,
    ) -> None:
        """Record what the response events say, for ``after_exchange``."""
        run = getattr(self, "_run", None)
        if run is None:
            return
        report = run.report
        run.complete = bool(
            report.answered
            and not report.upstream_error
            and read_in_full
            and inspection_error is None
        )
        run.response_events = copy.deepcopy(resp_events)
        # The provider's own word only: nothing for an error reply, a missing
        # response, or a body that carried no usage object.
        ok = (
            report.upstream_status is not None
            and report.upstream_status < 400
            and not report.upstream_error
        )
        if ok and _provider_reported_usage(resp_body):
            for event in resp_events:
                if event.get("event_type") == "model_response":
                    run.usage = {
                        key: value
                        for key, value in (event.get("cost") or {}).items()
                        if key not in ("estimated_usd", "pricing_version")
                        and value is not None
                    }
                    break
        if report.upstream_status is not None:
            run.cost_micros = exchange_ctx.get("cost_micros")

    def _finish_run(self) -> None:
        """Settle the exchange and call ``after_exchange`` exactly once."""
        run = getattr(self, "_run", None)
        if run is None or not run.entered or run.finished:
            return
        run.finished = True
        exchange = run.exchange
        report = run.report
        outcome = run.outcome or "aborted"
        usage = run.usage
        sent = report.request_sent and outcome not in (
            "rejected", "hook_error", "not_forwarded"
        )
        status = run.status
        # What the provider did, not what the client was told: Panoptes may
        # answer 502 to a 200 the provider billed.
        upstream_status = report.upstream_status
        provider_error = upstream_status is not None and upstream_status >= 400
        produced = (
            upstream_status is not None
            and upstream_status < 400
            and report.body_bytes > 0
        ) or (isinstance(usage.get("tokens_out"), int) and usage["tokens_out"] > 0)
        exchange._settle(
            outcome=outcome,
            request_sent=sent,
            produced_output=bool(produced),
            status=status,
            upstream_status=upstream_status,
            complete=bool(run.complete and outcome == "forwarded"),
            response_events=run.response_events,
            usage=usage,
            estimated_usd_micros=run.cost_micros,
            provider_error=bool(provider_error),
            duration_ms=int((time.monotonic() - run.t0) * 1000),
        )
        started = time.monotonic()
        try:
            self.hooks.after_exchange(exchange)
        except Exception as exc:
            log.exception("after_exchange raised")
            try:
                self.writer.write([self.writer.build_hook_error_event(run.ctx, exc)])
            except Exception:
                log.exception("Could not record the after_exchange failure")
        finally:
            self._warn_if_slow("after_exchange", started)
