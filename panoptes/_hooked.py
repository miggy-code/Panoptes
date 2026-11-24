"""The hook lifecycle of a proxied exchange (see docs/hooks.md).

``HookedLifecycle`` is the ``Lifecycle`` a server uses when it has
``ProxyHooks``. It builds the ``Exchange`` a hook sees, runs ``before_forward``
and acts on its answer, and settles the exchange for ``after_exchange``
exactly once. Everything that exists only because a hook may decide lives
here. Private to the proxy.
"""

from __future__ import annotations

import copy
import dataclasses
import logging
import time
from collections.abc import Mapping
from enum import Enum, auto
from typing import TYPE_CHECKING

from panoptes._events import AuditWriteError, provider_reported_usage
from panoptes._exchange import send_json
from panoptes._forward import Outbound, default_outbound_headers
from panoptes._request import strip_query_credentials
from panoptes.hooks import (
    QUERY_CREDENTIAL_PARAMS,
    STATIC_HOP_BY_HOP,
    Exchange,
    Identity,
    OutboundHeaders,
    ProxyHooks,
    RequestHeaders,
    reject_response,
)

if TYPE_CHECKING:
    from panoptes._exchange import ProxyExchange

log = logging.getLogger("panoptes")

# Outcomes in which the request never left Panoptes.
_NOT_SENT = ("rejected", "hook_error", "not_forwarded")


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


def _mark_hook_blocked(events: list[dict], hook: dict) -> None:
    _mark_preflight_blocked(events)
    for event in events:
        event.setdefault("attributes", {})["hook"] = dict(hook)


def final_outbound_headers(
    hook_headers: OutboundHeaders, client_headers: Mapping[str, str]
) -> dict[str, str]:
    """The hook's headers plus the invariants Panoptes always re-applies."""
    client = {k.lower(): (k, v) for k, v in client_headers.items()}
    headers = {
        name: value
        for name, value in hook_headers.as_dict().items()
        if name.lower() not in STATIC_HOP_BY_HOP
        and name.lower()
        not in ("host", "content-length", "content-type", "accept-encoding")
    }
    if "content-type" in client:
        name, value = client["content-type"]
        headers[name] = value
    headers["Accept-Encoding"] = "identity"
    return headers


class _HookPhase(Enum):
    PREPARED = auto()
    ENTERED = auto()
    FINISHED = auto()


@dataclasses.dataclass
class _HookRun:
    """What the hooks of one exchange have seen and are owed."""

    exchange: Exchange
    seeded_events: list[dict]  # the request events before any hook acted
    seeded_identity: Identity
    phase: _HookPhase = _HookPhase.PREPARED
    complete: bool = False
    response_events: list[dict] = dataclasses.field(default_factory=list)
    usage: dict = dataclasses.field(default_factory=dict)
    cost_micros: int | None = None

    def enter(self) -> None:
        if self.phase is not _HookPhase.PREPARED:
            raise RuntimeError("before_forward already entered")
        self.phase = _HookPhase.ENTERED

    def claim_finish(self) -> bool:
        if self.phase is not _HookPhase.ENTERED:
            return False
        self.phase = _HookPhase.FINISHED
        return True


class HookedLifecycle:
    """Runs a consumer's ``ProxyHooks`` around one exchange.

    Fails closed: a hook that raises or returns something unusable means the
    request is not forwarded, and so does a request intent that cannot be
    stored.
    """

    records_identity_source = True

    def __init__(
        self, hooks: ProxyHooks, *, slow_seconds: float, drain_seconds: float
    ) -> None:
        self._hooks = hooks
        self._slow_seconds = slow_seconds
        # Hooks are owed usage even if the client leaves.
        self.drain_seconds = drain_seconds
        self._run: _HookRun | None = None

    def split_query_credentials(self, raw_path: str) -> tuple[str, tuple[str, ...]]:
        # Routing and every record use the stripped path. What is forwarded is
        # the hook's choice (Exchange.drop_query_credentials()).
        return strip_query_credentials(raw_path, QUERY_CREDENTIAL_PARAMS, fold=True)

    def admit(self, ex: ProxyExchange) -> Outbound | None:
        exchange = self._new_exchange(ex)
        run = _HookRun(
            exchange=exchange,
            seeded_events=copy.deepcopy(ex.request_events),
            seeded_identity=exchange.identity,
        )
        self._run = run
        run.enter()  # after_exchange is owed from here
        reject, failure = self._before_forward(exchange)

        outbound: Outbound | None = None
        if failure is None:
            try:
                events, context = ex.request_events, ex.context
                if exchange._identity_assigned:
                    events, context = ex.config.writer.build_request_events(
                        path=ex.context.path,
                        method=exchange.method,
                        req_headers=ex.request.headers,
                        req_body=ex.request.json,
                        hook_mode=True,
                        hook_identity=exchange.identity,
                        exchange_id=exchange.exchange_id,
                    )
                if reject is None:
                    outbound = self._outbound(ex, exchange)
                ex.request_events, ex.context = events, context
            except Exception as exc:
                failure = exc
                log.exception("A hook returned an unusable identity or headers")

        if failure is not None:
            self._refuse_after_error(ex, run, failure)
            return None
        if reject is not None:
            self._refuse(ex, reject)
            return None
        if not ex.record_request_intent():
            ex.outcome, ex.status = "not_forwarded", 503
            send_json(
                ex.client,
                503,
                {
                    "error": "Request denied because its audit record could not "
                    "be persisted",
                    "audit_error": True,
                },
            )
            return None
        return outbound

    def note_response(
        self,
        ex: ProxyExchange,
        events: list[dict],
        body: dict | None,
        *,
        status: int,
        read_in_full: bool,
        inspected: bool,
    ) -> None:
        """Keep what ``after_exchange`` reports about the response."""
        run = self._entered()
        report = ex.report
        run.complete = bool(
            report.answered and not report.upstream_error and read_in_full and inspected
        )
        run.response_events = copy.deepcopy(events)
        # The provider's own word only: nothing for an error reply, a missing
        # response, or a body that carried no usage object.
        ok = (
            report.upstream_status is not None
            and report.upstream_status < 400
            and not report.upstream_error
        )
        if ok and provider_reported_usage(body):
            for event in events:
                if event.get("event_type") == "model_response":
                    run.usage = {
                        key: value
                        for key, value in (event.get("cost") or {}).items()
                        if key not in ("estimated_usd", "pricing_version")
                        and value is not None
                    }
                    break
        if report.upstream_status is not None:
            run.cost_micros = ex.config.writer.estimate_cost_micros(
                ex.context, status, body
            )

    def finish(self, ex: ProxyExchange) -> None:
        """Settle the exchange and call ``after_exchange`` exactly once."""
        run = self._run
        if run is None or not run.claim_finish():
            return
        exchange = run.exchange
        report = ex.report
        outcome = ex.outcome or "aborted"
        usage = run.usage
        # What the provider did, not what the client was told: Panoptes may
        # answer 502 to a 200 the provider billed.
        upstream_status = report.upstream_status
        produced = (
            upstream_status is not None
            and upstream_status < 400
            and report.body_bytes > 0
        ) or (isinstance(usage.get("tokens_out"), int) and usage["tokens_out"] > 0)
        exchange._settle(
            outcome=outcome,
            request_sent=report.request_sent and outcome not in _NOT_SENT,
            produced_output=bool(produced),
            status=ex.status,
            upstream_status=upstream_status,
            complete=bool(run.complete and outcome == "forwarded"),
            response_events=run.response_events,
            usage=usage,
            estimated_usd_micros=run.cost_micros,
            provider_error=upstream_status is not None and upstream_status >= 400,
            duration_ms=ex.elapsed_ms(),
        )
        started = time.monotonic()
        try:
            self._hooks.after_exchange(exchange)
        except Exception as exc:
            log.exception("after_exchange raised")
            writer = ex.config.writer
            try:
                writer.write([writer.build_hook_error_event(ex.context, exc)])
            except Exception:
                log.exception("Could not record the after_exchange failure")
        finally:
            self._warn_if_slow("after_exchange", started)

    # ------------------------------------------------------------------

    def _before_forward(
        self, exchange: Exchange
    ) -> tuple[tuple[int, bytes, str] | None, Exception | None]:
        """Ask the hook. Returns its rejection, if any, or what it raised."""
        started = time.monotonic()
        try:
            result = self._hooks.before_forward(exchange)
            return (reject_response(result) if result is not None else None), None
        except Exception as exc:
            log.exception("before_forward raised")
            return None, exc
        finally:
            exchange._freeze_identity()
            self._warn_if_slow("before_forward", started)

    def _new_exchange(self, ex: ProxyExchange) -> Exchange:
        """The ``Exchange`` a hook sees, seeded with what Panoptes derived."""
        context, request = ex.context, ex.request
        return Exchange(
            exchange_id=context.exchange_id,
            correlation_id=context.correlation_id,
            correlation_source=context.correlation_source,
            provider=context.provider,
            upstream_name=request.upstream_name,
            upstream_url=request.target.url(""),
            method=request.method,
            path=request.path,
            request_headers=RequestHeaders(list(request.header_items)),
            query_credentials=request.query_credentials,
            request_body=request.body,
            request_json=copy.deepcopy(request.json),
            request_events=copy.deepcopy(ex.request_events),
            identity=Identity(
                agent_type=context.agent_type,
                session_id=context.session_id,
                run_id=context.run_id,
            ),
            outbound_headers=OutboundHeaders(default_outbound_headers(request.headers)),
        )

    @staticmethod
    def _outbound(ex: ProxyExchange, exchange: Exchange) -> Outbound:
        headers = final_outbound_headers(exchange.outbound_headers, ex.request.headers)
        path = (
            ex.request.path if exchange._drop_query_credentials else ex.request.raw_path
        )
        return Outbound(headers, path)

    def _refuse(self, ex: ProxyExchange, reject: tuple[int, bytes, str]) -> None:
        status, encoded, reason = reject
        events = ex.request_events
        _mark_hook_blocked(
            events, {"action": "reject", "status": status, "reason": reason}
        )
        self._write_best_effort(ex, events, "Hook rejection audit was not durable")
        ex.outcome, ex.status = "rejected", status
        ex.client.send_reply(status, {"Content-Type": "application/json"}, encoded)

    def _refuse_after_error(
        self, ex: ProxyExchange, run: _HookRun, exc: BaseException
    ) -> None:
        """A failing hook never means "forward anyway"."""
        run.exchange._settle(identity=run.seeded_identity)
        events = copy.deepcopy(run.seeded_events)
        _mark_hook_blocked(
            events, {"action": "error", "error_type": type(exc).__name__}
        )
        self._write_best_effort(ex, events, "Hook error audit was not durable")
        ex.outcome, ex.status = "hook_error", 502
        send_json(ex.client, 502, {"error": "The request could not be processed"})

    @staticmethod
    def _write_best_effort(ex: ProxyExchange, events: list[dict], message: str) -> None:
        try:
            ex.config.writer.write(events)
        except AuditWriteError:
            log.exception(message)

    def _entered(self) -> _HookRun:
        if self._run is None:
            raise RuntimeError("the exchange was never admitted")
        return self._run

    def _warn_if_slow(self, hook: str, started: float) -> None:
        elapsed = time.monotonic() - started
        if elapsed > self._slow_seconds:
            log.warning(
                "%s took %.1fs (hook_slow_seconds=%s); a slow hook holds a "
                "request slot",
                hook,
                elapsed,
                self._slow_seconds,
            )
