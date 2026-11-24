"""One proxied exchange, from the client's request to its settlement.

``serve`` reads and routes a request and builds its request events. A
``ProxyExchange`` then takes it through the rest: admit, forward, inspect,
record, deliver, settle. Whether hooks take part is the ``Lifecycle`` that the
server chose once at start. Private to the proxy.
"""

from __future__ import annotations

import dataclasses
import io
import json
import logging
import time
from collections.abc import Callable, Mapping
from email.message import Message
from typing import Any, Protocol

from panoptes._events import (
    AmbiguousResponseError,
    AuditEventWriter,
    AuditWriteError,
    ExchangeContext,
    ResponseInspectionError,
    _mark_inspection_failure,
    _parse_provider_response,
)
from panoptes._forward import (
    Forwarder,
    ForwardReport,
    Outbound,
    StreamSink,
    UpstreamBodyTooLarge,
    UpstreamReply,
    default_outbound_headers,
)
from panoptes._request import ProxyRequest, ProxyRequestError, read_request
from panoptes.hooks import Upstream
from panoptes.providers.base import SSEParseError
from panoptes.schema import ValidationError

log = logging.getLogger("panoptes")

_WITHHELD_AMBIGUOUS = (
    "Upstream response denied because it could not be safely inspected"
)
_WITHHELD_INVALID = "Upstream response denied because its audit events were invalid"
_INVALID_AFTER_DELIVERY = (
    "Pass-through response produced invalid audit events after delivery"
)
_STREAM_NOT_INSPECTED = (
    "Audit capture limit reached during pass-through streaming; "
    "response was not fully inspected"
)


class ClientConnection(StreamSink, Protocol):
    """The client end of one exchange. ``ProxyHandler`` implements it."""

    path: str
    headers: Message
    rfile: io.BufferedIOBase

    def send_reply(self, status: int, headers: Mapping[str, str], body: bytes) -> None:
        """Send a whole reply; the length header is the connection's to set."""

    def end_stream(self) -> None:
        """Half-close after a stream, so the client sees its end now."""


class Lifecycle(Protocol):
    """How one exchange is admitted and settled.

    The server picks one kind when it starts: ``ObservedLifecycle`` without
    hooks, ``HookedLifecycle`` with them. Each exchange gets a fresh instance.
    """

    records_identity_source: bool  # events say whether a hook set the identity
    drain_seconds: float  # how long to keep reading after the client leaves

    def split_query_credentials(self, raw_path: str) -> tuple[str, tuple[str, ...]]:
        """The path to route and record, and any credentials taken out of it."""

    def admit(self, exchange: ProxyExchange) -> Outbound | None:
        """What to forward, or None when the client has already been answered."""

    def note_response(
        self,
        exchange: ProxyExchange,
        events: list[dict],
        body: dict | None,
        *,
        status: int,
        read_in_full: bool,
        inspected: bool,
    ) -> None:
        """See the response events before they are written."""

    def finish(self, exchange: ProxyExchange) -> None:
        """Settle the exchange, however it ended."""


class ObservedLifecycle:
    """No hooks: record the request intent if storage allows, then forward.

    A storage outage is logged; it does not stop the request.
    """

    records_identity_source = False
    drain_seconds = 0.0  # a client that leaves ends the relay

    def split_query_credentials(self, raw_path: str) -> tuple[str, tuple[str, ...]]:
        return raw_path, ()

    def admit(self, exchange: ProxyExchange) -> Outbound | None:
        exchange.record_request_intent()
        request = exchange.request
        return Outbound(default_outbound_headers(request.headers), request.path)

    def note_response(
        self,
        exchange: ProxyExchange,
        events: list[dict],
        body: dict | None,
        *,
        status: int,
        read_in_full: bool,
        inspected: bool,
    ) -> None:
        pass

    def finish(self, exchange: ProxyExchange) -> None:
        pass


@dataclasses.dataclass(frozen=True)
class ProxyConfig:
    """Everything a request handler needs, fixed when the server starts."""

    writer: AuditEventWriter
    forwarder: Forwarder
    upstreams: Mapping[str, tuple[str, Upstream]]
    max_request_body_bytes: int
    new_lifecycle: Callable[[], Lifecycle]


@dataclasses.dataclass(frozen=True)
class _Inspection:
    """What reading the reply body produced."""

    body: dict | None = None
    error: str | None = None
    ambiguous: bool = False  # two readings of one object; never deliver it


def send_json(client: ClientConnection, status: int, payload: dict[str, Any]) -> None:
    client.send_reply(
        status, {"Content-Type": "application/json"}, json.dumps(payload).encode()
    )


def serve(config: ProxyConfig, client: ClientConnection, method: str) -> None:
    """Handle one client request through to its settlement."""
    started = time.monotonic()
    lifecycle = config.new_lifecycle()
    path, query_credentials = lifecycle.split_query_credentials(client.path)
    try:
        request = read_request(
            method=method,
            path=path,
            raw_path=client.path,
            query_credentials=query_credentials,
            headers=client.headers,
            rfile=client.rfile,
            upstreams=config.upstreams,
            max_body_bytes=config.max_request_body_bytes,
        )
    except ProxyRequestError as exc:
        send_json(client, exc.status_code, {"error": str(exc)})
        return
    except Exception:
        log.exception("Failed to parse proxy request")
        send_json(client, 400, {"error": "Bad Request"})
        return

    try:
        events, context = config.writer.build_request_events(
            path=request.path,
            method=method,
            req_headers=request.headers,
            req_body=request.json,
            hook_mode=lifecycle.records_identity_source,
        )
    except (ValidationError, SSEParseError, ValueError) as exc:
        log.warning("Rejected invalid proxy audit context: %s", exc)
        send_json(
            client, 400, {"error": "Request metadata cannot be represented safely"}
        )
        return
    except Exception:
        # Forwarding would leave the exchange unrecorded, so any input that
        # broke event construction could pass unseen.
        log.exception("Request events could not be built")
        send_json(client, 500, {"error": "The request could not be recorded"})
        return

    ProxyExchange(
        config, client, request, context, events, lifecycle, started=started
    ).run()


class ProxyExchange:
    """One recorded request on its way upstream and back.

    The lifecycle may replace ``context`` and ``request_events`` while
    admitting the request (a hook can assign the identity). ``outcome`` and
    ``status`` say how the exchange ended for the client.
    """

    def __init__(
        self,
        config: ProxyConfig,
        client: ClientConnection,
        request: ProxyRequest,
        context: ExchangeContext,
        request_events: list[dict],
        lifecycle: Lifecycle,
        *,
        started: float,
    ) -> None:
        self.config = config
        self.client = client
        self.request = request
        self.context = context
        self.request_events = request_events
        self.lifecycle = lifecycle
        self.started = started
        self.report = ForwardReport()
        self.request_recorded = False
        self.outcome: str | None = None
        self.status: int | None = None

    def run(self) -> None:
        try:
            outbound = self.lifecycle.admit(self)
            if outbound is None:
                return
            if self.context.streaming:
                self._relay_stream(outbound)
            else:
                self._relay_buffered(outbound)
        finally:
            self.lifecycle.finish(self)

    def record_request_intent(self) -> bool:
        """Make the request durable before it leaves the process."""
        try:
            self.config.writer.write(self.request_events)
        except AuditWriteError:
            log.exception("Request-intent audit could not be persisted")
            return False
        self.request_recorded = True
        return True

    def elapsed_ms(self) -> int:
        return int((time.monotonic() - self.started) * 1000)

    # ------------------------------------------------------------------
    # The two ways a reply reaches the client
    # ------------------------------------------------------------------

    def _relay_buffered(self, outbound: Outbound) -> None:
        """Read the whole reply, record it, then deliver it or a denial."""
        request = self.request
        try:
            reply = self.config.forwarder.buffered(
                request.method, request.target, outbound, request.body, self.report
            )
        except UpstreamBodyTooLarge as exc:
            self._refuse_oversized(exc)
            return
        duration_ms = self.elapsed_ms()
        inspection = self._inspect(reply)
        if inspection.ambiguous:
            # Two readings of one object: the client could act on a different
            # one than the audit recorded, so the reply is withheld.
            self._record_failure(
                f"{_WITHHELD_AMBIGUOUS}: {inspection.error}",
                reply.status,
                duration_ms,
                blocked=True,
            )
            reply = _withheld(_WITHHELD_AMBIGUOUS)
        elif not self._record_response(reply, inspection, duration_ms, delivered=False):
            reply = _withheld(_WITHHELD_INVALID)
        self._settle(reply.status)
        self._deliver(reply)

    def _relay_stream(self, outbound: Outbound) -> None:
        """Relay the reply as it arrives, then record what was seen."""
        request = self.request
        reply = self.config.forwarder.stream(
            request.method,
            request.target,
            outbound,
            request.body,
            self.report,
            self.client,
            drain_seconds=self.lifecycle.drain_seconds,
        )
        duration_ms = self.elapsed_ms()
        if reply.relayed:
            self.client.end_stream()
        else:
            self._deliver(reply)  # an upstream failure the client has not seen
        self._settle(reply.status)
        self._record_response(reply, self._inspect(reply), duration_ms, delivered=True)

    # ------------------------------------------------------------------
    # Steps shared by both
    # ------------------------------------------------------------------

    def _inspect(self, reply: UpstreamReply) -> _Inspection:
        if reply.truncated:
            return _Inspection(error=_STREAM_NOT_INSPECTED)
        if not reply.body:
            return _Inspection()
        try:
            return _Inspection(
                body=_parse_provider_response(reply.body, reply.headers, self.context)
            )
        except AmbiguousResponseError as exc:
            return _Inspection(error=str(exc), ambiguous=True)
        except ResponseInspectionError as exc:
            return _Inspection(error=str(exc))

    def _record_response(
        self,
        reply: UpstreamReply,
        inspection: _Inspection,
        duration_ms: int,
        *,
        delivered: bool,
    ) -> bool:
        """Write the response events. False when they were invalid.

        Invalid events leave a failure record instead: blocked when the reply
        has not been ``delivered`` (the caller then withholds it), incomplete
        when it has.
        """
        try:
            events = self.config.writer.build_response_events(
                self.context,
                status=reply.status,
                body=inspection.body,
                duration_ms=duration_ms,
            )
            if inspection.error is not None:
                _mark_inspection_failure(
                    events, inspection.error, blocked=False, truncated=reply.truncated
                )
            self.lifecycle.note_response(
                self,
                events,
                inspection.body,
                status=reply.status,
                read_in_full=not reply.truncated,
                inspected=inspection.error is None,
            )
        except ValidationError as exc:
            message = _INVALID_AFTER_DELIVERY if delivered else _WITHHELD_INVALID
            log.warning("%s: %s", message, exc)
            self._record_failure(
                f"{message}: {exc}", reply.status, duration_ms, blocked=not delivered
            )
            return False
        except Exception as exc:
            log.exception(
                "Response event construction failed; recording an explicit "
                "incomplete fallback"
            )
            self._record_failure(
                f"Response event construction failed: {exc}",
                reply.status,
                duration_ms,
                blocked=False,
            )
            return True
        self._write(events)
        return True

    def _record_failure(
        self,
        message: str,
        status: int,
        duration_ms: int,
        *,
        blocked: bool,
        truncated: bool = False,
    ) -> None:
        """Record a response Panoptes could not inspect or did not deliver."""
        try:
            events = self.config.writer.build_response_events(
                self.context, status=status, body=None, duration_ms=duration_ms
            )
            _mark_inspection_failure(
                events, message, blocked=blocked, truncated=truncated
            )
        except Exception:
            log.exception("Could not build the response failure record")
            return
        self._write(events)

    def _write(self, response_events: list[dict]) -> None:
        """Write response events, with the request's if they are not stored yet."""
        events = (
            response_events
            if self.request_recorded
            else self.request_events + response_events
        )
        try:
            self.config.writer.write(events)
        except AuditWriteError:
            log.exception("Response audit could not be persisted")
            return
        self.request_recorded = True

    def _refuse_oversized(self, exc: UpstreamBodyTooLarge) -> None:
        message = (
            "Upstream response denied because it exceeded the "
            f"{exc.limit}-byte inspection limit"
        )
        self._record_failure(
            message,
            exc.upstream_status or 502,
            self.elapsed_ms(),
            blocked=True,
            truncated=True,
        )
        payload = {
            "error": message,
            "inspection_error": True,
            "response_too_large": True,
        }
        self._settle(502)
        self._deliver(
            UpstreamReply(
                502, {"content-type": "application/json"}, json.dumps(payload).encode()
            )
        )

    def _settle(self, status: int) -> None:
        self.outcome = "upstream_error" if self.report.upstream_error else "forwarded"
        self.status = status

    def _deliver(self, reply: UpstreamReply) -> None:
        try:
            self.client.send_reply(reply.status, reply.headers, reply.body)
        except OSError:
            # What Panoptes read from the upstream does not change because the
            # client has gone.
            log.warning(
                "Client disconnected before the %s reply was written", reply.status
            )


def _withheld(message: str) -> UpstreamReply:
    return UpstreamReply(
        502,
        {"content-type": "application/json", "x-panoptes-inspection-blocked": "true"},
        json.dumps({"error": message, "inspection_error": True}).encode(),
    )
