"""Opt-in, metadata-only export of committed audit observations as OTLP spans.

This module requires the ``otel`` extra. It is never loaded by capture/storage.
Each record is a zero-duration root observation: correlation is not parentage.
"""

from datetime import datetime, timezone
import hashlib
from typing import Iterable

from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import ReadableSpan
from opentelemetry.sdk.trace.export import SpanExporter, SpanExportResult
from opentelemetry.trace import SpanContext, SpanKind, Status, StatusCode, TraceFlags

from panoptes.schema import redact_secrets

MAPPING_VERSION = "1"
_CAPTURE_FIELDS = (
    "adapter", "fidelity", "observation_boundary", "identity_assurance",
    "execution_observed", "provenance", "authenticated", "streaming",
    "audit_body_truncated", "inspection_status", "delivery_status",
    "upstream_forwarded", "response_delivered",
)


class ExportError(RuntimeError):
    """A batch was not acknowledged; earlier batches may have been accepted."""


def observation_span(event: dict) -> ReadableSpan:
    """Map one stored record without inventing execution, duration or parentage."""
    attrs = {"panoptes.mapping_version": MAPPING_VERSION}
    fields = {
        "event_id": event["event_id"], "event_type": event["event_type"],
        "agent.type": (event.get("agent") or {}).get("type"),
        "agent.session_id": (event.get("agent") or {}).get("session_id"),
        "agent.run_id": (event.get("agent") or {}).get("run_id"),
        "agent.parent_run_id": (event.get("agent") or {}).get("parent_run_id"),
        "outcome.status": (event.get("outcome") or {}).get("status"),
    }
    context = event.get("context") or {}
    fields["correlation_id"] = event.get("correlation_id")
    fields["schema_version"] = context.get("schema_version")
    for key in ("exchange_id", "correlation_source"):
        fields[key] = (event.get("attributes") or {}).get(key)
    capture = context.get("capture") or {}
    fields.update({f"capture.{key}": capture.get(key) for key in _CAPTURE_FIELDS})
    for key in ("tokens_in", "tokens_out", "estimated_usd"):
        fields[f"cost.{key}"] = (event.get("cost") or {}).get(key)
    fields["action.call_id"] = (event.get("action") or {}).get("call_id")
    for key in ("model", "tool_name", "execution_scope"):
        fields[f"action.{key}"] = (event.get("action") or {}).get(key)
    for key, value in fields.items():
        if isinstance(value, (str, bool, int, float)):
            attrs[f"panoptes.{key}"] = redact_secrets(value)
    timestamp = datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
    if timestamp.tzinfo is None:
        raise ValueError("Export requires a timezone-aware audit timestamp")
    delta = timestamp.astimezone(timezone.utc) - datetime(1970, 1, 1, tzinfo=timezone.utc)
    nanos = ((delta.days * 86400 + delta.seconds) * 1000000 + delta.microseconds) * 1000
    digest = hashlib.sha256(("panoptes.observation.v1:" + event["event_id"]).encode()).digest()
    span_context = SpanContext(
        trace_id=int.from_bytes(digest[:16], "big") or 1,
        span_id=int.from_bytes(digest[16:24], "big") or 1,
        is_remote=False, trace_flags=TraceFlags(TraceFlags.SAMPLED),
    )
    failed = fields["outcome.status"] in ("error", "timeout")
    return ReadableSpan(
        name=f"panoptes.observation.{event['event_type']}",
        context=span_context, parent=None, kind=SpanKind.INTERNAL,
        resource=Resource({"service.name": "panoptes"}),
        attributes=attrs, start_time=nanos, end_time=nanos,
        status=Status(StatusCode.ERROR if failed else StatusCode.UNSET),
    )


def export_events(events: Iterable[dict], exporter: SpanExporter, *, batch_size: int = 128) -> int:
    """Export sequential bounded batches; caller owns exporter shutdown.

    No queue, delivery cursor or automatic application retry. Stable IDs permit
    receiver-side deduplication but do not guarantee it. Failures may be partial.
    """
    if isinstance(batch_size, bool) or not isinstance(batch_size, int) or not 1 <= batch_size <= 10000:
        raise ValueError("batch_size must be between 1 and 10000")
    accepted = 0
    batch = []

    def send() -> None:
        nonlocal accepted
        try:
            result = exporter.export(tuple(batch))
        except Exception:
            raise ExportError(f"Export failed after {accepted} acknowledged observations") from None
        if result is not SpanExportResult.SUCCESS:
            raise ExportError(f"Export failed after {accepted} acknowledged observations")
        accepted += len(batch)
        batch.clear()

    for event in events:
        batch.append(observation_span(event))
        if len(batch) == batch_size:
            send()
    if batch:
        send()
    return accepted
