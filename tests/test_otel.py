"""OTLP mapping and a real HTTP/protobuf receiver, without a backend service."""
import copy
import http.server
import threading

import pytest
from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import ExportTraceServiceRequest
from opentelemetry.sdk.trace.export import SpanExporter, SpanExportResult
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.trace import StatusCode

from panoptes.cli import main
from panoptes.db import AuditDB
from panoptes.otel import ExportError, export_events, observation_span


def event(eid="e1", kind="tool_call"):
    return {
        "event_id": eid, "event_type": kind,
        "timestamp": "2026-07-17T12:00:00.123456Z",
        "agent": {"type": "codex", "session_id": "s2", "run_id": "r3"},
        "correlation_id": "c4", "attributes": {"exchange_id": "x5"},
        "action": {"tool_name": "shell", "parameters": {"command": "PRIVATE COMMAND"}, "call_id": "call6"},
        "outcome": {"status": "pending", "summary": "PRIVATE SUMMARY"},
        "context": {"capture": {"adapter": "http_proxy", "provenance": "adapter_asserted",
                                  "authenticated": False, "execution_observed": False,
                                  "audit_body_truncated": True, "notes": "PRIVATE NOTES"}},
        "raw_payload": {"prompt": "PRIVATE PROMPT"},
    }


def test_metadata_only_stable_observation_preserves_uncertainty_and_correlation():
    raw = event()
    original = copy.deepcopy(raw)
    span = observation_span(raw)
    assert raw == original
    assert span.name == "panoptes.observation.tool_call"
    assert span.parent is None
    assert span.start_time == span.end_time == 1784289600123456000
    assert span.status.status_code == StatusCode.UNSET
    assert span.attributes["panoptes.agent.run_id"] == "r3"
    assert span.attributes["panoptes.correlation_id"] == "c4"
    assert span.attributes["panoptes.exchange_id"] == "x5"
    assert span.attributes["panoptes.capture.execution_observed"] is False
    assert span.attributes["panoptes.capture.audit_body_truncated"] is True
    assert "PRIVATE" not in str(dict(span.attributes))
    assert span.context == observation_span(raw).context
    assert span.context.trace_id != observation_span(event("e2")).context.trace_id


def test_failure_stops_export_and_reports_acknowledged_prefix():
    class RejectSecond(SpanExporter):
        calls = 0
        def export(self, spans):
            self.calls += 1
            return SpanExportResult.SUCCESS if self.calls == 1 else SpanExportResult.FAILURE
    exporter = RejectSecond()
    with pytest.raises(ExportError, match="after 2 acknowledged"):
        export_events((event(str(i)) for i in range(7)), exporter, batch_size=2)
    assert exporter.calls == 2


def test_export_batches_and_maps_errors():
    exporter = InMemorySpanExporter()
    raw = event()
    raw["outcome"]["status"] = "timeout"
    assert export_events([raw, event("e2")], exporter, batch_size=1) == 2
    spans = exporter.get_finished_spans()
    assert len(spans) == 2
    assert spans[0].status.status_code == StatusCode.ERROR


def test_exception_does_not_expose_exporter_details():
    class Broken(SpanExporter):
        def export(self, spans):
            raise RuntimeError("SECRET URL")
    with pytest.raises(ExportError) as exc:
        export_events([event()], Broken())
    assert "SECRET" not in str(exc.value)


@pytest.mark.parametrize("size", [0, True, 10001])
def test_invalid_batch_size(size):
    with pytest.raises(ValueError):
        export_events([], InMemorySpanExporter(), batch_size=size)


def test_cli_exports_bounded_readonly_selection_to_otlp_http(tmp_path, capsys):
    requests = []
    class Receiver(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            requests.append((self.path, self.headers.get("Content-Type"),
                             self.rfile.read(int(self.headers["Content-Length"]))))
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()
        def log_message(self, *args):
            pass
    receiver = http.server.HTTPServer(("127.0.0.1", 0), Receiver)
    thread = threading.Thread(target=receiver.serve_forever)
    path = str(tmp_path / "audit.db")
    db = AuditDB(path)
    try:
        db.insert_events([event("e1"), event("e2"), event("e3")])
        checkpoint = db.get_chain_checkpoint()
    finally:
        db.close()
    thread.start()
    try:
        main(["export-otel", "--db-path", path, "--limit", "2", "--session-id", "s2",
              "--endpoint", f"http://127.0.0.1:{receiver.server_port}/v1/traces"])
    finally:
        receiver.shutdown()
        receiver.server_close()
        thread.join()
    output = capsys.readouterr()
    assert "Selected 2 of 3 matching" in output.err
    assert "acknowledged 2" in output.out
    assert len(requests) == 1
    assert requests[0][:2] == ("/v1/traces", "application/x-protobuf")
    payload = ExportTraceServiceRequest.FromString(requests[0][2])
    spans = payload.resource_spans[0].scope_spans[0].spans
    assert len(spans) == 2
    ids = [next(a.value.string_value for a in span.attributes if a.key == "panoptes.event_id") for span in spans]
    assert ids == ["e2", "e3"]
    assert b"PRIVATE" not in requests[0][2]
    db = AuditDB.open_readonly(path)
    try:
        assert db.get_chain_checkpoint() == checkpoint
    finally:
        db.close()


def test_export_missing_db_does_not_create_it(tmp_path):
    path = tmp_path / "missing.db"
    with pytest.raises(SystemExit) as exc:
        main(["export-otel", "--db-path", str(path), "--endpoint", "http://127.0.0.1:1/v1/traces"])
    assert exc.value.code == 2
    assert not path.exists()


def test_cli_export_failure_exits_nonzero_and_shuts_down(tmp_path, capsys, monkeypatch):
    from opentelemetry.exporter.otlp.proto.http import trace_exporter

    class FailingExporter(SpanExporter):
        closed = False
        def export(self, spans):
            return SpanExportResult.FAILURE
        def shutdown(self):
            self.closed = True
    exporter = FailingExporter()
    monkeypatch.setattr(trace_exporter, "OTLPSpanExporter", lambda **kwargs: exporter)
    path = str(tmp_path / "audit.db")
    db = AuditDB(path)
    try:
        db.insert_event(event())
    finally:
        db.close()
    with pytest.raises(SystemExit) as exc:
        main(["export-otel", "--db-path", path, "--endpoint", "http://127.0.0.1:1/v1/traces"])
    assert exc.value.code == 1
    assert exporter.closed
    output = capsys.readouterr()
    assert "after 0 acknowledged" in output.err
    assert "Receiver acknowledged" not in output.out
