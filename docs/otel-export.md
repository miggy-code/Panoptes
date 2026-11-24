# OpenTelemetry export

`panoptes export-otel` sends stored events to an OpenTelemetry collector over
OTLP/HTTP. Use it to see Panoptes events in a tracing tool that you already
run. The SQLite database stays the source of record.

## Install and run

The export needs the `otel` extra:

```bash
pip install 'panoptes-observe[otel]'
```

Export the newest 1,000 events:

```bash
panoptes export-otel --db-path ~/.panoptes/audit.db \
  --endpoint http://127.0.0.1:4318/v1/traces --limit 1000
```

| Option | Meaning |
|---|---|
| `--endpoint` | Required. The full OTLP/HTTP traces URL, including `/v1/traces`. |
| `--limit` | Number of newest events to export, from 1 to 10,000. |
| `--session-id` | Export only this session. |
| `--since`, `--until` | Export only events in this ISO 8601 time range. |

Configure credentials and TLS for the collector with the standard
OpenTelemetry exporter environment variables.

## How events map to spans

Each event becomes one span:

- The span name is `panoptes.observation.<event_type>`.
- The span kind is `INTERNAL`. The span has no parent.
- The span starts at the event timestamp and has zero duration.
- The trace ID and span ID come from a SHA-256 hash of the event ID. The same
  event always gets the same IDs.

Panoptes does not make up parent spans, durations, or execution spans. A
`tool_call` span is still a proposal, with its `pending` status.

Session, run, parent run, exchange, and correlation IDs are span attributes.
They are not trace IDs.

## What the export sends

The export sends only metadata. Each attribute has the `panoptes.` prefix:

- Event ID, event type, and schema version.
- Agent type, session ID, run ID, and parent run ID.
- Correlation ID, exchange ID, and correlation source.
- Model, tool name, call ID, and execution scope.
- Outcome status.
- Token counts and estimated cost.
- Capture fields, such as the adapter, observation boundary, identity
  assurance, and whether Panoptes observed execution.

The export never sends these fields:

- Prompts, raw request bodies, or raw response bodies.
- Tool parameters or tool results.
- User identity, summaries, error text, or headers.
- Free-form `attributes`.

Panoptes also applies its secret redaction to the exported metadata. Metadata
can still be sensitive, for example a session ID. There is no option to export
raw content.

## Delivery

- The export reads the database only. It never migrates the database and never
  extends the hash chain.
- It sends spans in synchronous batches of 128.
- The OpenTelemetry SDK retries transport errors. Panoptes adds no retries.
- When a batch fails, the command stops and exits with a nonzero status. It
  prints how many events the collector acknowledged first.
- A failed batch can still reach the collector.
- A second run of the same command sends the same events again. Stable span
  IDs let a collector remove duplicates, if it supports that.
- The selection and the total count use separate reads. On a database that is
  being written, the two numbers can differ.

The export was tested with a local OTLP/HTTP receiver and the SDK in-memory
exporter. It was not tested with a specific tracing product.

## Why the export is separate from capture

Capture never waits for a collector. If the proxy exported during capture,
a slow or failed collector could delay or lose audit records. A separate,
read-only export keeps capture independent from the collector.
