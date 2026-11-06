# Research: OpenTelemetry and product priorities

**Date:** 2026-11-05  
**Status:** needs-discussion  
**Recommendation:** Validate a narrow opt-in, post-capture OTLP trace export before adding ingestion or a live pipeline. Prioritize capture reliability and a usable incident-review path alongside it.

## Question and criteria

Would OpenTelemetry and ideas from mature observability tools improve Panoptes without weakening its local audit purpose? Compare usefulness, integration effort, fidelity, privacy, reliability and maintenance. This is a documentation review, not a tested integration.

## Options

| Option | Benefit | Cost and risk |
| --- | --- | --- |
| No OTel | Preserves smallest dependency and operational footprint | Users must build their own integrations and visualizations |
| Opt-in offline or explicit export from SQLite | Leverages existing analysis platforms; local record remains canonical | Mapping can be lossy; destinations differ; export can expose sensitive data |
| Live OTLP export | Convenient near-real-time investigation | Delivery, retry, backpressure, duplicate handling and isolation from proxy availability |
| OTLP ingestion | Broader instrumentation coverage | Untrusted external assertions, semantics, schema and collection complexity; not equivalent to observed proxy traffic |

## Proposed export experiment

Use an optional dependency or separate adapter. Read committed normalized events through the read-only API and export to one locally configured OTLP receiver. Test Langfuse or Phoenix before claiming compatibility, then test the other. Start with supported model exchanges, preserve event IDs, session/run/exchange correlation and Panoptes capture boundary, fidelity, provenance, truncation, and outcome in namespaced attributes. Export tool proposals as events, not `execute_tool` spans; only use execution semantics if the source supports that claim. Do not infer parentage or timing beyond recorded evidence. Handle incomplete exchanges explicitly and document what cannot be mapped. Backend-specific semantic mappings and UI treatment must be verified.

Default to metadata only; do not export raw requests, responses, tool parameters or results unless explicitly opted in. Redaction is not complete DLP. Export is a derived view, not a cryptographic extension of SQLite's hash chain. A receiver acknowledgement does not establish end-to-end delivery or storage. Define duplicate/retry and failure reporting before any continuous mode. GenAI conventions are in development; version the mapping and test compatibility. OTel's own guidance recommends opt-in for sensitive model content.

## Other priorities

1. Validate a complete incident-review journey using a real representative capture: routing, an observed request and response, a tool proposal versus reported outcome, unknowns, partial capture, and a separately held checkpoint. Improve CLI output and docs based on actual friction.
2. Expand and validate capture for concrete target harnesses, including session attribution, outcome reporting, bypass and partial-stream cases. Prioritize demand and evidence rather than number of adapters.
3. Make externally retained checkpoints easy to use with a documented workflow and verification; external append-only storage or signing requires a separate threat model and explicit scope.
4. Make capture health and gaps visible: selected counts, truncated/unsupported data, routing assumptions and failed writes. First establish what is already exposed and measure actual failure cases.
5. Consider a small local viewer only if users cannot solve incident review with the CLI or a tested export. Do not duplicate evaluation, prompt management or policy enforcement without demonstrated demand.

## Follow-up

- [ ] Produce a mapping and one-receiver proof of concept with adversarial fixtures for incomplete events, privacy, correlation and proposed versus executed tools.
- [ ] Test the rendered result and attribute retention in each intended backend, including duplicates and export failures.
- [ ] Define success for a representative incident review and checkpoint workflow before expanding scope.

No implementation or adoption decision has been made; these are proposals, not filed issues.

## Sources

- [Panoptes API](../api.md), [README](../../README.md), [capture contracts](../../panoptes/capture.py).
- [OpenTelemetry GenAI spans and content guidance](https://github.com/open-telemetry/semantic-conventions-genai/blob/main/docs/gen-ai/gen-ai-spans.md); [execute-tool span definition](https://github.com/open-telemetry/semantic-conventions-genai/blob/main/model/gen-ai/spans.yaml).
- [Langfuse OpenTelemetry integration](https://langfuse.com/integrations/native/opentelemetry); [Phoenix tracing](https://arize.com/docs/phoenix/learn/tracing/how-tracing-works).
- Context7 discovery was attempted; no usable result was returned in this review. Official documentation was consulted directly.
