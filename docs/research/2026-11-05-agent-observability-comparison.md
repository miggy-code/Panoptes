# Research: Panoptes and mature agent observability tools

**Date:** 2026-11-05
**Status:** needs-discussion
**Recommendation:** Focus Panoptes on local, evidence-aware audit capture and interoperate with established observability platforms rather than recreating their full product suites.

## Question and criteria

How does the current repository compare with Langfuse, Arize Phoenix, and LangSmith for a developer investigating agents? Compare deployment and integration effort, observation fidelity, integrity, developer workflows, and operational maturity. This is a documentation and source review, not an independent benchmark or a complete feature audit.

## Comparison

| Criterion | Panoptes | Langfuse | Phoenix | LangSmith |
| --- | --- | --- | --- | --- |
| Core purpose | Local normalized audit events and CLI | AI engineering platform: traces, evals, prompts, datasets | Open-source tracing, evals, prompt workflows | Hosted or self-hosted tracing and evaluation platform |
| Deployment | Python and SQLite; proxy needs httpx | Cloud or self-hosted platform | Local or self-hosted; SQLite default, PostgreSQL available | Cloud or licensed self-hosted |
| Capture | Model API proxy and Hermes lifecycle hooks | SDK/OTel; proxy integrations and AI Gateway | OpenInference/OTel instrumentation | SDK and integrations |
| Integrity | Local hash chain and externally held prefix checkpoints | No equivalent verified in this research | No equivalent verified in this research | No equivalent verified in this research |
| Analysis | Local query, session, evidence CLI and Python API | Rich UI, dashboards, evaluation and prompt workflows | UI, datasets, experiments, evaluations and prompt workflows | UI, production evaluation and LangChain ecosystem |

Absence of a verified equivalent is not proof competitors lack the feature. Local deployment and proxy-based capture are not unique: Phoenix supports SQLite locally; Langfuse documents proxy logging and gateway tracing. Integration requires compatible routing or instrumentation in all cases.

## Panoptes' distinctive combination

- A small local package, SQLite audit database and CLI with no external service; its core has no runtime dependencies. This is simpler than operating a full platform, although Phoenix is also locally runnable.
- Explicit capture fidelity and provenance: a proposed tool call remains pending, and Hermes execution observations are host-reported. These are carefully stated evidence boundaries, not proof competitors cannot represent comparable distinctions.
- Optional chained storage and checkpoint verification directly support checking a stored history against a separately retained checkpoint. This does not establish source authenticity, completeness or protect against a whole-history rewrite without an external checkpoint.
- Model-protocol proxy and Hermes lifecycle events normalize into the same schema. The external hook seam permits another component to make decisions without building policy into Panoptes; hooks can reject or mutate traffic, so an embedded configuration is not necessarily observe-only end to end.
- Secret redaction and bounded capture occur before storage, but are not complete DLP. Proxy coverage is restricted to traffic routed through supported paths; it cannot independently establish arbitrary local tool execution.

## What mature platforms have

Langfuse offers nested application traces, a UI, OpenTelemetry integrations, evaluation, datasets, prompt management, dashboards, collaboration and platform APIs. Its gateway can capture model calls through a proxy. Phoenix offers local/self-hosted operation with a trace UI, OpenInference instrumentation, datasets, experiments, evaluation and prompt management. LangSmith provides tracing and online evaluators and integrates closely with the LangChain ecosystem. Availability, scale and commercial terms differ by edition and change over time.

Panoptes lacks an equivalent integrated UI, general application-level distributed tracing, native OTel ingestion/export, evaluation and experiment workflow, prompt management, team access controls, managed hosting, and platform-scale analytics. Its proxy adds an inline operational dependency and only sees configured supported traffic; stable session identity is client- or hook-asserted. Cost annotations require a supplied rate table. No independent performance, reliability, security, adoption, or integration benchmark was performed.

## Recommendation and follow-up

Lead with “local, evidence-aware agent audit trail,” not “Langfuse replacement” or “security boundary.” Validate the positioning with a concrete incident review: show a model proposal, a separately reported outcome, a clear unknown, and verification against a previously exported checkpoint. Investigate an optional OTel/export bridge only after defining which provenance, truncation, and integrity semantics survive export; a visualization platform and local audit store could then complement one another. Prioritize real adapter coverage and documented fidelity over duplicating eval and prompt tooling. No adoption decision was made; implementation issues are therefore not proposed as committed work.

## Sources

- Repository: [README](../../README.md), [API](../api.md), [hooks](../hooks.md), [security](../../SECURITY.md).
- [Langfuse observability data model](https://langfuse.com/docs/observability/data-model), [observability overview](https://langfuse.com/docs/observability/overview), [gateway tracing](https://langfuse.com/docs/gateway/features/tracing), [self-hosted feature comparison](https://langfuse.com/pricing-self-host).
- [Phoenix overview](https://arize.com/docs/phoenix/), [self-hosting](https://arize.com/docs/phoenix/self-hosting/deploying-phoenix), [tracing](https://arize.com/docs/phoenix/learn/tracing/how-tracing-works).
- [LangSmith online evaluation](https://docs.langchain.com/langsmith/online-evaluations-llm-as-judge), [deployment tracing](https://docs.langchain.com/langsmith/data-plane).
- Context7 discovery attempted; no Context7 results were available during this review. Vendor documentation was used directly.
