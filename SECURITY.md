# Security model

Panoptes is an alpha observability and policy tool. This document is the plain
answer to “what can I trust it to do?” The answer depends on which adapter is
in the execution path. A normalized event is never, by itself, proof that a
tool executed.

If you are evaluating Panoptes for enforcement, start with the guarantee table
below and then work through the deployment checklist. The strongest guarantee
available today is a synchronous decision at a boundary the host actually
honors; mandatory mediation of every local action is not implemented.

## Guarantee levels

| Mode | Observes | Can deny | Does not prove |
|---|---|---|---|
| Model API monitor | Model requests, responses, recognized tool instructions, and client-reported tool results | Nothing after response delivery | Local tool execution |
| Buffered model API gate | The same API traffic before delivery | Recognized model instructions and request-side policy matches | That an agent cannot reach the provider another way |
| Hermes lifecycle hooks | Host-reported session and step events | Nothing by themselves | A local action occurred exactly as reported |
| Hermes pre-tool authorizer | A host-supplied canonical tool request | The request, if the host synchronously honors `allowed=False` | That the host executed the exact authorized resource afterward |
| Privileged execution broker | Not implemented | Not implemented | Mandatory mediation |

Adapter-produced observations carry `context.capture` fields describing their
observation boundary, identity assurance, whether execution was observed, and
whether enforcement was mandatory. Consumers must preserve these fields when
exporting or scoring events. Internally generated records, such as some
integrity or policy records, must not be assigned stronger provenance by
inference.

## Trust assumptions

- The local proxy only binds to an explicit loopback address. It is not an
  authenticated or internet-facing gateway.
- Agent and session headers are assertions, not authenticated identities.
  Security-sensitive deployments must use credential injection (below) or
  place an authenticated adapter or workload-identity gateway in front of
  Panoptes.
- The proxy is bypassable unless provider credentials are isolated from the
  agent and direct provider egress is blocked.
- An agent running as the same operating-system user can modify local policies,
  stop the process, or alter the SQLite database. Protecting against that
  attacker requires a separately privileged service, read-only signed policy
  distribution, provider credential isolation, and direct-egress controls.
- Provider protocol support is versioned code. Enforcement mode must deny
  malformed or unsupported security-relevant responses rather than interpret
  an empty parse as safe. `fail_closed` also denies non-empty
  `action.unknown_tool_types` even when no user policy explicitly matches it;
  `fail_open` records a warning.
- An event that fails validation is denied in both modes while any enabled
  block policy is active. Fail-open covers Panoptes' own failures, not input a
  caller can shape to skip a block.
- The proxy forwards only an exact allowlist of model-API paths per provider.
  Other provider endpoints (batches, files, fine-tuning, OpenAI-compatible
  shims) are refused, because their responses cannot be inspected.
- Request parsing and buffered response inspection reject duplicate JSON object
  keys. Audit-only pass-through streams are delivered before post-hoc
  inspection and therefore cannot be retroactively denied.
- Proxy-created HTTP clients ignore ambient `HTTP_PROXY`, `HTTPS_PROXY`, and
  `NO_PROXY` settings. Configure only the documented Panoptes upstreams; do not
  rely on shell proxy variables to establish a security boundary.

## Credential injection

`panoptes proxy --inject-credentials` makes Panoptes the only holder of
provider API keys. It loads them at startup from `PANOPTES_ANTHROPIC_API_KEY`,
`PANOPTES_OPENAI_API_KEY`, and `PANOPTES_GEMINI_API_KEY`, or from a
`--credentials-file` that must be a regular file owned by the Panoptes user
with mode 0600. Agents receive a random Panoptes session token from
`panoptes token issue`. Only its SHA-256 hash is stored, in a `session_tokens`
table in the audit database, with its agent type, session id, and expiry.

On every request the proxy requires exactly one valid, unexpired, unrevoked
token in the routed provider's credential slot. Otherwise it returns 401,
records a blocked `model_request` event with `context.capture.identity_check`
set to the reason, and forwards nothing. On success it strips every client
credential (`Authorization`, `x-api-key`, `x-goog-api-key`, and `?key=`) and
adds the key for that upstream only. Tokens and keys are not written to the
audit log, logs, or responses; secret redaction is a backstop, not the
mechanism.

What this closes:

- An agent that holds only a Panoptes token cannot call the provider directly,
  so the proxy is no longer bypassable by reusing the agent's own key.
- Agent type and session id come from the token Panoptes issued, not from
  `X-Panoptes-*` headers. Those events carry
  `identity_assurance: "panoptes_session_token"` and
  `identity_source: "panoptes_token"`. `context.capture.authenticated` stays
  `false`: the capture block is still an adapter record, not a signature.
- Rejected requests ignore identity headers, so an unauthenticated caller
  cannot write into another session's timeline.

What it does not close, and you must still do:

- Run Panoptes as a separate OS user or in a separate container. An agent
  running as the same user can read the Panoptes environment, the credentials
  file, and the token table, or stop the proxy.
- Block direct egress from the agent to provider endpoints, so a key obtained
  some other way cannot be used around the proxy.
- Treat a token as a bearer credential: issue it per session with a short TTL
  and revoke it with `panoptes token revoke` when the session ends.

Hermes lifecycle hooks are observation-only and intentionally do not turn an
audit write outage into an execution boundary. The separate pre-tool
authorizer denies on policy or evidence-write failure when configured
`fail_closed`, but only if the host invokes and honors it.

## Audit evidence

Panoptes distinguishes proposed tool instructions, authorization decisions, and
host-reported execution events. Do not treat a model-issued `tool_call` as proof
of execution.

The local database hash chain detects mutation of chained events relative to
its recorded chain head. Databases migrated from an older schema have an
explicit legacy boundary: pre-boundary rows are counted but their historical
payloads were never hashed. The chain does not protect against a privileged
attacker who can rewrite both the database and its local chain metadata.
Audit-grade deployments must publish or sign checkpoints outside the database,
verify later history with `panoptes verify --checkpoint <file>`, or replicate
events to append-only storage.

Raw prompts, tool arguments, and results may contain secrets or personal data.
Redaction is defense in depth, not a guarantee that arbitrary secrets will
always be recognized. Capture the minimum content needed, restrict database
permissions, encrypt storage where required, and define retention before use.

`action.data_accessed` includes server-derived heuristic classification. It can
miss sensitive access or classify benign text as sensitive, so it is not an
authoritative record of what data was actually accessed. High-impact policies
should combine it with trusted adapter context and explicit resource identity.

Read-only CLI commands reject missing or uninitialized database paths rather
than silently creating an empty audit trail. `panoptes policy check` exits
nonzero and reports policy evaluation errors; a clean-scan message is not
evidence that every event was evaluated if the command failed.

The proxy applies request-body, response-buffer, audit-stream, tool-event,
client-socket-timeout, and concurrent-request limits. These defaults reduce
accidental local resource exhaustion.

## Enforcement deployment checklist

1. Run in fail-closed mode with a valid, non-empty, tested policy snapshot.
2. Keep provider credentials out of the agent with `--inject-credentials`, run
   Panoptes as a separate OS user or container, and block direct provider
   egress.
3. Use a native synchronous pre-tool hook or execution broker for local tools.
4. Protect policy files from the agent identity and audit every policy change.
5. Monitor proxy readiness, audit-write failures, disk capacity, and dropped
   events.
6. Publish chain checkpoints to a separate trust domain.
7. Test the exact provider and agent versions against adversarial fixtures
   before relying on blocking behavior.

## Reporting vulnerabilities

Please open a private security advisory at
<https://github.com/miggy-code/Panoptes/security/advisories/new>. Do not include
live credentials, proprietary prompts, or production audit records. A useful
report includes the affected adapter and provider path, the configured failure
mode, a minimal redacted reproduction, and the impact you observed.
