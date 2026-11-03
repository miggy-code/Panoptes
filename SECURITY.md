# Security model

Panoptes is an alpha observability tool. It records what crossed it and what a
host reported; it does not enforce anything and is not a security boundary. This
document is the plain answer to “what can I trust it to do?” A normalized event
is never, by itself, proof that a tool executed.

Enforcement (allowing, denying, injecting credentials, budgets) belongs to a
consumer that plugs in through the proxy hook seam described in
[docs/hooks.md](docs/hooks.md). What such a consumer guarantees is its own to
state; Panoptes only records the exchange.

## What each adapter observes

| Adapter | Observes | Does not prove |
|---|---|---|
| Model API proxy | Model requests, responses, recognized tool instructions, and client-reported tool results | Local tool execution, or that an agent cannot reach the provider another way |
| Hermes lifecycle hooks | Host-reported session and step events | That a local action occurred exactly as reported |

Adapter-produced observations carry `context.capture` fields describing their
observation boundary, identity assurance, and whether execution was observed.
Consumers must preserve these fields when exporting or scoring events, and must
not assign stronger provenance by inference.

## Trust assumptions

- The local proxy only binds to an explicit loopback address. It is not an
  authenticated or internet-facing gateway.
- Agent and session headers are assertions, not authenticated identities. An
  embedding hook can set the identity itself; the event then records that a hook
  asserted it, and Panoptes cannot know how that identity was established.
- The proxy is bypassable by an agent that holds provider credentials and can
  reach the provider directly.
- An agent running as the same operating-system user can stop the process or
  alter the SQLite database. Protecting against that attacker requires a
  separately privileged service, credential isolation, and egress controls that
  Panoptes does not provide.
- Provider protocol support is versioned code. A tool type or response item
  Panoptes does not recognize is recorded as unknown or as an incomplete
  inspection, never as safe.
- The proxy forwards only an exact allowlist of model-API paths per provider.
  Other provider endpoints (batches, files, fine-tuning, OpenAI-compatible
  shims) are refused, because their responses cannot be inspected.
- Request parsing and buffered response inspection reject duplicate JSON object
  keys: the client and the audit trail could otherwise read different values. A
  buffered reply with duplicate keys is withheld. Pass-through streams are
  delivered before inspection, and their capture is bounded and marked
  incomplete when cut short.
- Proxy-created HTTP clients ignore ambient `HTTP_PROXY`, `HTTPS_PROXY`, and
  `NO_PROXY` settings. Configure only the documented Panoptes upstreams.
- Hermes lifecycle hooks are best-effort observations; an audit write outage
  does not stop the agent.

## Audit evidence

Panoptes distinguishes proposed tool instructions from host-reported execution
events. Do not treat a model-issued `tool_call` as proof of execution.

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
authoritative record of what data was actually accessed.

Read-only CLI commands reject missing or uninitialized database paths rather
than silently creating an empty audit trail.

The proxy applies request-body, response-buffer, audit-stream, tool-event,
client-socket-timeout, and concurrent-request limits. These defaults reduce
accidental local resource exhaustion.

## Deployment checklist

1. Run Panoptes as a separate OS user or container if the agent is untrusted.
2. Protect the database file's permissions and plan its retention.
3. Publish chain checkpoints to a separate trust domain.
4. Monitor audit-write failures and disk capacity.
5. Test the exact provider and agent versions against adversarial fixtures
   before relying on what Panoptes parses.

## Reporting vulnerabilities

Please open a private security advisory at
<https://github.com/miggy-code/Panoptes/security/advisories/new>. Do not include
live credentials, proprietary prompts, or production audit records. A useful
report includes the affected adapter and provider path, a minimal redacted
reproduction, and the impact you observed.
