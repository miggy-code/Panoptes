# Security model

Panoptes is an alpha observability tool. It records what went through it and
what a host reported. It does not enforce anything, and it is not a security
boundary. This document tells you what you can trust Panoptes to do.

An event alone never proves that a tool ran.

Enforcement belongs in a separate package that uses the proxy hooks. Examples
are allow and deny rules, credential injection, and budgets. That package
states its own guarantees. Panoptes records only the exchange. The hook
contract is in [docs/hooks.md](docs/hooks.md).

## What each adapter observes

| Adapter | Observes | Does not prove |
|---|---|---|
| Model API proxy | Model requests, responses, recognized tool calls, and client-reported tool results | That a local tool ran, or that the agent has no other route to the provider |
| Hermes lifecycle hooks | Session and step events that the host reports | That a local action happened exactly as reported |

Each adapter event has `context.capture` fields. These fields record the
observation boundary, the identity assurance, and whether Panoptes observed
execution. Keep these fields when you export or score events. Do not give an
event stronger provenance than its capture fields state.

## Trust assumptions

- **Loopback only.** The proxy binds only to a loopback address. It is not an
  authenticated or internet-facing gateway.
- **Identity headers are claims.** Agent and session headers are not
  authenticated. A hook can set the identity. The event then records that a
  hook asserted it. Panoptes cannot know how the hook got that identity.
- **The proxy can be bypassed.** An agent that has provider credentials and
  network access can call the provider directly.
- **Same-user attacks.** An agent that runs as the same operating-system user
  can stop Panoptes or change the database. To stop that attacker, you need a
  separate privileged service, credential isolation, and egress controls.
  Panoptes does not supply these.
- **Unknown is not safe.** Provider support is versioned code. Panoptes records
  an unrecognized tool type or response item as unknown or as an incomplete
  inspection. It never records it as safe.
- **Allowlisted paths only.** The proxy forwards only a fixed list of model API
  paths for each provider. It refuses other endpoints, such as batches, files,
  fine-tuning, and OpenAI-compatible shims, because it cannot inspect their
  responses.
- **No duplicate JSON keys.** Request parsing and buffered response inspection
  reject duplicate JSON object keys. Otherwise the client and the audit trail
  could read different values. Panoptes withholds a buffered reply that has
  duplicate keys.
- **No unrecorded requests.** If Panoptes cannot build a request's audit
  events, it answers HTTP 500 and forwards nothing. Otherwise an input that
  breaks event construction would pass through unseen.
- **Streams pass through.** Panoptes sends stream data to the client before it
  inspects it. Stream capture has a size limit and is marked incomplete when it
  is cut short.
- **No ambient proxy settings.** The proxy's HTTP clients ignore `HTTP_PROXY`,
  `HTTPS_PROXY`, and `NO_PROXY`. Configure only the documented Panoptes
  upstreams.
- **Hermes is best-effort.** Hermes lifecycle hooks are best-effort
  observations. If an audit write fails, the agent continues.

## Audit evidence

Panoptes keeps proposed tool calls separate from host-reported execution
events. A model-issued `tool_call` is not proof of execution.

The local hash chain finds changes to chained events, compared to the recorded
chain head. A database migrated from an older schema has a legacy boundary.
Panoptes counts the rows before that boundary, but it never hashed their
contents.

The chain does not protect against an attacker who can rewrite both the
database and its chain metadata. For audit-grade use, do one or more of these:

- Publish or sign checkpoints outside the database. Then verify later history
  with `panoptes verify --checkpoint <file>`.
- Copy events to append-only storage.

## Sensitive data

Prompts, tool arguments, and results can contain secrets or personal data.
Redaction is a second layer of defense. It does not find every secret. Before
you use Panoptes:

- Capture only the content that you need.
- Restrict the database file permissions.
- Encrypt the storage where your rules require it.
- Define how long you keep the data.

`action.data_accessed` holds heuristic tags. A tag can miss sensitive access,
and it can mark harmless text as sensitive. It is not a record of the data that
the agent accessed.

## Built-in limits

- Read-only CLI commands reject a missing or uninitialized database path. They
  never create an empty audit trail.
- The proxy limits request body size, response buffer size, audit stream size,
  tool events per exchange, client socket time, and concurrent requests. These
  limits reduce accidental resource exhaustion on the local machine.

## Deployment checklist

1. If the agent is untrusted, run Panoptes as a separate OS user or in a
   separate container.
2. Restrict the database file permissions, and plan its retention.
3. Publish chain checkpoints to a separate trust domain.
4. Monitor audit write failures and disk space.
5. Before you rely on Panoptes, test your exact provider and agent versions
   against adversarial fixtures.

## Report a vulnerability

Open a private security advisory at
<https://github.com/miggy-code/Panoptes/security/advisories/new>.

Do not include live credentials, private prompts, or production audit records.
A useful report includes:

- The affected adapter and provider path.
- A minimal, redacted reproduction.
- The impact that you observed.
