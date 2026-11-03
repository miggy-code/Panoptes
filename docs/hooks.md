# Proxy hooks

> **Status: implemented**, in `panoptes/hooks.py` and `ProxyServer`. The
> contract below was approved before the code was written; changing it is a
> breaking change to every embedder. Decided: `after_exchange` is owed for every
> entered exchange; every exchange has a `correlation_id`; one hooks object per
> proxy.

The Panoptes reverse proxy observes model-API traffic: it forwards each request,
parses it and the response, prices the usage and records events. It never
decides anything and never blocks. Anything that decides plugs in through two
hooks, one before the request leaves and one after the exchange ends.

```python
from panoptes.db import AuditDB
from panoptes.hooks import Exchange, Identity, ProxyHooks, Reject
from panoptes.proxy import ProxyServer, Upstream

class MyHooks(ProxyHooks):
    def before_forward(self, exchange: Exchange) -> Reject | None: ...
    def after_exchange(self, exchange: Exchange) -> None: ...

server = ProxyServer(
    port=0,                                   # 0 = pick a free port
    db=my_audit_db,                           # or db_path="~/.panoptes/audit.db"
    upstreams={"openai": Upstream("https://api.deepseek.com", name="deepseek")},
    pricing=my_pricing_table,
    hooks=MyHooks(),
)
port = server.start()        # non-blocking: serves from a background thread
...
server.stop()                # stops accepting, finishes in-flight exchanges
```

## Entry point

`ProxyServer(...)` is the embeddable entry point and its own handle:
`start()` returns without blocking and returns the bound port, `.port` holds it,
and `.stop()` shuts the proxy down. It takes `hooks=`, `db=`, `upstreams=` and
`pricing=` in addition to the arguments it takes today. `start_proxy(...)` is the
command-line entry point; it **blocks** until interrupted, takes `db_path` only,
and gains no hook support.

`panoptes.hooks` imports no HTTP client, so it loads without the `[proxy]`
extra. With `hooks=None` (the default) the proxy is pure observe and
pass-through: no hook code runs, nothing new is buffered, and behaviour is
unchanged.

`stop()` waits for in-flight exchanges, so every entered exchange still gets
its `after_exchange` on an orderly shutdown (bounded by the upstream timeout,
120 seconds; it logs a warning if exchanges are still running after that).

A hooked proxy cannot also do credential injection (`provider_keys`) or run the
policy engine (`policies_dir`): `ProxyServer` raises `ValueError`. A hook is the
replacement for both. The constructor arguments are `hooks`, `db`, `chain`,
`upstreams`, `pricing`, `disconnect_drain_seconds` and `hook_slow_seconds`.

## What a hook may and may not do

A hook may **reject** the request, **set the identity** the exchange is recorded
under, **set or remove outbound headers** (that is how a credential is
injected), **drop the credentials from the forwarded query string**, and keep
**private state** from `before_forward` to `after_exchange`. It cannot change
the request body, the target or the response. Panoptes forwards the request body
bytes unchanged, and what it records is what it observed, not what a hook
wished.

Panoptes never learns *why* a hook rejects, and never interprets the reason.

Hooks **never force buffering.** Installing a hook does not delay a streamed
response; `before_forward` runs before anything is sent upstream and
`after_exchange` after the response is delivered.

## Lifecycle

```
client request
  └ parse target, read body, parse JSON, build the request events
      └ before_forward(exchange)            ← entered: after_exchange is now owed
          ├ Reject → record, answer the client, never forward
          ├ raises → 502, record, never forward
          └ None   → record the request, forward
              └ response relayed to the client, response events recorded
                  └ response flushed and finished
                      └ after_exchange(exchange)   ← once
```

### The `after_exchange` guarantee

If `before_forward` was entered, `after_exchange` is called **exactly once per
exchange within a process**, whatever happens: a rejection, a hook exception, an
upstream error, a client that disconnects mid-stream, an unexpected exception in
the proxy, an orderly `stop()`.

It is **at most once across a crash.** If the process dies between
`before_forward` and `after_exchange`, nothing calls it afterwards. A hook that
reserves a resource must therefore not depend on `after_exchange` alone to
release it: use a lease or expiry that a restarted process can reclaim.

`after_exchange` runs **after the response has been sent to the client**: the
body (or the final stream chunk) is written and flushed and the response is
finished. A slow `after_exchange` therefore never delays the client. It still
runs in the request thread and holds one of the proxy's bounded request slots
until it returns (see [Concurrency](#concurrency-and-starvation)).

An exception from `after_exchange` is **recorded as an event** (below) and
logged; it cannot change the response, and the next request is unaffected. Make
it idempotent.

### Requests Panoptes refuses before the hook

A request that is malformed (not a strict JSON object, ambiguous framing,
duplicate keys), oversized, or unroutable (no supported provider route) is
answered with an error by Panoptes **before** `before_forward` is entered. The
hook never sees it and no `after_exchange` follows. Panoptes records the refusal
as an observation where it can, but a hook that keeps its own decision log will
have no entry for these requests. That is fail-closed: nothing was forwarded.
If your audit of model requests must account for every request, join your log
against Panoptes' events on `exchange_id` rather than assuming one entry per
request.

## `Exchange`

One object per proxied request, passed to both hooks. Request fields are
read-only; a hook sets only `identity`, `outbound_headers` and `state`, and may
call `drop_query_credentials()`.

### Request fields

| Field | Meaning |
|---|---|
| `exchange_id` | unique id of this request, generated by Panoptes. **The join key**: recorded on every event as `attributes.exchange_id` |
| `correlation_id` | the id every event of this exchange carries as `correlation_id`: the client's `X-Panoptes-Correlation-Id` if it sent a valid one, else `exchange_id` |
| `correlation_source` | `"client"` or `"proxy"`. A client value is asserted, never trusted, and may be reused across requests, so join on `exchange_id`, not on `correlation_id` |
| `provider` | the **wire protocol** the request speaks: `"openai"`, `"anthropic"`, `"gemini"` or `"unknown"` |
| `upstream_name` | the configured upstream's name (see [Upstreams](#upstreams)); defaults to `provider`. With `Upstream("https://api.deepseek.com", name="deepseek")`, `provider` is `"openai"` and `upstream_name` is `"deepseek"` |
| `upstream_url` | the upstream origin, `scheme://host[:port]` |
| `method`, `path` | the request line as routed, **without the credential query parameters** (this is also the form that is recorded) |
| `request_headers` | read-only header list as received, credentials included. Keeps repeated lines: `get_all(name)` returns every value in order, `get(name)` the first, `items()` every `(name, value)` pair in received order and case. Lookup is case-insensitive |
| `query_credentials` | tuple of the decoded values of every credential query parameter, in order of appearance. The parameters are `key`, `api_key`, `apikey` and `access_token`, matched case-insensitively after percent-decoding. Gemini sends its credential this way |
| `request_body` | the raw body bytes, as received |
| `request_json` | the body parsed as a strict JSON object, or `None` |
| `request_events` | the parsed request events (`model_request` and any `tool_result`) as deep copies; mutating them changes nothing |

`request_headers` and `query_credentials` are how a hook sees **every**
credential the client presented, including two different ones in one request
(for example a bearer token and a different `x-api-key`, or a header plus
`?key=`). Neither appears in `repr(exchange)` or in any recorded event.

### What a hook may set

| Field | Meaning |
|---|---|
| `identity` | the identity this exchange is recorded under; assign a whole `Identity` |
| `outbound_headers` | case-insensitive map of the headers that will be sent upstream |
| `drop_query_credentials()` | method; removes every credential query parameter from the URL that is forwarded |
| `state` | a dict private to the hook, carried to `after_exchange` |

#### `identity`

```python
@dataclass(frozen=True)
class Identity:
    agent_type: str
    session_id: str                 # required; consumers without sessions use the run id
    run_id: str | None = None
    parent_run_id: str | None = None
    user: User | None = None        # User(id: str | None, auth_method: str | None)
    assurance: str | None = None    # the hook's own label for how it established this

exchange.identity = Identity(agent_type="claude_code", session_id=run, run_id=run, ...)
```

`Identity` is a frozen value and assignment replaces it as a whole, so a hook
never leaves a half-updated identity. Panoptes seeds `exchange.identity` as it
does today: from the client's `X-Panoptes-Agent` and `X-Panoptes-Session`
headers, the User-Agent, and a generated `run_id`. Those are **client
assertions**, nothing more. A hook that authenticates the caller replaces it
wholesale, and the exchange is joined to that run, not to whatever the client
claimed. `session_id` stays required and its type is frozen as `str`.

A hook-set identity whose `run_id` is `None` records no `run_id` on its events:
Panoptes never invents one.

Panoptes reads `exchange.identity` once, when `before_forward` returns, and
records every event of the exchange, request and response alike, under it,
including the events of a rejected exchange. After a **hook error**, the
**seeded identity** is recorded, never one the hook half-set before raising.
Assignments after `before_forward` returns, including in `after_exchange`, are
ignored; `exchange.identity` then holds what was recorded.

Every field is validated as an identifier (at most 256 characters, no control
characters, no secret-shaped text). An invalid value is a hook error (below).

**How it was set is recorded.** Events carry
`attributes.identity = {"source": "hook" | "seeded", "assurance": <label or null>}`.
A hook-set identity also sets `context.capture.identity_assurance` to
`"hook_asserted"`: Panoptes cannot know how the hook authenticated, so it records
that an embedder asserted the identity, and the hook's own `assurance` label
says what it claims. Neither is proof of anything.

#### `outbound_headers`

Starts as the request's headers as Panoptes would forward them: repeated lines
combined, hop-by-hop headers (including any header the client's `Connection`
header nominates), `host` and `X-Panoptes-*` headers removed. It **still
contains the client's credentials**; a hook that injects a provider key removes
them first (`panoptes.hooks.CLIENT_CREDENTIAL_HEADERS` lists `authorization`,
`x-api-key` and `x-goog-api-key`).

Lookup is case-insensitive. Values must be strings without CR, LF or NUL.
Nothing in `outbound_headers` is ever recorded.

After the hook returns, Panoptes re-applies only its own fixed invariants:

- the static hop-by-hop names (`connection`, `keep-alive`,
  `proxy-authenticate`, `proxy-authorization`, `proxy-connection`, `te`,
  `trailer`, `trailers`, `transfer-encoding`, `upgrade`) and `host` are dropped;
- `content-length` is recomputed for the forwarded body and `content-type` is
  the client's, so a value a hook sets for either is discarded;
- `Accept-Encoding: identity` is forced so responses stay inspectable.

**It never removes a header the hook set because of anything in the client's
request.** In particular, headers nominated by the client's `Connection` header
are removed from the client's set *before* the hook runs, so a request carrying
`Connection: x-api-key` loses the client's `x-api-key` and cannot make Panoptes
strip an `x-api-key` the hook injects.

#### `drop_query_credentials()`

Query credentials are **not** stripped merely because a hook is installed:
attaching a logging-only hook must not change what is forwarded, so by default
the forwarded URL is the received URL. A hook that injects its own credential
calls `exchange.drop_query_credentials()` so the client's `?key=` cannot travel
upstream beside it. The call removes every credential parameter (the four named
above) from the forwarded URL, is idempotent, and does not change
`query_credentials`. A hook that wants a client credential to reach the
provider in another form copies it from `query_credentials` into
`outbound_headers`.

The recorded `path`, and every recorded event, never contain a credential query
value either way.

### Fields set for `after_exchange`

| Field | Meaning |
|---|---|
| `outcome` | one of the values below |
| `request_sent` | see below |
| `produced_output` | see below |
| `status` | the HTTP status Panoptes answered the client with (or would have, if the client had already gone), or `None` if none was produced |
| `upstream_status` | the HTTP status **the provider itself** sent, or `None` if no response arrived (a rejection, a connect failure, a timeout before the response head). It differs from `status` whenever Panoptes replaced the reply: a `200` it could not safely read is answered `502`, but `upstream_status` is still `200` and the call was billed. `provider_error` and `produced_output` follow `upstream_status`, never `status` |
| `complete` | a plain `bool`: `True` only if the whole upstream response was read and parsed, so `usage` is final. `False` whenever that is not known: a broken relay, a truncated audit capture, an upstream drop, no response. Never `None` |
| `response_events` | the response events recorded (`model_response`, `tool_call`) as deep copies; empty if none |
| `usage` | the token counts the provider reported in a successful reply (`tokens_in`, `tokens_out`, and cache/reasoning counts), leaving out any it did not report. `{}` whenever the provider reported none: an error reply, no response, a body without a usage object, or a response Panoptes could not read. Never zeros standing in for "unknown" |
| `estimated_usd_micros` | the exact priced cost of the response in whole micro-dollars (an `int`), or `None` if unpriced: no rate table, an unknown model, or missing token counts. Panoptes never guesses a rate. `0` for a provider error (an error reply is not billed). Rounding is described in [api.md](api.md#pricing) |
| `provider_error` | `True` if `upstream_status` is 4xx or 5xx. `False` when no response arrived; a Panoptes-made 502/504 is not a provider error |
| `duration_ms` | proxy-measured wall time for the exchange |

`repr(exchange)` omits headers, bodies and query credentials, so logging an
exchange cannot leak a credential.

#### `request_sent`

`False` only when Panoptes can show **no byte of the request was written
upstream**. `True` otherwise: the provider may have received it, and a provider
that received a request may have generated, and billed, tokens even if no usable
reply came back.

It is `False` for a rejection, a hook error, a `not_forwarded` exchange, and an
upstream connection that failed to establish (DNS, connect error or timeout,
TLS handshake failure, pool exhaustion). It is `True` once the request has been
handed to an established upstream connection, and stays `True` whatever follows:
a read timeout, a broken stream, a client that disconnects mid-stream, an
upstream 5xx. The HTTP client does not report the first byte written, so
Panoptes errs toward `True`, the safe direction for a caller that settles money.

#### `produced_output`

`True` if there is evidence the provider generated output for this request:
`upstream_status` is non-error and the provider sent any body bytes (for a
stream, any bytes after the headers), or it reported `tokens_out > 0`. This holds
whatever Panoptes did next: an oversized or unreadable `200` that Panoptes
answered `502` is still `True`. `False` otherwise, including for an error status
with an error body, an empty reply, and every exchange that never reached the
provider.

It exists because `complete` and `usage` can be unknown while output was
produced (a stream that broke after the first token). A caller that settles
money reads the four facts together:

| `request_sent` | `produced_output` | usage known (`complete`) | Settle |
|---|---|---|---|
| `False` | – | – | release the reservation |
| `True` | `False` | – | provider 4xx/5xx (`provider_error`): release; otherwise unknown: keep the reservation |
| `True` | `True` | `True` | charge `estimated_usd_micros` (or the reservation if unpriced) |
| `True` | `True` | `False` | charge the full reservation |

(The last column is guidance for consumers; Panoptes enforces none of it.)

#### `outcome`

| Value | Meaning |
|---|---|
| `"forwarded"` | the upstream answered (any status) and the response was relayed |
| `"upstream_error"` | no usable upstream response: connect error, timeout, unsafe framing, or oversized body. Panoptes answered 502/504 |
| `"rejected"` | `before_forward` returned `Reject` |
| `"hook_error"` | `before_forward` raised or returned something invalid |
| `"not_forwarded"` | `before_forward` accepted, but Panoptes then refused to forward for its own reasons (for example the durable record of the request could not be written) |
| `"aborted"` | the exchange ended abnormally with no result, such as an unexpected proxy error |

## `before_forward(exchange) -> Reject | None`

Runs in the request thread, after the request events are built and before
anything is recorded or sent upstream. It sees the parsed request, the provider
and the raw bytes.

- **`None`**: forward. Panoptes records the request events under
  `exchange.identity`, applies `outbound_headers` and forwards.
- **`Reject(status, body, reason)`**: do not forward.
  - `status`: an integer 400-599 sent to the client.
  - `body`: a JSON-serializable object sent as `application/json`
    (default `{"error": reason}`). Panoptes adds nothing to it.
  - `reason`: a short code (a Panoptes identifier: at most 256 characters, no
    control characters or secret-shaped text). Recorded, never interpreted.

  Panoptes marks the request events `blocked`, records
  `attributes.hook = {"action": "reject", "status": ..., "reason": ...}` on
  them, writes them under `exchange.identity`, and answers the client. If that
  record cannot be written the request is still rejected and never forwarded.
- **An exception, or an invalid return value** (not `None`/`Reject`, a status
  outside 400-599, a body that is not JSON, a bad reason, an invalid identity or
  header value): Panoptes answers **502** with a generic body that does not
  include the exception text, records the request events as `blocked` with
  `attributes.hook.action = "error"` under the **seeded** identity, logs the
  exception, and never forwards. A failing hook can never mean "forward anyway".

## `after_exchange(exchange) -> None`

See [the guarantee](#the-after_exchange-guarantee). All the `Exchange` fields
above are set. It is for settling: charge the priced cost, release a
reservation, emit your own record.

If it raises, Panoptes records a `panoptes.hook_error` event (a namespaced type)
under the exchange's identity and correlation id, with `outcome.status =
"error"` and `attributes = {"hook": "after_exchange", "exchange_id": ...,
"error_type": <exception class name>, "error": <redacted, truncated message>}`.
Writing that event is best-effort; a failure to write it is logged.

## Streaming and client disconnects

For a streamed response Panoptes relays chunks to the client as they arrive and
keeps a bounded capture (`max_audit_stream_bytes`) for parsing. A hook never
changes that.

If the **client disconnects mid-stream**, Panoptes stops writing to the client
but keeps **draining the upstream** and capturing it, up to
`disconnect_drain_seconds` (default 30) and the capture bound, so it can read the
provider's final usage. If the stream ends inside the bound, the usage is parsed
normally and `complete` is `True`: `complete` describes what Panoptes read, not
what the client received. If the bound is hit first, Panoptes closes the upstream
connection, `complete` is `False` and `usage` is `{}`. `request_sent` is `True`
either way. Draining holds the request slot, so the bound is the cost cap.

A buffered (non-streamed) response is read in full before it is written, so a
client that disconnects before the write has no effect on `complete`.

Draining is part of hook support: a proxy with no hooks ends the relay when the
client leaves, as it always has.

## Upstreams

Panoptes routes a request to an upstream by its wire protocol, so a proxy serves
**one upstream per wire protocol**. `upstreams` sets it explicitly and names it:

```python
upstreams={
    "openai": Upstream("https://api.deepseek.com", name="deepseek"),
    "anthropic": Upstream("https://api.anthropic.com"),   # name defaults to "anthropic"
}
```

`Upstream(url, name=None)` is the **only** form (no string shorthand). `url` must
be an origin, `scheme://host[:port]`: a path, query or credentials in it raises
`ValueError` at construction, so there are no path prefixes. Keys are
wire-protocol names.

**Precedence**, highest first: `upstreams=`, then the
`PANOPTES_UPSTREAM_ANTHROPIC` / `_OPENAI` / `_GEMINI` environment variables, then
the provider's public API. `upstreams=` therefore overrides the environment.

`Exchange.provider` is always the wire protocol; `upstream_name` is the
operator's label and `upstream_url` the origin. Panoptes attaches no meaning to
the name. A hook maps `(provider, upstream_name)` to whatever it calls the
provider.

## Sharing the audit file and its chain

`ProxyServer(db=<AuditDB>)` makes the proxy write through an `AuditDB` the caller
owns, so a hook's own sink and the proxy share one object. The proxy neither
migrates nor closes it. `db=` and `db_path=` are mutually exclusive; `chain=`
applies only when the proxy opens `db_path` itself.

Two `AuditDB` handles on one file also stay on **one chain**, so `db=` is a
convenience rather than a requirement. The chain tip is never cached on the
`AuditDB` object: every insert reads it from the database inside a
`BEGIN IMMEDIATE` transaction, so concurrent writers, from one process or
several, serialize on the file and extend the same chain.
`test_concurrent_batches_across_db_instances_do_not_fork_chain` exercises this. A
hook's decision events and the proxy's exchange events can therefore live in one
file under one chain and be joined on `run_id` and `exchange_id`.

## Concurrency and starvation

Hooks run in the proxy's request threads and are called concurrently. They must
be thread-safe.

The proxy serves at most `max_concurrent_requests` (default 64) requests at
once; when every slot is taken it answers new connections **503 "Proxy request
capacity reached"**. A hook holds its slot for as long as it runs, `before_forward`
before the upstream call and `after_exchange` after the response. A hook that
blocks, for example on a lock or a slow network call, can therefore **starve the
proxy**: 64 stuck hooks mean every new request gets 503.

Panoptes does not time-box a hook. A running Python function cannot be
interrupted safely, and abandoning it on a timer would let it keep mutating an
exchange that `after_exchange` has already settled. The contract is instead:

- keep hooks fast, and give any I/O they do its own timeout;
- never call the model API through the same proxy from a hook;
- Panoptes logs a warning when a hook takes longer than `hook_slow_seconds`
  (default 5), so a stuck hook is visible before it exhausts the slots.

With no hooks the proxy does no extra work. With hooks, the cost is the
`Exchange` construction (deep copies of the request events) per request.

## Recorded events

A hook decides; Panoptes records what it observed. Events of an exchange carry
`correlation_id`, `attributes.exchange_id`, `attributes.correlation_source`,
`attributes.identity`, and, when a hook acted, `attributes.hook`. They never
carry header values or query credentials. If your hook also writes its own
records (a decision log), join them to Panoptes' events on `exchange_id`.

## Not in this contract

- **Response-side hooks.** Inspecting or withholding a response (for example to
  block a tool call in a streamed answer) needs buffering and is a separate,
  opt-in hook that does not exist yet.
- **Multiple hooks.** One `ProxyHooks` object per proxy. Compose several in your
  own class.
- **Enforced hook timeouts.**
- **Several upstreams for one wire protocol** in a single proxy, and upstream
  path prefixes.
