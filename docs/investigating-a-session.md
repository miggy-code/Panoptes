# Investigating a session

This walkthrough records a short agent session and then investigates it. It
uses a fake upstream on your machine, so it needs no API key and makes no
paid model calls.

You will:

1. Start a fake Anthropic upstream and the Panoptes proxy.
2. Send two requests: one where the model proposes a tool call, and one where
   the client reports the tool result.
3. Read the session timeline and the evidence for one event.
4. Verify the hash chain against a stored checkpoint.

## Before you start

Install Panoptes with the proxy extra:

```bash
pipx install 'panoptes-observe[proxy]'
```

Make an empty working directory and go into it:

```bash
mkdir panoptes-demo && cd panoptes-demo
```

## 1. Start a fake upstream and the proxy

Save this script as `fake_upstream.py`. It answers every request with the same
Anthropic Messages reply. The reply proposes one `terminal` tool call.

```python
import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

REPLY = {
    "id": "msg_demo", "type": "message", "role": "assistant",
    "model": "claude-example",
    "content": [
        {"type": "text", "text": "I'll list the pods."},
        {"type": "tool_use", "id": "toolu_demo1", "name": "terminal",
         "input": {"command": "kubectl get pods -n prod"}},
    ],
    "stop_reason": "tool_use",
    "usage": {"input_tokens": 812, "output_tokens": 46},
}


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        self.rfile.read(int(self.headers["content-length"]))
        body = json.dumps(REPLY).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


HTTPServer(("127.0.0.1", int(sys.argv[1])), Handler).serve_forever()
```

Start the fake upstream in the background:

```bash
python fake_upstream.py 9911 &
```

Start the proxy. `PANOPTES_UPSTREAM_ANTHROPIC` sends Anthropic traffic to the
fake upstream instead of the real API:

```bash
PANOPTES_UPSTREAM_ANTHROPIC=http://127.0.0.1:9911 \
  panoptes proxy --port 8091 --db-path demo.db &
```

## 2. Send two requests

Send the first request. The `X-Panoptes-Session` header puts both requests in
one session. The API key is a placeholder; the fake upstream ignores it.

```bash
curl -s http://127.0.0.1:8091/v1/messages \
  -H 'content-type: application/json' \
  -H 'anthropic-version: 2023-06-01' \
  -H 'x-api-key: sk-ant-placeholder-0000000000000000' \
  -H 'X-Panoptes-Session: demo-session' \
  -H 'X-Panoptes-Agent: claude_code' \
  -d '{"model": "claude-example", "max_tokens": 256,
       "messages": [{"role": "user", "content": "What is running in prod?"}],
       "tools": [{"name": "terminal", "description": "Run a shell command",
                  "input_schema": {"type": "object",
                                   "properties": {"command": {"type": "string"}}}}]}'
```

Send the second request. It contains the tool result, as a real client would
send it after it runs the command:

```bash
curl -s -o /dev/null http://127.0.0.1:8091/v1/messages \
  -H 'content-type: application/json' \
  -H 'anthropic-version: 2023-06-01' \
  -H 'x-api-key: sk-ant-placeholder-0000000000000000' \
  -H 'X-Panoptes-Session: demo-session' \
  -H 'X-Panoptes-Agent: claude_code' \
  -d '{"model": "claude-example", "max_tokens": 256,
       "messages": [
         {"role": "user", "content": "What is running in prod?"},
         {"role": "assistant", "content": [{"type": "tool_use", "id": "toolu_demo1",
           "name": "terminal", "input": {"command": "kubectl get pods -n prod"}}]},
         {"role": "user", "content": [{"type": "tool_result",
           "tool_use_id": "toolu_demo1", "content": "api-7d9f 1/1 Running"}]}],
       "tools": [{"name": "terminal", "description": "Run a shell command",
                  "input_schema": {"type": "object",
                                   "properties": {"command": {"type": "string"}}}}]}'
```

Stop both background processes:

```bash
kill %1 %2
```

## 3. Read the timeline

Show the event counts:

```bash
panoptes status --db-path demo.db
```

```text
Total events: 7

By agent:
  claude_code: 7

By type:
  model_request: 2
  model_response: 2
  tool_call: 2
  tool_result: 1

Schema version: 5
```

Show the session timeline:

```bash
panoptes session demo-session --db-path demo.db
```

The output looks like this. Your IDs and times will be different. Long ID lines
are shortened here:

```text
Session: demo-session (7 of 7 events)
Chronological order; tool proposals and authorizations do not prove execution.
2026-11-23T20:07:34.246Z  model_request  claude-example  SUCCESS
  id=3ca0ebeb… run=5414fcd0… exchange=1b0d5af0… correlation=1b0d5af0…
  via=http_proxy

2026-11-23T20:07:34.252Z  model_response  claude-example  SUCCESS (6 ms)
  id=453e9877… run=5414fcd0… exchange=1b0d5af0… correlation=1b0d5af0…
  HTTP 200 | via=http_proxy

2026-11-23T20:07:34.252Z  tool_call  terminal  PENDING
  id=9de60de1… run=5414fcd0… exchange=1b0d5af0… correlation=1b0d5af0… call=toolu_demo1
  command=kubectl get pods -n prod | Model proposed this tool call; local execution was not observed | via=http_proxy | execution=not observed

2026-11-23T20:07:34.266Z  model_request  claude-example  SUCCESS
  id=34aa5369… run=44efae0f… exchange=2e4e33d5… correlation=2e4e33d5…
  via=http_proxy

2026-11-23T20:07:34.266Z  tool_result  unknown  SUCCESS
  id=8e8f3a89… run=44efae0f… exchange=2e4e33d5… correlation=2e4e33d5… call=toolu_demo1
  api-7d9f 1/1 Running | via=http_proxy | execution=client-reported
...
```

Read the timeline like this:

- **Each exchange has its own `exchange` ID.** The first three events come
  from the first request. The next events come from the second request.
- **The `tool_call` is `PENDING`.** The model proposed the command. The proxy
  did not see it run, so the event says `execution=not observed`.
- **The `tool_result` says `execution=client-reported`.** The client sent the
  result in its next request. Panoptes records that claim. It cannot prove
  that the command ran or that the output is real.
- **The `call` ID links the proposal to the result.** Both events carry
  `call=toolu_demo1`. The second response proposes the same call again,
  because the fake upstream always sends the same reply.

To get the full stored events, add `--json`. The JSON output also has
`selected_count`, `matching_count`, and `partial`.

## 4. Follow the evidence for one event

Copy the full `id` of the `tool_result` event from the timeline. Then run
`evidence` with it:

```bash
panoptes evidence <tool-result-event-id> --db-path demo.db
```

```text
Evidence chain for 8e8f3a89… (5 steps):
Related recorded events; correlation does not prove causality or execution.
2026-11-23T20:07:34.252Z  tool_call  terminal  PENDING
...
2026-11-23T20:07:34.266Z  tool_result  unknown  SUCCESS
...
```

`evidence` selects related events from the same session. It uses the call and
run IDs first. If those are not available, it uses nearby turns and times.
The result helps an investigation. It is not a causal trace.

## 5. Verify the history

Verify the local hash chain:

```bash
panoptes verify --db-path demo.db
```

The result includes `"chain": "intact"` and `"valid": true`.

Save a checkpoint. In real use, keep this file outside the database host, in a
place that the agent cannot change:

```bash
panoptes checkpoint --db-path demo.db > checkpoint.json
```

Later, check that the history only grew after the checkpoint:

```bash
panoptes verify --db-path demo.db --checkpoint checkpoint.json
```

The result includes `"valid": true` and the number of `appended_events`.

The local chain finds changes to stored events. It cannot find a full rewrite
of the history. A checkpoint stored somewhere else can find that rewrite. For
details, read the hash chain section in [api.md](api.md#hash-chain).

## What this walkthrough shows

| Question | Where the answer is |
|---|---|
| What did the model propose? | `tool_call` events, status `pending` |
| What did the client say happened? | `tool_result` events, `execution=client-reported` |
| Which events belong to one request? | The `exchange` ID |
| Which proposal matches which result? | The `call` ID |
| Did the stored history change? | `panoptes verify --checkpoint` |

To capture a real session, point your agent at the proxy with a stable
`X-Panoptes-Session` value. Then use the same commands.
