"""A scriptable model API upstream for proxy tests.

``FakeUpstream`` is a real HTTP server on a free loopback port. Each ``mode``
answers one way: a normal JSON reply, an SSE stream, a stalled or dropped
connection, an oversized body. ``mode = "raw"`` serves ``raw`` as given.
"""

import http.server
import json
import threading
import time

BODY = {
    "model": "claude-test",
    "max_tokens": 8,
    "messages": [{"role": "user", "content": "hello"}],
}
RESPONSE = {
    "id": "msg_1",
    "type": "message",
    "role": "assistant",
    "model": "claude-test",
    "content": [{"type": "text", "text": "hi"}],
    "usage": {"input_tokens": 3, "output_tokens": 1},
}
SSE_HEAD = (
    b"event: message_start\n"
    b'data: {"type":"message_start","message":{"id":"msg_1","type":"message",'
    b'"role":"assistant","content":[],"model":"claude-test","stop_reason":null,'
    b'"usage":{"input_tokens":3,"output_tokens":1}}}\n\n'
    b"event: content_block_start\n"
    b'data: {"type":"content_block_start","index":0,'
    b'"content_block":{"type":"text","text":""}}\n\n'
    b"event: content_block_delta\n"
    b'data: {"type":"content_block_delta","index":0,'
    b'"delta":{"type":"text_delta","text":"hi"}}\n\n'
)
SSE_TAIL = (
    b"event: content_block_stop\n"
    b'data: {"type":"content_block_stop","index":0}\n\n'
    b"event: message_delta\n"
    b'data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},'
    b'"usage":{"output_tokens":9}}\n\n'
    b'event: message_stop\ndata: {"type":"message_stop"}\n\n'
)


class FakeUpstream:
    """Records what it receives and answers as configured."""

    def __init__(self):
        self.requests = []
        self.mode = "json"
        self.stream_body = False
        self.piece_delay = 0.05  # between the pieces of a stream's tail
        self.gate = threading.Event()  # releases the tail of a gated stream
        self.head_sent = threading.Event()
        self.stall = threading.Event()  # holds a "stalled" stream silent
        # (status, headers, body) for mode "raw"
        self.raw: tuple[int, list[tuple[str, str]], bytes] = (200, [], b"")
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                length = int(self.headers.get("Content-Length") or 0)
                outer.requests.append(
                    {
                        "path": self.path,
                        "headers": [(k, v) for k, v in self.headers.items()],
                        "body": self.rfile.read(length),
                    }
                )
                if outer.mode == "raw":
                    status, headers, payload = outer.raw
                    self.send_response(status)
                    for name, value in headers:
                        self.send_header(name, value)
                    self.send_header("Content-Length", str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)
                elif outer.mode == "dupkey":
                    payload = b'{"id": "a", "id": "b", "usage": {"input_tokens": 3}}'
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)
                elif outer.mode == "huge":
                    payload = b'{"pad": "' + b"x" * 4096 + b'"}'
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)
                elif outer.mode == "truncated":
                    # A stream that ends after its first events, without a stop.
                    self.send_response(200)
                    self.send_header("Content-Type", "text/event-stream")
                    self.end_headers()
                    self.wfile.write(SSE_HEAD)
                    self.close_connection = True
                elif outer.mode == "hang":
                    outer.gate.wait(10)  # never answers in time
                elif outer.mode == "middrop":
                    self.send_response(200)
                    self.send_header(
                        "Content-Type",
                        "text/event-stream"
                        if outer.stream_body
                        else "application/json",
                    )
                    self.send_header("Content-Length", "400")
                    self.end_headers()
                    self.wfile.write(b'{"id": "msg_1", "content": [{"ty')
                    self.wfile.flush()
                    self.close_connection = True  # 400 promised, 35 sent
                elif outer.mode == "hugenolen":
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(b'{"pad": "' + b"x" * 4096 + b'"}')
                    self.close_connection = True
                elif outer.mode == "nousage":
                    payload = json.dumps(
                        {k: v for k, v in RESPONSE.items() if k != "usage"}
                    ).encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)
                elif outer.mode == "error500nobody":
                    self.send_response(500)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                elif outer.mode == "error500":
                    payload = b'{"error":"boom"}'
                    self.send_response(500)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)
                elif outer.mode == "stalled":
                    self.send_response(200)
                    self.send_header("Content-Type", "text/event-stream")
                    self.end_headers()
                    self.wfile.write(SSE_HEAD)
                    self.wfile.flush()
                    outer.head_sent.set()
                    outer.gate.wait(10)
                    try:
                        for piece in SSE_TAIL.split(b"\n\n")[:2]:
                            self.wfile.write(piece + b"\n\n")
                            self.wfile.flush()
                            time.sleep(0.05)
                        outer.stall.wait(10)  # then goes silent
                    except OSError:
                        pass
                elif outer.mode in ("stream", "gated"):
                    self.send_response(200)
                    self.send_header("Content-Type", "text/event-stream")
                    self.end_headers()
                    self.wfile.write(SSE_HEAD)
                    self.wfile.flush()
                    outer.head_sent.set()
                    if outer.mode == "gated":
                        outer.gate.wait(10)
                    try:
                        # Several writes: the first one after a client leaves
                        # still succeeds locally, a later one fails.
                        for piece in SSE_TAIL.split(b"\n\n"):
                            if piece:
                                self.wfile.write(piece + b"\n\n")
                                self.wfile.flush()
                                time.sleep(outer.piece_delay)
                    except OSError:
                        pass
                else:
                    payload = json.dumps(RESPONSE).encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.port = self.server.server_address[1]
        threading.Thread(
            target=self.server.serve_forever,
            kwargs={"poll_interval": 0.05},
            daemon=True,
        ).start()

    def header(self, index, name):
        return [v for k, v in self.requests[index]["headers"] if k.lower() == name]

    def close(self):
        self.gate.set()
        self.stall.set()
        self.server.shutdown()
        self.server.server_close()
