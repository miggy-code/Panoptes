"""A small threaded HTTP server with bounded workers and a per-client timeout.

Shared by the reverse proxy and the Hermes ingest endpoint. It imports no HTTP
client, so the ingest side loads without the ``[proxy]`` extra.
"""

from __future__ import annotations

import http.server
import threading


class BoundedThreadingHTTPServer(http.server.ThreadingHTTPServer):
    """Threaded HTTP server with bounded workers and per-client I/O timeout."""

    daemon_threads = True

    def __init__(
        self,
        server_address: tuple[str, int],
        request_handler: type[http.server.BaseHTTPRequestHandler],
        *,
        client_socket_timeout_seconds: float,
        max_concurrent_requests: int,
    ) -> None:
        self.client_socket_timeout_seconds = client_socket_timeout_seconds
        self._request_slots = threading.BoundedSemaphore(max_concurrent_requests)
        self._in_flight = 0
        self._idle = threading.Condition()
        super().__init__(server_address, request_handler)

    def wait_idle(self, timeout: float) -> bool:
        """Wait until no request is being served. False if *timeout* passed."""
        with self._idle:
            return self._idle.wait_for(lambda: self._in_flight == 0, timeout)

    def get_request(self):
        request, client_address = super().get_request()
        request.settimeout(self.client_socket_timeout_seconds)
        return request, client_address

    def process_request(self, request, client_address) -> None:
        if not self._request_slots.acquire(blocking=False):
            try:
                request.sendall(
                    b"HTTP/1.1 503 Service Unavailable\r\n"
                    b"Connection: close\r\n"
                    b"Content-Type: text/plain\r\n"
                    b"Content-Length: 30\r\n\r\n"
                    b"Proxy request capacity reached"
                )
            except OSError:
                pass
            finally:
                self.shutdown_request(request)
            return
        with self._idle:
            self._in_flight += 1
        try:
            super().process_request(request, client_address)
        except Exception:
            self._request_done()
            raise

    def process_request_thread(self, request, client_address) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._request_done()

    def _request_done(self) -> None:
        self._request_slots.release()
        with self._idle:
            self._in_flight -= 1
            self._idle.notify_all()
