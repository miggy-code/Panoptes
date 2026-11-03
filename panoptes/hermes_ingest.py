"""Receive native Hermes observations in a separate, protected Panoptes process."""
import json
import threading
import time
from http.server import BaseHTTPRequestHandler
from pathlib import Path

from ._json import _strict_json_loads
from .hermes_hooks import HOOKS, LegacyHooks, normalize, record_detail
from .hermes_plugin import AuditPlugin
from .schema import redact_secrets
from ._server import BoundedThreadingHTTPServer


def make_server(address, db_path, journal_path=None):
    plugin = AuditPlugin(db_path=str(db_path), policies_dir=None)
    hooks = LegacyHooks()
    plugin.register(hooks)
    journal = Path(journal_path) if journal_path else None
    lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            if self.path != '/lifecycle':
                self.send_error(404); return
            try:
                length = int(self.headers.get('Content-Length', '0'))
                if not 0 < length <= 65536:
                    raise ValueError('invalid length')
                payload = _strict_json_loads(self.rfile.read(length))
                hook = payload['hook']
                if hook not in HOOKS or not isinstance(payload['data'], dict):
                    raise ValueError('invalid hook')
                if HOOKS[hook] is None:
                    if journal is not None:
                        payload['observed_at'] = time.time()
                        with lock, journal.open('a', encoding='utf-8') as stream:
                            stream.write(json.dumps(redact_secrets(payload), sort_keys=True) + '\n')
                    record_detail(hooks.callbacks, hook, payload['data'])
                else:
                    hooks.callbacks[HOOKS[hook]](normalize(hook, payload['data']))
            except (ValueError, KeyError, TypeError):
                self.send_error(400); return
            self.send_response(204); self.end_headers()

        def log_message(self, *args):
            pass

    return BoundedThreadingHTTPServer(address, Handler, client_socket_timeout_seconds=5, max_concurrent_requests=32)
