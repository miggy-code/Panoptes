"""Native Hermes plugin hooks for local Panoptes or a protected observation sink.

Hermes lifecycle hooks are host-reported observations, not proof of execution.
"""
import hashlib
import json
import os
from urllib.request import Request, urlopen

HOOKS = {'on_session_start': 'agent:start', 'post_tool_call': 'agent:step', 'on_session_end': 'agent:step', 'on_session_finalize': 'agent:end',
         'subagent_start': None, 'subagent_stop': None, 'pre_api_request': None}


def normalize(hook, data):
    session = data.get('session_id')
    if not isinstance(session, str) or not session:
        raise ValueError('lifecycle event requires a session id')
    event = {'session_id': session, 'platform': data.get('platform') or 'cli'}
    if hook == 'post_tool_call':
        event.update(tool_names=[data.get('tool_name')], tool_input=data.get('args') or {},
                     outcome_status='success' if data.get('status') in ('success', 'ok') else 'error')
    elif hook == 'on_session_end':
        event.update(tool_names=[], outcome_status='error' if data.get('failed') or data.get('interrupted') else 'success',
                     outcome_summary='Hermes conversation turn ended')
    elif hook == 'on_session_finalize':
        event['outcome_status'] = 'error' if data.get('failed') or data.get('interrupted') else 'success'
    elif hook != 'on_session_start':
        raise ValueError('unknown lifecycle hook')
    return event


class LegacyHooks:
    """Collect the established Panoptes lifecycle handlers for the current Hermes API."""
    def __init__(self):
        self.callbacks = {}

    def on(self, name):
        def bind(callback):
            self.callbacks[name] = callback
            return callback
        return bind


def request_fingerprint(data):
    messages = data.get('request_messages') or []
    history = [m for m in messages if isinstance(m, dict) and m.get('role') not in ('system', 'developer')]
    result = {k: data.get(k) for k in ('session_id', 'turn_id', 'api_request_id', 'model')}
    result['messages'] = [hashlib.sha256(json.dumps(m, sort_keys=True).encode()).hexdigest()[:16] for m in history]
    return result


def record_detail(callbacks, hook, data):
    """Preserve child identity and model-request fingerprints as host-reported steps."""
    session = data.get('session_id') if hook == 'pre_api_request' else data.get('parent_session_id')
    if isinstance(session, str) and session:
        callbacks['agent:step']({'session_id': session, 'tool_names': [], 'tool_input': {'hook': hook, **data},
                                 'outcome_status': 'success', 'outcome_summary': 'Hermes reported ' + hook})
    if hook == 'subagent_stop' and data.get('child_session_id'):
        callbacks['agent:end']({'session_id': data['child_session_id'],
                                'outcome_status': 'success' if data.get('child_status') == 'completed' else 'error'})


def register(ctx):
    """Register with Hermes' current PluginContext. An optional sink isolates the audit store."""
    endpoint = os.environ.get('PANOPTES_HERMES_SINK')
    if endpoint:
        def deliver(hook, data):
            body = json.dumps({'hook': hook, 'data': data}, default=str).encode()
            request = Request(endpoint, body, {'Content-Type': 'application/json'})
            with urlopen(request, timeout=3) as response:
                if response.status != 204:
                    raise RuntimeError('Panoptes observation sink rejected event')
    else:
        from panoptes.hermes_plugin import get_plugin
        legacy = LegacyHooks()
        get_plugin().register(legacy)
        def deliver(hook, data):
            if HOOKS[hook] is not None:
                legacy.callbacks[HOOKS[hook]](normalize(hook, data))
            else:
                record_detail(legacy.callbacks, hook, data)

    def callback(hook):
        def observe(**data):
            deliver(hook, request_fingerprint(data) if hook == 'pre_api_request' else data)
        return observe

    for hook in HOOKS:
        ctx.register_hook(hook, callback(hook))
