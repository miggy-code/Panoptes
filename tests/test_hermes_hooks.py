"""Current Hermes hooks use the actual Panoptes observation implementation."""
import json
import threading

from panoptes.db import AuditDB
from panoptes.hermes_hooks import register
from panoptes.hermes_ingest import make_server


class CurrentContext:
    def __init__(self):
        self.hooks = {}

    def register_hook(self, name, callback):
        self.hooks[name] = callback


def test_current_hermes_hooks_record_through_protected_sink(tmp_path, monkeypatch):
    db_path = tmp_path / 'audit.sqlite'
    journal = tmp_path / 'hermes-events.jsonl'
    server = make_server(('127.0.0.1', 0), db_path, journal)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setenv('PANOPTES_HERMES_SINK', f'http://127.0.0.1:{server.server_port}/lifecycle')
    ctx = CurrentContext()
    try:
        register(ctx)
        ctx.hooks['on_session_start'](session_id='root')
        ctx.hooks['post_tool_call'](session_id='root', tool_name='skill_view', args={'name': 'orders'}, status='success')
        ctx.hooks['subagent_start'](parent_session_id='root', child_session_id='child')
        ctx.hooks['pre_api_request'](session_id='child', model='test', request_messages=[{'role': 'user', 'content': 'sensitive prompt'}])
        ctx.hooks['on_session_end'](session_id='root')
        ctx.hooks['on_session_finalize'](session_id='root')
        db = AuditDB(str(db_path))
        try:
            events = db.query(agent_type='hermes', session_id='root')
            assert {e['event_type'] for e in events} == {'agent_start', 'agent_step', 'agent_end'}
            assert any(e['event_type'] == 'agent_step' and e['action']['tool_name'] == 'skill_view' for e in events)
        finally:
            db.close()
        records = [json.loads(line) for line in journal.read_text().splitlines()]
        assert [r['hook'] for r in records] == ['subagent_start', 'pre_api_request']
        assert records[0]['data']['child_session_id'] == 'child'
        assert 'sensitive prompt' not in journal.read_text()
        assert len(records[1]['data']['messages'][0]) == 16
    finally:
        server.shutdown(); thread.join(); server.server_close()


def test_current_hermes_hooks_support_direct_local_capture(tmp_path, monkeypatch):
    from panoptes.hermes_plugin import AuditPlugin
    plugin = AuditPlugin(db_path=str(tmp_path / 'local.sqlite'), policies_dir=None)
    monkeypatch.delenv('PANOPTES_HERMES_SINK', raising=False)
    monkeypatch.setattr('panoptes.hermes_plugin.get_plugin', lambda: plugin)
    ctx = CurrentContext()
    try:
        register(ctx)
        ctx.hooks['on_session_start'](session_id='local')
        ctx.hooks['on_session_end'](session_id='local')
        ctx.hooks['on_session_finalize'](session_id='local')
        assert {e['event_type'] for e in plugin.db.query(session_id='local')} == {'agent_start', 'agent_step', 'agent_end'}
    finally:
        plugin.db.close()


def test_multiple_turns_preserve_same_lifecycle_run(tmp_path, monkeypatch):
    from panoptes.hermes_plugin import AuditPlugin
    plugin = AuditPlugin(db_path=str(tmp_path / 'multi.sqlite'), policies_dir=None)
    monkeypatch.delenv('PANOPTES_HERMES_SINK', raising=False)
    monkeypatch.setattr('panoptes.hermes_plugin.get_plugin', lambda: plugin)
    ctx = CurrentContext()
    try:
        register(ctx)
        ctx.hooks['on_session_start'](session_id='multi')
        ctx.hooks['on_session_end'](session_id='multi')
        ctx.hooks['post_tool_call'](session_id='multi', tool_name='skill_view', args={}, status='success')
        ctx.hooks['on_session_end'](session_id='multi')
        ctx.hooks['on_session_finalize'](session_id='multi')
        events = plugin.db.query(session_id='multi')
        assert len({event['agent']['run_id'] for event in events}) == 1
        assert sum(event['event_type'] == 'agent_end' for event in events) == 1
    finally:
        plugin.db.close()


def test_local_capture_records_child_links_and_request_fingerprints(tmp_path, monkeypatch):
    from panoptes.hermes_plugin import AuditPlugin
    plugin = AuditPlugin(db_path=str(tmp_path / 'details.sqlite'), policies_dir=None)
    monkeypatch.delenv('PANOPTES_HERMES_SINK', raising=False)
    monkeypatch.setattr('panoptes.hermes_plugin.get_plugin', lambda: plugin)
    ctx = CurrentContext()
    try:
        register(ctx)
        ctx.hooks['on_session_start'](session_id='root')
        ctx.hooks['subagent_start'](parent_session_id='root', child_session_id='child')
        ctx.hooks['pre_api_request'](session_id='root', model='test', request_messages=[{'role': 'user', 'content': 'private input'}])
        events = plugin.db.query(session_id='root')
        params = [event['action']['parameters'] for event in events if event['event_type'] == 'agent_step']
        assert any(p.get('hook') == 'subagent_start' and p.get('child_session_id') == 'child' for p in params)
        assert any(p.get('hook') == 'pre_api_request' and len(p['messages'][0]) == 16 for p in params)
        assert 'private input' not in json.dumps(events)
    finally:
        plugin.db.close()


def test_sink_rejects_duplicate_json_keys(tmp_path):
    from urllib.error import HTTPError
    from urllib.request import Request, urlopen
    import pytest
    server = make_server(('127.0.0.1', 0), tmp_path / 'audit.sqlite')
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        body = b'{"hook":"on_session_start","hook":"on_session_end","data":{"session_id":"a"}}'
        request = Request(f'http://127.0.0.1:{server.server_port}/lifecycle', body, {'Content-Type': 'application/json'})
        with pytest.raises(HTTPError) as error:
            urlopen(request)
        assert error.value.code == 400
    finally:
        server.shutdown(); thread.join(); server.server_close()
