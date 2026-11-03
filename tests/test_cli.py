"""CLI behavior for the read, integrity and setup commands."""

import json

import pytest

from panoptes import __version__
from panoptes.cli import main
from panoptes.db import AuditDB
from panoptes.schema import SCHEMA_VERSION


def _event(event_id: str) -> dict:
    return {
        "event_id": event_id,
        "timestamp": "2026-07-17T12:00:00.000Z",
        "agent": {"type": "hermes", "session_id": "s1", "run_id": "r1"},
        "event_type": "model_request",
        "action": {},
        "outcome": {"status": "success"},
        "context": {},
    }


def test_version_command_reports_installed_distribution(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])

    assert exc.value.code == 0
    assert capsys.readouterr().out == f"panoptes {__version__}\n"


def test_verify_and_checkpoint_commands(tmp_path, capsys):
    db_path = tmp_path / "audit.db"
    db = AuditDB(str(db_path))
    db.insert_event(_event("event-1"))
    expected_head = db.get_chain_checkpoint()["head"]
    db.close()

    main(["verify", "--db-path", str(db_path)])
    verified = json.loads(capsys.readouterr().out)
    assert verified["valid"] is True

    main(["checkpoint", "--db-path", str(db_path)])
    checkpoint = json.loads(capsys.readouterr().out)
    assert checkpoint["head"] == expected_head
    assert checkpoint["event_count"] == 1


def test_verify_exits_nonzero_after_tampering(tmp_path):
    db_path = tmp_path / "audit.db"
    db = AuditDB(str(db_path))
    db.insert_event(_event("event-1"))
    conn = db._get_conn()
    try:
        conn.execute(
            "UPDATE events SET outcome = ? WHERE event_id = ?",
            ('{"status":"blocked"}', "event-1"),
        )
        conn.commit()
    finally:
        db._put_conn(conn)
        db.close()

    with pytest.raises(SystemExit) as exc:
        main(["verify", "--db-path", str(db_path)])
    assert exc.value.code == 1

    with pytest.raises(SystemExit) as exc:
        main(["checkpoint", "--db-path", str(db_path)])
    assert exc.value.code == 1


def test_verify_checkpoint_cli_accepts_prefix_and_rejects_forgery(
    tmp_path, capsys
):
    db_path = tmp_path / "audit.db"
    checkpoint_path = tmp_path / "checkpoint.json"
    db = AuditDB(str(db_path))
    db.insert_event(_event("event-1"))
    checkpoint = db.get_chain_checkpoint()
    checkpoint_path.write_text(json.dumps(checkpoint), encoding="utf-8")
    db.insert_event(_event("event-2"))
    db.close()

    main([
        "verify",
        "--db-path",
        str(db_path),
        "--checkpoint",
        str(checkpoint_path),
    ])
    verified = json.loads(capsys.readouterr().out)
    assert verified["valid"] is True
    assert verified["exact"] is False
    assert verified["appended_events"] == 1

    checkpoint["head"] = "0" * 64
    checkpoint_path.write_text(json.dumps(checkpoint), encoding="utf-8")
    with pytest.raises(SystemExit) as exc:
        main([
            "verify",
            "--db-path",
            str(db_path),
            "--checkpoint",
            str(checkpoint_path),
        ])
    assert exc.value.code == 1


@pytest.mark.parametrize(
    "argv",
    [
        ["query"],
        ["status"],
        ["session", "session-1"],
        ["evidence", "event-1"],
        ["verify"],
        ["checkpoint"],
        ["doctor"],
    ],
)
def test_read_only_commands_refuse_missing_database(argv, tmp_path, capsys):
    missing = tmp_path / "typo.db"

    with pytest.raises(SystemExit) as exc:
        main([*argv, "--db-path", str(missing)])

    assert exc.value.code == 2
    assert not missing.exists()
    assert "not found or not initialized" in capsys.readouterr().err


def test_read_only_command_does_not_initialize_empty_file(tmp_path, capsys):
    empty = tmp_path / "empty.db"
    empty.touch()

    with pytest.raises(SystemExit) as exc:
        main(["verify", "--db-path", str(empty)])

    assert exc.value.code == 2
    assert empty.read_bytes() == b""
    assert "not found or not initialized" in capsys.readouterr().err


def _write_events(db_path, *event_ids):
    db = AuditDB(str(db_path))
    for event_id in event_ids:
        db.insert_event(_event(event_id))
    db.close()


def test_verify_reads_a_read_only_copy_without_changing_it(tmp_path, capsys):
    db_path = tmp_path / "audit.db"
    _write_events(db_path, "event-1")
    db_path.chmod(0o444)
    before = db_path.read_bytes()

    try:
        main(["verify", "--db-path", str(db_path)])
    finally:
        db_path.chmod(0o600)

    assert json.loads(capsys.readouterr().out)["valid"] is True
    assert db_path.read_bytes() == before


def test_verify_never_re_anchors_a_stripped_chain(tmp_path, capsys):
    import sqlite3

    db_path = tmp_path / "audit.db"
    _write_events(db_path, "event-1", "event-2")
    conn = sqlite3.connect(db_path)
    conn.execute("UPDATE events SET prev_hash = NULL, event_hash = NULL")
    conn.execute("DELETE FROM chain_meta")
    conn.execute(
        "UPDATE events SET outcome = ? WHERE event_id = 'event-1'",
        ('{"status": "blocked"}',),
    )
    conn.commit()
    conn.close()

    with pytest.raises(SystemExit) as exc:
        main(["verify", "--db-path", str(db_path)])
    assert exc.value.code == 1
    result = json.loads(capsys.readouterr().out)
    assert result["valid"] is False
    assert result["chain"] == "broken"
    assert "missing" in result["error"]

    # A writer refuses to bless the stripped history with a fresh anchor.
    from panoptes.db import ChainIntegrityError

    with pytest.raises(ChainIntegrityError):
        AuditDB(str(db_path))


def test_session_timeline_keeps_order_correlations_and_execution_boundaries(tmp_path, capsys):
    from panoptes.capture import PROXY_CAPABILITIES

    db_path = tmp_path / "audit.db"
    db = AuditDB(str(db_path))
    events = []
    for event_id, kind, status in (
        ("request", "model_request", "success"),
        ("proposal", "tool_call", "pending"),
        ("decision", "decision_point", "blocked"),
        ("result", "tool_result", "error"),
    ):
        event = _event(event_id)
        event["event_type"] = kind
        event["action"] = {
            "tool_name": "bash", "call_id": "call-1",
            "parameters": {"command": "echo hello"},
        }
        event["outcome"] = {"status": status, "summary": "Run bash\n\x1b[31m sk-proj-fake-secret-01234567890123456789"}
        event["context"] = {"capture": PROXY_CAPABILITIES.as_context()}
        if kind == "model_request":
            event["context"]["policy"] = "adapter-defined extension"
        if kind == "tool_call":
            event["action"]["execution_scope"] = {}
        if kind == "decision_point":
            event["context"].update({
                "decision_kind": "tool_authorization", "source_event_id": "proposal",
                "policy": {"action": "block", "matched_policies": [{"policy_name": "no-bash"}]},
            })
        if kind == "tool_result":
            event["action"]["duration_ms"] = 123
            event["context"]["capture"]["inspection_status"] = "incomplete"
        events.append(event)
    db.insert_events(events)
    db.close()
    before = db_path.read_bytes()

    main(["session", "s1", "--db-path", str(db_path)])
    output = capsys.readouterr().out
    assert "4 of 4 events" in output
    assert output.index("id=request") < output.index("id=proposal") < output.index("id=decision") < output.index("id=result")
    assert "authorization bash  BLOCKED" in output
    assert "execution=not observed" in output
    assert "execution=client-reported" in output
    assert "(123 ms)" in output
    assert "event policy=block [no-bash]" in output
    assert "command=echo hello" in output
    assert "call=call-1" in output and "source=proposal" in output and "run=r1" in output
    assert "inspection=incomplete" in output
    assert "\x1b" not in output
    assert "sk-proj-fake-secret" not in output
    assert db_path.read_bytes() == before


def test_session_partial_selection_json_and_empty_session(tmp_path, capsys):
    db_path = tmp_path / "audit.db"
    _write_events(db_path, "one", "two", "three")
    argv = ["session", "s1", "--db-path", str(db_path), "--limit", "2"]
    main(argv)
    output = capsys.readouterr().out
    assert "2 of 3 events; showing the newest 2; partial timeline" in output
    assert "id=one" not in output
    assert output.index("id=two") < output.index("id=three")

    main([*argv, "--json"])
    data = json.loads(capsys.readouterr().out)
    assert data["selected_count"] == 2 and data["matching_count"] == 3
    assert data["partial"] is True
    assert [event["event_id"] for event in data["events"]] == ["two", "three"]

    main(["session", "missing", "--db-path", str(db_path), "--json"])
    data = json.loads(capsys.readouterr().out)
    assert data["events"] == [] and data["matching_count"] == 0
    assert data["partial"] is False


@pytest.mark.parametrize("argv", [
    ["token", "list"],
    ["policy", "check"],
    ["policy", "list"],
    ["proxy", "--inject-credentials"],
    ["proxy", "--policies-dir", "p"],
    ["proxy", "--policy-failure-mode", "fail_closed"],
    ["doctor", "--credentials-file", "keys.yaml"],
])
def test_the_gateway_commands_and_options_are_gone(argv, capsys):
    with pytest.raises(SystemExit) as exc:
        main(argv)
    assert exc.value.code == 2
    assert "usage:" in capsys.readouterr().err


def test_credential_injection_is_not_part_of_the_package():
    import importlib.util

    from panoptes.proxy import ProxyServer

    assert importlib.util.find_spec("panoptes.credentials") is None
    with pytest.raises(TypeError):
        ProxyServer(port=0, provider_keys={"openai": "k"})


def test_doctor_checks_storage_and_capture_without_writing(tmp_path, monkeypatch, capsys):
    db_path = tmp_path / "audit.db"
    _write_events(db_path, "recent-event")
    before = db_path.read_bytes()
    mode = db_path.stat().st_mode
    monkeypatch.setattr(AuditDB, "insert_events", lambda *args: pytest.fail("doctor wrote audit events"))

    main(["doctor", "--db-path", str(db_path)])

    captured = capsys.readouterr()
    assert f"[OK] Database: schema {SCHEMA_VERSION}, 1 events" in captured.out
    assert "Last audit event: 2026-07-17" in captured.out
    assert "client routing, and direct egress are not verified" in captured.out
    assert "olicies" not in captured.out and "redential" not in captured.out
    assert db_path.read_bytes() == before
    assert db_path.stat().st_mode == mode


def test_doctor_reports_an_unavailable_database_without_creating_it(tmp_path, capsys):
    db_path = tmp_path / "missing.db"
    with pytest.raises(SystemExit) as exc:
        main(["doctor", "--db-path", str(db_path)])
    assert exc.value.code == 2
    assert "[ERROR] Database" in capsys.readouterr().out
    assert not db_path.exists()


def test_doctor_flags_a_database_with_no_recorded_activity(tmp_path, capsys):
    db_path = tmp_path / "audit.db"
    AuditDB(str(db_path)).close()
    main(["doctor", "--db-path", str(db_path)])
    assert "[WARN] Capture: no recorded activity" in capsys.readouterr().out
