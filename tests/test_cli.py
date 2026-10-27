"""CLI behavior for integrity and policy-readiness commands."""

import json

import pytest

from panoptes import __version__
from panoptes.cli import main
from panoptes.db import AuditDB
from panoptes.policy import PolicyResult


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
        ["policy", "check"],
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


def test_policy_check_surfaces_evaluation_errors(
    tmp_path, monkeypatch, capsys
):
    db_path = tmp_path / "audit.db"
    db = AuditDB(str(db_path))
    db.insert_event(_event("event-with-policy-error"))
    db.close()

    class _ErrorEngine:
        policy_snapshot_id = "snapshot-test"
        load_errors = []
        policies = [object()]

        def __init__(self, *args, **kwargs):
            pass

        def evaluate(self, event):
            return PolicyResult(
                action="allow",
                evaluation_errors=["condition evaluation failed"],
            )

    monkeypatch.setattr("panoptes.cli.PolicyEngine", _ErrorEngine)

    with pytest.raises(SystemExit) as exc:
        main([
            "policy",
            "check",
            "--db-path",
            str(db_path),
            "--policies-dir",
            str(tmp_path),
        ])

    assert exc.value.code == 2
    captured = capsys.readouterr()
    assert "Policy evaluation incomplete" in captured.out
    assert "No policy violations detected" not in captured.out
    assert "condition evaluation failed" in captured.err


def test_policy_check_labels_bounded_selection_as_partial(
    tmp_path, monkeypatch, capsys
):
    db_path = tmp_path / "audit.db"
    db = AuditDB(str(db_path))
    for index in range(3):
        db.insert_event(_event(f"event-{index}"))
    db.close()

    class _AllowEngine:
        policy_snapshot_id = "snapshot-test"
        load_errors = []
        policies = [object()]

        def __init__(self, *args, **kwargs):
            pass

        def evaluate(self, event):
            return PolicyResult(action="allow")

    monkeypatch.setattr("panoptes.cli.PolicyEngine", _AllowEngine)
    main([
        "policy",
        "check",
        "--db-path",
        str(db_path),
        "--policies-dir",
        str(tmp_path),
        "--limit",
        "1",
    ])

    output = capsys.readouterr().out
    assert "newest 1 of 3 matching events; partial scan" in output
    assert "Checked 1 of 3 matching events" in output


def test_policy_list_exits_nonzero_without_valid_snapshot(tmp_path, capsys):
    with pytest.raises(SystemExit) as exc:
        main(["policy", "list", "--policies-dir", str(tmp_path)])

    assert exc.value.code == 2
    captured = capsys.readouterr()
    assert "No valid policy snapshot" in captured.out
    assert "Policy load error" in captured.err


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
    assert "not initialized" in result["error"]

    # A writer refuses to bless the stripped history with a fresh anchor.
    from panoptes.db import ChainIntegrityError

    with pytest.raises(ChainIntegrityError):
        AuditDB(str(db_path))


def test_policy_add_refuses_a_file_that_breaks_the_policy_set(tmp_path, capsys):
    policies = tmp_path / "policies"
    policies.mkdir()
    (policies / "block.yaml").write_text(
        "name: block-bash\naction: block\nrule:\n  conditions:\n"
        "    - field: action.tool_name\n      operator: ==\n      value: bash\n",
        encoding="utf-8",
    )
    typo = tmp_path / "typo.yaml"
    typo.write_text("name: typo\naction: block\nrul:\n  conditions: []\n", encoding="utf-8")

    with pytest.raises(SystemExit) as exc:
        main(["policy", "add", str(typo), "--policies-dir", str(policies)])
    assert exc.value.code == 1
    assert "was not added" in capsys.readouterr().out
    assert sorted(p.name for p in policies.iterdir()) == ["block.yaml"]

    good = tmp_path / "block.yaml"
    good.write_text((policies / "block.yaml").read_text(encoding="utf-8"), encoding="utf-8")
    with pytest.raises(SystemExit) as exc:
        main(["policy", "add", str(good), "--policies-dir", str(policies)])
    assert exc.value.code == 1
    assert "--force" in capsys.readouterr().out
    main(["policy", "add", str(good), "--policies-dir", str(policies), "--force"])
