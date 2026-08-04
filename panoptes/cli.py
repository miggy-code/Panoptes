"""Panoptes CLI for adapter observations, local audit trails, and policy gates."""

import argparse
import json
import os
from pathlib import Path
import shutil
import sqlite3
import sys

from panoptes.db import AuditDB
from panoptes.policy import DEFAULT_POLICIES_DIR, PolicyEngine


def _open_existing_db(db_path: str) -> AuditDB:
    """Open an initialized audit database without creating one by typo.

    ``AuditDB`` intentionally creates and migrates databases for write paths.
    Read-only CLI commands first probe the path with SQLite's ``mode=ro`` and
    require Panoptes' events table, so a missing or empty path is never silently
    turned into a new audit trail.
    """
    expanded = os.path.expanduser(db_path)
    if expanded == ":memory:" or not os.path.isfile(expanded):
        print(
            f"Audit database not found or not initialized: {expanded}",
            file=sys.stderr,
        )
        raise SystemExit(2)

    connection = None
    try:
        uri = f"{Path(expanded).resolve().as_uri()}?mode=ro"
        connection = sqlite3.connect(uri, uri=True)
        initialized = connection.execute(
            "SELECT 1 FROM sqlite_master "
            "WHERE type = 'table' AND name = 'events'"
        ).fetchone()
    except sqlite3.Error as exc:
        print(f"Cannot read audit database {expanded}: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
    finally:
        if connection is not None:
            connection.close()

    if initialized is None:
        print(
            f"Audit database not found or not initialized: {expanded}",
            file=sys.stderr,
        )
        raise SystemExit(2)
    return AuditDB(expanded)


def cmd_query(args):
    """Query audit events from the database."""
    db = _open_existing_db(args.db_path)
    results = db.query(
        agent_type=args.agent,
        event_type=args.event_type,
        tool_name=args.tool,
        since=args.since,
        until=args.until,
        limit=args.limit,
    )
    if not results:
        print("No events found.")
        return

    for r in results:
        agent = r.get("agent", {}) or {}
        action = r.get("action", {}) or {}
        outcome = r.get("outcome", {}) or {}
        agent_type = agent.get("type", "-")
        tool = action.get("tool_name", "-")
        status = outcome.get("status", "-")
        print(
            f"[{r['timestamp']}] {agent_type} | "
            f"{r['event_type']} | {tool} | {status}"
        )


def cmd_status(args):
    """Show audit database statistics."""
    db = _open_existing_db(args.db_path)
    stats = db.get_stats()
    print(f"Total events: {stats['total_events']}")

    print("\nBy agent:")
    for agent, count in stats.get("events_by_agent", {}).items():
        print(f"  {agent}: {count}")

    print("\nBy type:")
    for etype, count in stats.get("events_by_type", {}).items():
        print(f"  {etype}: {count}")

    if stats.get("schema_version"):
        print(f"\nSchema version: {stats['schema_version']}")


def cmd_session(args):
    """Show a bounded session timeline selection."""
    db = _open_existing_db(args.db_path)
    events = db.get_session(args.session_id)
    total_rows = db.aggregate(
        group_by=[],
        metrics=["count"],
        session_id=args.session_id,
    )
    matching_total = int(total_rows[0]["count"]) if total_rows else 0

    if not events:
        print(f"No events found for session: {args.session_id}")
        return

    selection = f"{len(events)} of {matching_total} events"
    if len(events) < matching_total:
        selection += "; showing the newest 10,000"
    print(f"Session: {args.session_id} ({selection})\n")
    for i, e in enumerate(events, 1):
        print(f"--- Event {i} ---")
        print(json.dumps(e, indent=2, default=str))
        print()


def cmd_evidence(args):
    """Show evidence chain for an event."""
    db = _open_existing_db(args.db_path)
    chain = db.get_evidence_chain(args.event_id)
    if not chain:
        print(f"No evidence chain found for event: {args.event_id}")
        return

    print(f"Evidence chain for {args.event_id} ({len(chain)} steps):")
    for i, e in enumerate(chain, 1):
        outcome = e.get("outcome", {}) or {}
        print(f"\n--- Step {i} ---")
        print(f"[{e['event_type']}] {outcome.get('summary', 'no summary')}")


def cmd_verify(args):
    """Verify the chain, optionally against a separately stored checkpoint."""
    db = _open_existing_db(args.db_path)
    if args.checkpoint:
        checkpoint_path = os.path.expanduser(args.checkpoint)
        try:
            with open(checkpoint_path, "r", encoding="utf-8") as handle:
                checkpoint = json.load(handle)
        except (OSError, json.JSONDecodeError) as exc:
            print(
                f"Cannot read checkpoint {checkpoint_path}: {exc}",
                file=sys.stderr,
            )
            raise SystemExit(2)
        result = db.verify_checkpoint(checkpoint)
    else:
        result = db.verify_chain()
    print(json.dumps(result, indent=2, sort_keys=True))
    if not result.get("valid"):
        raise SystemExit(1)


def cmd_checkpoint(args):
    """Print a checkpoint that can be stored in a separate trust domain."""
    db = _open_existing_db(args.db_path)
    verification = db.verify_chain()
    if not verification.get("valid"):
        print(
            "Refusing to export a checkpoint for an invalid chain: "
            f"{verification.get('error') or 'verification failed'}",
            file=sys.stderr,
        )
        raise SystemExit(1)
    print(json.dumps(db.get_chain_checkpoint(), indent=2, sort_keys=True))


# ── Policy subcommands ────────────────────────────────────────────────────────


def cmd_policy_check(args):
    """Check configured policies against stored events."""
    db = _open_existing_db(args.db_path)
    engine = PolicyEngine(args.policies_dir, db)
    if engine.policy_snapshot_id is None:
        for error in engine.load_errors:
            print(f"Policy load error: {error}", file=sys.stderr)
        raise SystemExit(2)

    results = db.query(
        event_type=args.event_type,
        since=args.since,
        until=args.until,
        limit=args.limit,
    )
    total_rows = db.aggregate(
        group_by=[],
        metrics=["count"],
        event_type=args.event_type,
        since=args.since,
        until=args.until,
    )
    matching_total = int(total_rows[0]["count"]) if total_rows else 0

    if not results:
        print("No events to check.")
        return

    violations = []
    evaluation_errors: list[tuple[dict, str]] = []
    for event in results:
        result = engine.evaluate(event)
        for error in getattr(result, "evaluation_errors", []):
            evaluation_errors.append((event, str(error)))
        if result.action in ("warn", "block"):
            violations.append((event, result))

    if violations:
        print(f"Policy violations found: {len(violations)}")
        for event, result in violations:
            action = event.get("action", {}) or {}
            agent = event.get("agent", {}) or {}
            policy_names = ", ".join(
                vp["policy_name"] for vp in result.violated_policies
            )
            print(
                f"  [{event['timestamp']}] {result.action.upper()}: "
                f"agent={agent.get('type', '?')} "
                f"tool={action.get('tool_name', '?')} "
                f"policies=[{policy_names}]"
            )
    elif not evaluation_errors:
        if len(results) < matching_total:
            print(
                "No policy violations detected in the selected events "
                f"(newest {len(results)} of {matching_total} matching events; "
                "partial scan)."
            )
        else:
            print(
                "No policy violations detected in the selected events "
                f"({len(results)} matching events scanned)."
            )
    else:
        print("Policy evaluation incomplete; no reliable clean result.")

    if evaluation_errors:
        for event, error in evaluation_errors:
            print(
                "Policy evaluation error "
                f"for event {event.get('event_id', '?')}: {error}",
                file=sys.stderr,
            )
    print(
        f"\nChecked {len(results)} of {matching_total} matching events "
        f"against {len(engine.policies)} policies."
    )
    if evaluation_errors:
        raise SystemExit(2)


def cmd_policy_list(args):
    """List all loaded policies."""
    engine = PolicyEngine(args.policies_dir)
    if not engine.policies:
        print("No valid policy snapshot loaded.")
        print(f"Policies directory: {engine._policies_dir}")
        for error in engine.load_errors:
            print(f"Policy load error: {error}", file=sys.stderr)
        raise SystemExit(2)

    print(f"Loaded {len(engine.policies)} policies from {engine._policies_dir}:\n")
    print(f"Snapshot: {engine.policy_snapshot_id}\n")
    for p in engine.policies:
        status = "✓" if p.enabled else "✗ (disabled)"
        scope_str = _format_scope(p.scope)
        print(f"  {status} {p.name}")
        if p.description:
            print(f"     {p.description}")
        print(f"     action: {p.action}")
        print(f"     scope:  {scope_str}")
        print()


def cmd_policy_add(args):
    """Copy a policy YAML file into the policies directory."""
    src = os.path.expanduser(args.source)
    if not os.path.isfile(src):
        print(f"Error: source file not found: {src}")
        sys.exit(1)

    dst_dir = os.path.expanduser(args.policies_dir)
    os.makedirs(dst_dir, exist_ok=True)

    dst = os.path.join(dst_dir, os.path.basename(src))
    shutil.copy2(src, dst)
    print(f"Added policy: {os.path.basename(src)} -> {dst}")
    print("Reload the policy engine to apply changes.")


def cmd_policy_test(args):
    """Test a policy file against a JSON event string."""
    try:
        result = PolicyEngine.test_policy(args.policy_file, args.event_json)
    except ValueError as exc:
        print(f"Error: {exc}")
        sys.exit(1)

    print(f"Policy file: {args.policy_file}")
    print(f"Result:     {result.action.upper()}")
    if result.violated_policies:
        for vp in result.violated_policies:
            print(f"  Policy:   {vp['policy_name']}")
            print(f"  Message:  {vp['message']}")
            print(f"  Reason:   {vp['reason']}")
    else:
        print("  No policy violation — conditions did not match.")
    if result.warnings:
        print("  Warnings:")
        for w in result.warnings:
            print(f"    - {w}")


# ── Helpers ───────────────────────────────────────────────────────────────────


def _format_scope(scope: dict) -> str:
    """Format a policy scope dict for display."""
    parts = []
    agents = scope.get("agents", [])
    if agents:
        parts.append(f"agents={agents}")
    sessions = scope.get("sessions", [])
    if sessions:
        parts.append(f"sessions={sessions}")
    if not parts:
        return "* (all)"
    return ", ".join(parts)


# ── Main CLI ──────────────────────────────────────────────────────────────────


def main(argv=None):
    """Entry point for the panoptes CLI."""
    # Shared options — inherited by subparsers via parents=[...]
    db_opts = argparse.ArgumentParser(add_help=False)
    db_opts.add_argument(
        "--db-path", default="~/.panoptes/audit.db", help="Path to audit database"
    )
    policy_opts = argparse.ArgumentParser(add_help=False)
    policy_opts.add_argument(
        "--policies-dir",
        default=None,
        help="Path to policy definitions directory",
    )

    parser = argparse.ArgumentParser(
        prog="panoptes",
        description="Panoptes — adapter-based agent observability, local audit trails, and policy gates.",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # --- proxy ---
    proxy_parser = subparsers.add_parser(
        "proxy", help="Start the model-API reverse proxy", parents=[db_opts, policy_opts]
    )
    proxy_parser.add_argument("--port", default=8081, type=int, help="Proxy listen port")
    proxy_parser.add_argument(
        "--host", default="127.0.0.1", help="Host to bind to (default: 127.0.0.1)"
    )
    proxy_parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Log level (default: INFO)",
    )
    proxy_parser.add_argument(
        "--policy-failure-mode",
        choices=["fail_open", "fail_closed"],
        default="fail_open",
        help=(
            "Allow or deny traffic when policy loading/evaluation fails "
            "(default: fail_open)"
        ),
    )
    proxy_parser.add_argument(
        "--client-timeout",
        type=float,
        default=30.0,
        help="Seconds allowed for client socket reads/writes (default: 30)",
    )
    proxy_parser.add_argument(
        "--max-concurrent-requests",
        type=int,
        default=64,
        help="Maximum simultaneous proxy requests (default: 64)",
    )

    # --- query ---
    query_parser = subparsers.add_parser(
        "query", help="Query audit events", parents=[db_opts]
    )
    query_parser.add_argument("--agent", help="Filter by agent type (e.g. hermes)")
    query_parser.add_argument(
        "--event-type",
        help="Filter by event type (e.g. tool_call, model_request)",
    )
    query_parser.add_argument("--tool", help="Filter by tool name")
    query_parser.add_argument("--since", help="ISO8601 start time")
    query_parser.add_argument("--until", help="ISO8601 end time")
    query_parser.add_argument("--limit", default=50, type=int, help="Max results")

    # --- status ---
    subparsers.add_parser("status", help="Show audit statistics", parents=[db_opts])

    # --- session ---
    session_parser = subparsers.add_parser(
        "session", help="Show up to 10,000 newest session events", parents=[db_opts]
    )
    session_parser.add_argument("session_id", help="Session ID to inspect")

    # --- evidence ---
    evidence_parser = subparsers.add_parser(
        "evidence", help="Show evidence chain", parents=[db_opts]
    )
    evidence_parser.add_argument("event_id", help="Event ID to inspect")

    # --- local hash-chain integrity ---
    verify_parser = subparsers.add_parser(
        "verify",
        help="Verify the local tamper-evidence hash chain",
        parents=[db_opts],
    )
    verify_parser.add_argument(
        "--checkpoint",
        help="Prove a separately stored JSON checkpoint is a prefix of this chain",
    )
    subparsers.add_parser(
        "checkpoint",
        help="Print the current hash-chain checkpoint",
        parents=[db_opts],
    )

    # --- policy ---
    policy_parser = subparsers.add_parser("policy", help="Policy management commands")
    policy_subs = policy_parser.add_subparsers(dest="policy_command")

    # policy check
    policy_check = policy_subs.add_parser(
        "check", help="Check policies against events", parents=[db_opts, policy_opts]
    )
    policy_check.add_argument("--event-type", help="Filter by event type")
    policy_check.add_argument("--since", help="ISO8601 start time")
    policy_check.add_argument("--until", help="ISO8601 end time")
    policy_check.add_argument(
        "--limit", default=100, type=int, help="Max events to check"
    )

    # policy list
    policy_subs.add_parser(
        "list", help="List all loaded policies", parents=[policy_opts]
    )

    # policy add
    policy_add = policy_subs.add_parser(
        "add", help="Add a policy file to the policies directory",
        parents=[policy_opts],
    )
    policy_add.add_argument("source", help="Path to the policy YAML file to add")

    # policy test
    policy_test = policy_subs.add_parser(
        "test", help="Test a policy file against a JSON event"
    )
    policy_test.add_argument("policy_file", help="Path to the policy YAML file")
    policy_test.add_argument("event_json", help="JSON event string to test against")

    args = parser.parse_args(argv)

    # Resolve policies_dir defaults where needed
    if hasattr(args, "policies_dir") and not args.policies_dir:
        args.policies_dir = DEFAULT_POLICIES_DIR

    if args.command == "proxy":
        from panoptes.proxy import start_proxy

        start_proxy(
            port=args.port,
            host=args.host,
            db_path=args.db_path,
            policies_dir=args.policies_dir,
            log_level=args.log_level,
            policy_failure_mode=args.policy_failure_mode,
            client_socket_timeout_seconds=args.client_timeout,
            max_concurrent_requests=args.max_concurrent_requests,
        )
    elif args.command == "policy":
        policy_commands = {
            "check": cmd_policy_check,
            "list": cmd_policy_list,
            "add": cmd_policy_add,
            "test": cmd_policy_test,
        }
        handler = policy_commands.get(args.policy_command)
        if handler:
            handler(args)
        else:
            policy_parser.print_help()
    else:
        commands = {
            "query": cmd_query,
            "status": cmd_status,
            "session": cmd_session,
            "evidence": cmd_evidence,
            "verify": cmd_verify,
            "checkpoint": cmd_checkpoint,
        }
        handler = commands.get(args.command)
        if handler:
            handler(args)
        else:
            parser.print_help()


if __name__ == "__main__":
    main()
