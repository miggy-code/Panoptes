"""Panoptes CLI — universal agent observability and audit trail."""

import argparse
import json
import os
import shutil
import sys

from panoptes.db import AuditDB
from panoptes.policy import DEFAULT_POLICIES_DIR, PolicyEngine


def cmd_query(args):
    """Query audit events from the database."""
    db = AuditDB(args.db_path)
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
    db = AuditDB(args.db_path)
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
    """Show full session timeline."""
    db = AuditDB(args.db_path)
    events = db.get_session(args.session_id)

    if not events:
        print(f"No events found for session: {args.session_id}")
        return

    print(f"Session: {args.session_id} ({len(events)} events)\n")
    for i, e in enumerate(events, 1):
        print(f"--- Event {i} ---")
        print(json.dumps(e, indent=2, default=str))
        print()


def cmd_evidence(args):
    """Show evidence chain for an event."""
    db = AuditDB(args.db_path)
    chain = db.get_evidence_chain(args.event_id)
    if not chain:
        print(f"No evidence chain found for event: {args.event_id}")
        return

    print(f"Evidence chain for {args.event_id} ({len(chain)} steps):")
    for i, e in enumerate(chain, 1):
        outcome = e.get("outcome", {}) or {}
        print(f"\n--- Step {i} ---")
        print(f"[{e['event_type']}] {outcome.get('summary', 'no summary')}")


# ── Policy subcommands ────────────────────────────────────────────────────────


def cmd_policy_check(args):
    """Check configured policies against stored events."""
    db = AuditDB(args.db_path)
    engine = PolicyEngine(args.policies_dir, db)

    results = db.query(
        event_type=args.event_type,
        since=args.since,
        until=args.until,
        limit=args.limit,
    )

    if not results:
        print("No events to check.")
        return

    violations = []
    for event in results:
        result = engine.evaluate(event)
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
    else:
        print("No policy violations detected.")
    print(f"\nChecked {len(results)} events against {len(engine.policies)} policies.")


def cmd_policy_list(args):
    """List all loaded policies."""
    engine = PolicyEngine(args.policies_dir)
    if not engine.policies:
        print("No policies loaded.")
        print(f"Policies directory: {engine._policies_dir}")
        print("Add .yaml policy files to this directory to define policies.")
        return

    print(f"Loaded {len(engine.policies)} policies from {engine._policies_dir}:\n")
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
    engine = PolicyEngine.__new__(PolicyEngine)
    engine._db = None
    import threading
    engine._rate_lock = threading.Lock()
    engine._rate_limits = {}
    engine.policies = []

    try:
        result = engine.test_policy(args.policy_file, args.event_json)
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


def _resolve_policies_dir(args) -> str:
    """Resolve policies directory from args, with default."""
    if hasattr(args, "policies_dir") and args.policies_dir:
        return args.policies_dir
    return DEFAULT_POLICIES_DIR


# ── Main CLI ──────────────────────────────────────────────────────────────────


def main(argv=None):
    """Entry point for the panoptes CLI."""
    parser = argparse.ArgumentParser(
        prog="panoptes",
        description="Panoptes — universal agent observability, audit trail, and policy enforcement.",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # --- proxy ---
    proxy_parser = subparsers.add_parser("proxy", help="Start the MITM audit proxy")
    proxy_parser.add_argument("--port", default=8081, type=int, help="Proxy listen port")
    proxy_parser.add_argument(
        "--db-path", default="~/.panoptes/audit.db", help="Path to audit database"
    )
    proxy_parser.add_argument(
        "--policies-dir",
        default=None,
        help="Path to policy definitions directory",
    )

    # --- query ---
    query_parser = subparsers.add_parser("query", help="Query audit events")
    query_parser.add_argument("--agent", help="Filter by agent type (e.g. hermes)")
    query_parser.add_argument(
        "--event-type",
        help="Filter by event type (e.g. tool_call, model_request)",
    )
    query_parser.add_argument("--tool", help="Filter by tool name")
    query_parser.add_argument("--since", help="ISO8601 start time")
    query_parser.add_argument("--until", help="ISO8601 end time")
    query_parser.add_argument("--limit", default=50, type=int, help="Max results")
    query_parser.add_argument(
        "--db-path", default="~/.panoptes/audit.db", help="Path to audit database"
    )

    # --- status ---
    status_parser = subparsers.add_parser("status", help="Show audit statistics")
    status_parser.add_argument(
        "--db-path", default="~/.panoptes/audit.db", help="Path to audit database"
    )

    # --- session ---
    session_parser = subparsers.add_parser("session", help="Show session timeline")
    session_parser.add_argument("session_id", help="Session ID to inspect")
    session_parser.add_argument(
        "--db-path", default="~/.panoptes/audit.db", help="Path to audit database"
    )

    # --- evidence ---
    evidence_parser = subparsers.add_parser("evidence", help="Show evidence chain")
    evidence_parser.add_argument("event_id", help="Event ID to inspect")
    evidence_parser.add_argument(
        "--db-path", default="~/.panoptes/audit.db", help="Path to audit database"
    )

    # --- policy ---
    policy_parser = subparsers.add_parser("policy", help="Policy management commands")
    policy_subs = policy_parser.add_subparsers(dest="policy_command")

    # policy check
    policy_check = policy_subs.add_parser("check", help="Check policies against events")
    policy_check.add_argument("--event-type", help="Filter by event type")
    policy_check.add_argument("--since", help="ISO8601 start time")
    policy_check.add_argument("--until", help="ISO8601 end time")
    policy_check.add_argument(
        "--limit", default=100, type=int, help="Max events to check"
    )
    policy_check.add_argument(
        "--db-path", default="~/.panoptes/audit.db", help="Path to audit database"
    )
    policy_check.add_argument(
        "--policies-dir",
        default=None,
        help="Path to policy definitions directory",
    )

    # policy list
    policy_list = policy_subs.add_parser("list", help="List all loaded policies")
    policy_list.add_argument(
        "--policies-dir",
        default=None,
        help="Path to policy definitions directory",
    )

    # policy add
    policy_add = policy_subs.add_parser(
        "add", help="Add a policy file to the policies directory"
    )
    policy_add.add_argument("source", help="Path to the policy YAML file to add")
    policy_add.add_argument(
        "--policies-dir",
        default=None,
        help="Path to policy definitions directory",
    )

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
            db_path=args.db_path,
            policies_dir=args.policies_dir,
        )
    elif args.command == "query":
        cmd_query(args)
    elif args.command == "status":
        cmd_status(args)
    elif args.command == "session":
        cmd_session(args)
    elif args.command == "evidence":
        cmd_evidence(args)
    elif args.command == "policy":
        if args.policy_command == "check":
            cmd_policy_check(args)
        elif args.policy_command == "list":
            cmd_policy_list(args)
        elif args.policy_command == "add":
            cmd_policy_add(args)
        elif args.policy_command == "test":
            cmd_policy_test(args)
        else:
            policy_parser.print_help()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
