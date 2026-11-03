"""Panoptes CLI for adapter observations and local audit trails."""

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sqlite3
import sys

from panoptes import __version__
from panoptes.db import AuditDB
from panoptes.schema import redact_secrets


def _open_existing_db(db_path: str, *, read_only: bool = True) -> AuditDB:
    """Open an initialized audit database without creating one by typo.

    ``AuditDB`` intentionally creates and migrates databases for write paths.
    CLI commands first probe the path with SQLite's ``mode=ro`` and require
    Panoptes' events table, so a missing or empty path is never silently
    turned into a new audit trail. Inspection commands then stay read-only, so
    verifying evidence never migrates, re-anchors, or re-permissions it.
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
    try:
        return AuditDB(expanded, read_only=read_only)
    except (sqlite3.Error, RuntimeError, ValueError) as exc:
        print(f"Cannot open audit database {expanded}: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc


def _display_text(value, limit=180):
    """Keep untrusted audit text redacted, bounded, and on one terminal line."""
    text = str(redact_secrets(value))
    text = " ".join("".join(c if c.isprintable() else " " for c in text).split())
    return text if len(text) <= limit else text[:limit - 3] + "..."


def cmd_doctor(args):
    """Inspect local setup without changing audit data or contacting a provider."""
    failed = False
    print("Panoptes doctor — requested configuration (read-only)")
    print("Running proxy settings, client routing, and direct egress are not verified.\n")
    db = None
    try:
        db = _open_existing_db(args.db_path)
        stats = db.get_stats()
        print(f"[OK] Database: schema {stats['schema_version']}, {stats['total_events']} events")
        latest = db.query(limit=1)
        if latest:
            event = latest[0]
            timestamp = datetime.fromisoformat(event['timestamp'].replace('Z', '+00:00'))
            stale = (datetime.now(timezone.utc) - timestamp).total_seconds() > 86400
            status = "WARN" if stale else "INFO"
            age = "; older than 24 hours" if stale else ""
            print(f"[{status}] Last audit event: {_display_text(event['timestamp'])} ({_display_text(event['event_type'])}{age})")
        else:
            print("[WARN] Capture: no recorded activity; run a client through Panoptes first")
        if not (os.access(os.path.expanduser(args.db_path), os.W_OK)
                and os.access(Path(os.path.expanduser(args.db_path)).parent, os.W_OK)):
            print("[WARN] Database write permissions unavailable; capture needs write access")
        print("[INFO] No database write attempted; use 'panoptes verify' to check chain integrity")
    except SystemExit as exc:
        if exc.code != 2:
            raise
        print("[ERROR] Database unavailable; check --db-path or start the proxy to initialize it")
        failed = True
    except (sqlite3.Error, RuntimeError, ValueError) as exc:
        print(f"[ERROR] Database: {_display_text(str(exc), limit=1200)}")
        failed = True
    finally:
        if db is not None:
            db.close()

    if failed:
        raise SystemExit(2)


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
    """Show a bounded chronological timeline, or full events as JSON."""
    db = _open_existing_db(args.db_path)
    try:
        events = db.query(session_id=args.session_id, limit=args.limit)
        events.reverse()
        total_rows = db.aggregate(
            group_by=[], metrics=["count"], session_id=args.session_id,
        )
        matching_total = int(total_rows[0]["count"]) if total_rows else 0
    finally:
        db.close()

    if args.json:
        print(json.dumps({
            "session_id": args.session_id,
            "selected_count": len(events),
            "matching_count": matching_total,
            "partial": len(events) < matching_total,
            "events": events,
        }, indent=2))
        return
    if not events:
        print(f"No events found for session: {_display_text(args.session_id)}")
        return

    selection = f"{len(events)} of {matching_total} events"
    if len(events) < matching_total:
        selection += f"; showing the newest {args.limit}; partial timeline"
    print(f"Session: {_display_text(args.session_id)} ({selection})")
    print("Chronological order; tool proposals and authorizations do not prove execution.")
    for event in events:
        _print_timeline_event(event)


def _print_timeline_event(event):
    action = event.get("action") or {}
    outcome = event.get("outcome") or {}
    context = event.get("context") or {}
    capture = context.get("capture") or {}
    policy = context.get("policy")
    if not isinstance(policy, dict):
        policy = {}
    kind = event["event_type"]
    label = action.get("tool_name") or action.get("model") or ""
    if kind == "decision_point":
        label = f"authorization {label}" if context.get("decision_kind") == "tool_authorization" else label
    duration = action.get("duration_ms")
    timing = f" ({_display_text(duration)} ms)" if duration is not None else ""
    print(
        f"{_display_text(event['timestamp'])}  {_display_text(kind)}  "
        f"{_display_text(label)}  "
        f"{_display_text(outcome.get('status', 'unknown').upper())}{timing}"
    )

    refs = [f"id={event['event_id']}", f"run={event['agent'].get('run_id', '-')}"]
    for name, value in (("call", action.get("call_id")), ("source", context.get("source_event_id"))):
        if value:
            refs.append(f"{name}={value}")
    print("  " + _display_text("  ".join(refs), limit=1200))
    details = []
    parameters = action.get("parameters") or {}
    for field in ("command", "file_path", "path"):
        if isinstance(parameters.get(field), str):
            details.append(_display_text(f"{field}={parameters[field]}"))
    if action.get("target") and action["target"] != action.get("call_id"):
        details.append(_display_text(f"target={action['target']}"))
    if outcome.get("summary"):
        details.append(_display_text(outcome["summary"]))
    if policy.get("action"):
        matches = policy.get("matched_policies")
        names = ", ".join(
            _display_text(match.get("policy_name", "unknown"))
            for match in (matches if isinstance(matches, list) else [])
            if isinstance(match, dict)
        )
        details.append(_display_text(f"event policy={policy['action']}" + (f" [{names}]" if names else "")))
    elif context.get("policy_name"):
        details.append(_display_text(f"event policy={context.get('policy_action', 'unknown')} [{context['policy_name']}]"))
    if policy.get("evaluation_errors"):
        details.append(_display_text(f"policy errors={policy['evaluation_errors']}"))
    if capture.get("adapter"):
        details.append(_display_text(f"via={capture['adapter']}"))
    if kind in {"tool_call", "tool_result", "agent_step"}:
        if action.get("execution_scope") in ("provider", "server"):
            details.append("execution=provider-reported")
        elif capture.get("adapter") == "http_proxy":
            details.append("execution=client-reported" if kind == "tool_result" else "execution=not observed")
        elif capture.get("adapter") == "hermes_authorizer":
            details.append("execution=not observed")
        elif capture.get("adapter") == "hermes_plugin":
            details.append("execution=host-reported")
        else:
            details.append("execution=not verified")
    if capture.get("inspection_status"):
        details.append(_display_text(f"inspection={capture['inspection_status']}"))
    if any(capture.get(key) for key in ("audit_body_truncated", "raw_request_truncated", "raw_response_truncated")):
        details.append("capture=truncated")
    if details:
        print("  " + " | ".join(details))
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


# ── Main CLI ──────────────────────────────────────────────────────────────────


def main(argv=None):
    """Entry point for the panoptes CLI."""
    # Shared options — inherited by subparsers via parents=[...]
    db_opts = argparse.ArgumentParser(add_help=False)
    db_opts.add_argument(
        "--db-path", default="~/.panoptes/audit.db", help="Path to audit database"
    )
    proxy_opts = argparse.ArgumentParser(add_help=False)
    proxy_opts.add_argument(
        "--pricing",
        help="Versioned JSON rate table; annotates responses with an estimated cost",
    )

    parser = argparse.ArgumentParser(
        prog="panoptes",
        description="Panoptes — adapter-based agent observability and local audit trails.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # --- proxy ---
    proxy_parser = subparsers.add_parser(
        "proxy", help="Start the model-API reverse proxy", parents=[db_opts, proxy_opts]
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

    subparsers.add_parser(
        "doctor", help="Check local setup and requested proxy configuration (read-only)",
        parents=[db_opts, proxy_opts],
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
    session_parser.add_argument("--limit", type=int, default=10000, help="Newest events to show (1–10000; default: 10000)")
    session_parser.add_argument("--json", action="store_true", help="Print full events and selection counts as JSON")

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

    args = parser.parse_args(argv)

    if args.command == "session" and not 1 <= args.limit <= 10000:
        parser.error("--limit must be between 1 and 10000")

    if args.command == "proxy":
        try:
            from panoptes.proxy import start_proxy
        except ModuleNotFoundError as exc:
            if exc.name != "httpx":
                raise
            print(
                "Error: the proxy needs httpx. Install it with: "
                "pip install 'panoptes-observe[proxy]'",
                file=sys.stderr,
            )
            raise SystemExit(2)

        pricing = None
        if getattr(args, "pricing", None):
            from panoptes.pricing import PricingError, PricingTable

            try:
                pricing = PricingTable.load(args.pricing)
            except PricingError as exc:
                print(f"Error: {exc}", file=sys.stderr)
                raise SystemExit(2)

        start_proxy(
            port=args.port,
            host=args.host,
            db_path=args.db_path,
            log_level=args.log_level,
            client_socket_timeout_seconds=args.client_timeout,
            max_concurrent_requests=args.max_concurrent_requests,
            pricing=pricing,
        )
    else:
        commands = {
            "doctor": cmd_doctor,
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
