#!/usr/bin/env python3
"""Tests for panoptes/schema.py — normalization, derivation, and redaction.

Covers:
  - DATA_ACCESS_CLASSIFIERS: tag derivation from parameter strings and targets
  - _is_sensitive_key: token-based matching (author preserved, authorization redacted)
  - redact_secrets: key-based and content-based redaction
  - normalize_event: data_accessed derivation end-to-end
  - extract_index_fields: call_id extraction (explicit vs target fallback)
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from panoptes.schema import (
    DATA_ACCESS_CLASSIFIERS,
    _derive_data_accessed,
    _is_sensitive_key,
    _tokenize_key,
    extract_index_fields,
    normalize_event,
    redact_secrets,
)


# ── _tokenize_key ─────────────────────────────────────────────────────────────

def test_tokenize_snake_case():
    """Snake_case keys are split into tokens."""
    print("--- test_tokenize_snake_case ---")
    assert _tokenize_key("db_password") == ["db", "password"]
    assert _tokenize_key("aws_secret_key") == ["aws", "secret", "key"]
    assert _tokenize_key("api_key") == ["api", "key"]
    assert _tokenize_key("access_token") == ["access", "token"]
    print("  PASSED")


def test_tokenize_camel_case():
    """camelCase keys are split on boundaries."""
    print("--- test_tokenize_camel_case ---")
    assert _tokenize_key("apiKey") == ["api", "key"]
    assert _tokenize_key("dbPassword") == ["db", "password"]
    assert _tokenize_key("Authorization") == ["authorization"]
    print("  PASSED")


def test_tokenize_kebab_case():
    """kebab-case keys are split on hyphens."""
    print("--- test_tokenize_kebab_case ---")
    assert _tokenize_key("api-key") == ["api", "key"]
    assert _tokenize_key("refresh-token") == ["refresh", "token"]
    print("  PASSED")


# ── _is_sensitive_key ─────────────────────────────────────────────────────────

def test_sensitive_key_false_positives_fixed():
    """Keys that caused false positives with substring matching are now safe."""
    print("--- test_sensitive_key_false_positives_fixed ---")

    # 'auth' is sensitive, but 'author' must NOT be redacted
    assert not _is_sensitive_key("author"), "'author' should NOT be sensitive"
    assert not _is_sensitive_key("authors"), "'authors' should NOT be sensitive"
    assert not _is_sensitive_key("authentication_docs"), (
        "'authentication_docs' should NOT be sensitive (whole-token match only)"
    )

    # 'pwd' is sensitive, but 'cwd' must NOT be redacted
    assert not _is_sensitive_key("cwd"), "'cwd' should NOT be sensitive"

    # 'token' is sensitive, but 'tokenizer' should NOT be (token boundary)
    # Note: 'tokenizer' → ["tokenizer"], no match
    assert not _is_sensitive_key("tokenizer"), "'tokenizer' should NOT be sensitive"

    print("  PASSED")


def test_sensitive_key_true_positives():
    """Genuinely sensitive keys are still detected correctly."""
    print("--- test_sensitive_key_true_positives ---")

    # Direct single-token matches
    assert _is_sensitive_key("auth"), "'auth' should be sensitive"
    assert _is_sensitive_key("authorization"), "'authorization' should be sensitive"
    assert _is_sensitive_key("Authorization"), "'Authorization' should be sensitive"
    assert _is_sensitive_key("password"), "'password' should be sensitive"
    assert _is_sensitive_key("passwd"), "'passwd' should be sensitive"
    assert _is_sensitive_key("pwd"), "'pwd' should be sensitive"
    assert _is_sensitive_key("secret"), "'secret' should be sensitive"
    assert _is_sensitive_key("token"), "'token' should be sensitive"
    assert _is_sensitive_key("credential"), "'credential' should be sensitive"
    assert _is_sensitive_key("credentials"), "'credentials' should be sensitive"

    # Multi-token sensitive keys detected via token pairs
    assert _is_sensitive_key("api_key"), "'api_key' should be sensitive (pair match)"
    assert _is_sensitive_key("apiKey"), "'apiKey' should be sensitive (camelCase pair)"
    assert _is_sensitive_key("private_key"), "'private_key' should be sensitive (pair match)"
    assert _is_sensitive_key("access_key"), "'access_key' should be sensitive (pair match)"

    # Compound keys where a sensitive token appears as part of the key
    assert _is_sensitive_key("db_password"), "'db_password' single token 'password'"
    assert _is_sensitive_key("aws_secret_key"), "'aws_secret_key' has token 'secret'"
    assert _is_sensitive_key("refresh_token"), "'refresh_token' has token 'token'"
    assert _is_sensitive_key("access_token"), "'access_token' has token 'token'"
    assert _is_sensitive_key("auth_header"), "'auth_header' has token 'auth'"

    print("  PASSED")


def test_redact_author_not_redacted():
    """Dicts with 'author' or 'authors' keys pass through unmodified."""
    print("--- test_redact_author_not_redacted ---")

    data = {
        "author": "Alice",
        "authors": ["Alice", "Bob"],
        "authentication_docs": "https://example.com/auth",
    }
    cleaned = redact_secrets(data)
    assert cleaned["author"] == "Alice", f"'author' should not be redacted, got {cleaned['author']}"
    assert cleaned["authors"] == ["Alice", "Bob"]
    assert cleaned["authentication_docs"] == "https://example.com/auth"

    print("  PASSED")


def test_redact_authorization_redacted():
    """Dict with 'authorization' key is redacted."""
    print("--- test_redact_authorization_redacted ---")

    data = {"authorization": "Bearer secret-token-value-here"}
    cleaned = redact_secrets(data)
    assert cleaned["authorization"] == "[REDACTED]", (
        f"'authorization' should be redacted, got {cleaned['authorization']}"
    )

    # camelCase variant
    data2 = {"Authorization": "Basic dXNlcjpwYXNz"}
    cleaned2 = redact_secrets(data2)
    assert cleaned2["Authorization"] == "[REDACTED]"

    print("  PASSED")


# ── DATA_ACCESS_CLASSIFIERS / _derive_data_accessed ───────────────────────────

def test_derive_prod_tag():
    """Commands/paths containing 'prod' or 'production' get the 'prod' tag."""
    print("--- test_derive_prod_tag ---")

    action = {
        "tool_name": "bash",
        "parameters": {"command": "ssh admin@prod.example.com"},
        "target": None,
        "data_accessed": [],
    }
    tags = _derive_data_accessed(action, "tool_call")
    assert "prod" in tags, f"Expected 'prod' tag, got {tags}"

    # 'production' variant
    action2 = {
        "tool_name": "Read",
        "parameters": {"file_path": "/etc/production/config.yaml"},
        "target": None,
        "data_accessed": [],
    }
    tags2 = _derive_data_accessed(action2, "tool_call")
    assert "prod" in tags2, f"Expected 'prod' from 'production', got {tags2}"

    print("  PASSED")


def test_derive_infra_tag():
    """kubectl, helm, terraform, and gcloud commands get the 'infra' tag."""
    print("--- test_derive_infra_tag ---")

    for cmd, tool in [
        ("kubectl get pods -n prod", "kubectl"),
        ("helm upgrade --install myapp ./chart", "helm"),
        ("terraform apply", "terraform"),
        ("gcloud compute instances list", "gcloud"),
    ]:
        action = {
            "tool_name": "bash",
            "parameters": {"command": cmd},
            "target": None,
            "data_accessed": [],
        }
        tags = _derive_data_accessed(action, "tool_call")
        assert "infra" in tags, (
            f"Expected 'infra' from '{tool}' command, got {tags} for cmd={cmd!r}"
        )

    print("  PASSED")


def test_derive_kubectl_prod_gets_both_tags():
    """kubectl command with /prod/ path yields both 'infra' and 'prod' tags."""
    print("--- test_derive_kubectl_prod_gets_both_tags ---")

    action = {
        "tool_name": "bash",
        "parameters": {"command": "kubectl apply -f /prod/deployment.yaml"},
        "target": None,
        "data_accessed": [],
    }
    tags = _derive_data_accessed(action, "tool_call")
    assert "prod" in tags, f"Expected 'prod' tag, got {tags}"
    assert "infra" in tags, f"Expected 'infra' tag, got {tags}"

    print("  PASSED")


def test_derive_secrets_tag():
    """References to credential files get the 'secrets' tag."""
    print("--- test_derive_secrets_tag ---")

    for path in [".env", "id_rsa", "server.pem", "private.key", "/etc/passwd", "/etc/shadow"]:
        action = {
            "tool_name": "Read",
            "parameters": {"file_path": path},
            "target": None,
            "data_accessed": [],
        }
        tags = _derive_data_accessed(action, "tool_call")
        assert "secrets" in tags, (
            f"Expected 'secrets' from path {path!r}, got {tags}"
        )

    print("  PASSED")


def test_derive_database_tag():
    """Database CLI commands get the 'database' tag."""
    print("--- test_derive_database_tag ---")

    for cmd in ["psql -U admin prod_db", "mysql -h db.internal orders", "redis-cli ping"]:
        action = {
            "tool_name": "bash",
            "parameters": {"command": cmd},
            "target": None,
            "data_accessed": [],
        }
        tags = _derive_data_accessed(action, "tool_call")
        assert "database" in tags, (
            f"Expected 'database' from cmd {cmd!r}, got {tags}"
        )

    print("  PASSED")


def test_derive_network_tag():
    """curl/wget commands and HTTP URLs get the 'network' tag."""
    print("--- test_derive_network_tag ---")

    for s in ["curl https://api.example.com/v1", "wget http://example.com/file.tar.gz"]:
        action = {
            "tool_name": "bash",
            "parameters": {"command": s},
            "target": None,
            "data_accessed": [],
        }
        tags = _derive_data_accessed(action, "tool_call")
        assert "network" in tags, f"Expected 'network' from {s!r}, got {tags}"

    print("  PASSED")


def test_derive_skips_non_tool_events():
    """Derivation returns [] for non tool_call/tool_result event types."""
    print("--- test_derive_skips_non_tool_events ---")

    action = {
        "tool_name": None,
        "parameters": {"message": "kubectl apply to prod"},
        "target": None,
        "data_accessed": [],
    }
    for et in ("model_request", "model_response", "policy_violation"):
        tags = _derive_data_accessed(action, et)
        assert tags == [], f"Expected no tags for event_type={et!r}, got {tags}"

    print("  PASSED")


def test_derive_skips_when_data_accessed_set():
    """normalize_event does NOT override explicitly set data_accessed."""
    print("--- test_derive_skips_when_data_accessed_set ---")

    raw = {
        "agent": {"type": "hermes", "session_id": "s1", "run_id": "r1"},
        "event_type": "tool_call",
        "action": {
            "tool_name": "bash",
            "parameters": {"command": "kubectl apply -f /prod/deployment.yaml"},
            "data_accessed": ["custom_tag"],  # explicitly set
        },
        "outcome": {"status": "success"},
        "context": {},
    }
    norm = normalize_event(raw)
    # Must preserve explicit value, not override with derived tags
    assert norm["action"]["data_accessed"] == ["custom_tag"], (
        f"Explicit data_accessed should not be overridden, got {norm['action']['data_accessed']}"
    )

    print("  PASSED")


def test_derive_tags_sorted_deduped():
    """Derived tags are sorted and deduplicated."""
    print("--- test_derive_tags_sorted_deduped ---")

    # Command that matches prod twice (word "prod" appears twice)
    action = {
        "tool_name": "bash",
        "parameters": {"command": "kubectl apply -f /prod/app.yaml --namespace prod"},
        "target": None,
        "data_accessed": [],
    }
    tags = _derive_data_accessed(action, "tool_call")
    # No duplicates
    assert len(tags) == len(set(tags)), f"Tags should be deduplicated: {tags}"
    # Sorted
    assert tags == sorted(tags), f"Tags should be sorted: {tags}"

    print("  PASSED")


def test_derive_target_scanned():
    """action.target is included in the classifier scan."""
    print("--- test_derive_target_scanned ---")

    action = {
        "tool_name": "bash",
        "parameters": {},
        "target": "/prod/secrets/id_rsa",
        "data_accessed": [],
    }
    tags = _derive_data_accessed(action, "tool_call")
    assert "prod" in tags, f"Expected 'prod' from target, got {tags}"
    assert "secrets" in tags, f"Expected 'secrets' from target, got {tags}"

    print("  PASSED")


def test_derive_skips_large_strings():
    """Strings longer than 10KB are not scanned."""
    print("--- test_derive_skips_large_strings ---")

    big_str = "kubectl apply " + "x" * 20_000  # > 10KB, contains infra keyword at start
    action = {
        "tool_name": "bash",
        "parameters": {"content": big_str},
        "target": None,
        "data_accessed": [],
    }
    # The large string is skipped; no tags derived
    tags = _derive_data_accessed(action, "tool_call")
    assert "infra" not in tags, (
        f"Large string should be skipped by classifier, but got 'infra' in {tags}"
    )

    print("  PASSED")


# ── extract_index_fields: call_id ─────────────────────────────────────────────

def test_extract_call_id_explicit():
    """extract_index_fields uses action.call_id when present."""
    print("--- test_extract_call_id_explicit ---")

    event = {
        "agent": {"type": "hermes", "session_id": "s1", "run_id": "r1"},
        "event_type": "tool_call",
        "action": {
            "tool_name": "bash",
            "parameters": {},
            "target": "some-target",
            "call_id": "explicit-call-001",
            "data_accessed": [],
        },
    }
    flat = extract_index_fields(event)
    assert flat["call_id"] == "explicit-call-001", (
        f"Expected explicit call_id, got {flat['call_id']!r}"
    )

    print("  PASSED")


def test_extract_call_id_falls_back_to_target():
    """extract_index_fields falls back to action.target when call_id absent."""
    print("--- test_extract_call_id_falls_back_to_target ---")

    event = {
        "agent": {"type": "hermes", "session_id": "s1", "run_id": "r1"},
        "event_type": "tool_call",
        "action": {
            "tool_name": "bash",
            "parameters": {},
            "target": "/etc/app/config.yaml",
            "call_id": None,
            "data_accessed": [],
        },
    }
    flat = extract_index_fields(event)
    assert flat["call_id"] == "/etc/app/config.yaml", (
        f"Expected target as call_id fallback, got {flat['call_id']!r}"
    )

    print("  PASSED")


def test_extract_call_id_empty_when_neither():
    """extract_index_fields returns empty string when both call_id and target absent."""
    print("--- test_extract_call_id_empty_when_neither ---")

    event = {
        "agent": {"type": "hermes", "session_id": "s1", "run_id": "r1"},
        "event_type": "model_request",
        "action": {
            "tool_name": None,
            "parameters": {},
            "target": None,
            "call_id": None,
            "data_accessed": [],
        },
    }
    flat = extract_index_fields(event)
    assert flat["call_id"] == "", (
        f"Expected empty string when neither call_id nor target, got {flat['call_id']!r}"
    )

    print("  PASSED")


# ── normalize_event: end-to-end data_accessed derivation ─────────────────────

def test_normalize_derives_data_accessed():
    """normalize_event auto-populates data_accessed for tool events."""
    print("--- test_normalize_derives_data_accessed ---")

    raw = {
        "agent": {"type": "hermes", "session_id": "s1", "run_id": "r1"},
        "event_type": "tool_call",
        "action": {
            "tool_name": "bash",
            "parameters": {"command": "kubectl apply -f /prod/deployment.yaml"},
            "data_accessed": [],
        },
        "outcome": {"status": "success"},
        "context": {},
    }
    norm = normalize_event(raw)

    da = norm["action"]["data_accessed"]
    assert "prod" in da, f"Expected 'prod' derived, got {da}"
    assert "infra" in da, f"Expected 'infra' derived, got {da}"
    assert da == sorted(set(da)), f"data_accessed should be sorted+deduped: {da}"

    print("  PASSED")


def test_normalize_no_derive_for_model_events():
    """normalize_event does NOT derive data_accessed for model_request/response."""
    print("--- test_normalize_no_derive_for_model_events ---")

    raw = {
        "agent": {"type": "hermes", "session_id": "s1", "run_id": "r1"},
        "event_type": "model_request",
        "action": {
            "tool_name": None,
            "parameters": {"message": "kubectl apply -f /prod/deployment.yaml"},
            "data_accessed": [],
        },
        "outcome": {"status": "success"},
        "context": {},
    }
    norm = normalize_event(raw)
    assert norm["action"]["data_accessed"] == [], (
        f"model_request should not derive data_accessed, got {norm['action']['data_accessed']}"
    )

    print("  PASSED")


def test_normalize_preserves_call_id():
    """normalize_event preserves action.call_id in the action dict."""
    print("--- test_normalize_preserves_call_id ---")

    raw = {
        "agent": {"type": "hermes", "session_id": "s1", "run_id": "r1"},
        "event_type": "tool_call",
        "action": {
            "tool_name": "bash",
            "parameters": {},
            "call_id": "explicit-123",
            "data_accessed": [],
        },
        "outcome": {"status": "success"},
        "context": {},
    }
    norm = normalize_event(raw)
    assert norm["action"].get("call_id") == "explicit-123", (
        f"normalize_event should preserve call_id, got {norm['action'].get('call_id')!r}"
    )

    print("  PASSED")


if __name__ == "__main__":
    test_tokenize_snake_case()
    test_tokenize_camel_case()
    test_tokenize_kebab_case()
    test_sensitive_key_false_positives_fixed()
    test_sensitive_key_true_positives()
    test_redact_author_not_redacted()
    test_redact_authorization_redacted()
    test_derive_prod_tag()
    test_derive_infra_tag()
    test_derive_kubectl_prod_gets_both_tags()
    test_derive_secrets_tag()
    test_derive_database_tag()
    test_derive_network_tag()
    test_derive_skips_non_tool_events()
    test_derive_skips_when_data_accessed_set()
    test_derive_tags_sorted_deduped()
    test_derive_target_scanned()
    test_derive_skips_large_strings()
    test_extract_call_id_explicit()
    test_extract_call_id_falls_back_to_target()
    test_extract_call_id_empty_when_neither()
    test_normalize_derives_data_accessed()
    test_normalize_no_derive_for_model_events()
    test_normalize_preserves_call_id()
    print("\n=== ALL SCHEMA TESTS PASSED ===")
