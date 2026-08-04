#!/usr/bin/env python3
"""Tests for panoptes/schema.py — normalization, derivation, and redaction.

Covers:
  - DATA_ACCESS_CLASSIFIERS: tag derivation from parameter strings and targets
  - _is_sensitive_key: token-based matching (author preserved, authorization redacted)
  - redact_secrets: key-based and content-based redaction
  - normalize_event: data_accessed derivation end-to-end
  - extract_index_fields: explicit call_id extraction
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from panoptes.capture import HERMES_AUTHORIZER_CAPABILITIES
from panoptes.schema import (
    DATA_ACCESS_CLASSIFIERS,
    ValidationError,
    _derive_data_accessed,
    _is_sensitive_key,
    _tokenize_key,
    extract_index_fields,
    normalize_event,
    redact_secrets,
    validate_event,
)


def _assert_validation_error(fn):
    try:
        fn()
    except ValidationError:
        return
    raise AssertionError("Expected ValidationError")


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


def test_derive_skips_model_events_but_preserves_action_evidence_records():
    """Prompts stay unclassified; action-derived decision evidence does not."""
    print("--- test_derive_skips_non_tool_events ---")

    action = {
        "tool_name": None,
        "parameters": {"message": "kubectl apply to prod"},
        "target": None,
        "data_accessed": [],
    }
    for et in ("model_request", "model_response"):
        tags = _derive_data_accessed(action, et)
        assert tags == [], f"Expected no tags for event_type={et!r}, got {tags}"

    for et in ("decision_point", "policy_violation"):
        assert _derive_data_accessed(action, et) == ["infra", "prod"]

    print("  PASSED")


def test_derive_unions_declared_and_authoritative_tags():
    """Declared tags cannot suppress authoritative server-side classification."""
    print("--- test_derive_unions_declared_and_authoritative_tags ---")

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
    assert norm["action"]["declared_data_accessed"] == ["custom_tag"]
    assert norm["action"]["derived_data_accessed"] == ["infra", "prod"]
    assert norm["action"]["data_accessed"] == ["custom_tag", "infra", "prod"]

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


def test_derive_scans_large_strings():
    """Security classification must not disappear above an arbitrary size."""
    print("--- test_derive_scans_large_strings ---")

    big_str = "x" * 20_000 + " /etc/shadow"
    action = {
        "tool_name": "bash",
        "parameters": {"content": big_str},
        "target": None,
        "data_accessed": [],
    }
    tags = _derive_data_accessed(action, "tool_call")
    assert "secrets" in tags

    print("  PASSED")


def test_derive_scans_parameter_keys():
    """Structured resource names in dictionary keys are security-relevant."""
    action = {
        "tool_name": "write",
        "parameters": {"production_credentials": "value"},
        "target": None,
        "data_accessed": [],
    }
    tags = _derive_data_accessed(action, "tool_call")
    assert "prod" in tags
    assert "secrets" in tags

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


def test_extract_call_id_does_not_use_target():
    """Resource targets are not idempotency keys."""
    print("--- test_extract_call_id_does_not_use_target ---")

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
    assert flat["call_id"] == ""

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


def test_normalize_preserves_event_specific_fields():
    """Normalization keeps structured adapter fields instead of dropping them."""
    raw = {
        "agent": {"type": "codex", "session_id": "s1", "run_id": "r1"},
        "event_type": "model_request",
        "action": {
            "method": "POST",
            "path": "/v1/responses",
            "model": "gpt-test",
            "messages_count": 2,
            "streaming": True,
        },
        "outcome": {"status": "success", "status_code": 200},
        "context": {},
        "cost": {"tokens_in": 10, "cached_tokens": 4},
    }

    normalized = normalize_event(raw)

    assert normalized["action"]["method"] == "POST"
    assert normalized["action"]["path"] == "/v1/responses"
    assert normalized["action"]["model"] == "gpt-test"
    assert normalized["outcome"]["status_code"] == 200
    assert normalized["cost"]["cached_tokens"] == 4


def test_normalize_redacts_every_persisted_content_field():
    """Secrets cannot escape through target, outcome, context, or raw payloads."""
    token = "Bearer abcdefghijklmnopqrstuvwxyz"
    raw = {
        "agent": {
            "type": "hermes",
            "session_id": "s1",
            "run_id": "r1",
            "access_token": token,
        },
        "user": {"id": "user", "auth_method": "cli", "credential": token},
        "event_type": "tool_call",
        "action": {"tool_name": "terminal", "parameters": {}, "target": token},
        "outcome": {"status": "success", "summary": token, "error": token},
        "context": {"user_message": token, "reasoning": token},
        "cost": {"tokens_in": 1, "billing_token": token},
        "raw_request": token,
        "raw_response": token,
    }

    normalized = normalize_event(raw)
    serialized = str({
        "agent": normalized["agent"],
        "user": normalized["user"],
        "action": normalized["action"],
        "outcome": normalized["outcome"],
        "context": normalized["context"],
        "cost": normalized["cost"],
        "raw_request": normalized["raw_request"],
        "raw_response": normalized["raw_response"],
    })

    assert "abcdefghijklmnopqrstuvwxyz" not in serialized
    assert "[REDACTED]" in serialized
    assert normalized["user"]["auth_method"] == "cli"


def test_redacts_bare_keys_credential_urls_and_signed_queries():
    raw = {
        "bare": "sk-proj-abcdefghijklmnopqrstuvwxyz012345",
        "database": "postgresql://admin:hunter2@db.internal/prod",
        "signed": "https://example.test/file?X-Amz-Signature=abcdef123456",
    }

    redacted = redact_secrets(raw)
    serialized = str(redacted)
    assert "abcdefghijklmnopqrstuvwxyz012345" not in serialized
    assert "admin:hunter2" not in serialized
    assert "abcdef123456" not in serialized
    assert serialized.count("[REDACTED") >= 3


def test_redacts_secret_bearing_mapping_keys_without_collisions():
    first = "sk-proj-abcdefghijklmnopqrstuvwxyz012345"
    second = "sk-proj-zyxwvutsrqponmlkjihgfedcba543210"
    normalized = normalize_event({
        "agent": {"type": "hermes", "session_id": "s1", "run_id": "r1"},
        "event_type": "tool_call",
        "action": {
            "tool_name": "terminal",
            "parameters": {first: "one", second: "two"},
        },
        "outcome": {"status": "pending"},
        "context": {},
    })

    serialized = str(normalized)
    assert first not in serialized
    assert second not in serialized
    assert sorted(normalized["action"]["parameters"].values()) == ["one", "two"]


def test_redacts_long_pem_before_truncating_user_message():
    private_key = (
        "prefix "
        "-----BEGIN PRIVATE KEY-----"
        + ("A" * 800)
        + "-----END PRIVATE KEY----- suffix"
    )
    normalized = normalize_event({
        "agent": {"type": "hermes", "session_id": "s1", "run_id": "r1"},
        "event_type": "model_request",
        "action": {},
        "outcome": {"status": "success"},
        "context": {"user_message": private_key},
    })

    message = normalized["context"]["user_message"]
    assert "BEGIN PRIVATE KEY" not in message
    assert "A" * 50 not in message
    assert "[REDACTED PRIVATE KEY]" in message


def test_validate_requires_evidence_grade_identifiers_and_costs():
    base = {
        "agent": {"type": "hermes", "session_id": "s1", "run_id": "r1"},
        "event_type": "tool_call",
        "action": {"tool_name": "terminal", "parameters": {}},
        "outcome": {"status": "pending"},
        "context": {"turn_number": 0},
        "cost": {"tokens_in": 0},
    }
    assert validate_event(base) is not None

    invalid_variants = [
        {**base, "agent": {**base["agent"], "session_id": None}},
        {**base, "agent": {**base["agent"], "run_id": ""}},
        {**base, "timestamp": "not-a-timestamp"},
        {**base, "context": {"turn_number": -1}},
        {**base, "cost": {"tokens_in": -1}},
        {**base, "cost": {"estimated_usd": float("nan")}},
        {**base, "action": {**base["action"], "data_accessed": "prod"}},
    ]
    for event in invalid_variants:
        try:
            validate_event(event)
        except ValidationError:
            continue
        raise AssertionError(f"Expected ValidationError for {event!r}")


def test_non_utc_timestamp_is_normalized_for_lexicographic_ordering():
    event = {
        "timestamp": "2026-07-17T08:30:00-05:00",
        "agent": {"type": "hermes", "session_id": "s1", "run_id": "r1"},
        "event_type": "model_request",
        "action": {},
        "outcome": {"status": "success"},
        "context": {},
    }

    validate_event(event)
    normalized = normalize_event(event)

    assert normalized["timestamp"] == "2026-07-17T13:30:00.000Z"


def test_validation_rejects_unsafe_identifiers_and_non_json_content():
    base = {
        "event_id": "event-1",
        "agent": {"type": "hermes", "session_id": "s1", "run_id": "r1"},
        "event_type": "tool_call",
        "action": {"tool_name": "terminal", "parameters": {}},
        "outcome": {"status": "pending"},
        "context": {},
    }
    cyclic = {}
    cyclic["self"] = cyclic

    invalid_variants = [
        {**base, "event_id": "x" * 257},
        {
            **base,
            "agent": {**base["agent"], "session_id": "session\nforged"},
        },
        {**base, "action": {**base["action"], "tool_name": ""}},
        {
            **base,
            "action": {**base["action"], "call_id": "call\x1b[31m"},
        },
        {**base, "action": {**base["action"], "parameters": cyclic}},
        {
            **base,
            "context": {"unsupported": object()},
        },
        {
            **base,
            "action": {
                **base["action"],
                "parameters": {"threshold": float("inf")},
            },
        },
    ]

    for event in invalid_variants:
        try:
            validate_event(event)
        except ValidationError:
            continue
        raise AssertionError(f"Expected ValidationError for {event!r}")


def test_normalization_rejects_cycles_before_redaction_or_classification():
    cyclic = {}
    cyclic["self"] = cyclic
    event = {
        "agent": {"type": "hermes", "session_id": "s1", "run_id": "r1"},
        "event_type": "tool_call",
        "action": {"tool_name": "terminal", "parameters": cyclic},
        "outcome": {"status": "pending"},
        "context": {},
    }

    try:
        normalize_event(event)
    except ValidationError as exc:
        assert "cyclic" in str(exc)
    else:
        raise AssertionError("cyclic raw input must be rejected before redaction")


def test_validation_rejects_pathological_integer_size():
    event = {
        "agent": {"type": "hermes", "session_id": "s1", "run_id": "r1"},
        "event_type": "model_request",
        "action": {"parameters": {"huge": 1 << 5000}},
        "outcome": {"status": "success"},
        "context": {},
    }

    try:
        normalize_event(event)
    except ValidationError as exc:
        assert "integer" in str(exc)
    else:
        raise AssertionError("pathologically large JSON integers must be rejected")


def test_cost_validation_does_not_float_convert_large_valid_json_integer():
    event = {
        "agent": {"type": "hermes", "session_id": "s1", "run_id": "r1"},
        "event_type": "model_request",
        "action": {},
        "outcome": {"status": "success"},
        "context": {},
        "cost": {"tokens_in": 1 << 4095, "tokens_out": 0},
    }

    normalized = normalize_event(event)
    validate_event(normalized)
    assert normalized["cost"]["tokens_in"] == 1 << 4095


def test_normalization_preserves_prior_supported_schema_version():
    event = {
        "agent": {"type": "hermes", "session_id": "s1", "run_id": "r1"},
        "event_type": "model_request",
        "action": {},
        "outcome": {"status": "success"},
        "context": {"schema_version": 3},
    }

    normalized = normalize_event(event)
    validate_event(normalized)

    assert normalized["context"]["schema_version"] == 3


def test_agent_step_derives_visibility_tags_and_requires_tool_identity():
    event = {
        "agent": {"type": "hermes", "session_id": "s1", "run_id": "r1"},
        "event_type": "agent_step",
        "action": {
            "tool_name": "terminal",
            "tool_names": ["terminal"],
            "parameters": {"command": "kubectl get pods -n prod"},
        },
        "outcome": {"status": "pending"},
        "context": {},
    }

    normalized = normalize_event(event)
    validate_event(normalized)
    assert normalized["action"]["data_accessed"] == ["infra", "prod"]

    normalized["action"]["tool_names"] = [""]
    try:
        validate_event(normalized)
    except ValidationError:
        pass
    else:
        raise AssertionError("agent_step with a malformed tool identity must be invalid")


def test_normalization_is_idempotent_for_derived_access_metadata():
    raw = {
        "event_id": "event-1",
        "timestamp": "2026-07-17T12:00:00.000Z",
        "agent": {"type": "hermes", "session_id": "s1", "run_id": "r1"},
        "event_type": "tool_call",
        "action": {
            "tool_name": "terminal",
            "parameters": {"command": "kubectl get pods -n prod"},
            "data_accessed": [],
        },
        "outcome": {"status": "pending"},
        "context": {},
    }

    first = normalize_event(raw)
    second = normalize_event(first)

    assert first == second
    assert first["action"]["declared_data_accessed"] == []
    assert first["action"]["derived_data_accessed"] == ["infra", "prod"]


def test_normalization_recomputes_instead_of_trusting_derived_access_metadata():
    normalized = normalize_event({
        "agent": {"type": "hermes", "session_id": "s1", "run_id": "r1"},
        "event_type": "tool_call",
        "action": {
            "tool_name": "read_file",
            "parameters": {"path": "README.md"},
            "derived_data_accessed": ["forged-authoritative"],
        },
        "outcome": {"status": "pending"},
        "context": {},
    })

    assert normalized["action"]["derived_data_accessed"] == []
    assert "forged-authoritative" not in normalized["action"]["data_accessed"]


def test_event_schema_version_enforces_the_versioned_contract():
    event = normalize_event({
        "agent": {"type": "hermes", "session_id": "s1", "run_id": "r1"},
        "event_type": "agent_step",
        "action": {"tool_names": []},
        "outcome": {"status": "pending"},
        "context": {"schema_version": 1},
    })

    try:
        validate_event(event)
    except ValidationError:
        pass
    else:
        raise AssertionError("v1 events must not use v4-only lifecycle semantics")


def test_capture_metadata_is_key_aware_but_preserves_safe_authorization_label():
    secret = "Bearer abcdefghijklmnopqrstuvwxyz"
    capture = HERMES_AUTHORIZER_CAPABILITIES.as_context(
        authorization_check="pre_execution",
        token=secret,
        diagnostics={"api_key": "sk-proj-abcdefghijklmnopqrstuvwxyz012345"},
    )
    normalized = normalize_event({
        "agent": {"type": "hermes", "session_id": "s1", "run_id": "r1"},
        "event_type": "decision_point",
        "action": {},
        "outcome": {"status": "success"},
        "context": {"capture": capture},
    })

    stored_capture = normalized["context"]["capture"]
    assert stored_capture["authorization_check"] == "pre_execution"
    assert stored_capture["token"] == "[REDACTED]"
    assert stored_capture["diagnostics"]["api_key"] == "[REDACTED]"
    assert stored_capture["provenance"] == "adapter_asserted"
    assert stored_capture["authenticated"] is False
    validate_event(normalized)


def test_capture_core_field_types_and_event_names_are_validated():
    capture = HERMES_AUTHORIZER_CAPABILITIES.as_context(
        authorization_check="pre_execution",
    )
    invalid_captures = [
        {**capture, "adapter": 7},
        {**capture, "observed_events": "tool_call"},
        {**capture, "observed_events": ["tool_call", "invented_event"]},
        {**capture, "execution_observed": 0},
        {**capture, "enforcement_points": [1]},
        {**capture, "authenticated": True},
        {**capture, "provenance": "cryptographically_verified"},
        {**capture, "authorization_check": "Bearer abcdefghijklmnopqrstuvwxyz"},
    ]

    for invalid_capture in invalid_captures:
        _assert_validation_error(lambda capture=invalid_capture: normalize_event({
            "agent": {"type": "hermes", "session_id": "s1", "run_id": "r1"},
            "event_type": "decision_point",
            "action": {},
            "outcome": {"status": "success"},
            "context": {"capture": capture},
        }))


def test_secret_shaped_structural_identifiers_are_rejected_before_redaction():
    secret_id = "sk-proj-abcdefghijklmnopqrstuvwxyz012345"
    base = {
        "event_id": "event-1",
        "agent": {"type": "hermes", "session_id": "s1", "run_id": "r1"},
        "user": {"id": "user-1", "auth_method": "cli"},
        "event_type": "tool_call",
        "action": {
            "tool_name": "read_file",
            "call_id": "call-1",
            "parameters": {},
        },
        "outcome": {"status": "pending"},
        "context": {},
    }
    invalid_events = [
        {**base, "event_id": secret_id},
        {
            **base,
            "agent": {**base["agent"], "session_id": secret_id},
        },
        {
            **base,
            "agent": {**base["agent"], "run_id": secret_id},
        },
        {
            **base,
            "user": {**base["user"], "id": secret_id},
        },
        {
            **base,
            "action": {**base["action"], "tool_name": secret_id},
        },
        {
            **base,
            "action": {**base["action"], "call_id": secret_id},
        },
    ]

    for invalid_event in invalid_events:
        _assert_validation_error(
            lambda event=invalid_event: normalize_event(event)
        )

    _assert_validation_error(lambda: validate_event({
        **base,
        "event_id": "[REDACTED]",
    }))


def test_validated_structural_identifiers_survive_normalization_unchanged():
    raw = {
        "event_id": "event-author-1",
        "agent": {
            "type": "hermes",
            "session_id": "session-author-1",
            "run_id": "run-tokenizer-1",
        },
        "user": {"id": "author-1", "auth_method": "cli"},
        "event_type": "tool_call",
        "action": {
            "tool_name": "authentication_docs",
            "call_id": "call-tokenizer-1",
            "parameters": {},
        },
        "outcome": {"status": "pending"},
        "context": {},
    }

    normalized = normalize_event(raw)
    assert normalized["event_id"] == raw["event_id"]
    assert normalized["agent"]["session_id"] == raw["agent"]["session_id"]
    assert normalized["agent"]["run_id"] == raw["agent"]["run_id"]
    assert normalized["user"]["id"] == raw["user"]["id"]
    assert normalized["action"]["tool_name"] == raw["action"]["tool_name"]
    assert normalized["action"]["call_id"] == raw["action"]["call_id"]
    validate_event(normalized)


def test_unknown_user_authentication_claim_is_rejected():
    event = {
        "agent": {
            "type": "hermes",
            "session_id": "auth-session",
            "run_id": "auth-run",
        },
        "user": {
            "id": "local-user",
            "auth_method": "cryptographically_verified",
        },
        "event_type": "model_request",
        "action": {},
        "outcome": {"status": "success"},
        "context": {},
    }
    with pytest.raises(ValidationError, match="Unknown auth_method"):
        normalize_event(event)


@pytest.mark.parametrize(
    "action, message",
    [
        (
            {"tool_name": "terminal", "parameters": [], "data_accessed": []},
            "action.parameters must be a dict",
        ),
        (
            {"tool_name": "terminal", "parameters": {}, "data_accessed": "prod"},
            "action.data_accessed must be a list",
        ),
        (
            {
                "tool_name": "terminal",
                "parameters": {},
                "declared_data_accessed": {"prod": True},
            },
            "action.declared_data_accessed must be a list",
        ),
    ],
)
def test_normalize_rejects_malformed_action_collections(action, message):
    raw = {
        "agent": {
            "type": "codex",
            "session_id": "session-collections",
            "run_id": "run-collections",
        },
        "event_type": "tool_call",
        "action": action,
        "outcome": {"status": "pending"},
        "context": {},
    }

    with pytest.raises(ValidationError, match=message):
        normalize_event(raw)


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
    test_derive_unions_declared_and_authoritative_tags()
    test_derive_tags_sorted_deduped()
    test_derive_target_scanned()
    test_derive_scans_large_strings()
    test_derive_scans_parameter_keys()
    test_extract_call_id_explicit()
    test_extract_call_id_does_not_use_target()
    test_extract_call_id_empty_when_neither()
    test_normalize_derives_data_accessed()
    test_normalize_no_derive_for_model_events()
    test_normalize_preserves_call_id()
    print("\n=== ALL SCHEMA TESTS PASSED ===")
