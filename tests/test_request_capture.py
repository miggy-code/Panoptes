"""Model-request events carry hashes and names, never prompt text."""

import hashlib
import json

import pytest

import panoptes.providers as providers
from panoptes.proxy import AuditEventWriter

SECRET_TEXT = "the confidential system prompt wording"
TURN_TEXT = "an earlier user turn about project orchid"


def sha(value):
    canonical = json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def fingerprint(path, body):
    return providers.detect(path, body).request_fingerprint(body)


ANTHROPIC = {
    "model": "claude-test", "system": SECRET_TEXT,
    "messages": [
        {"role": "user", "content": TURN_TEXT},
        {"role": "assistant", "content": "ok"},
        {"role": "user", "content": "latest"},
    ],
    "tools": [{"name": "read_file", "input_schema": {}},
              {"name": "write_file", "input_schema": {}},
              {"type": "web_search_20250305", "name": "web_search"}],
}
OPENAI_CHAT = {
    "model": "gpt-test",
    "messages": [
        {"role": "system", "content": SECRET_TEXT},
        {"role": "user", "content": TURN_TEXT},
        {"role": "assistant", "content": "ok"},
        {"role": "user", "content": "latest"},
    ],
    "tools": [{"type": "function", "function": {"name": "read_file"}}],
}
OPENAI_RESPONSES = {
    "model": "gpt-test", "instructions": SECRET_TEXT,
    "input": [{"role": "user", "content": TURN_TEXT},
              {"role": "user", "content": "latest"}],
    "tools": [{"type": "function", "name": "read_file"}, {"type": "web_search"}],
}
GEMINI = {
    "system_instruction": {"parts": [{"text": SECRET_TEXT}]},
    "contents": [{"role": "user", "parts": [{"text": TURN_TEXT}]},
                 {"role": "model", "parts": [{"text": "ok"}]},
                 {"role": "user", "parts": [{"text": "latest"}]}],
    "tools": [{"function_declarations": [{"name": "read_file"}, {"name": "write_file"}]},
              {"google_search": {}}],
}


def test_anthropic_fingerprint():
    fp = fingerprint("/v1/messages", ANTHROPIC)
    assert fp["system_prompt_sha256"] == sha(SECRET_TEXT)
    assert fp["history_sha256"] == sha(ANTHROPIC["messages"][:2])
    assert fp["declared_tools"] == ["read_file", "write_file", "web_search"]


def test_openai_chat_separates_system_from_history():
    fp = fingerprint("/v1/chat/completions", OPENAI_CHAT)
    assert fp["system_prompt_sha256"] == sha([SECRET_TEXT])
    assert fp["history_sha256"] == sha(OPENAI_CHAT["messages"][1:3])
    assert fp["declared_tools"] == ["read_file"]


def test_openai_responses_dialect():
    fp = fingerprint("/v1/responses", OPENAI_RESPONSES)
    assert fp["system_prompt_sha256"] == sha(SECRET_TEXT)
    assert fp["history_sha256"] == sha(OPENAI_RESPONSES["input"][:1])
    assert fp["declared_tools"] == ["read_file", "web_search"]


def test_gemini_fingerprint():
    fp = fingerprint("/v1beta/models/gemini-test:generateContent", GEMINI)
    assert fp["system_prompt_sha256"] == sha(GEMINI["system_instruction"])
    assert fp["history_sha256"] == sha(GEMINI["contents"][:2])
    assert fp["declared_tools"] == ["read_file", "write_file", "google_search"]


def test_the_history_hash_ignores_the_newest_turn_only():
    a = fingerprint("/v1/messages", ANTHROPIC)
    other = json.loads(json.dumps(ANTHROPIC))
    other["messages"][-1]["content"] = "a different latest turn"
    b = fingerprint("/v1/messages", other)
    assert a["history_sha256"] == b["history_sha256"]
    other["messages"][0]["content"] = "a different first turn"
    assert fingerprint("/v1/messages", other)["history_sha256"] != a["history_sha256"]


def test_nothing_is_reported_when_there_is_nothing_to_hash():
    assert fingerprint("/v1/messages", {"model": "m", "messages": [
        {"role": "user", "content": "hi"}]}) == {}
    assert fingerprint("/v1/messages", None) == {}


@pytest.mark.parametrize("body", [
    {"messages": "not a list", "tools": "nope", "system": 5},
    {"messages": [1, None], "tools": [1, "x", None]},
])
def test_malformed_bodies_never_raise(body):
    fingerprint("/v1/messages", body)
    fingerprint("/v1/chat/completions", body)
    fingerprint("/v1beta/models/g:generateContent", {"contents": 3, "tools": 4})


def test_the_event_carries_the_fields_and_no_text_in_them():
    writer = AuditEventWriter(db=None)
    events, _ = writer.build_request_events(
        path="/v1/messages", method="POST", req_headers={}, req_body=ANTHROPIC)
    action = next(e for e in events if e["event_type"] == "model_request")["action"]
    assert action["messages_count"] == 4          # 3 messages + the system prompt
    assert len(action["system_prompt_sha256"]) == 64
    assert action["declared_tools"] == ["read_file", "write_file", "web_search"]
    derived = json.dumps({k: action[k] for k in (
        "system_prompt_sha256", "history_sha256", "declared_tools")})
    assert SECRET_TEXT not in derived and TURN_TEXT not in derived


def test_chat_message_hashes_survive_raw_request_truncation():
    messages = [{"role": "user", "content": "hello world " * 6000}]
    events, _ = AuditEventWriter(db=None).build_request_events(
        path="/v1/chat/completions", method="POST", req_headers={},
        req_body={"model": "m", "messages": messages})
    request = next(e for e in events if e["event_type"] == "model_request")
    assert request["raw_request"].endswith("...[truncated]")
    assert request["action"]["message_hashes"] == ["b886fe52ddceb949"]
    from panoptes.schema import normalize_event
    assert normalize_event(request)["action"]["message_hashes"] == request["action"]["message_hashes"]


def test_chat_message_hashes_are_bounded():
    messages = [{"role": "user", "content": "hello"}] * 1025
    events, _ = AuditEventWriter(db=None).build_request_events(
        path="/v1/chat/completions", method="POST", req_headers={},
        req_body={"model": "m", "messages": messages})
    assert "message_hashes" not in events[0]["action"]
