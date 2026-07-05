"""Quick integration test for panoptes.proxy.

Starts the proxy server, sends a mock OpenAI chat completion request
through it, and verifies audit events are captured.
"""

import json
import tempfile
import time
import os
import httpx
from panoptes.proxy import ProxyServer


def test_proxy_capture_openai():
    """Start proxy, send mock request, verify events captured."""
    # Use a temp file for the database
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        db_path = tmp.name

    # Start proxy
    server = ProxyServer(host="127.0.0.1", port=0, db_path=db_path)
    port = server.start()
    print(f"Proxy started on port {port}")

    try:
        # Build a mock OpenAI chat completion request body
        req_body = {
            "model": "gpt-4",
            "messages": [
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "user", "content": "What is 2+2?"},
                {"role": "assistant", "content": None, "tool_calls": [
                    {"id": "call_123", "type": "function",
                     "function": {"name": "calculator", "arguments": '{"expr": "2+2"}'}}
                ]},
                {"role": "tool", "tool_call_id": "call_123", "name": "calculator",
                 "content": "4"},
            ],
            "tools": [
                {"type": "function", "function": {"name": "calculator",
                 "parameters": {"type": "object", "properties": {"expr": {"type": "string"}}}}},
            ],
            "stream": False,
        }

        # Send the request through the proxy to an HTTP endpoint for testing.
        # (HTTP so httpx uses plain forward-proxy mode, not CONNECT tunneling.)
        proxy_url = f"http://127.0.0.1:{port}"
        test_url = "http://httpbin.org/post"

        print(f"Sending test request through proxy at {proxy_url} to {test_url}")

        try:
            resp = httpx.post(
                test_url,
                json=req_body,
                proxy=proxy_url,
                timeout=15,
            )
            print(f"Response status: {resp.status_code}")
            print(f"Response body (truncated): {resp.text[:200]}...")
        except Exception as e:
            print(f"Request error (expected if no internet): {e}")
            print("This is fine — the proxy handler ran and captured the event.")

        # Give the proxy a moment to process
        time.sleep(0.5)

        # Check captured events
        events = server.events
        print(f"\nCaptured {len(events)} events:")
        for i, event in enumerate(events):
            print(f"\n--- Event {i+1} ---")
            print(f"  event_type: {event.get('event_type')}")
            print(f"  agent.type: {event.get('agent', {}).get('type')}")
            print(f"  action: {json.dumps(event.get('action', {}), indent=2)}")
            print(f"  outcome: {json.dumps(event.get('outcome', {}), indent=2)}")
            print(f"  cost: {json.dumps(event.get('cost', {}), indent=2)}")

        # Assertions
        event_types = [e["event_type"] for e in events]
        assert "model_request" in event_types, f"Expected model_request event, got {event_types}"
        assert "tool_result" in event_types, f"Expected tool_result event, got {event_types}"

        # Verify event structure
        for event in events:
            assert "event_id" in event, "Missing event_id"
            assert "timestamp" in event, "Missing timestamp"
            assert "agent" in event, "Missing agent"
            assert "type" in event["agent"], "Missing agent.type"
            assert "session_id" in event["agent"], "Missing agent.session_id"
            assert "run_id" in event["agent"], "Missing agent.run_id"
            assert "event_type" in event, "Missing event_type"
            assert "context" in event, "Missing context"

        print("\n✅ All assertions passed!")
        return True

    finally:
        server.stop()
        print("Proxy stopped")
        # Clean up
        try:
            os.unlink(db_path)
        except OSError:
            pass


if __name__ == "__main__":
    test_proxy_capture_openai()
