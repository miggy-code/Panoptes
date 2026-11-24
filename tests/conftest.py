"""Fixtures shared by the proxy test modules."""

import pytest

from fake_upstream import FakeUpstream


@pytest.fixture
def upstream(monkeypatch):
    """A fake upstream that every provider route points at."""
    fake = FakeUpstream()
    origin = f"http://127.0.0.1:{fake.port}"
    for provider in ("ANTHROPIC", "OPENAI", "GEMINI"):
        monkeypatch.setenv(f"PANOPTES_UPSTREAM_{provider}", origin)
    yield fake
    fake.close()
