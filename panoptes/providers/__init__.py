"""Provider registry for Panoptes.

Exposes a REGISTRY (ordered list of Provider instances) and a detect()
function that picks the right provider from a request path + body.

Detection order matters: Gemini must come before OpenAI because Gemini paths
can contain "/models" which would otherwise match the OpenAI pattern.
"""

from __future__ import annotations

from .anthropic import AnthropicProvider
from .base import Provider, UnknownProvider
from .gemini import GeminiProvider
from .openai import OpenAIProvider

# Ordered registry: first match wins.
REGISTRY: list[Provider] = [
    AnthropicProvider(),
    GeminiProvider(),   # before OpenAI — Gemini paths contain /v1beta/models/...
    OpenAIProvider(),
]

_UNKNOWN = UnknownProvider()


def detect(path: str, body: dict | None) -> Provider:
    """Detect the provider for a request from its path and body.

    The routed API path takes priority because provider request bodies can be
    structurally ambiguous (for example, both OpenAI and Anthropic use a
    ``messages`` list). Body matching is only a fallback for custom paths.
    """
    # 1. Route-based detection (highest specificity)
    for provider in REGISTRY:
        if provider.matches_path(path):
            return provider

    # 2. Body-based fallback for custom upstream paths
    if isinstance(body, dict):
        for provider in REGISTRY:
            if provider.matches_body(body):
                return provider

    return _UNKNOWN


__all__ = [
    "Provider",
    "AnthropicProvider",
    "OpenAIProvider",
    "GeminiProvider",
    "UnknownProvider",
    "REGISTRY",
    "detect",
]
