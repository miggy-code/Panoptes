"""Strict JSON decoding shared by policy and provider boundaries."""

import json
from typing import Any


def _strict_json_loads(value: str | bytes | bytearray) -> Any:
    """Decode standards-compliant JSON while rejecting ambiguous objects.

    Duplicate object names are a parser-differential risk at an enforcement
    boundary: Panoptes and the eventual consumer might otherwise make policy
    decisions from different values in the same byte sequence. Non-finite
    constants are outside JSON and are rejected as well.
    """

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in pairs:
            if key in result:
                raise ValueError("duplicate JSON object key")
            result[key] = item
        return result

    def reject_constant(constant: str) -> Any:
        raise ValueError(f"non-finite JSON number {constant!r}")

    try:
        return json.loads(
            value,
            object_pairs_hook=unique_object,
            parse_constant=reject_constant,
        )
    except RecursionError as exc:
        raise ValueError("JSON nesting exceeds the parser limit") from exc
