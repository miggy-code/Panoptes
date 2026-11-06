"""Versioned model rate tables used to price audited responses.

Panoptes never guesses a price. A response is priced only when the operator supplied a
rate table that names the model and the provider reported the token counts the formula
needs. Everything else is reported as unpriced.
"""

from __future__ import annotations

import json
import math
import os
from dataclasses import dataclass
from decimal import ROUND_CEILING, Decimal, InvalidOperation
from fractions import Fraction
from typing import Any

MICROS_PER_USD = 1_000_000
RATE_FIELDS = ("input_per_million", "cached_input_per_million", "output_per_million")
# Optional rates. A table without them still loads; a response that reports the
# tokens they price is then unpriced rather than billed at a guessed rate.
OPTIONAL_RATE_FIELDS = ("cache_write_per_million", "cache_write_1h_per_million")


class PricingError(ValueError):
    """The rate table is missing, malformed, or unversioned."""


def usd_to_micros(value: Any) -> int:
    """Convert a USD amount to whole micro-dollars, rounding up (never under-count)."""
    try:
        amount = Decimal(str(value))
    except InvalidOperation:
        raise PricingError("dollar amount must be a number") from None
    if not amount.is_finite() or amount <= 0:
        raise PricingError("dollar amount must be positive and finite")
    return int((amount * MICROS_PER_USD).to_integral_value(rounding=ROUND_CEILING))


def _count(cost: dict, field: str) -> int | None:
    value = cost.get(field)
    if value is None:
        return 0
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


@dataclass(frozen=True)
class PricingTable:
    version: str
    source: str
    models: dict[str, dict[str, Decimal]]

    @classmethod
    def load(cls, path: str) -> "PricingTable":
        try:
            with open(os.path.expanduser(path), encoding="utf-8") as handle:
                raw = json.load(handle)
        except (OSError, json.JSONDecodeError) as exc:
            raise PricingError(f"cannot read pricing file: {type(exc).__name__}") from None
        return cls.from_dict(raw)

    @classmethod
    def from_dict(cls, raw: Any) -> "PricingTable":
        if not isinstance(raw, dict) or raw.get("currency") != "USD":
            raise PricingError("pricing table must be a USD object")
        version, source = raw.get("version"), raw.get("source")
        if not isinstance(version, str) or not version or not isinstance(source, str) or not source:
            raise PricingError("pricing table needs a version and a source")
        models: dict[str, dict[str, Decimal]] = {}
        for name, rate in (raw.get("models") or {}).items():
            if not isinstance(rate, dict):
                raise PricingError(f"rate for {name} must be an object")
            parsed = {}
            for field in RATE_FIELDS + OPTIONAL_RATE_FIELDS:
                if field in OPTIONAL_RATE_FIELDS and field not in rate:
                    continue
                try:
                    value = Decimal(str(rate[field]))
                except (KeyError, InvalidOperation):
                    raise PricingError(f"rate for {name} lacks a valid {field}") from None
                if not value.is_finite() or value < 0:
                    raise PricingError(f"rate for {name} has an invalid {field}")
                parsed[field] = value
            models[str(name)] = parsed
        if not models:
            raise PricingError("pricing table names no models")
        return cls(version=version, source=source, models=models)

    def cost_micros(self, model: str | None, cost: dict) -> int | None:
        """Price one response in micro-dollars, or None when it cannot be priced exactly.

        ``tokens_in`` is the whole prompt: cache reads (``cached_input_tokens``) and
        cache writes (``cache_creation_input_tokens``) are parts of it. Cache reads are
        billed at the cached rate; cache writes at ``cache_write_per_million``, except
        the ``cache_creation_1h_input_tokens`` part at ``cache_write_1h_per_million``;
        the rest of the prompt plus ``tool_prompt_tokens`` at the input rate; output
        (which already includes reasoning) at the output rate. Absent read and tool
        counts are zero, which never under-counts. A response that reports cache
        writes the table has no rate for, or a TTL split that is partial or does not
        sum to the total, is unpriced: Panoptes never guesses.

        The arithmetic is exact (rates are converted to fractions), and the result is
        rounded up to a whole micro-dollar once, at the end.
        """
        rate = self.models.get(model or "")
        tokens_in, tokens_out = cost.get("tokens_in"), cost.get("tokens_out")
        if rate is None or any(isinstance(v, bool) or not isinstance(v, int) or v < 0 for v in (tokens_in, tokens_out)):
            return None
        cached, tool_prompt = _count(cost, "cached_input_tokens"), _count(cost, "tool_prompt_tokens")
        writes = _count(cost, "cache_creation_input_tokens")
        if None in (cached, tool_prompt, writes) or cached + writes > tokens_in:
            return None
        split = _write_split(cost, writes)
        if split is _INVALID or cost.get("cache_creation_split_invalid") is True:
            return None
        # A rate in USD per million tokens times a token count is exactly micro-dollars.
        micros = (
            Fraction(tokens_in - cached - writes + tool_prompt) * Fraction(rate["input_per_million"])
            + Fraction(cached) * Fraction(rate["cached_input_per_million"])
            + Fraction(tokens_out) * Fraction(rate["output_per_million"])
        )
        if writes:
            write_cost = _cache_write_cost(rate, writes, split)
            if write_cost is None:
                return None
            micros += write_cost
        return math.ceil(micros)


_INVALID = object()


def _write_split(cost: dict, writes: int) -> tuple[int, int] | None | object:
    """The (5-minute, 1-hour) split of cache writes; None when no split is reported; _INVALID when
    the split is partial, malformed, or does not sum to the total (including a nonzero split with no
    writes)."""
    present = [field in cost and cost[field] is not None for field in _SPLIT_FIELDS]
    if not any(present):
        return None
    if not all(present):
        return _INVALID
    five, hour = (_count(cost, field) for field in _SPLIT_FIELDS)
    if five is None or hour is None or five + hour != writes:
        return _INVALID
    return five, hour


_SPLIT_FIELDS = ("cache_creation_5m_input_tokens", "cache_creation_1h_input_tokens")


def _cache_write_cost(rate: dict[str, Decimal], writes: int, split: tuple[int, int] | None) -> Fraction | None:
    """Exact cost of ``writes`` cache-write tokens in micro-dollars, or None when unknown."""
    write_rate = rate.get("cache_write_per_million")
    hour_rate = rate.get("cache_write_1h_per_million")
    if split is None:
        # No TTL breakdown. With a separate 1-hour rate on the table the split
        # changes the price and is unknown, so the response stays unpriced.
        if write_rate is None or hour_rate is not None:
            return None
        return Fraction(writes) * Fraction(write_rate)
    five, hour = split
    if (five and write_rate is None) or (hour and hour_rate is None):
        return None
    return Fraction(five) * Fraction(write_rate or 0) + Fraction(hour) * Fraction(hour_rate or 0)
