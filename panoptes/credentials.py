"""Provider credential isolation and Panoptes session tokens.

In credential-injection mode the proxy process holds the only copy of each
provider API key. Agents receive a random Panoptes session token instead. The
proxy resolves that token to an agent type and session id, strips every client
credential, and adds the provider key for the routed upstream only.

Only a SHA-256 digest of each token is stored, next to the audit events in the
same SQLite database. Neither a token nor a provider key is ever written to the
audit trail or to logs.
"""

from __future__ import annotations

import hashlib
import os
import secrets
import stat
import time
from dataclasses import dataclass
from typing import Any, Mapping

import yaml

from .pricing import PricingError, usd_to_micros
from .schema import KNOWN_AGENT_TYPES, ValidationError, validate_identifier


PROVIDER_KEY_ENV: dict[str, str] = {
    "anthropic": "PANOPTES_ANTHROPIC_API_KEY",
    "openai": "PANOPTES_OPENAI_API_KEY",
    "gemini": "PANOPTES_GEMINI_API_KEY",
}

TOKEN_PREFIX = "pnpt_"
DEFAULT_TOKEN_TTL_SECONDS = 8 * 60 * 60
MAX_TOKEN_TTL_SECONDS = 30 * 24 * 60 * 60

CREATE_SESSION_TOKENS = """
CREATE TABLE IF NOT EXISTS session_tokens (
    token_id    TEXT PRIMARY KEY,
    token_hash  TEXT    NOT NULL UNIQUE,
    agent_type  TEXT    NOT NULL,
    session_id  TEXT    NOT NULL,
    issued_at   INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    revoked_at  INTEGER,
    max_requests  INTEGER,
    requests_used INTEGER NOT NULL DEFAULT 0,
    max_usd_micros      INTEGER,
    reserve_usd_micros  INTEGER NOT NULL DEFAULT 0,
    usd_used_micros     INTEGER NOT NULL DEFAULT 0,
    usd_reserved_micros INTEGER NOT NULL DEFAULT 0
)
"""
# Databases created before request budgets existed lack these columns.
SESSION_TOKEN_BUDGET_COLUMNS = (
    ("max_requests", "INTEGER"),
    ("requests_used", "INTEGER NOT NULL DEFAULT 0"),
    ("max_usd_micros", "INTEGER"),
    ("reserve_usd_micros", "INTEGER NOT NULL DEFAULT 0"),
    ("usd_used_micros", "INTEGER NOT NULL DEFAULT 0"),
    ("usd_reserved_micros", "INTEGER NOT NULL DEFAULT 0"),
)
MAX_TOKEN_REQUEST_BUDGET = 10_000_000


class CredentialConfigError(ValueError):
    """Provider keys are missing or stored unsafely. Messages never include values."""


class TokenRejected(Exception):
    """A request did not present exactly one valid, live Panoptes token."""

    def __init__(self, reason: str, identity: "SessionIdentity | None" = None) -> None:
        super().__init__(reason)
        # One of: missing, ambiguous, unknown, expired, revoked, budget_exhausted,
        # usd_budget_exhausted.
        self.reason = reason
        # Set only when the token itself was valid (budget_exhausted).
        self.identity = identity


@dataclass(frozen=True)
class SessionIdentity:
    """The agent identity a Panoptes token was issued for."""

    token_id: str
    agent_type: str
    session_id: str
    # Micro-dollars held for this request until ``settle`` charges the real cost.
    reserved_usd_micros: int = 0


# ---------------------------------------------------------------------------
# Provider keys
# ---------------------------------------------------------------------------


def _validate_provider_key(provider: str, value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise CredentialConfigError(f"{provider} API key must be a non-empty string")
    value = value.strip()
    if any(ch.isspace() or ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value):
        raise CredentialConfigError(
            f"{provider} API key must not contain whitespace or control characters"
        )
    if value.startswith(TOKEN_PREFIX):
        raise CredentialConfigError(
            f"{provider} API key looks like a Panoptes session token"
        )
    return value


def _read_credentials_file(path: str) -> dict[str, Any]:
    """Read an owner-only YAML mapping of provider name to API key."""
    expanded = os.path.expanduser(path)
    # O_NONBLOCK keeps a FIFO in place of the file from hanging startup inside
    # open() before the regular-file check; it does not affect regular files.
    flags = (
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        fd = os.open(expanded, flags)
    except OSError as exc:
        raise CredentialConfigError(
            f"Cannot open credentials file {expanded}: {exc.strerror}"
        ) from None
    with os.fdopen(fd, "r", encoding="utf-8") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise CredentialConfigError(
                f"Credentials file {expanded} must be a regular file"
            )
        if info.st_mode & 0o077:
            raise CredentialConfigError(
                f"Credentials file {expanded} must not be readable by group or "
                "others (chmod 600)"
            )
        if hasattr(os, "getuid") and info.st_uid != os.getuid():
            raise CredentialConfigError(
                f"Credentials file {expanded} must be owned by the user running Panoptes"
            )
        try:
            data = yaml.safe_load(handle)
        except yaml.YAMLError:
            # The parser error can quote file content, which is a secret.
            raise CredentialConfigError(
                f"Credentials file {expanded} is not valid YAML"
            ) from None
    if not isinstance(data, dict):
        raise CredentialConfigError(
            f"Credentials file {expanded} must contain a mapping of provider to key"
        )
    unknown = sorted(str(name) for name in data if name not in PROVIDER_KEY_ENV)
    if unknown:
        raise CredentialConfigError(
            f"Credentials file {expanded} names unknown providers: {unknown}"
        )
    return data


def load_provider_keys(
    credentials_file: str | None = None,
    environ: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Load provider API keys from a credentials file, else the environment."""
    if credentials_file:
        raw = _read_credentials_file(credentials_file)
    else:
        env = os.environ if environ is None else environ
        raw = {
            provider: env[var]
            for provider, var in PROVIDER_KEY_ENV.items()
            if env.get(var)
        }
    keys = {
        provider: _validate_provider_key(provider, value)
        for provider, value in raw.items()
    }
    if not keys:
        raise CredentialConfigError(
            "Credential injection needs at least one provider key: set "
            + ", ".join(PROVIDER_KEY_ENV.values())
            + " or pass --credentials-file"
        )
    return keys


# ---------------------------------------------------------------------------
# Session tokens
# ---------------------------------------------------------------------------


def _token_hash(token: str) -> str:
    # Tokens carry 256 random bits, so a fast digest is sufficient.
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class SessionTokenStore:
    """Issue, revoke, and resolve Panoptes session tokens in the audit DB."""

    def __init__(self, db: Any) -> None:
        self._db = db
        if getattr(db, "_read_only", False):
            return
        conn = db._get_conn()
        try:
            conn.execute(CREATE_SESSION_TOKENS)
            existing = {row[1] for row in conn.execute("PRAGMA table_info(session_tokens)")}
            for name, definition in SESSION_TOKEN_BUDGET_COLUMNS:
                if name not in existing:
                    conn.execute(f"ALTER TABLE session_tokens ADD COLUMN {name} {definition}")
            conn.commit()
        finally:
            db._put_conn(conn)

    def issue(
        self,
        agent_type: str,
        session_id: str,
        ttl_seconds: int = DEFAULT_TOKEN_TTL_SECONDS,
        max_requests: int | None = None,
        max_usd: Any = None,
        reserve_usd: Any = None,
    ) -> tuple[str, dict]:
        """Return ``(token, record)``. The token is not recoverable afterwards.

        ``max_requests`` caps how many proxied requests the token may authorize.
        Every request that presents a live token consumes one unit, including
        requests the provider later rejects. ``None`` means unlimited.

        ``max_usd`` caps the dollars the token may spend and needs ``reserve_usd``, the
        most one request is expected to cost. Admitting a request holds its reservation;
        ``settle`` replaces the hold with the priced cost (the whole reservation when the
        response cannot be priced). A request is refused when settled spend plus all
        holds plus its own reservation would pass the cap, so the cap stays hard as long
        as no single response costs more than ``reserve_usd``.
        """
        if agent_type not in KNOWN_AGENT_TYPES or agent_type == "unknown":
            raise ValidationError(
                f"agent type must be one of {sorted(KNOWN_AGENT_TYPES - {'unknown'})}"
            )
        validate_identifier(session_id, "session_id")
        if (
            isinstance(ttl_seconds, bool)
            or not isinstance(ttl_seconds, int)
            or not 0 < ttl_seconds <= MAX_TOKEN_TTL_SECONDS
        ):
            raise ValidationError(
                f"ttl must be between 1 and {MAX_TOKEN_TTL_SECONDS} seconds"
            )
        if max_requests is not None and (
            isinstance(max_requests, bool)
            or not isinstance(max_requests, int)
            or not 0 < max_requests <= MAX_TOKEN_REQUEST_BUDGET
        ):
            raise ValidationError(
                f"max requests must be between 1 and {MAX_TOKEN_REQUEST_BUDGET}"
            )
        max_usd_micros = reserve_usd_micros = None
        if (max_usd is None) != (reserve_usd is None):
            raise ValidationError("a dollar cap needs both a cap and a per-request reservation")
        if max_usd is not None:
            try:
                max_usd_micros, reserve_usd_micros = usd_to_micros(max_usd), usd_to_micros(reserve_usd)
            except PricingError as exc:
                raise ValidationError(str(exc)) from None
            if reserve_usd_micros > max_usd_micros:
                raise ValidationError("the per-request reservation exceeds the dollar cap")
        token = TOKEN_PREFIX + secrets.token_urlsafe(32)
        issued_at = int(time.time())
        record = {
            "token_id": secrets.token_hex(8),
            "agent_type": agent_type,
            "session_id": session_id,
            "issued_at": issued_at,
            "expires_at": issued_at + ttl_seconds,
            "revoked_at": None,
            "max_requests": max_requests,
            "requests_used": 0,
            "max_usd_micros": max_usd_micros,
            "reserve_usd_micros": reserve_usd_micros or 0,
            "usd_used_micros": 0,
            "usd_reserved_micros": 0,
        }
        conn = self._db._get_conn()
        try:
            conn.execute(
                "INSERT INTO session_tokens (token_id, token_hash, agent_type, "
                "session_id, issued_at, expires_at, max_requests, max_usd_micros, "
                "reserve_usd_micros) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    record["token_id"], _token_hash(token), agent_type,
                    session_id, record["issued_at"], record["expires_at"],
                    max_requests, max_usd_micros, reserve_usd_micros or 0,
                ),
            )
            conn.commit()
        finally:
            self._db._put_conn(conn)
        return token, record

    def revoke(self, token_id: str) -> bool:
        """Revoke a token by id. Returns False if no live token had that id."""
        conn = self._db._get_conn()
        try:
            cursor = conn.execute(
                "UPDATE session_tokens SET revoked_at = ? "
                "WHERE token_id = ? AND revoked_at IS NULL",
                (int(time.time()), token_id),
            )
            conn.commit()
            return cursor.rowcount > 0
        finally:
            self._db._put_conn(conn)

    def list_tokens(self) -> list[dict]:
        """Return token metadata, newest first. Hashes are not included."""
        conn = self._db._get_conn()
        try:
            if conn.execute(
                "SELECT 1 FROM sqlite_master "
                "WHERE type = 'table' AND name = 'session_tokens'"
            ).fetchone() is None:
                return []
            columns = {row[1] for row in conn.execute("PRAGMA table_info(session_tokens)")}
            budget = ", ".join(
                name if name in columns else f"{default} AS {name}"
                for name, default in (
                    ("max_requests", "NULL"), ("requests_used", "0"),
                    ("max_usd_micros", "NULL"), ("reserve_usd_micros", "0"),
                    ("usd_used_micros", "0"), ("usd_reserved_micros", "0"),
                )
            )
            rows = conn.execute(
                "SELECT token_id, agent_type, session_id, issued_at, expires_at, "
                f"revoked_at, {budget} "
                "FROM session_tokens ORDER BY issued_at DESC, token_id"
            ).fetchall()
        finally:
            self._db._put_conn(conn)
        return [dict(row) for row in rows]

    def resolve(
        self,
        token: str | None,
        now: float | None = None,
        consume: bool = False,
    ) -> SessionIdentity:
        """Return the identity for a live token or raise ``TokenRejected``.

        With ``consume=True`` the call also spends one unit of the token's request
        budget atomically, raising ``TokenRejected("budget_exhausted")`` when none
        remains.
        """
        if not token:
            raise TokenRejected("missing")
        if not token.startswith(TOKEN_PREFIX):
            raise TokenRejected("unknown")
        conn = self._db._get_conn()
        try:
            row = conn.execute(
                "SELECT token_id, agent_type, session_id, expires_at, revoked_at "
                "FROM session_tokens WHERE token_hash = ?",
                (_token_hash(token),),
            ).fetchone()
            if row is None:
                raise TokenRejected("unknown")
            if row["revoked_at"] is not None:
                raise TokenRejected("revoked")
            if (time.time() if now is None else now) >= row["expires_at"]:
                raise TokenRejected("expired")
            reserve = 0
            if consume:
                # One atomic statement spends a request and places the dollar hold, so
                # concurrent requests cannot jointly pass either cap.
                cursor = conn.execute(
                    "UPDATE session_tokens SET requests_used = requests_used + 1, "
                    "usd_reserved_micros = usd_reserved_micros + reserve_usd_micros "
                    "WHERE token_id = ? AND (max_requests IS NULL "
                    "OR requests_used < max_requests) AND (max_usd_micros IS NULL "
                    "OR usd_used_micros + usd_reserved_micros + reserve_usd_micros "
                    "<= max_usd_micros)",
                    (row["token_id"],),
                )
                conn.commit()
                if cursor.rowcount == 0:
                    state = conn.execute(
                        "SELECT max_requests, requests_used FROM session_tokens "
                        "WHERE token_id = ?",
                        (row["token_id"],),
                    ).fetchone()
                    requests_spent = (
                        state["max_requests"] is not None
                        and state["requests_used"] >= state["max_requests"]
                    )
                    raise TokenRejected(
                        "budget_exhausted" if requests_spent else "usd_budget_exhausted",
                        SessionIdentity(
                            token_id=row["token_id"],
                            agent_type=row["agent_type"],
                            session_id=row["session_id"],
                        ),
                    )
                reserve = conn.execute(
                    "SELECT CASE WHEN max_usd_micros IS NULL THEN 0 "
                    "ELSE reserve_usd_micros END FROM session_tokens WHERE token_id = ?",
                    (row["token_id"],),
                ).fetchone()[0]
        finally:
            self._db._put_conn(conn)
        return SessionIdentity(
            token_id=row["token_id"],
            agent_type=row["agent_type"],
            session_id=row["session_id"],
            reserved_usd_micros=reserve,
        )

    def settle(self, identity: SessionIdentity, actual_usd_micros: int | None) -> None:
        """Replace an admitted request's dollar hold with what it actually cost.

        ``None`` means the response could not be priced, so the whole reservation is
        charged. A no-op for tokens without a dollar cap.
        """
        if identity.reserved_usd_micros <= 0:
            return
        charge = identity.reserved_usd_micros if actual_usd_micros is None else actual_usd_micros
        conn = self._db._get_conn()
        try:
            conn.execute(
                "UPDATE session_tokens SET "
                "usd_reserved_micros = MAX(usd_reserved_micros - ?, 0), "
                "usd_used_micros = usd_used_micros + ? WHERE token_id = ?",
                (identity.reserved_usd_micros, charge, identity.token_id),
            )
            conn.commit()
        finally:
            self._db._put_conn(conn)
