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

from .schema import ALLOWED_AGENT_TYPES, ValidationError, validate_identifier


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
    revoked_at  INTEGER
)
"""


class CredentialConfigError(ValueError):
    """Provider keys are missing or stored unsafely. Messages never include values."""


class TokenRejected(Exception):
    """A request did not present exactly one valid, live Panoptes token."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        # One of: missing, ambiguous, unknown, expired, revoked.
        self.reason = reason


@dataclass(frozen=True)
class SessionIdentity:
    """The agent identity a Panoptes token was issued for."""

    token_id: str
    agent_type: str
    session_id: str


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
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
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
        conn = db._get_conn()
        try:
            conn.execute(CREATE_SESSION_TOKENS)
            conn.commit()
        finally:
            db._put_conn(conn)

    def issue(
        self,
        agent_type: str,
        session_id: str,
        ttl_seconds: int = DEFAULT_TOKEN_TTL_SECONDS,
    ) -> tuple[str, dict]:
        """Return ``(token, record)``. The token is not recoverable afterwards."""
        if agent_type not in ALLOWED_AGENT_TYPES or agent_type == "unknown":
            raise ValidationError(
                f"agent type must be one of {sorted(ALLOWED_AGENT_TYPES - {'unknown'})}"
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
        token = TOKEN_PREFIX + secrets.token_urlsafe(32)
        issued_at = int(time.time())
        record = {
            "token_id": secrets.token_hex(8),
            "agent_type": agent_type,
            "session_id": session_id,
            "issued_at": issued_at,
            "expires_at": issued_at + ttl_seconds,
            "revoked_at": None,
        }
        conn = self._db._get_conn()
        try:
            conn.execute(
                "INSERT INTO session_tokens (token_id, token_hash, agent_type, "
                "session_id, issued_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)",
                (
                    record["token_id"], _token_hash(token), agent_type,
                    session_id, record["issued_at"], record["expires_at"],
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
            rows = conn.execute(
                "SELECT token_id, agent_type, session_id, issued_at, expires_at, "
                "revoked_at FROM session_tokens ORDER BY issued_at DESC, token_id"
            ).fetchall()
        finally:
            self._db._put_conn(conn)
        return [dict(row) for row in rows]

    def resolve(self, token: str | None, now: float | None = None) -> SessionIdentity:
        """Return the identity for a live token or raise ``TokenRejected``."""
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
        finally:
            self._db._put_conn(conn)
        if row is None:
            raise TokenRejected("unknown")
        if row["revoked_at"] is not None:
            raise TokenRejected("revoked")
        if (time.time() if now is None else now) >= row["expires_at"]:
            raise TokenRejected("expired")
        return SessionIdentity(
            token_id=row["token_id"],
            agent_type=row["agent_type"],
            session_id=row["session_id"],
        )
