"""Password hashing and JWT primitives.

Tokens carry ``iss``/``aud``/``iat``/``nbf``/``jti``/``type`` and are verified strictly:
the audience and issuer are checked, the algorithm is pinned by configuration (never
taken from the token header), and access and refresh tokens are not interchangeable.
"""

from __future__ import annotations

import hashlib
import secrets
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

import bcrypt
from jose import JWTError, jwt

from app.core.config import settings

TokenType = Literal["access", "refresh"]


class TokenError(Exception):
    """Raised for any token that fails validation, with a stable reason code."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class IssuedToken:
    token: str
    jti: str
    expires_at: datetime
    family_id: uuid.UUID | None = None


# --------------------------------------------------------------------- passwords
def hash_password(password: str) -> str:
    """Hash a password with bcrypt. The platform password policy validates first."""
    password_bytes = password.encode("utf-8")
    if len(password_bytes) > settings.PASSWORD_MAX_LENGTH:
        raise ValueError(f"Password cannot exceed {settings.PASSWORD_MAX_LENGTH} bytes.")
    return bcrypt.hashpw(password_bytes, bcrypt.gensalt(rounds=12)).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    """Constant-time-ish verification. Over-long input is rejected, never truncated."""
    if not password or not password_hash:
        return False
    password_bytes = password.encode("utf-8")
    if len(password_bytes) > settings.PASSWORD_MAX_LENGTH:
        return False
    try:
        return bcrypt.checkpw(password_bytes, password_hash.encode("utf-8"))
    except (ValueError, TypeError):
        return False


def password_fingerprint(password: str) -> str:
    """Stable, non-reversible fingerprint used to detect password reuse in tests/logs."""
    return hashlib.sha256(password.encode("utf-8")).hexdigest()[:16]


# --------------------------------------------------------------------- tokens
def _now() -> datetime:
    return datetime.now(UTC)


def _encode(payload: dict[str, Any]) -> str:
    return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def _base_payload(
    subject: str, token_type: TokenType, expires_at: datetime, jti: str, extra: dict[str, Any] | None = None
) -> dict[str, Any]:
    now = _now()
    payload: dict[str, Any] = {
        "sub": subject,
        "type": token_type,
        "jti": jti,
        "iss": settings.JWT_ISSUER,
        "aud": settings.JWT_AUDIENCE,
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int(expires_at.timestamp()),
    }
    if extra:
        payload.update(extra)
    return payload


def issue_access_token(
    subject: str, user_id: str, role: str, expires_delta: timedelta | None = None
) -> IssuedToken:
    expires_at = _now() + (expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES))
    jti = uuid.uuid4().hex
    token = _encode(_base_payload(subject, "access", expires_at, jti, {"uid": user_id, "role": role}))
    return IssuedToken(token=token, jti=jti, expires_at=expires_at)


def issue_refresh_token(
    subject: str, user_id: str, family_id: str | None = None, expires_delta: timedelta | None = None
) -> IssuedToken:
    expires_at = _now() + (expires_delta or timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS))
    jti = uuid.uuid4().hex
    # The family is a UUID so it can be stored in a UUID column; the claim is a string.
    family = uuid.UUID(str(family_id)) if family_id else uuid.uuid4()
    token = _encode(_base_payload(subject, "refresh", expires_at, jti, {"uid": user_id, "fam": str(family)}))
    return IssuedToken(token=token, jti=jti, expires_at=expires_at, family_id=family)


def decode_token(token: str, expected_type: TokenType | None = None) -> dict[str, Any]:
    """Decode and validate a token. Raises :class:`TokenError` with a reason code."""
    if not token or not isinstance(token, str):
        raise TokenError("missing")
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],  # pinned: never trust the header
            audience=settings.JWT_AUDIENCE,
            issuer=settings.JWT_ISSUER,
            options={
                "require_exp": True,
                "require_iat": True,
                "require_sub": True,
                "verify_aud": True,
                "verify_iss": True,
            },
        )
    except JWTError as exc:
        message = str(exc).lower()
        if "expired" in message:
            raise TokenError("expired") from exc
        raise TokenError("invalid") from exc

    if expected_type and payload.get("type") != expected_type:
        raise TokenError("wrong_type")
    if not payload.get("sub") or not payload.get("jti"):
        raise TokenError("incomplete")
    return payload


def token_fingerprint(token: str) -> str:
    """Store this, never the token itself."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def new_secret(length: int = 48) -> str:
    """Helper for generating a suitable JWT secret."""
    return secrets.token_urlsafe(length)
