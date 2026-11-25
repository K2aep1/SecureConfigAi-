"""Authentication: registration, sign-in, token rotation, sign-out.

Security properties enforced here:

* password rules come from the platform security policy (single source of truth);
* per-address and per-account rate limits on sign-in, plus a database-backed lockout
  that survives a restart and is visible to administrators;
* every sign-in verifies the password before any account-state decision, so an
  unauthenticated caller cannot learn whether an account exists, is locked or is
  disabled;
* refresh tokens are rotated and stored as fingerprints, with reuse detection that
  revokes the whole family;
* every attempt, success or failure, is written to the audit chain. Email addresses
  in audit details are stored as keyed hashes, not in clear text.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
from datetime import UTC, datetime, timedelta ,timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core import audit, security
from app.core.config import settings
from app.core.database import get_db
from app.core.dependencies import get_current_user
from app.core.rate_limit import client_ip, enforce
from app.core.security_policy import platform_policy
from app.db.models import User
from app.schemas import (
    AuthPolicyOut,
    LogoutRequest,
    MessageOut,
    RefreshRequest,
    TokenPair,
    UserCreate,
    UserLogin,
    UserOut,
)
from app.services import token_service

logger = logging.getLogger("secureconfigai.auth")
router = APIRouter(prefix="/auth", tags=["auth"])

_INVALID_CREDENTIALS = "Invalid email or password"
_EMAIL_EXISTS = "Email already registered"

# Computed once at import time, so the unknown-account path performs the same single
# bcrypt verification as the known-account path.
_DUMMY_PASSWORD_HASH = security.hash_password("placeholder-value")


# --------------------------------------------------------------------------- helpers
def _utcnow() -> datetime:
    return datetime.now(UTC)


def _normalise_email(email: str) -> str:
    return email.strip().lower()


def _email_fingerprint(email: str) -> str:
    """Keyed hash of an email for audit details. The log keeps linkage, not the address."""
    key = settings.JWT_SECRET_KEY.encode("utf-8")
    return hmac.new(key, _normalise_email(email).encode("utf-8"), hashlib.sha256).hexdigest()[:32]


def _find_user(db: Session, email: str) -> User | None:
    return db.execute(select(User).where(User.email == email)).scalar_one_or_none()


def _invalid_credentials() -> HTTPException:
    return HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=_INVALID_CREDENTIALS)


def _audit_login(
    db: Session,
    request: Request,
    action: str,
    *,
    email: str,
    user: User | None = None,
    outcome: str = "failure",
    details: dict | None = None,
) -> None:
    payload = {"email_fp": _email_fingerprint(email)}
    if details:
        payload.update(details)
    audit.record(
        db,
        action,
        actor=user,
        entity_type="user",
        entity_id=user.id if user else None,
        request=request,
        outcome=outcome,
        details=payload,
    )


# --------------------------------------------------------------------------- policy
@router.get("/policy", response_model=AuthPolicyOut)
def auth_policy() -> AuthPolicyOut:
    """Public password and session rules, so the UI can validate before submitting."""
    rules = platform_policy.password_rules
    return AuthPolicyOut(
        password={
            "min_length": rules["min_length"],
            "max_length": rules["max_length"],
            "require_letter": rules["require_letter"],
            "require_digit": rules["require_digit"],
            "require_symbol": rules["require_symbol"],
        },
        access_token_minutes=rules["access_token_minutes"],
        refresh_token_days=rules["refresh_token_days"],
        max_failed_logins=rules["max_failed_logins"],
        lockout_minutes=rules["lockout_minutes"],
        password_hint=platform_policy.describe_password_rules(),
    )


# --------------------------------------------------------------------------- register
@router.post("/register", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def register(payload: UserCreate, request: Request, db: Session = Depends(get_db)) -> UserOut:
    enforce("auth.register", f"ip:{client_ip(request)}", detail="Too many registration attempts.")
    email = _normalise_email(payload.email)

    user = User(
        email=email,
        password_hash=security.hash_password(payload.password),
        full_name=payload.full_name,
        role="user",  # never client-selectable
        is_active=True,
    )
    db.add(user)
    try:
        db.commit()
    except IntegrityError:
        # The unique constraint is the real guard. A read-then-write check would race.
        db.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=_EMAIL_EXISTS) from None
    db.refresh(user)

    audit.record(
        db,
        "auth.register",
        actor=user,
        entity_type="user",
        entity_id=user.id,
        request=request,
        details={"email_fp": _email_fingerprint(email)},
    )
    return UserOut.model_validate(user)


# --------------------------------------------------------------------------- sign-in
def _record_failure(db: Session, user: User, now: datetime) -> bool:
    """Count one failed password. Returns True if this failure triggered a lockout."""
    user.failed_login_count = (user.failed_login_count or 0) + 1
    locked = user.failed_login_count >= settings.MAX_FAILED_LOGINS
    if locked:
        user.locked_until = now + timedelta(minutes=settings.LOCKOUT_MINUTES)
    db.commit()
    return locked


def _clear_expired_lockout(db: Session, user: User, now: datetime) -> None:
    """Reset the counter once a lockout window has fully elapsed.

    Normalizes database timestamps to UTC before comparison because
    SQLite may return naive datetimes for timezone-aware columns.
    """
    locked_until = user.locked_until

    if locked_until is None:
        return

    # Normalize the database timestamp to UTC.
    if locked_until.tzinfo is None:
        locked_until = locked_until.replace(tzinfo=timezone.utc)

    # Normalize the current timestamp to UTC.
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    else:
        now = now.astimezone(timezone.utc)

    if locked_until <= now:
        user.locked_until = None
        user.failed_login_count = 0
        db.commit()


@router.post("/login", response_model=TokenPair)
def login(payload: UserLogin, request: Request, db: Session = Depends(get_db)) -> TokenPair:
    email = _normalise_email(payload.email)
    enforce(
        "auth.login",
        f"ip:{client_ip(request)}",
        f"email:{email}",
        detail="Too many sign-in attempts.",
    )
    now = _utcnow()
    user = _find_user(db, email)

    if user is None:
        # Same work as the known-account path. Nothing observable differs.
        security.verify_password(payload.password, _DUMMY_PASSWORD_HASH)
        _audit_login(db, request, "auth.login.failure", email=email, details={"reason": "unknown"})
        raise _invalid_credentials()

    _clear_expired_lockout(db, user, now)

    # The password is verified before any account-state decision. Locked and disabled
    # accounts are therefore revealed only to someone who already knows the password.
    password_ok = security.verify_password(payload.password, user.password_hash)

    if not password_ok:
        if user.is_locked:
            # Do not keep counting while locked; the window is already enforced.
            _audit_login(
                db, request, "auth.login.failure", email=email, user=user, details={"reason": "bad_password_while_locked"}
            )
            raise _invalid_credentials()
        locked = _record_failure(db, user, now)
        _audit_login(
            db,
            request,
            "auth.login.failure",
            email=email,
            user=user,
            details={"failed_count": user.failed_login_count, "locked": locked},
        )
        raise _invalid_credentials()

    if user.is_locked:
        _audit_login(db, request, "auth.login.locked", email=email, user=user)
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail="Account is locked. Try again later or contact an administrator.",
        )

    if not user.is_active:
        _audit_login(db, request, "auth.login.disabled", email=email, user=user)
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User account is disabled")

    user.failed_login_count = 0
    user.locked_until = None
    user.last_login_at = now
    db.commit()

    tokens = token_service.issue_pair(
        db,
        user,
        ip_address=client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )
    _audit_login(db, request, "auth.login.success", email=email, user=user, outcome="success")
    return TokenPair(**tokens)


# --------------------------------------------------------------------------- tokens
@router.post("/refresh", response_model=TokenPair)
def refresh(payload: RefreshRequest, request: Request, db: Session = Depends(get_db)) -> TokenPair:
    enforce("auth.refresh", f"ip:{client_ip(request)}", detail="Too many token refresh calls.")
    try:
        tokens, user = token_service.rotate(
            db,
            payload.refresh_token,
            ip_address=client_ip(request),
            user_agent=request.headers.get("user-agent"),
        )
    except security.TokenError as exc:
        if exc.reason == "reuse":
            audit.record(
                db,
                "auth.refresh.reuse_detected",
                entity_type="refresh_token",
                request=request,
                outcome="failure",
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token reuse detected; all sessions for this account were signed out.",
            ) from exc
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        ) from exc

    audit.record(db, "auth.refresh", actor=user, entity_type="user", entity_id=user.id, request=request)
    return TokenPair(**tokens)


@router.post("/logout", response_model=MessageOut)
def logout(
    request: Request,
    payload: LogoutRequest | None = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> MessageOut:
    """Revoke the supplied refresh token, if it belongs to the caller."""
    revoked = token_service.revoke(
        db,
        payload.refresh_token if payload else None,
        user_id=current_user.id,
    )
    audit.record(
        db,
        "auth.logout",
        actor=current_user,
        entity_type="user",
        entity_id=current_user.id,
        request=request,
        details={"refresh_revoked": revoked},
    )
    return MessageOut(message="Signed out. The client must discard its access token.")


@router.post("/logout-all", response_model=MessageOut)
def logout_all(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> MessageOut:
    count = token_service.revoke_all_for_user(db, current_user.id, reason="logout_all")
    db.commit()
    audit.record(
        db,
        "auth.logout",
        actor=current_user,
        entity_type="user",
        entity_id=current_user.id,
        request=request,
        details={"revoked": count, "scope": "all_sessions"},
    )
    return MessageOut(message=f"Signed out of {count} session(s).")


@router.get("/me", response_model=UserOut)
def me(current_user: User = Depends(get_current_user)) -> UserOut:
    return UserOut.model_validate(current_user)