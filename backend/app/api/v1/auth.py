"""Authentication: registration, sign-in, token rotation, sign-out.

Security properties enforced here:
* password rules come from the platform security policy (single source of truth);
* per-address and per-account rate limits on sign-in, plus a database-backed lockout
  that survives a restart and is visible to administrators;
* identical error text for "unknown account" and "wrong password" (no enumeration);
* refresh tokens are rotated and stored as fingerprints, with reuse detection that
  revokes the whole family;
* every attempt — success or failure — is written to the audit chain.
"""

from __future__ import annotations

import logging
from datetime import UTC, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, status
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

# V4 fix (L-1): computed once at import time so the unknown-account login path costs
# exactly one bcrypt verify — identical to the known-account path.
_DUMMY_PASSWORD_HASH = security.hash_password("placeholder-value")


def _utcnow():
    from datetime import datetime

    return datetime.now(UTC)


@router.get("/policy", response_model=AuthPolicyOut)
def auth_policy() -> AuthPolicyOut:
    """Public password/session rules so the UI can validate before submitting."""
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


@router.post("/register", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def register(payload: UserCreate, request: Request, db: Session = Depends(get_db)) -> UserOut:
    enforce("auth.register", f"ip:{client_ip(request)}", detail="Too many registration attempts.")
    existing = db.query(User).filter(User.email == payload.email).one_or_none()
    if existing is not None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered")

    user = User(
        email=payload.email,
        password_hash=security.hash_password(payload.password),
        full_name=payload.full_name,
        role="user",  # never client-selectable
        is_active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    audit.record(
        db,
        "auth.register",
        actor=user,
        entity_type="user",
        entity_id=user.id,
        request=request,
        details={"email": user.email},
    )
    return UserOut.model_validate(user)


@router.post("/login", response_model=TokenPair)
def login(payload: UserLogin, request: Request, db: Session = Depends(get_db)) -> TokenPair:
    enforce(
        "auth.login",
        f"ip:{client_ip(request)}",
        f"email:{payload.email}",
        detail="Too many sign-in attempts.",
    )
    user = db.query(User).filter(User.email == payload.email).one_or_none()

    if user is None:
        # Same message and exactly the same work regardless of account existence.
        # V4 fix (L-1): a precomputed dummy hash keeps this path at ONE bcrypt
        # operation — the same cost as the known-user path below — removing the
        # ~2x timing oracle (hash + verify) that previously betrayed whether an
        # email existed.
        security.verify_password(payload.password, _DUMMY_PASSWORD_HASH)
        audit.record(
            db,
            "auth.login.failure",
            entity_type="user",
            request=request,
            outcome="failure",
            details={"email": payload.email, "reason": "unknown"},
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=_INVALID_CREDENTIALS)

    if user.is_locked:
        audit.record(
            db,
            "auth.login.locked",
            actor=user,
            entity_type="user",
            entity_id=user.id,
            request=request,
            outcome="failure",
            details={"locked_until": user.locked_until.isoformat()},
        )
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail="Account is locked. Try again later or contact an administrator.",
        )

    # V4 fix (H-2): the failure counter decays once a lockout window has fully
    # elapsed. Previously the counter was only cleared by a successful login or an
    # administrator, so after any lockout a single new failure re-locked the
    # account — one request per lockout period kept a known user locked forever.
    if user.locked_until is not None:
        user.locked_until = None
        user.failed_login_count = 0
        db.commit()

    if not user.is_active:
        audit.record(
            db,
            "auth.login.disabled",
            actor=user,
            entity_type="user",
            entity_id=user.id,
            request=request,
            outcome="failure",
        )
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User account is disabled")

    if not security.verify_password(payload.password, user.password_hash):
        user.failed_login_count = (user.failed_login_count or 0) + 1
        locked = user.failed_login_count >= settings.MAX_FAILED_LOGINS
        if locked:
            user.locked_until = _utcnow() + timedelta(minutes=settings.LOCKOUT_MINUTES)
        db.commit()
        audit.record(
            db,
            "auth.login.failure",
            actor=user,
            entity_type="user",
            entity_id=user.id,
            request=request,
            outcome="failure",
            details={"failed_count": user.failed_login_count, "locked": locked},
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=_INVALID_CREDENTIALS)

    user.failed_login_count = 0
    user.locked_until = None
    user.last_login_at = _utcnow()
    db.commit()

    tokens = token_service.issue_pair(
        db, user, ip_address=client_ip(request), user_agent=request.headers.get("user-agent")
    )
    audit.record(db, "auth.login.success", actor=user, entity_type="user", entity_id=user.id, request=request)
    return TokenPair(**tokens)


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
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired refresh token"
        ) from exc
    audit.record(db, "auth.refresh", actor=user, entity_type="user", entity_id=user.id, request=request)
    return TokenPair(**tokens)


@router.post("/logout", response_model=MessageOut)
def logout(
    payload: LogoutRequest | None = None,
    request: Request = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> MessageOut:
    revoked = token_service.revoke(db, payload.refresh_token if payload else None)
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
    request: Request, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)
) -> MessageOut:
    count = token_service.revoke_all_for_user(db, current_user.id)
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
