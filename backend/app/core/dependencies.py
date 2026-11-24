"""Reusable FastAPI dependencies: authentication, roles and request context."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from app.core import security
from app.core.config import settings
from app.core.database import get_db
from app.db.models import User

bearer_scheme = OAuth2PasswordBearer(tokenUrl=f"{settings.API_PREFIX}/auth/login", auto_error=False)


def get_current_user(
    request: Request,
    token: str | None = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if not token:
        raise credentials_exception
    try:
        payload = security.decode_token(token, expected_type="access")
    except security.TokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=(
                "Access token has expired" if exc.reason == "expired" else "Could not validate credentials"
            ),
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    user = None
    raw_uid = payload.get("uid")
    if raw_uid:
        try:
            user = db.get(User, uuid.UUID(str(raw_uid)))
        except (ValueError, TypeError):
            user = None
    if user is None:
        user = db.query(User).filter(User.email == str(payload.get("sub", "")).strip().lower()).one_or_none()
    if user is None or not user.is_active:
        raise credentials_exception
    request.state.user_id = str(user.id)
    return user


def require_role(*allowed_roles: str):
    """Dependency factory enforcing role membership."""

    def role_checker(current_user: User = Depends(get_current_user)) -> User:
        if current_user.role not in allowed_roles:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not enough permissions")
        return current_user

    return role_checker


require_admin = require_role("admin")


def utcnow() -> datetime:
    return datetime.now(UTC)
