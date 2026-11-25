"""Server-side refresh-token lifecycle: rotation, reuse detection and revocation.

Refresh tokens are stored as SHA-256 fingerprints. Every issuance belongs to a
family (one sign-in). Rotating a token revokes the old one and links it to its
replacement, so if an already-rotated token is presented again the whole family is
revoked — the standard mitigation for a stolen refresh token.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.core import security
from app.core.config import settings
from app.db.models import RefreshToken, User

logger = logging.getLogger("secureconfigai.tokens")


def _now() -> datetime:
    return datetime.now(UTC)


def issue_pair(
    db: Session,
    user: User,
    *,
    ip_address: str | None = None,
    user_agent: str | None = None,
    family_id: str | None = None,
) -> dict:
    """Issue an access/refresh pair and record the refresh token."""
    access = security.issue_access_token(user.email, str(user.id), user.role)
    refresh = security.issue_refresh_token(
        user.email,
        str(user.id),
        family_id=family_id,
    )

    db.add(
        RefreshToken(
            user_id=user.id,
            token_hash=security.token_fingerprint(refresh.token),
            family_id=refresh.family_id,
            expires_at=refresh.expires_at,
            ip_address=ip_address,
            user_agent=(user_agent or "")[:255] or None,
        )
    )

    db.commit()

    return {
        "access_token": access.token,
        "refresh_token": refresh.token,
        "token_type": "bearer",
        "expires_in": int((access.expires_at - _now()).total_seconds()),
    }


def rotate(
    db: Session,
    token: str,
    *,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> tuple[dict, User]:
    """Rotate a refresh token.

    Raises security.TokenError when the token must not be used.
    """

    # Validate signature, issuer, audience, expiry and token type.
    security.decode_token(token, expected_type="refresh")

    fingerprint = security.token_fingerprint(token)

    record = db.execute(
        select(RefreshToken).where(
            RefreshToken.token_hash == fingerprint
        )
    ).scalar_one_or_none()

    if record is None:
        raise security.TokenError("unknown")

    # Reuse detection must distinguish a rotated token from a token
    # revoked through logout or another administrative operation.
    if (
        record.revoked_at is not None
        and record.replaced_by_hash is not None
        and settings.REFRESH_REUSE_DETECTION
    ):
        revoke_family(
            db,
            record.family_id,
            reason="reuse_detected",
        )

        logger.warning(
            "refresh token reuse detected user_id=%s family=%s",
            record.user_id,
            record.family_id,
        )

        raise security.TokenError("reuse")

    if not record.is_active:
        raise security.TokenError("expired")

    user = db.get(User, record.user_id)

    if user is None or not user.is_active:
        raise security.TokenError("user_inactive")

    if settings.REFRESH_ROTATION:
        new_refresh = security.issue_refresh_token(
            user.email,
            str(user.id),
            family_id=str(record.family_id),
        )

        new_hash = security.token_fingerprint(new_refresh.token)
        family_id = str(record.family_id)

        # Atomic conditional claim:
        # Only one concurrent request can rotate this token.
        claimed = db.execute(
            update(RefreshToken)
            .where(
                RefreshToken.token_hash == fingerprint,
                RefreshToken.revoked_at.is_(None),
            )
            .values(
                revoked_at=_now(),
                replaced_by_hash=new_hash,
            )
        )

        db.flush()

        if claimed.rowcount == 0:
            db.rollback()

            if settings.REFRESH_REUSE_DETECTION:
                revoke_family(
                    db,
                    family_id,
                    reason="reuse_detected",
                )

                logger.warning(
                    "refresh token concurrent use detected "
                    "user_id=%s family=%s",
                    record.user_id,
                    family_id,
                )

                raise security.TokenError("reuse")

            raise security.TokenError("expired")

        db.add(
            RefreshToken(
                user_id=user.id,
                token_hash=new_hash,
                family_id=record.family_id,
                expires_at=new_refresh.expires_at,
                ip_address=ip_address,
                user_agent=(user_agent or "")[:255] or None,
            )
        )

        access = security.issue_access_token(
            user.email,
            str(user.id),
            user.role,
        )

        db.commit()

        return {
            "access_token": access.token,
            "refresh_token": new_refresh.token,
            "token_type": "bearer",
            "expires_in": int(
                (access.expires_at - _now()).total_seconds()
            ),
        }, user

    # Rotation disabled: retain the existing refresh token.
    access = security.issue_access_token(
        user.email,
        str(user.id),
        user.role,
    )

    db.commit()

    return {
        "access_token": access.token,
        "refresh_token": token,
        "token_type": "bearer",
        "expires_in": int(
            (access.expires_at - _now()).total_seconds()
        ),
    }, user


def revoke(
    db: Session,
    token: str | None,
    *,
    user_id=None,
) -> bool:
    """Revoke one refresh token.

    When user_id is supplied, the token must belong to that user.
    Returns True only when an active token was revoked.
    """

    if not token:
        return False

    query = select(RefreshToken).where(
        RefreshToken.token_hash == security.token_fingerprint(token),
        RefreshToken.revoked_at.is_(None),
    )

    if user_id is not None:
        query = query.where(
            RefreshToken.user_id == user_id
        )

    record = db.execute(query).scalar_one_or_none()

    if record is None:
        return False

    record.revoked_at = _now()

    db.commit()

    return True


def revoke_all_for_user(
    db: Session,
    user_id,
    *,
    reason: str = "sign_out_all",
) -> int:
    """Revoke all active refresh tokens belonging to one user."""

    records = list(
        db.execute(
            select(RefreshToken).where(
                RefreshToken.user_id == user_id,
                RefreshToken.revoked_at.is_(None),
            )
        ).scalars()
    )

    now = _now()

    for record in records:
        record.revoked_at = now

    db.commit()

    logger.info(
        "revoked %d refresh tokens user_id=%s reason=%s",
        len(records),
        user_id,
        reason,
    )

    return len(records)


def revoke_family(
    db: Session,
    family_id,
    *,
    reason: str = "family_revoked",
) -> int:
    """Revoke every active refresh token belonging to one token family."""

    records = list(
        db.execute(
            select(RefreshToken).where(
                RefreshToken.family_id == family_id,
                RefreshToken.revoked_at.is_(None),
            )
        ).scalars()
    )

    now = _now()

    for record in records:
        record.revoked_at = now

    db.commit()

    logger.info(
        "revoked refresh family %s (%d tokens, %s)",
        family_id,
        len(records),
        reason,
    )

    return len(records)


def prune_expired(
    db: Session,
    older_than_days: int = 30,
) -> int:
    """Delete expired refresh-token records older than the retention period."""

    cutoff = _now() - timedelta(days=older_than_days)

    records = list(
        db.execute(
            select(RefreshToken).where(
                RefreshToken.expires_at < cutoff
            )
        ).scalars()
    )

    for record in records:
        db.delete(record)

    if records:
        db.commit()

    return len(records)