"""Administration: user lifecycle, audit trail, platform security policy and stats."""

from __future__ import annotations
from pathlib import Path
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import func, select
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session

from app.core import audit
from app.core.config import EVIDENCE_DIR, settings
from app.core.database import get_db
from app.core.dependencies import require_admin
from app.core.pagination import Page, apply_keyset
from app.core.security_policy import platform_policy
from app.db.models import AuditLog, Device, Finding, Report, Scan, User
from app.schemas import (
    AdminStatsOut,
    AuditLogOut,
    AuditVerifyOut,
    MessageOut,
    RoleUpdate,
    StatusUpdate,
    UserAdminOut,
)
from app.schemas import (
    Page as PageSchema,
)
from app.services import maintenance
from app.services.token_service import revoke_all_for_user

router = APIRouter(prefix="/admin", tags=["admin"])

PROJECT_ROOT_DEPTH = 3  # app/api/routes/admin.py -> project root, used for relative SQLite paths


# --------------------------------------------------------------------------- helpers
def _user_or_404(db: Session, user_id: UUID) -> User:
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return user


def _user_out(user: User) -> UserAdminOut:
    return UserAdminOut(
        id=user.id,
        email=user.email,
        full_name=user.full_name,
        role=user.role,
        is_active=user.is_active,
        created_at=user.created_at,
        failed_login_count=user.failed_login_count or 0,
        locked_until=user.locked_until,
        last_login_at=user.last_login_at,
        is_locked=user.is_locked,
    )


def _as_utc(value: datetime) -> datetime:
    """Treat a naive query timestamp as UTC so comparisons never raise."""
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _active_admin_count(db: Session) -> int:
    return int(
        db.execute(
            select(func.count()).select_from(User).where(User.role == "admin", User.is_active.is_(True))
        ).scalar_one()
    )


def _ensure_not_last_active_admin(db: Session, target: User) -> None:
    """Refuse any change that would leave the platform with no active administrator."""
    if target.role == "admin" and target.is_active and _active_admin_count(db) <= 1:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="This change would leave the platform without an active administrator.",
        )


def _sqlite_file_bytes(database_url: str) -> int:
    database = make_url(database_url).database
    if not database or database == ":memory:":
        return 0
    path = Path(database)
    if not path.is_absolute():
        path = (Path(__file__).resolve().parents[PROJECT_ROOT_DEPTH] / path).resolve()
    try:
        return path.stat().st_size
    except OSError:
        return 0


def _evidence_bytes() -> int:
    if not EVIDENCE_DIR.exists():
        return 0
    total = 0
    for entry in EVIDENCE_DIR.iterdir():
        try:
            if entry.is_file():
                total += entry.stat().st_size
        except OSError:
            # A file can disappear between listing and stat during retention runs.
            continue
    return total


# --------------------------------------------------------------------------- users
@router.get("/users", response_model=PageSchema[UserAdminOut])
def list_users(
    limit: int = Query(50, ge=1, le=200),
    cursor: str | None = Query(None),
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> PageSchema[UserAdminOut]:
    page: Page[User] = apply_keyset(
        db, select(User), order_column=User.created_at, id_column=User.id, limit=limit, cursor=cursor
    )
    return PageSchema[UserAdminOut](
        items=[_user_out(user) for user in page.items],
        next_cursor=page.next_cursor,
        has_more=page.has_more,
        limit=page.limit,
    )


@router.patch("/users/{user_id}/role", response_model=MessageOut)
def update_role(
    user_id: UUID,
    payload: RoleUpdate,
    request: Request,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> MessageOut:
    target = _user_or_404(db, user_id)
    if target.id == current_user.id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="You cannot change your own role.")

    previous = target.role
    if payload.role == previous:
        return MessageOut(message=f"Role is already {previous}")

    if previous == "admin" and payload.role != "admin":
        _ensure_not_last_active_admin(db, target)

    target.role = payload.role
    # Revoke refresh tokens so the new role takes effect at the next refresh rather
    # than whenever the old session happens to expire.
    revoke_all_for_user(db, target.id, reason="role_changed")
    db.commit()

    audit.record(
        db,
        "user.role_change",
        actor=current_user,
        entity_type="user",
        entity_id=target.id,
        request=request,
        details={"from": previous, "to": payload.role, "email": target.email},
    )
    return MessageOut(message=f"Role updated to {payload.role}")


@router.patch("/users/{user_id}/status", response_model=MessageOut)
def update_status(
    user_id: UUID,
    payload: StatusUpdate,
    request: Request,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> MessageOut:
    target = _user_or_404(db, user_id)
    if target.id == current_user.id and not payload.is_active:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="You cannot disable your own account.")

    if target.is_active == payload.is_active:
        return MessageOut(message="Account enabled" if payload.is_active else "Account disabled")

    if not payload.is_active:
        _ensure_not_last_active_admin(db, target)

    target.is_active = payload.is_active
    if not payload.is_active:
        revoke_all_for_user(db, target.id, reason="account_disabled")
    db.commit()

    audit.record(
        db,
        "user.status_change",
        actor=current_user,
        entity_type="user",
        entity_id=target.id,
        request=request,
        details={"is_active": payload.is_active, "email": target.email},
    )
    return MessageOut(message="Account enabled" if payload.is_active else "Account disabled")


@router.post("/users/{user_id}/unlock", response_model=MessageOut)
def unlock_user(
    user_id: UUID,
    request: Request,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> MessageOut:
    target = _user_or_404(db, user_id)
    target.failed_login_count = 0
    target.locked_until = None
    db.commit()

    audit.record(
        db,
        "user.unlock",
        actor=current_user,
        entity_type="user",
        entity_id=target.id,
        request=request,
        details={"email": target.email},
    )
    return MessageOut(message="Lockout cleared")


@router.post("/users/{user_id}/revoke-sessions", response_model=MessageOut)
def revoke_sessions(
    user_id: UUID,
    request: Request,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> MessageOut:
    """Revoke every active refresh token of one user.

    Use after a credential incident or a lost device. The access token keeps working
    until it expires (at most ACCESS_TOKEN_EXPIRE_MINUTES); every later refresh is refused.
    """
    target = _user_or_404(db, user_id)
    revoked = revoke_all_for_user(db, target.id, reason="admin_revoked_sessions")
    db.commit()

    audit.record(
        db,
        "user.sessions_revoke",
        actor=current_user,
        entity_type="user",
        entity_id=target.id,
        request=request,
        details={"email": target.email, "revoked_tokens": revoked},
    )
    return MessageOut(message=f"Revoked {revoked} refresh token(s) for {target.email}")


# --------------------------------------------------------------------------- audit
@router.get("/audit-logs", response_model=PageSchema[AuditLogOut])
def list_audit_logs(
    limit: int = Query(50, ge=1, le=200),
    cursor: str | None = Query(None),
    action: str | None = Query(None, max_length=64),
    actor_id: UUID | None = Query(None),
    outcome: str | None = Query(None, max_length=16),
    date_from: datetime | None = Query(None, alias="from"),
    date_to: datetime | None = Query(None, alias="to"),
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> PageSchema[AuditLogOut]:
    query = select(AuditLog)
    if action:
        query = query.where(AuditLog.action == action)
    if actor_id:
        query = query.where(AuditLog.user_id == actor_id)
    if outcome:
        query = query.where(AuditLog.outcome == outcome)
    if date_from:
        query = query.where(AuditLog.created_at >= _as_utc(date_from))
    if date_to:
        query = query.where(AuditLog.created_at <= _as_utc(date_to))

    page: Page[AuditLog] = apply_keyset(
        db, query, order_column=AuditLog.created_at, id_column=AuditLog.id, limit=limit, cursor=cursor
    )

    actor_ids = {row.user_id for row in page.items if row.user_id}
    emails: dict[UUID, str] = {}
    if actor_ids:
        emails = {
            user.id: user.email
            for user in db.execute(select(User).where(User.id.in_(actor_ids))).scalars()
        }

    items: list[AuditLogOut] = []
    for row in page.items:
        out = AuditLogOut.model_validate(row)
        out.actor_email = emails.get(row.user_id) if row.user_id else None
        items.append(out)

    return PageSchema[AuditLogOut](
        items=items, next_cursor=page.next_cursor, has_more=page.has_more, limit=page.limit
    )


@router.get("/audit-logs/verify", response_model=AuditVerifyOut)
def verify_audit_chain(
    request: Request,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> AuditVerifyOut:
    """Verify the hash chain. The verification itself is audited afterwards."""
    result = audit.verify_chain(db)
    audit.record(
        db,
        "admin.audit_verify",
        actor=current_user,
        entity_type="audit_log",
        request=request,
        outcome="success" if result["chain_valid"] else "failure",
        details={"checked": result["checked"]},
    )
    return AuditVerifyOut(**result)


# --------------------------------------------------------------------------- policy & stats
@router.get("/security-policy")
def security_policy(
    request: Request,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """The effective platform security policy: what the service enforces on itself."""
    payload = platform_policy.as_dict()
    payload["audit_actions"] = sorted(audit.ACTIONS)
    audit.record(
        db,
        "admin.security_policy_view",
        actor=current_user,
        entity_type="security_policy",
        request=request,
    )
    return payload


@router.get("/stats", response_model=AdminStatsOut)
def stats(current_user: User = Depends(require_admin), db: Session = Depends(get_db)) -> AdminStatsOut:
    if settings.is_sqlite:
        database_bytes = _sqlite_file_bytes(settings.DATABASE_URL)
    else:
        database_bytes = int(db.execute(select(func.pg_database_size(func.current_database()))).scalar() or 0)

    def count(model: type) -> int:
        return int(db.execute(select(func.count()).select_from(model)).scalar_one())

    return AdminStatsOut(
        users=count(User),
        devices=count(Device),
        scans=count(Scan),
        findings=count(Finding),
        audit_entries=count(AuditLog),
        reports=count(Report),
        database_bytes=database_bytes,
        evidence_bytes=_evidence_bytes(),
    )


@router.post("/maintenance/retention")
def run_retention(
    request: Request,
    dry_run: bool = Query(True, description="Plan only. Set to false to delete."),
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Apply, or preview, the configured retention windows.

    Dry run is the default so an operator can inspect the plan first. Only terminal
    scans are eligible; work in progress is never touched. A real pass is audited.
    """
    report = maintenance.run_retention(db, dry_run=dry_run, actor=current_user, request=request)
    return {"actor": current_user.email, **report}