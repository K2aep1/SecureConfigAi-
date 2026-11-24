"""Administration: user lifecycle, audit trail, platform security policy and stats."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import func, select
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


def _utcnow() -> datetime:
    return datetime.now(UTC)


@router.get("/users", response_model=PageSchema[UserAdminOut])
def list_users(
    limit: int = Query(50, ge=1, le=200),
    cursor: str | None = Query(None),
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> PageSchema[UserAdminOut]:
    query = select(User)
    page: Page[User] = apply_keyset(
        db, query, order_column=User.created_at, id_column=User.id, limit=limit, cursor=cursor
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
    payload: RoleUpdate | None = None,
    role: str | None = Query(None, pattern="^(admin|user)$"),
    request: Request = None,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> MessageOut:
    target_role = (payload.role if payload else None) or role
    if not target_role:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Provide a role in the body or as ?role="
        )
    target = db.get(User, user_id)
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    if target.id == current_user.id and target_role != current_user.role:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="You cannot change your own role."
        )
    previous = target.role
    target.role = target_role
    db.commit()
    audit.record(
        db,
        "user.role_change",
        actor=current_user,
        entity_type="user",
        entity_id=target.id,
        request=request,
        details={"from": previous, "to": target_role, "email": target.email},
    )
    return MessageOut(message=f"Role updated to {target_role}")


@router.patch("/users/{user_id}/status", response_model=MessageOut)
def update_status(
    user_id: UUID,
    payload: StatusUpdate | None = None,
    is_active: bool | None = Query(None),
    request: Request = None,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> MessageOut:
    active = payload.is_active if payload else is_active
    if active is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Provide is_active in the body or as ?is_active=",
        )
    if user_id == current_user.id and not active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="You cannot disable your own account."
        )
    target = db.get(User, user_id)
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    target.is_active = active
    if not active:
        revoke_all_for_user(db, target.id, reason="account_disabled")
    db.commit()
    audit.record(
        db,
        "user.status_change",
        actor=current_user,
        entity_type="user",
        entity_id=target.id,
        request=request,
        details={"is_active": active, "email": target.email},
    )
    return MessageOut(message="Account enabled" if active else "Account disabled")


@router.post("/users/{user_id}/unlock", response_model=MessageOut)
def unlock_user(
    user_id: UUID,
    request: Request,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> MessageOut:
    target = db.get(User, user_id)
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
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
    """V4: revoke every active refresh token of one user.

    Pairs with the secret-rotation runbook: after a credential incident or a lost
    device an administrator can force a full re-authentication for the affected
    account without disabling it. The access token keeps working until it expires
    (at most ACCESS_TOKEN_EXPIRE_MINUTES); every subsequent refresh is refused.
    """
    target = db.get(User, user_id)
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    revoked = revoke_all_for_user(db, target.id, reason="admin_revoked_sessions")
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
        query = query.where(AuditLog.created_at >= date_from)
    if date_to:
        query = query.where(AuditLog.created_at <= date_to)

    page: Page[AuditLog] = apply_keyset(
        db, query, order_column=AuditLog.created_at, id_column=AuditLog.id, limit=limit, cursor=cursor
    )
    emails = {
        user.id: user.email
        for user in db.execute(
            select(User).where(User.id.in_([row.user_id for row in page.items if row.user_id]))
        ).scalars()
    }
    items = []
    for row in page.items:
        payload = AuditLogOut.model_validate(row)
        payload.actor_email = emails.get(row.user_id)
        items.append(payload)
    return PageSchema[AuditLogOut](
        items=items, next_cursor=page.next_cursor, has_more=page.has_more, limit=page.limit
    )


@router.get("/audit-logs/verify", response_model=AuditVerifyOut)
def verify_audit_chain(
    request: Request, current_user: User = Depends(require_admin), db: Session = Depends(get_db)
) -> AuditVerifyOut:
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


@router.get("/security-policy")
def security_policy(
    request: Request, current_user: User = Depends(require_admin), db: Session = Depends(get_db)
) -> dict[str, Any]:
    """The effective platform security policy: what the service enforces on itself."""
    payload = platform_policy.as_dict()
    payload["audit_actions"] = sorted(audit.ACTIONS)
    audit.record(
        db, "admin.security_policy_view", actor=current_user, entity_type="security_policy", request=request
    )
    return payload


@router.get("/stats", response_model=AdminStatsOut)
def stats(current_user: User = Depends(require_admin), db: Session = Depends(get_db)) -> AdminStatsOut:
    database_bytes = 0
    if settings.is_sqlite:
        path = Path(settings.DATABASE_URL.replace("sqlite:///", ""))
        if not path.is_absolute():
            path = (Path(__file__).resolve().parents[3] / path).resolve()
        database_bytes = path.stat().st_size if path.exists() else 0
    else:
        row = db.execute(select(func.pg_database_size(func.current_database()))).scalar()
        database_bytes = int(row or 0)

    evidence_bytes = 0
    if EVIDENCE_DIR.exists():
        evidence_bytes = sum(p.stat().st_size for p in EVIDENCE_DIR.glob("*") if p.is_file())

    return AdminStatsOut(
        users=db.query(User).count(),
        devices=db.query(Device).count(),
        scans=db.query(Scan).count(),
        findings=db.query(Finding).count(),
        audit_entries=db.query(AuditLog).count(),
        reports=db.query(Report).count(),
        database_bytes=database_bytes,
        evidence_bytes=evidence_bytes,
    )


@router.post("/maintenance/retention")
def run_retention(
    request: Request,
    dry_run: bool = Query(True, description="Plan only. Set to false to delete."),
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Apply (or preview) the configured retention windows.

    Dry run is the default so an operator can inspect the plan before anything is
    deleted. Only terminal scans are ever eligible; work in progress is never touched.
    A real pass is recorded in the audit chain.
    """
    report = maintenance.run_retention(db, dry_run=dry_run, actor=current_user, request=request)
    return {"actor": current_user.email, **report}
