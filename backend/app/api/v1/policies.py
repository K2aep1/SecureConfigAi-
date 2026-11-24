"""Baseline and policy-management endpoints.

Two layers of "policy" are exposed:

* ``GET /baseline`` — the shipped, versioned control baseline with its standard
  references (read-only for everyone).
* ``/policies`` — global overrides an administrator can make: change a weight or
  severity, disable a control, replace its remediation text. ``/policies/effective``
  shows the resolved result and which layer supplied each value.

Static paths are registered before ``/policies/{policy_id}`` on purpose: a literal
segment must never be parsed as a UUID.
"""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core import audit
from app.core.database import get_db
from app.core.dependencies import get_current_user, require_admin
from app.core.pagination import Page, apply_keyset
from app.db.models import DeviceExemption, Policy, User
from app.schemas import (
    BaselineOut,
    EffectiveControlOut,
    EffectivePolicyOut,
    PolicyCreate,
    PolicyOut,
    PolicyUpdate,
)
from app.schemas import (
    Page as PageSchema,
)
from app.services.baseline import load_baseline, resolve_effective

router = APIRouter(tags=["baseline"])


# --------------------------------------------------------------------------- baseline
@router.get("/baseline", response_model=BaselineOut)
def get_baseline(current_user: User = Depends(get_current_user)) -> BaselineOut:
    baseline = load_baseline()
    return BaselineOut(**baseline.as_dict())


# --------------------------------------------------------------------------- policies
@router.get("/policies", response_model=PageSchema[PolicyOut])
def list_policies(
    limit: int = Query(50, ge=1, le=200),
    cursor: str | None = Query(None),
    include_disabled: bool = Query(True, description="Include disabled overrides."),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> PageSchema[PolicyOut]:
    query = select(Policy)
    if not include_disabled:
        query = query.where(Policy.is_enabled.is_(True))
    page: Page[Policy] = apply_keyset(
        db, query, order_column=Policy.created_at, id_column=Policy.id, limit=limit, cursor=cursor
    )
    return PageSchema[PolicyOut](
        items=[PolicyOut.model_validate(row) for row in page.items],
        next_cursor=page.next_cursor,
        has_more=page.has_more,
        limit=page.limit,
    )


@router.get("/policies/effective", response_model=EffectivePolicyOut)
def effective_policies(
    current_user: User = Depends(require_admin), db: Session = Depends(get_db)
) -> EffectivePolicyOut:
    baseline = load_baseline()
    overrides = list(db.execute(select(Policy)).scalars())
    effective = resolve_effective(baseline, overrides, [])
    return EffectivePolicyOut(
        baseline_id=baseline.baseline_id,
        baseline_version=baseline.version,
        total_weight=effective.total_weight,
        controls=[EffectiveControlOut(**control.as_dict()) for control in effective.controls],
    )


@router.post("/policies", response_model=PolicyOut, status_code=status.HTTP_201_CREATED)
def create_policy(
    payload: PolicyCreate,
    request: Request,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> PolicyOut:
    baseline_ids = {c.control_id for c in load_baseline().controls}
    if payload.control_id not in baseline_ids:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown control id {payload.control_id!r}. See GET /baseline for the control list.",
        )
    if db.query(Policy).filter(Policy.control_id == payload.control_id).one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An override already exists for this control. Update it instead.",
        )
    policy = Policy(
        control_id=payload.control_id,
        name=payload.name,
        description=payload.description,
        category=payload.category,
        weight=payload.weight,
        severity=payload.severity,
        expected_value=payload.expected_value or {},
        recommendation_template=payload.recommendation_template,
        is_enabled=payload.is_enabled,
        created_by=current_user.id,
    )
    db.add(policy)
    db.commit()
    db.refresh(policy)
    audit.record(
        db,
        "policy.create",
        actor=current_user,
        entity_type="policy",
        entity_id=policy.id,
        request=request,
        details={
            "control_id": policy.control_id,
            "weight": policy.weight,
            "severity": policy.severity,
            "is_enabled": policy.is_enabled,
        },
    )
    return PolicyOut.model_validate(policy)


@router.get("/policies/{policy_id}", response_model=PolicyOut)
def get_policy(
    policy_id: UUID, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)
) -> PolicyOut:
    policy = db.get(Policy, policy_id)
    if policy is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Policy override not found")
    return PolicyOut.model_validate(policy)


@router.put("/policies/{policy_id}", response_model=PolicyOut)
def update_policy(
    policy_id: UUID,
    payload: PolicyUpdate,
    request: Request,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> PolicyOut:
    policy = db.get(Policy, policy_id)
    if policy is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Policy override not found")
    updates = payload.model_dump(exclude_unset=True)
    for field, value in updates.items():
        setattr(policy, field, value)
    db.commit()
    db.refresh(policy)
    audit.record(
        db,
        "policy.update",
        actor=current_user,
        entity_type="policy",
        entity_id=policy.id,
        request=request,
        details={"fields": sorted(updates)},
    )
    return PolicyOut.model_validate(policy)


@router.patch("/policies/{policy_id}/toggle", response_model=PolicyOut)
def toggle_policy(
    policy_id: UUID,
    request: Request,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> PolicyOut:
    policy = db.get(Policy, policy_id)
    if policy is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Policy override not found")
    policy.is_enabled = not policy.is_enabled
    db.commit()
    db.refresh(policy)
    audit.record(
        db,
        "policy.toggle",
        actor=current_user,
        entity_type="policy",
        entity_id=policy.id,
        request=request,
        details={"control_id": policy.control_id, "is_enabled": policy.is_enabled},
    )
    return PolicyOut.model_validate(policy)


@router.delete("/policies/{policy_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_policy(
    policy_id: UUID,
    request: Request,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> Response:
    policy = db.get(Policy, policy_id)
    if policy is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Policy override not found")
    control_id = policy.control_id
    db.delete(policy)
    db.commit()
    audit.record(
        db,
        "policy.delete",
        actor=current_user,
        entity_type="policy",
        entity_id=policy_id,
        request=request,
        details={"control_id": control_id},
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# --------------------------------------------------------------------------- exemptions overview
@router.get("/exemptions", response_model=list[dict])
def list_all_exemptions(
    current_user: User = Depends(require_admin), db: Session = Depends(get_db)
) -> list[dict]:
    rows = db.execute(select(DeviceExemption)).scalars()
    return [
        {
            "id": str(row.id),
            "device_id": str(row.device_id),
            "control_id": row.control_id,
            "reason": row.reason,
            "expires_at": row.expires_at.isoformat() if row.expires_at else None,
            "created_at": row.created_at.isoformat() if row.created_at else None,
        }
        for row in rows
    ]
