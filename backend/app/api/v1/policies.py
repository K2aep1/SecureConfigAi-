"""Baseline and policy-management endpoints.

Two layers of "policy" are exposed:

* ``GET /baseline``: the shipped, versioned control baseline with its standard
  references (read-only for every authenticated user).
* ``/policies``: global overrides an administrator can make. An override can change
  a weight or severity, disable a control, or replace its remediation text.
  ``/policies/effective`` shows the resolved result.

Static paths are registered before ``/policies/{policy_id}`` on purpose: a literal
segment must never be parsed as a UUID.
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core import audit
from app.core.database import get_db
from app.core.dependencies import get_current_user, require_admin
from app.core.pagination import Page, apply_keyset
from app.db.models import Device, DeviceExemption, Policy, User
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

# Columns that the database declares NOT NULL. Clearing one of these through PUT
# would otherwise surface as an IntegrityError and a 500. Keep in step with the
# Policy model.
REQUIRED_ON_UPDATE = frozenset({"name", "category", "weight", "severity", "is_enabled"})

# Fields that identify an override. They are fixed at creation and never updated.
IMMUTABLE_FIELDS = frozenset({"control_id", "created_by", "id"})


class ExemptionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    device_id: UUID
    control_id: str
    reason: str | None = None
    expires_at: datetime | None = None
    created_at: datetime | None = None


# --------------------------------------------------------------------------- helpers
def _policy_or_404(db: Session, policy_id: UUID) -> Policy:
    policy = db.get(Policy, policy_id)
    if policy is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Policy override not found")
    return policy


def _known_control_ids() -> set[str]:
    return {control.control_id for control in load_baseline().controls}


# --------------------------------------------------------------------------- baseline
@router.get("/baseline", response_model=BaselineOut)
def get_baseline(current_user: User = Depends(get_current_user)) -> BaselineOut:
    return BaselineOut(**load_baseline().as_dict())


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
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> EffectivePolicyOut:
    """Resolved control set after applying every enabled override to the baseline.

    Exemptions are per device, so they are not applied here. This view is the
    global policy; per-device results come from ``/scans/{id}/results``.
    """
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
    if payload.control_id not in _known_control_ids():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown control id {payload.control_id!r}. See GET /baseline for the control list.",
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
    try:
        # The unique constraint on control_id is the real guard. A pre-check alone
        # would let two admins create duplicates at the same moment.
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An override already exists for this control. Update it instead.",
        ) from None
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
    policy_id: UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> PolicyOut:
    return PolicyOut.model_validate(_policy_or_404(db, policy_id))


@router.put("/policies/{policy_id}", response_model=PolicyOut)
def update_policy(
    policy_id: UUID,
    payload: PolicyUpdate,
    request: Request,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> PolicyOut:
    policy = _policy_or_404(db, policy_id)

    updates = {
        field: value
        for field, value in payload.model_dump(exclude_unset=True).items()
        if field not in IMMUTABLE_FIELDS
    }
    cleared = sorted(field for field in REQUIRED_ON_UPDATE if field in updates and updates[field] is None)
    if cleared:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"These fields cannot be cleared: {', '.join(cleared)}.",
        )
    if not updates:
        return PolicyOut.model_validate(policy)

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
        details={"control_id": policy.control_id, "fields": sorted(updates)},
    )
    return PolicyOut.model_validate(policy)


@router.patch("/policies/{policy_id}/toggle", response_model=PolicyOut)
def toggle_policy(
    policy_id: UUID,
    request: Request,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> PolicyOut:
    """Flip ``is_enabled``. Prefer PUT with an explicit value when clients may race."""
    policy = _policy_or_404(db, policy_id)
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
    policy = _policy_or_404(db, policy_id)
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


# --------------------------------------------------------------------------- exemptions
@router.get("/exemptions", response_model=PageSchema[ExemptionOut])
def list_exemptions(
    limit: int = Query(50, ge=1, le=200),
    cursor: str | None = Query(None),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> PageSchema[ExemptionOut]:
    """Exemptions on the caller's own devices, paginated.

    Scoped to the owner, matching every other per-scan and per-device route. The
    previous admin-wide listing exposed every tenant's exemptions in one unbounded
    response.
    """
    query = (
        select(DeviceExemption)
        .join(Device, Device.id == DeviceExemption.device_id)
        .where(Device.user_id == current_user.id)
    )
    page: Page[DeviceExemption] = apply_keyset(
        db,
        query,
        order_column=DeviceExemption.created_at,
        id_column=DeviceExemption.id,
        limit=limit,
        cursor=cursor,
    )
    return PageSchema[ExemptionOut](
        items=[ExemptionOut.model_validate(row) for row in page.items],
        next_cursor=page.next_cursor,
        has_more=page.has_more,
        limit=page.limit,
    )