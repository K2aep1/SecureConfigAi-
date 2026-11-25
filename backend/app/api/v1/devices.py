"""Device inventory: registration, criticality, comparison and per-device exemptions.

Asset criticality is a real input: it scales the risk calculation, so registering a
high-value host with a higher criticality raises the risk score for the same set of
failing controls on subsequent assessments.

Exemptions are documented decisions to accept a deviation. They require a reason and
may have an expiry. Existing authorization semantics are preserved: device owners can
read exemptions for their own devices, while administrators create and delete them.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core import audit
from app.core.database import get_db
from app.core.dependencies import get_current_user, require_admin
from app.core.pagination import Page, apply_keyset
from app.db.models import Device, DeviceExemption, Scan, ScanResult, User
from app.schemas import (
    DeviceCompareOut,
    DeviceCreate,
    DeviceLatestResult,
    DeviceOut,
    DeviceUpdate,
    ExemptionCreate,
    ExemptionOut,
    Page as PageSchema,
)
from app.services.baseline import load_baseline
from app.services.jobs import manager

router = APIRouter(prefix="/devices", tags=["devices"])

CRITICALITY_LABELS = {1: "low", 2: "standard", 3: "standard", 4: "elevated", 5: "critical"}
DEFAULT_CRITICALITY = 3
ACTIVE_SCAN_STATUSES = ("queued", "running")
COMPARE_LIMIT = 200


# --------------------------------------------------------------------------- helpers
def _utcnow() -> datetime:
    return datetime.now(UTC)


def _label(level: Any) -> str:
    try:
        return CRITICALITY_LABELS[int(level)]
    except (KeyError, TypeError, ValueError):
        return "standard"


def _owned_device(db: Session, device_id: UUID, user: User) -> Device:
    """Return a device only when it belongs to the caller; hide other tenants as 404."""
    device = db.execute(
        select(Device).where(Device.id == device_id, Device.user_id == user.id)
    ).scalar_one_or_none()
    if device is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")
    return device


def _find_by_hostname(db: Session, user: User, hostname: str) -> Device | None:
    """Match hostnames case-insensitively within one user's inventory."""
    return db.execute(
        select(Device).where(
            Device.user_id == user.id,
            func.lower(Device.hostname) == hostname.strip().lower(),
        )
    ).scalar_one_or_none()


def _lock_user_inventory(db: Session, user: User) -> None:
    """Serialize inventory writes per user on databases supporting row-level locks.

    PostgreSQL honors FOR UPDATE. SQLite does not; a database uniqueness constraint
    and migration are still required for a strict cross-process guarantee there.
    """
    db.execute(select(User.id).where(User.id == user.id).with_for_update()).scalar_one()


def _validate_expiry(value: datetime | None) -> datetime | None:
    """Require timezone-aware future expiry values; normalize them to UTC."""
    if value is None:
        return None
    if value.tzinfo is None or value.utcoffset() is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="expires_at must include a timezone offset",
        )
    value = value.astimezone(UTC)
    if value <= _utcnow():
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="expires_at must be in the future",
        )
    return value


def _latest_completed(
    db: Session, device_ids: list[UUID]
) -> dict[UUID, tuple[Scan, ScanResult | None]]:
    """Fetch the latest completed scan per device in one query.

    The scan id is a deterministic tie-breaker when start timestamps are equal.
    """
    if not device_ids:
        return {}

    ranked = (
        select(
            Scan.id.label("scan_id"),
            func.row_number()
            .over(
                partition_by=Scan.device_id,
                order_by=[Scan.started_at.desc(), Scan.id.desc()],
            )
            .label("rn"),
        )
        .where(Scan.device_id.in_(device_ids), Scan.status == "completed")
        .subquery()
    )
    rows = db.execute(
        select(Scan, ScanResult)
        .select_from(Scan)
        .join(ranked, ranked.c.scan_id == Scan.id)
        .outerjoin(ScanResult, ScanResult.scan_id == Scan.id)
        .where(ranked.c.rn == 1)
    ).all()
    return {scan.device_id: (scan, result) for scan, result in rows}


def _device_out(
    device: Device,
    scan_count: int,
    pair: tuple[Scan, ScanResult | None] | None,
) -> DeviceOut:
    latest: DeviceLatestResult | None = None
    if pair is not None:
        scan, result = pair
        if result is not None:
            latest = DeviceLatestResult(
                security_score=result.security_score,
                compliance_score=result.compliance_score,
                assessment_coverage=result.assessment_coverage,
                risk_score=result.risk_score,
                risk_level=result.risk_level,
                evidence_quality=result.evidence_quality,
                completed_at=scan.completed_at,
            )

    return DeviceOut(
        id=device.id,
        hostname=device.hostname,
        os_type=device.os_type,
        os_version=device.os_version,
        os_build=device.os_build,
        criticality=device.criticality or DEFAULT_CRITICALITY,
        criticality_label=_label(device.criticality),
        first_seen_at=device.first_seen_at,
        last_scan_at=device.last_scan_at,
        scan_count=scan_count,
        latest=latest,
    )


def _summaries(db: Session, devices: list[Device]) -> dict[UUID, DeviceOut]:
    """Build device projections with a fixed number of queries."""
    if not devices:
        return {}

    device_ids = [device.id for device in devices]
    counts = dict(
        db.execute(
            select(Scan.device_id, func.count())
            .where(Scan.device_id.in_(device_ids))
            .group_by(Scan.device_id)
        ).all()
    )
    latest = _latest_completed(db, device_ids)
    return {
        device.id: _device_out(
            device,
            int(counts.get(device.id, 0)),
            latest.get(device.id),
        )
        for device in devices
    }


def _changes(device: Device, updates: dict[str, Any]) -> dict[str, tuple[Any, Any]]:
    """Return only values that actually change."""
    return {
        field: (getattr(device, field), value)
        for field, value in updates.items()
        if getattr(device, field) != value
    }


# --------------------------------------------------------------------------- list & compare
@router.get("", response_model=PageSchema[DeviceOut])
def list_devices(
    limit: int = Query(25, ge=1, le=200),
    cursor: str | None = Query(None),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> PageSchema[DeviceOut]:
    page: Page[Device] = apply_keyset(
        db,
        select(Device).where(Device.user_id == current_user.id),
        order_column=Device.created_at,
        id_column=Device.id,
        limit=limit,
        cursor=cursor,
        descending=False,
    )
    summaries = _summaries(db, list(page.items))
    return PageSchema[DeviceOut](
        items=[summaries[device.id] for device in page.items],
        next_cursor=page.next_cursor,
        has_more=page.has_more,
        limit=page.limit,
    )


@router.get("/compare", response_model=DeviceCompareOut)
def compare_devices(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> DeviceCompareOut:
    devices = list(
        db.execute(
            select(Device)
            .where(Device.user_id == current_user.id)
            .order_by(Device.hostname.asc())
            .limit(COMPARE_LIMIT)
        ).scalars()
    )
    summaries = _summaries(db, devices)
    rows: list[dict[str, Any]] = []
    for device in devices:
        out = summaries[device.id]
        latest = out.latest
        rows.append(
            {
                "device_id": str(device.id),
                "hostname": device.hostname,
                "os_type": device.os_type,
                "os_version": device.os_version,
                "criticality": device.criticality,
                "criticality_label": out.criticality_label,
                "last_scan_at": device.last_scan_at.isoformat() if device.last_scan_at else None,
                "security_score": latest.security_score if latest else None,
                "risk_score": latest.risk_score if latest else None,
                "risk_level": latest.risk_level if latest else None,
                "evidence_quality": latest.evidence_quality if latest else None,
            }
        )
    return DeviceCompareOut(devices=rows)


# --------------------------------------------------------------------------- write
@router.post("/register", response_model=DeviceOut, status_code=status.HTTP_201_CREATED)
def register_device(
    payload: DeviceCreate,
    request: Request,
    response: Response,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> DeviceOut:
    """Create a device (201) or update the same user's hostname (200)."""
    hostname = payload.hostname.strip()
    if not hostname:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="hostname cannot be blank",
        )

    # Lock the user's row to serialize concurrent inventory writes on PostgreSQL.
    _lock_user_inventory(db, current_user)
    device = _find_by_hostname(db, current_user, hostname)
    created = device is None
    if created:
        device = Device(user_id=current_user.id, hostname=hostname)
        db.add(device)
        previous_criticality = None
    else:
        response.status_code = status.HTTP_200_OK
        previous_criticality = device.criticality

    device.os_type = payload.os_type
    device.os_version = payload.os_version
    device.os_build = payload.os_build
    device.criticality = payload.criticality if payload.criticality is not None else DEFAULT_CRITICALITY

    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A device with this hostname conflicts with an existing record. Retry.",
        ) from None

    db.refresh(device)
    audit.record(
        db,
        "device.create" if created else "device.update",
        actor=current_user,
        entity_type="device",
        entity_id=device.id,
        request=request,
        details={
            "hostname": device.hostname,
            "criticality": device.criticality,
            "criticality_from": previous_criticality,
        },
    )
    return _summaries(db, [device])[device.id]


@router.get("/{device_id}", response_model=DeviceOut)
def get_device(
    device_id: UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> DeviceOut:
    device = _owned_device(db, device_id, current_user)
    return _summaries(db, [device])[device.id]


@router.put("/{device_id}", response_model=DeviceOut)
def update_device(
    device_id: UUID,
    payload: DeviceUpdate,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> DeviceOut:
    device = _owned_device(db, device_id, current_user)
    updates = payload.model_dump(exclude_unset=True)

    for required in ("hostname", "criticality", "os_type"):
        if required in updates and updates[required] is None:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"{required} cannot be cleared",
            )

    if "hostname" in updates:
        updates["hostname"] = updates["hostname"].strip()
        if not updates["hostname"]:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="hostname cannot be blank",
            )

    # Serialize hostname checks and writes for this user's inventory on PostgreSQL.
    _lock_user_inventory(db, current_user)
    if "hostname" in updates:
        clash = _find_by_hostname(db, current_user, updates["hostname"])
        if clash is not None and clash.id != device.id:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Another device already uses this hostname.",
            )

    changes = _changes(device, updates)
    if not changes:
        return _summaries(db, [device])[device.id]

    for field, (_, new_value) in changes.items():
        setattr(device, field, new_value)

    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Device update conflicts with an existing record.",
        ) from None

    db.refresh(device)

    if "criticality" in changes:
        old, new = changes["criticality"]
        audit.record(
            db,
            "device.criticality_change",
            actor=current_user,
            entity_type="device",
            entity_id=device.id,
            request=request,
            details={"from": old, "to": new},
        )

    other_fields = sorted(field for field in changes if field != "criticality")
    if other_fields:
        audit.record(
            db,
            "device.update",
            actor=current_user,
            entity_type="device",
            entity_id=device.id,
            request=request,
            details={"fields": other_fields},
        )

    return _summaries(db, [device])[device.id]


@router.delete("/{device_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_device(
    device_id: UUID,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Response:
    device = _owned_device(db, device_id, current_user)
    hostname = device.hostname

    active = list(
        db.execute(
            select(Scan).where(
                Scan.device_id == device.id,
                Scan.status.in_(ACTIVE_SCAN_STATUSES),
            )
        ).scalars()
    )
    now = _utcnow()
    for scan in active:
        manager.cancel(scan.id)
        scan.status = "cancelled"
        scan.stage = "Cancelled"
        scan.completed_at = now
        scan.error_message = "The device was removed."

    # Explicitly remove exemptions and detach scans so assessment history survives.
    exemptions_removed = (
        db.query(DeviceExemption)
        .filter(DeviceExemption.device_id == device.id)
        .delete(synchronize_session=False)
    )
    db.query(Scan).filter(Scan.device_id == device.id).update(
        {Scan.device_id: None}, synchronize_session=False
    )
    db.delete(device)
    db.commit()

    audit.record(
        db,
        "device.delete",
        actor=current_user,
        entity_type="device",
        entity_id=device_id,
        request=request,
        details={
            "hostname": hostname,
            "exemptions_removed": exemptions_removed,
            "active_scans_cancelled": len(active),
        },
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# --------------------------------------------------------------------------- exemptions
@router.get("/{device_id}/exemptions", response_model=list[ExemptionOut])
def list_exemptions(
    device_id: UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[ExemptionOut]:
    """Return the caller-owned device's exemptions using the existing array contract."""
    device = _owned_device(db, device_id, current_user)
    rows = db.execute(
        select(DeviceExemption)
        .where(DeviceExemption.device_id == device.id)
        .order_by(DeviceExemption.created_at.desc(), DeviceExemption.id.desc())
    ).scalars()
    return [ExemptionOut.model_validate(row) for row in rows]


@router.post(
    "/{device_id}/exemptions",
    response_model=ExemptionOut,
    status_code=status.HTTP_201_CREATED,
)
def create_exemption(
    device_id: UUID,
    payload: ExemptionCreate,
    request: Request,
    response: Response,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> ExemptionOut:
    """Create or update an exemption; preserve the administrator-only write policy."""
    known_control_ids = {control.control_id for control in load_baseline().controls}
    if payload.control_id not in known_control_ids:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown control id {payload.control_id!r}. See GET /baseline for the control list.",
        )

    device = db.get(Device, device_id)
    if device is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")

    expires_at = _validate_expiry(payload.expires_at)
    existing = db.execute(
        select(DeviceExemption).where(
            DeviceExemption.device_id == device.id,
            DeviceExemption.control_id == payload.control_id,
        )
    ).scalar_one_or_none()

    if existing is not None:
        previous = {
            "reason": existing.reason,
            "expires_at": existing.expires_at.isoformat() if existing.expires_at else None,
        }
        existing.reason = payload.reason
        existing.expires_at = expires_at
        exemption = existing
        response.status_code = status.HTTP_200_OK
        details: dict[str, Any] = {
            "control_id": payload.control_id,
            "updated": True,
            "previous": previous,
        }
    else:
        exemption = DeviceExemption(
            device_id=device.id,
            control_id=payload.control_id,
            reason=payload.reason,
            created_by=current_user.id,
            expires_at=expires_at,
        )
        db.add(exemption)
        details = {"control_id": payload.control_id, "updated": False}

    details["reason"] = payload.reason
    details["expires_at"] = expires_at.isoformat() if expires_at else None

    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An exemption for this control was created or changed concurrently. Retry.",
        ) from None

    db.refresh(exemption)
    audit.record(
        db,
        "exemption.create",
        actor=current_user,
        entity_type="device",
        entity_id=device.id,
        request=request,
        details=details,
    )
    return ExemptionOut.model_validate(exemption)


@router.delete(
    "/{device_id}/exemptions/{control_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def delete_exemption(
    device_id: UUID,
    control_id: str,
    request: Request,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> Response:
    device = db.get(Device, device_id)
    if device is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")

    exemption = db.execute(
        select(DeviceExemption).where(
            DeviceExemption.device_id == device.id,
            DeviceExemption.control_id == control_id,
        )
    ).scalar_one_or_none()
    if exemption is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Exemption not found")

    reason = exemption.reason
    db.delete(exemption)
    db.commit()
    audit.record(
        db,
        "exemption.delete",
        actor=current_user,
        entity_type="device",
        entity_id=device.id,
        request=request,
        details={"control_id": control_id, "reason": reason},
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)
