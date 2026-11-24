"""Device inventory: registration, criticality, comparison and per-device exemptions.

Asset criticality is a real input: it scales the risk calculation, so registering a
domain controller as criticality 5 legitimately raises the risk score for the same set
of failing controls. Exemptions are the documented way to accept a deviation — they are
recorded with a reason and an optional expiry, never applied silently.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from sqlalchemy import func, select
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
)
from app.schemas import (
    Page as PageSchema,
)
from app.services.baseline import load_baseline

router = APIRouter(prefix="/devices", tags=["devices"])

CRITICALITY_LABELS = {1: "low", 2: "standard", 3: "standard", 4: "elevated", 5: "critical"}


def _label(level: Any) -> str:
    try:
        return CRITICALITY_LABELS[int(level)]
    except (KeyError, TypeError, ValueError):
        return "standard"


def _device_out(
    db: Session,
    device: Device,
    *,
    scan_count: int | None = None,
    latest: ScanResult | None = None,
    latest_scan: Scan | None = None,
) -> DeviceOut:
    if scan_count is None:
        scan_count = db.query(Scan).filter(Scan.device_id == device.id).count()
    if latest is None:
        latest_scan = db.execute(
            select(Scan)
            .where(Scan.device_id == device.id, Scan.status == "completed")
            .order_by(Scan.started_at.desc())
            .limit(1)
        ).scalar_one_or_none()
        latest = (
            db.execute(select(ScanResult).where(ScanResult.scan_id == latest_scan.id)).scalar_one_or_none()
            if latest_scan
            else None
        )
    return DeviceOut(
        id=device.id,
        hostname=device.hostname,
        os_type=device.os_type,
        os_version=device.os_version,
        os_build=device.os_build,
        criticality=device.criticality or 3,
        criticality_label=_label(device.criticality),
        first_seen_at=device.first_seen_at,
        last_scan_at=device.last_scan_at,
        scan_count=int(scan_count or 0),
        latest=DeviceLatestResult(
            security_score=latest.security_score,
            compliance_score=latest.compliance_score,
            assessment_coverage=latest.assessment_coverage,
            risk_score=latest.risk_score,
            risk_level=latest.risk_level,
            evidence_quality=latest.evidence_quality,
            completed_at=latest_scan.completed_at if latest_scan else None,
        )
        if latest
        else None,
    )


@router.get("", response_model=PageSchema[DeviceOut])
def list_devices(
    limit: int = Query(25, ge=1, le=200),
    cursor: str | None = Query(None),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> PageSchema[DeviceOut]:
    query = select(Device).where(Device.user_id == current_user.id)
    page: Page[Device] = apply_keyset(
        db,
        query,
        order_column=Device.created_at,
        id_column=Device.id,
        limit=limit,
        cursor=cursor,
        descending=False,
    )
    if not page.items:
        return PageSchema[DeviceOut](items=[], next_cursor=None, has_more=False, limit=limit)

    device_ids = [d.id for d in page.items]
    counts = dict(
        db.execute(
            select(Scan.device_id, func.count())
            .where(Scan.device_id.in_(device_ids))
            .group_by(Scan.device_id)
        ).all()
    )

    # Latest completed scan per device in one query.
    latest_rows = db.execute(
        select(Scan.device_id, func.max(Scan.started_at).label("mx"))
        .where(Scan.device_id.in_(device_ids), Scan.status == "completed")
        .group_by(Scan.device_id)
    ).all()
    latest_scan_map: dict[Any, Scan] = {}
    for device_id, moment in latest_rows:
        scan = db.execute(
            select(Scan).where(Scan.device_id == device_id, Scan.started_at == moment).limit(1)
        ).scalar_one_or_none()
        if scan is not None:
            latest_scan_map[device_id] = scan
    result_map = (
        {
            row.scan_id: row
            for row in db.execute(
                select(ScanResult).where(ScanResult.scan_id.in_([s.id for s in latest_scan_map.values()]))
            ).scalars()
        }
        if latest_scan_map
        else {}
    )

    return PageSchema[DeviceOut](
        items=[
            _device_out(
                db,
                device,
                scan_count=int(counts.get(device.id, 0)),
                latest=result_map.get(latest_scan_map[device.id].id)
                if device.id in latest_scan_map
                else None,
                latest_scan=latest_scan_map.get(device.id),
            )
            for device in page.items
        ],
        next_cursor=page.next_cursor,
        has_more=page.has_more,
        limit=page.limit,
    )


@router.get("/compare", response_model=DeviceCompareOut)
def compare_devices(
    current_user: User = Depends(get_current_user), db: Session = Depends(get_db)
) -> DeviceCompareOut:
    devices = list(
        db.execute(
            select(Device).where(Device.user_id == current_user.id).order_by(Device.hostname.asc())
        ).scalars()
    )
    rows: list[dict[str, Any]] = []
    for device in devices:
        latest_scan = db.execute(
            select(Scan)
            .where(Scan.device_id == device.id, Scan.status == "completed")
            .order_by(Scan.started_at.desc())
            .limit(1)
        ).scalar_one_or_none()
        latest = (
            db.execute(select(ScanResult).where(ScanResult.scan_id == latest_scan.id)).scalar_one_or_none()
            if latest_scan
            else None
        )
        rows.append(
            {
                "device_id": str(device.id),
                "hostname": device.hostname,
                "os_type": device.os_type,
                "os_version": device.os_version,
                "criticality": device.criticality,
                "criticality_label": _label(device.criticality),
                "last_scan_at": device.last_scan_at.isoformat() if device.last_scan_at else None,
                "security_score": latest.security_score if latest else None,
                "risk_score": latest.risk_score if latest else None,
                "risk_level": latest.risk_level if latest else None,
                "evidence_quality": latest.evidence_quality if latest else None,
            }
        )
    return DeviceCompareOut(devices=rows)


@router.post("/register", response_model=DeviceOut, status_code=status.HTTP_201_CREATED)
def register_device(
    payload: DeviceCreate,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> DeviceOut:
    device = (
        db.query(Device)
        .filter(Device.user_id == current_user.id, Device.hostname == payload.hostname)
        .one_or_none()
    )
    created = device is None
    if device is None:
        device = Device(user_id=current_user.id, hostname=payload.hostname)
        db.add(device)
    device.os_type = payload.os_type
    device.os_version = payload.os_version
    device.os_build = payload.os_build
    device.criticality = payload.criticality
    db.commit()
    db.refresh(device)
    audit.record(
        db,
        "device.create" if created else "device.update",
        actor=current_user,
        entity_type="device",
        entity_id=device.id,
        request=request,
        details={"hostname": device.hostname, "criticality": device.criticality},
    )
    return _device_out(db, device)


@router.get("/{device_id}", response_model=DeviceOut)
def get_device(
    device_id: UUID, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)
) -> DeviceOut:
    device = db.query(Device).filter(Device.id == device_id, Device.user_id == current_user.id).one_or_none()
    if device is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")
    return _device_out(db, device)


@router.put("/{device_id}", response_model=DeviceOut)
def update_device(
    device_id: UUID,
    payload: DeviceUpdate,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> DeviceOut:
    device = db.query(Device).filter(Device.id == device_id, Device.user_id == current_user.id).one_or_none()
    if device is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")
    updates = payload.model_dump(exclude_unset=True)
    previous_criticality = device.criticality
    for field, value in updates.items():
        setattr(device, field, value)
    db.commit()
    db.refresh(device)
    if "criticality" in updates and updates["criticality"] != previous_criticality:
        audit.record(
            db,
            "device.criticality_change",
            actor=current_user,
            entity_type="device",
            entity_id=device.id,
            request=request,
            details={"from": previous_criticality, "to": device.criticality},
        )
    else:
        audit.record(
            db,
            "device.update",
            actor=current_user,
            entity_type="device",
            entity_id=device.id,
            request=request,
            details={"fields": sorted(updates)},
        )
    return _device_out(db, device)


@router.delete("/{device_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_device(
    device_id: UUID,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Response:
    device = db.query(Device).filter(Device.id == device_id, Device.user_id == current_user.id).one_or_none()
    if device is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")
    # Detach rather than cascade: assessment history must survive device removal.
    db.query(Scan).filter(Scan.device_id == device.id).update({Scan.device_id: None})
    hostname = device.hostname
    db.delete(device)
    db.commit()
    audit.record(
        db,
        "device.delete",
        actor=current_user,
        entity_type="device",
        entity_id=device_id,
        request=request,
        details={"hostname": hostname},
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# --------------------------------------------------------------------------- exemptions
@router.get("/{device_id}/exemptions", response_model=list[ExemptionOut])
def list_exemptions(
    device_id: UUID, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)
) -> list[ExemptionOut]:
    device = db.query(Device).filter(Device.id == device_id, Device.user_id == current_user.id).one_or_none()
    if device is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")
    rows = db.execute(
        select(DeviceExemption)
        .where(DeviceExemption.device_id == device.id)
        .order_by(DeviceExemption.created_at.desc())
    ).scalars()
    return [ExemptionOut.model_validate(row) for row in rows]


@router.post("/{device_id}/exemptions", response_model=ExemptionOut, status_code=status.HTTP_201_CREATED)
def create_exemption(
    device_id: UUID,
    payload: ExemptionCreate,
    request: Request,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> ExemptionOut:
    known = {c.control_id for c in load_baseline().controls}
    if payload.control_id not in known:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=f"Unknown control id {payload.control_id!r}"
        )
    device = db.get(Device, device_id)
    if device is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")
    existing = (
        db.query(DeviceExemption)
        .filter(DeviceExemption.device_id == device.id, DeviceExemption.control_id == payload.control_id)
        .one_or_none()
    )
    if existing is not None:
        existing.reason = payload.reason
        existing.expires_at = payload.expires_at
        db.commit()
        db.refresh(existing)
        audit.record(
            db,
            "exemption.create",
            actor=current_user,
            entity_type="device",
            entity_id=device.id,
            request=request,
            details={"control_id": payload.control_id, "updated": True},
        )
        return ExemptionOut.model_validate(existing)

    exemption = DeviceExemption(
        device_id=device.id,
        control_id=payload.control_id,
        reason=payload.reason,
        created_by=current_user.id,
        expires_at=payload.expires_at,
    )
    db.add(exemption)
    db.commit()
    db.refresh(exemption)
    audit.record(
        db,
        "exemption.create",
        actor=current_user,
        entity_type="device",
        entity_id=device.id,
        request=request,
        details={
            "control_id": payload.control_id,
            "reason": payload.reason,
            "expires_at": payload.expires_at.isoformat() if payload.expires_at else None,
        },
    )
    return ExemptionOut.model_validate(exemption)


@router.delete("/{device_id}/exemptions/{control_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_exemption(
    device_id: UUID,
    control_id: str,
    request: Request,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> Response:
    exemption = (
        db.query(DeviceExemption)
        .filter(DeviceExemption.device_id == device_id, DeviceExemption.control_id == control_id)
        .one_or_none()
    )
    if exemption is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Exemption not found")
    db.delete(exemption)
    db.commit()
    audit.record(
        db,
        "exemption.delete",
        actor=current_user,
        entity_type="device",
        entity_id=device_id,
        request=request,
        details={"control_id": control_id},
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


def _utcnow() -> datetime:
    return datetime.now(UTC)
