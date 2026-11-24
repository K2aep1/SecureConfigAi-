"""Assessment endpoints: queue a live scan, ingest uploads, read results and reports.

Route ordering matters: every static path (``/scans/start``, ``/scans/upload``,
``/scans/trend``) is registered before the ``/scans/{scan_id}`` routes so a literal
segment can never be parsed as a scan id.
"""

from __future__ import annotations

import gzip
import io
import json
import logging
import uuid
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Any, Literal
from uuid import UUID

from fastapi import (
    APIRouter,
    Depends,
    File,
    HTTPException,
    Query,
    Request,
    Response,
    UploadFile,
    status,
)
from fastapi.responses import FileResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session, load_only, selectinload

from app.core import audit
from app.core.config import EVIDENCE_DIR, UPLOAD_DIR, settings
from app.core.database import get_db
from app.core.dependencies import get_current_user
from app.core.pagination import Page, apply_keyset
from app.core.rate_limit import enforce
from app.core.timeutil import elapsed_ms
from app.db.models import Device, Finding, Scan, ScanResult, User
from app.schemas import (
    CategoryOut,
    ControlResultOut,
    FindingOut,
    RecommendationOut,
    ScanDocumentOut,
    ScanQueuedOut,
    ScanResultsOut,
    ScanStartRequest,
    ScanStatusOut,
    ScanSummaryOut,
    UploadResultOut,
    UploadSummaryOut,
)
from app.schemas import (
    Page as PageSchema,
)
from app.services import report_service
from app.services.baseline import load_baseline
from app.services.configuration_snapshot import SnapshotValidationError, load_snapshot
from app.services.jobs import manager
from app.services.scan_service import (
    criticality_for,
    document_evidence_bytes,
    effective_for_device,
    ingest_document,
    project_document,
    scan_summary,
    summary_row,
    utcnow,
)
from app.services.scoring import SCORING_MODEL_VERSION

logger = logging.getLogger("secureconfigai.scans")
router = APIRouter(prefix="/scans", tags=["scans"])

QUARANTINE_DIR = UPLOAD_DIR / "quarantine"


# --------------------------------------------------------------------------- helpers
def _owned_scan(scan_id: UUID, user: User, db: Session, *, load_document: bool = False) -> Scan:
    scan = db.get(Scan, scan_id)
    if scan is None or scan.user_id != user.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    if load_document:
        # Deferred columns need an explicit refresh to be populated.
        _ = scan.normalized_data
    return scan


def _resolve_or_create_device(db: Session, user: User, document: dict[str, Any]) -> Device | None:
    device_info = document.get("device") if isinstance(document.get("device"), dict) else {}
    hostname = str(device_info.get("hostname") or "").strip()
    if not hostname or hostname == "unknown-host":
        return None
    device = db.query(Device).filter(Device.user_id == user.id, Device.hostname == hostname).one_or_none()
    if device is None:
        device = Device(
            user_id=user.id,
            hostname=hostname,
            os_type=str(device_info.get("os") or "windows")[:32],
            os_version=(str(device_info.get("version"))[:64] if device_info.get("version") else None),
            os_build=(str(device_info.get("build"))[:64] if device_info.get("build") else None),
            criticality=settings.SCAN_DEFAULT_CRITICALITY,
        )
        db.add(device)
        db.flush()
        audit.record(
            db,
            "device.create",
            actor=user,
            entity_type="device",
            entity_id=device.id,
            details={"hostname": hostname},
            commit=False,
        )
    else:
        if device_info.get("version"):
            device.os_version = str(device_info["version"])[:64]
        if device_info.get("build"):
            device.os_build = str(device_info["build"])[:64]
    return device


def _findings_payload(db: Session, scan_id: UUID) -> list[FindingOut]:
    findings = list(
        db.execute(
            select(Finding).options(selectinload(Finding.recommendations)).where(Finding.scan_id == scan_id)
        ).scalars()
    )
    baseline = load_baseline()
    reference_map = {c.control_id: list(c.references) for c in baseline.controls}
    payload: list[FindingOut] = []
    for finding in findings:
        recommendation = finding.recommendations[0] if finding.recommendations else None
        payload.append(
            FindingOut(
                id=finding.id,
                control_id=finding.control_id,
                title=finding.title,
                category=finding.category,
                severity=finding.severity,
                status=finding.status,
                description=finding.description,
                current_value=finding.current_value,
                expected_value=finding.expected_value,
                evidence=finding.evidence,
                standard_refs=reference_map.get(str(finding.control_id), []),
                recommendation=(RecommendationOut.model_validate(recommendation) if recommendation else None),
            )
        )
    return payload


# --------------------------------------------------------------------------- queue
@router.post("/start", response_model=ScanQueuedOut, status_code=status.HTTP_202_ACCEPTED)
def start_scan(
    payload: ScanStartRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> ScanQueuedOut:
    """Queue an assessment. Returns immediately; poll ``/scans/{id}/status``."""
    enforce("scans.start", f"user:{current_user.id}", detail="Too many assessments queued.")

    queued = db.query(Scan).filter(Scan.status.in_(["queued", "running"])).count()
    if queued >= settings.SCAN_MAX_QUEUE:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="The assessment queue is full. Try again shortly.",
            headers={"Retry-After": "60"},
        )

    device: Device | None = None
    if payload.device_id is not None:
        device = (
            db.query(Device)
            .filter(Device.id == payload.device_id, Device.user_id == current_user.id)
            .one_or_none()
        )
        if device is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")

    scan = Scan(
        user_id=current_user.id,
        device_id=device.id if device else None,
        status="queued",
        stage="Queued",
        progress=0,
        source=payload.source[:32],
        raw_data={
            "inventory": payload.inventory if payload.inventory is not None else settings.SCAN_INVENTORY,
            "collectors": payload.collectors,
        },
        started_at=utcnow(),
        heartbeat_at=utcnow(),
        scoring_model_version=SCORING_MODEL_VERSION,
        baseline_version=load_baseline().version,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    audit.record(
        db,
        "scan.start",
        actor=current_user,
        entity_type="scan",
        entity_id=scan.id,
        request=request,
        details={"device_id": str(device.id) if device else None, "source": scan.source},
    )
    manager.submit(scan.id)
    return ScanQueuedOut(scan_id=scan.id, status=scan.status, stage=scan.stage, progress=scan.progress)


@router.post("/upload", response_model=UploadResultOut)
def upload_snapshot(
    request: Request,
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> UploadResultOut:
    """Ingest an offline configuration snapshot (JSON or ZIP).

    Rejected uploads are part of the audit trail: an attempted hostile archive is a
    security event even though nothing was stored.
    """
    filename = Path(file.filename or "scan_result.json").name
    try:
        return _ingest_upload(request=request, file=file, current_user=current_user, db=db)
    except HTTPException as exc:
        audit.record(
            db,
            "scan.upload.rejected",
            actor=current_user,
            entity_type="scan",
            request=request,
            outcome="failure",
            details={"filename": filename, "status": exc.status_code, "reason": str(exc.detail)[:300]},
        )
        raise


def _ingest_upload(*, request: Request, file: UploadFile, current_user: User, db: Session) -> UploadResultOut:
    enforce("scans.upload", f"user:{current_user.id}", detail="Too many uploads.")

    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > settings.MAX_UPLOAD_BYTES + 4096:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Upload exceeds the {settings.MAX_UPLOAD_BYTES // (1024 * 1024)} MB limit.",
        )

    original_name = Path(file.filename or "scan_result.json").name
    suffix = Path(original_name).suffix.lower()
    if suffix not in settings.allowed_upload_extensions:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "Only "
                + " and ".join(sorted(settings.allowed_upload_extensions))
                + " SecureConfigAI evidence files are supported"
            ),
        )

    raw = file.file.read(settings.MAX_UPLOAD_BYTES + 1)
    if not raw:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Uploaded file is empty")
    if len(raw) > settings.MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Upload exceeds the {settings.MAX_UPLOAD_BYTES // (1024 * 1024)} MB limit.",
        )

    QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
    quarantine = QUARANTINE_DIR / f"upload_{uuid.uuid4().hex}{suffix}"
    quarantine.write_bytes(raw)
    keep_file = False
    try:
        if suffix == ".zip":
            try:
                with zipfile.ZipFile(io.BytesIO(raw)) as archive:
                    names = archive.namelist()
                    if any(Path(n).is_absolute() or ".." in Path(n).parts for n in names):
                        raise HTTPException(
                            status_code=status.HTTP_400_BAD_REQUEST,
                            detail="Unsafe ZIP archive paths are not allowed",
                        )
                    json_names = [n for n in names if n.lower().endswith(".json") and not n.endswith("/")]
                    if not json_names:
                        raise HTTPException(
                            status_code=status.HTTP_400_BAD_REQUEST,
                            detail="No JSON file found in the uploaded archive",
                        )
                    selected = next(
                        (n for n in json_names if Path(n).name.lower() == "configuration_snapshot.json"),
                        json_names[0],
                    )
                    info = archive.getinfo(selected)
                    if info.file_size > settings.MAX_UPLOAD_BYTES:
                        raise HTTPException(
                            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                            detail="JSON inside the archive exceeds the size limit",
                        )
                    payload = json.loads(archive.open(selected).read().decode("utf-8"))
            except zipfile.BadZipFile as exc:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST, detail="Uploaded ZIP archive is invalid"
                ) from exc
        else:
            try:
                payload = json.loads(raw.decode("utf-8"))
            except UnicodeDecodeError as exc:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST, detail="Uploaded JSON must be UTF-8 encoded"
                ) from exc
            except json.JSONDecodeError as exc:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST, detail="Uploaded file is not valid JSON"
                ) from exc

        try:
            snapshot = load_snapshot(payload, raw_size=len(raw))
        except SnapshotValidationError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

        document = snapshot.document
        device = _resolve_or_create_device(db, current_user, document)
        effective = effective_for_device(db, device)

        scan = Scan(
            user_id=current_user.id,
            device_id=device.id if device else None,
            status="running",
            stage="Scoring evidence",
            progress=90,
            source="offline_upload",
            started_at=utcnow(),
            heartbeat_at=utcnow(),
            scanner_version=snapshot.scanner_version,
            evidence_bytes=len(raw),
            raw_data={
                "snapshot_id": snapshot.snapshot_id,
                "schema_version": snapshot.schema_version,
                "integrity_verified": snapshot.integrity_verified,
                "authenticity_verified": snapshot.authenticity_verified,
                "warnings": snapshot.warnings,
            },
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)

        ingested = None
        try:
            projection = project_document(document, effective)
            projection_bytes = document_evidence_bytes(projection)
            if settings.STORE_RAW_EVIDENCE or projection_bytes > settings.MAX_STORED_EVIDENCE_BYTES:
                EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
                evidence_path = EVIDENCE_DIR / f"{scan.id}.json.gz"
                with gzip.open(evidence_path, "wt", encoding="utf-8") as handle:
                    json.dump(document, handle, default=str, separators=(",", ":"))
                scan.uploaded_file_path = str(evidence_path)

            scan.normalized_data = projection
            db.commit()

            ingested = ingest_document(db, scan, document, device=device, user=current_user)
        except Exception as exc:
            # V4 fix (HIGH): a crash between the "running" commit and completion used to
            # leave the scan row in status="running" forever — recover_stale only runs at
            # startup, so the UI showed an in-progress scan that could never finish. The
            # row is now failed explicitly, mirroring jobs._fail, and the reason is audited.
            logger.exception("upload ingestion failed for scan %s", scan.id)
            scan.status = "failed"
            scan.stage = "Failed"
            scan.error_message = f"Ingestion failed: {exc}"[:2000]
            scan.completed_at = utcnow()
            db.commit()
            audit.record(
                db,
                "scan.fail",
                actor=current_user,
                entity_type="scan",
                entity_id=scan.id,
                request=request,
                outcome="failure",
                details={"source": "offline_upload", "reason": "ingestion_error"},
            )
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="The snapshot was accepted but could not be scored. The scan is marked failed.",
            ) from exc

        scan.status = "completed"
        scan.stage = "Completed"
        scan.progress = 100
        scan.completed_at = utcnow()
        scan.duration_ms = elapsed_ms(scan.started_at, scan.completed_at)
        db.commit()

        audit.record(
            db,
            "scan.upload",
            actor=current_user,
            entity_type="scan",
            entity_id=scan.id,
            request=request,
            details={
                "filename": original_name,
                "bytes": len(raw),
                "integrity_verified": snapshot.integrity_verified,
                "authenticity_verified": snapshot.authenticity_verified,
                "warnings": snapshot.warnings,
            },
        )
        keep_file = settings.STORE_RAW_EVIDENCE

        result = ingested["result"]
        if settings.REPORT_CACHE_ENABLED:
            try:
                report_service.ensure_reports(db, scan)
            except Exception:  # pragma: no cover - reports must not fail an ingest
                logger.warning("report generation failed for scan %s", scan.id, exc_info=True)

        return UploadResultOut(
            scan_id=scan.id,
            status=scan.status,
            message="Snapshot analysed. " + " ".join(snapshot.warnings),
            snapshot_id=snapshot.snapshot_id,
            schema_version=snapshot.schema_version,
            integrity_verified=snapshot.integrity_verified,
            authenticity_verified=snapshot.authenticity_verified,
            original_filename=original_name,
            finding_count=len(ingested["findings"]),
            device_id=device.id if device else None,
            summary=UploadSummaryOut(
                scan_status="Completed",
                duration_seconds=round((scan.duration_ms or 0) / 1000, 3),
                rules_checked=result["assessment"]["assessed_controls"],
                total_findings=len(ingested["findings"]),
                critical_findings=result["critical_count"],
                high_findings=result["high_count"],
                medium_findings=result["medium_count"],
                low_findings=result["low_count"],
                security_score=result["security_score"],
                compliance_score=result["compliance_score"],
                assessment_coverage=result["assessment_coverage"],
                risk_level=result["risk_level"],
                risk_score=result["risk_score"],
                evidence_quality=result["evidence_quality"],
            ),
            categories=[CategoryOut(**row) for row in result["categories"]],
            findings=_findings_payload(db, scan.id),
        )
    finally:
        if not keep_file:
            quarantine.unlink(missing_ok=True)


# --------------------------------------------------------------------------- listing
@router.get("", response_model=PageSchema[ScanSummaryOut])
def list_scans(
    limit: int = Query(25, ge=1, le=200),
    cursor: str | None = Query(None),
    status_filter: str | None = Query(None, alias="status"),
    device_id: UUID | None = Query(None),
    source: str | None = Query(None),
    q: str | None = Query(None, max_length=255),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> PageSchema[ScanSummaryOut]:
    query = select(Scan).where(Scan.user_id == current_user.id)
    if status_filter:
        query = query.where(Scan.status == status_filter)
    if device_id:
        query = query.where(Scan.device_id == device_id)
    if source:
        query = query.where(Scan.source == source)
    if q:
        query = query.join(Device, Device.id == Scan.device_id, isouter=True).where(
            Device.hostname.ilike(f"%{q}%")
        )

    page: Page[Scan] = apply_keyset(
        db, query, order_column=Scan.started_at, id_column=Scan.id, limit=limit, cursor=cursor
    )
    return PageSchema[ScanSummaryOut](
        items=_summaries(db, page.items),
        next_cursor=page.next_cursor,
        has_more=page.has_more,
        limit=page.limit,
    )


def _summaries(db: Session, scans: list[Scan]) -> list[ScanSummaryOut]:
    """Build list projections with a fixed number of queries (no N+1).

    ``ScanResult.controls`` and ``categories`` are deliberately not loaded: a summary row
    needs eight integers and the assessment counters, while the control list is roughly
    16 KB of JSON per scan. Deferring those columns is what keeps the history endpoint
    inside its payload and latency budget.
    """
    if not scans:
        return []
    scan_ids = [scan.id for scan in scans]
    device_ids = [scan.device_id for scan in scans if scan.device_id]
    counts = dict(
        db.execute(
            select(Finding.scan_id, func.count())
            .where(Finding.scan_id.in_(scan_ids))
            .group_by(Finding.scan_id)
        ).all()
    )
    results = {
        row.scan_id: row
        for row in db.execute(
            select(ScanResult)
            .options(
                load_only(
                    ScanResult.scan_id,
                    ScanResult.security_score,
                    ScanResult.compliance_score,
                    ScanResult.assessment_coverage,
                    ScanResult.risk_score,
                    ScanResult.risk_level,
                    ScanResult.evidence_quality,
                    ScanResult.critical_count,
                    ScanResult.high_count,
                    ScanResult.medium_count,
                    ScanResult.low_count,
                    ScanResult.informational_count,
                    ScanResult.assessment,
                )
            )
            .where(ScanResult.scan_id.in_(scan_ids))
        ).scalars()
    }
    devices = (
        {row.id: row for row in db.execute(select(Device).where(Device.id.in_(device_ids))).scalars()}
        if device_ids
        else {}
    )
    return [
        ScanSummaryOut(
            **summary_row(
                scan, results.get(scan.id), devices.get(scan.device_id), int(counts.get(scan.id, 0))
            )
        )
        for scan in scans
    ]


@router.get("/trend", response_model=list[dict[str, Any]])
def scan_trend(
    limit: int = Query(30, ge=1, le=200),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[dict[str, Any]]:
    """Compact posture trend. Only the columns needed are loaded."""
    rows = db.execute(
        select(
            Scan.id,
            Scan.started_at,
            Scan.scoring_model_version,
            Scan.baseline_version,
            ScanResult.security_score,
            ScanResult.compliance_score,
            ScanResult.assessment_coverage,
            ScanResult.risk_score,
            ScanResult.risk_level,
        )
        .join(ScanResult, ScanResult.scan_id == Scan.id)
        .where(Scan.user_id == current_user.id, Scan.status == "completed")
        .order_by(Scan.started_at.desc())
        .limit(limit)
    ).all()
    return [
        {
            "scan_id": str(row.id),
            "timestamp": row.started_at.isoformat() if row.started_at else None,
            "security_score": row.security_score,
            "compliance_score": row.compliance_score,
            "assessment_coverage": row.assessment_coverage,
            "risk_score": row.risk_score,
            "risk_level": row.risk_level,
            "scoring_model_version": row.scoring_model_version,
            "baseline_version": row.baseline_version,
        }
        for row in reversed(rows)
    ]


@router.get("/alerts", response_model=list[dict[str, Any]])
def scan_alerts(
    limit: int = Query(20, ge=1, le=100),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[dict[str, Any]]:
    rows = db.execute(
        select(
            Scan.id,
            Scan.started_at,
            ScanResult.risk_score,
            ScanResult.risk_level,
            ScanResult.critical_count,
            ScanResult.high_count,
        )
        .join(ScanResult, ScanResult.scan_id == Scan.id)
        .where(Scan.user_id == current_user.id, Scan.status == "completed")
        .order_by(Scan.started_at.desc())
        .limit(limit)
    ).all()
    alerts = []
    for row in rows:
        if (row.critical_count or 0) + (row.high_count or 0) == 0:
            continue
        alerts.append(
            {
                "scan_id": str(row.id),
                "severity": "critical" if row.critical_count else "high",
                "message": (
                    f"{row.critical_count or row.high_count} high-impact control "
                    f"failure(s) in the most recent assessment"
                ),
                "risk_score": row.risk_score,
                "risk_level": row.risk_level,
                "timestamp": row.started_at.isoformat() if row.started_at else None,
            }
        )
    return alerts


@router.get("/{scan_id}/status", response_model=ScanStatusOut)
def scan_status(
    scan_id: UUID, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)
) -> ScanStatusOut:
    scan = _owned_scan(scan_id, current_user, db)
    return ScanStatusOut(
        scan_id=scan.id,
        status=scan.status,
        stage=scan.stage,
        progress=scan.progress,
        heartbeat_at=scan.heartbeat_at,
        error_message=scan.error_message,
        duration_ms=scan.duration_ms,
    )


@router.get("/{scan_id}/results", response_model=ScanResultsOut)
def scan_results(
    scan_id: UUID, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)
) -> ScanResultsOut:
    scan = _owned_scan(scan_id, current_user, db)
    result = db.execute(select(ScanResult).where(ScanResult.scan_id == scan.id)).scalar_one_or_none()
    device = db.get(Device, scan.device_id) if scan.device_id else None
    findings = _findings_payload(db, scan.id)

    if result is None:
        return ScanResultsOut(
            scan_id=scan.id,
            status=scan.status,
            scanner_error=scan.error_message,
            device={"hostname": device.hostname if device else None},
            results={
                "assessment_unavailable": True,
                "reason": "No assessment is stored for this scan.",
                "assessment": {},
            },
            findings=findings,
        )

    assessment = dict(result.assessment or {})
    assessment["asset_criticality"] = assessment.get("asset_criticality", criticality_for(device))
    controls = [ControlResultOut(**row) for row in (result.controls or [])]
    stored_model = result.scoring_model_version or assessment.get("scoring_model_version")
    health = (
        assessment.get("collector_health") if isinstance(assessment.get("collector_health"), dict) else {}
    )
    results: dict[str, Any] = {
        "security_score": result.security_score,
        "compliance_score": result.compliance_score,
        "assessment_coverage": result.assessment_coverage,
        "risk_score": result.risk_score,
        "risk_level": result.risk_level,
        "evidence_quality": result.evidence_quality,
        "posture_band": (load_baseline().posture_band(result.security_score)),
        "critical_count": result.critical_count,
        "high_count": result.high_count,
        "medium_count": result.medium_count,
        "low_count": result.low_count,
        "informational_count": result.informational_count,
        "total_findings": len(findings),
        "controls": [_jsonable(c.model_dump()) for c in controls],
        "assessment": assessment,
        "categories": result.categories or [],
        "scoring_model_current": stored_model == SCORING_MODEL_VERSION,
        "stored_scoring_model_version": stored_model,
        "current_scoring_model_version": SCORING_MODEL_VERSION,
        "collector_health": health,
        "evidence_quality_explained": _evidence_quality_reason(result.evidence_quality, health),
        "asset_criticality": criticality_for(device),
        "criticality_label": _criticality_label(criticality_for(device)),
    }
    return ScanResultsOut(
        scan_id=scan.id,
        status=scan.status,
        scanner_error=scan.error_message,
        device={
            "id": str(device.id) if device else None,
            "hostname": device.hostname if device else None,
            "os": device.os_type if device else None,
            "version": device.os_version if device else None,
            "build": device.os_build if device else None,
            "criticality": criticality_for(device),
            "criticality_label": _criticality_label(criticality_for(device)),
        },
        results=results,
        findings=findings,
    )


@router.get("/{scan_id}/document", response_model=ScanDocumentOut)
def scan_document(
    scan_id: UUID,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> ScanDocumentOut:
    scan = _owned_scan(scan_id, current_user, db, load_document=True)
    audit.record(
        db, "scan.document_view", actor=current_user, entity_type="scan", entity_id=scan.id, request=request
    )
    return ScanDocumentOut(
        scan_id=scan.id,
        schema_version=(scan.normalized_data or {}).get("schema_version")
        if isinstance(scan.normalized_data, dict)
        else None,
        baseline_version=scan.baseline_version,
        scoring_model_version=scan.scoring_model_version,
        evidence_bytes=scan.evidence_bytes,
        normalized_data=scan.normalized_data if isinstance(scan.normalized_data, dict) else None,
    )


@router.get("/{scan_id}/report/{fmt}")
def scan_report(
    scan_id: UUID,
    fmt: Literal["html", "pdf"],
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Response:
    enforce("reports.generate", f"user:{current_user.id}", detail="Too many report renders.")
    scan = _owned_scan(scan_id, current_user, db)
    if scan.status != "completed":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="The assessment has not completed yet."
        )
    artifact = report_service.get_report(db, scan, fmt)
    etag = f'"{artifact.content_hash}"'
    if request.headers.get("if-none-match") == etag:
        return Response(
            status_code=status.HTTP_304_NOT_MODIFIED,
            headers={"ETag": etag, "Cache-Control": "private, max-age=0, must-revalidate"},
        )
    if not artifact.cached:
        audit.record(
            db,
            "scan.report",
            actor=current_user,
            entity_type="scan",
            entity_id=scan.id,
            request=request,
            details={"format": fmt},
        )
    media = "text/html" if fmt == "html" else "application/pdf"
    return FileResponse(
        artifact.path,
        media_type=media,
        filename=f"SecureConfigAI_{scan.id}.{fmt}",
        headers={"ETag": etag, "Cache-Control": "private, max-age=0, must-revalidate"},
    )


@router.post("/{scan_id}/cancel", status_code=status.HTTP_202_ACCEPTED)
def cancel_scan(
    scan_id: UUID,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    scan = _owned_scan(scan_id, current_user, db)
    if scan.is_terminal:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail=f"Assessment is already {scan.status}."
        )
    manager.cancel(scan.id)
    scan.status = "cancelled"
    scan.stage = "Cancelled"
    scan.completed_at = utcnow()
    scan.error_message = "Cancelled by the operator."
    db.commit()
    audit.record(
        db, "scan.cancel", actor=current_user, entity_type="scan", entity_id=scan.id, request=request
    )
    return {"scan_id": str(scan.id), "status": scan.status}


@router.post("/{scan_id}/reassess", response_model=ScanSummaryOut)
def reassess_scan(
    scan_id: UUID,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> ScanSummaryOut:
    """Re-run the current scoring model over stored evidence (never re-collects)."""
    scan = _owned_scan(scan_id, current_user, db, load_document=True)
    document = scan.normalized_data if isinstance(scan.normalized_data, dict) else None
    if not document or not isinstance(document.get("checks"), dict):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="No stored evidence is available to re-assess."
        )
    device = db.get(Device, scan.device_id) if scan.device_id else None
    ingest_document(db, scan, document, device=device, user=current_user)
    db.commit()
    audit.record(
        db,
        "scan.reassess",
        actor=current_user,
        entity_type="scan",
        entity_id=scan.id,
        request=request,
        details={"scoring_model_version": SCORING_MODEL_VERSION},
    )
    db.refresh(scan)
    return ScanSummaryOut(**scan_summary(db, scan))


@router.get("/{scan_id}", response_model=ScanSummaryOut)
def get_scan(
    scan_id: UUID, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)
) -> ScanSummaryOut:
    scan = _owned_scan(scan_id, current_user, db)
    return ScanSummaryOut(**scan_summary(db, scan))


@router.delete("/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_scan(
    scan_id: UUID,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Response:
    scan = _owned_scan(scan_id, current_user, db)
    for report in list(scan.reports):
        try:
            Path(report.file_path).unlink(missing_ok=True)
        except OSError:  # pragma: no cover
            pass
    if scan.uploaded_file_path:
        try:
            Path(scan.uploaded_file_path).unlink(missing_ok=True)
        except OSError:  # pragma: no cover
            pass
    db.delete(scan)
    db.commit()
    audit.record(
        db, "scan.delete", actor=current_user, entity_type="scan", entity_id=scan_id, request=request
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


def _criticality_label(level: int) -> str:
    return {1: "low", 2: "standard", 3: "standard", 4: "elevated", 5: "critical"}.get(int(level), "standard")


def _evidence_quality_reason(quality: str | None, health: dict[str, Any]) -> str:
    """Explain the evidence-quality label instead of showing a bare word."""
    coverage_note = {
        "high": "every applicable control was assessed",
        "medium": "most applicable controls were assessed",
        "low": "only some applicable controls were assessed",
        "unavailable": "no applicable control could be assessed",
    }.get(str(quality or "unavailable"), "coverage could not be classified")
    if not health:
        return coverage_note + "."
    counts = health.get("counts") or {}
    problems = [
        f"{counts[key]} {key}" for key in ("error", "timeout", "unavailable", "skipped") if counts.get(key)
    ]
    if not problems:
        return coverage_note + "; all collectors reported."
    return coverage_note + "; degraded collection: " + ", ".join(problems) + " collector(s)."


def _jsonable(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_jsonable(v) for v in value]
    if isinstance(value, (datetime, UUID)):
        return str(value)
    return value


def purge_quarantine(max_age_minutes: int | None = None) -> int:
    """Delete stale quarantine files left behind by interrupted uploads.

    Thin compatibility wrapper: the retention policy lives in
    :mod:`app.services.maintenance` so every cleanup rule has one owner.
    """
    from app.services import maintenance

    plan = maintenance.purge_quarantine(max_age_minutes, dry_run=False)
    return plan.quarantine_files_removed
