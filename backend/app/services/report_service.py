"""Report generation with content-addressed caching.

Reports are generated once per assessment (on completion, or on first request if that
did not happen) and then served with an ``ETag`` derived from the assessment content.
A repeat view costs a header round trip instead of a full document rebuild — ReportLab
builds the whole document in memory every time, so regenerating per request is pure
waste.
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.core.config import REPORT_DIR, settings
from app.db.models import Device, Finding, Report, Scan, ScanResult
from app.services import report_generator
from app.services.baseline import load_baseline
from app.services.scan_service import effective_for_device

logger = logging.getLogger("secureconfigai.reports")

Format = Literal["pdf", "html"]


@dataclass
class ReportArtifact:
    path: Path
    content_hash: str
    format: Format
    cached: bool
    size_bytes: int


def _utcnow() -> datetime:
    return datetime.now(UTC)


def report_path(scan_id: Any, fmt: Format) -> Path:
    return REPORT_DIR / f"{scan_id}.{fmt}"


#: Bump when a renderer change alters the produced document, so cached artefacts for
#: the previous template are regenerated rather than served.
REPORT_TEMPLATE_VERSION = "2.0.0"


def content_etag(data: dict[str, Any]) -> str:
    """Stable validator over the *substance* of a report.

    ``generated_at`` and ``report_id`` are deliberately excluded: they change on every
    build, so including them would produce a new ETag for identical content and make
    ``If-None-Match`` never match. What is hashed is the content a reader would notice —
    the assessment, the device, the scores, the findings and the engine versions.
    """
    payload = {
        "template_version": REPORT_TEMPLATE_VERSION,
        "assessment": data.get("assessment"),
        "device": data.get("device"),
        "scores": data.get("scores"),
        "categories": data.get("categories"),
        "risk": data.get("risk"),
        "counts": data.get("counts"),
        "findings": [
            {key: value for key, value in finding.items() if key != "generated_at"}
            for finding in data.get("findings", [])
        ],
    }
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    ).hexdigest()


def build_data(db: Session, scan: Scan) -> dict[str, Any]:
    """Assemble the render model from stored state (never recomputes the assessment)."""
    result = db.execute(select(ScanResult).where(ScanResult.scan_id == scan.id)).scalar_one_or_none()
    findings = list(
        db.execute(
            select(Finding)
            .options(selectinload(Finding.recommendations))
            .where(Finding.scan_id == scan.id)
            .order_by(Finding.severity, Finding.control_id)
        ).scalars()
    )
    device = db.get(Device, scan.device_id) if scan.device_id else None
    baseline = load_baseline()

    risk: dict[str, Any] = {}
    if result and result.controls:
        from app.services.scoring import ControlResult, explain_risk  # local import: cycle-free

        effective = effective_for_device(db, device)
        controls = []
        for raw in result.controls:
            controls.append(
                ControlResult(
                    control_id=str(raw.get("control_id")),
                    title=str(raw.get("title")),
                    category=str(raw.get("category")),
                    weight=int(raw.get("weight", 0)),
                    severity=str(raw.get("severity", "medium")),
                    status=str(raw.get("status", "unknown")),
                    applicability=str(raw.get("applicability", "applicable")),
                    expected_state=raw.get("expected_state"),
                    actual_state=raw.get("actual_state"),
                    evidence=raw.get("evidence"),
                    standard_refs=list(raw.get("standard_refs") or []),
                    rationale=str(raw.get("rationale", "")),
                    remediation=dict(raw.get("remediation") or {}),
                    collector=str(raw.get("collector", "")),
                    collector_status=str(raw.get("collector_status", "")),
                    notes=list(raw.get("notes") or []),
                    exempted=bool(raw.get("exempted")),
                    exemption_reason=raw.get("exemption_reason"),
                    risk_impact=float(raw.get("risk_impact") or 0.0),
                )
            )
        risk = explain_risk(controls, effective, int((result.assessment or {}).get("asset_criticality", 3)))

    return report_generator.build_report_data(
        scan=scan,
        findings=findings,
        result=result,
        device=device,
        baseline=baseline,
        risk_explanation=risk,
    )


def ensure_reports(db: Session, scan: Scan) -> dict[Format, ReportArtifact]:
    """Generate any missing/stale artefacts for a scan and record them."""
    data = build_data(db, scan)
    etag = content_etag(data)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    artifacts: dict[Format, ReportArtifact] = {}

    existing = {
        report.format: report
        for report in db.execute(select(Report).where(Report.scan_id == scan.id)).scalars()
    }

    for fmt in ("html", "pdf"):
        path = report_path(scan.id, fmt)  # type: ignore[arg-type]
        record = existing.get(fmt)
        if (
            path.exists()
            and record is not None
            and record.content_hash == etag
            and record.size_bytes == path.stat().st_size
        ):
            artifacts[fmt] = ReportArtifact(path, etag, fmt, True, path.stat().st_size)  # type: ignore[arg-type]
            continue
        if fmt == "html":
            path.write_text(report_generator.render_html(data), encoding="utf-8", newline="\n")
        else:
            report_generator.render_pdf(data, path)
        size = path.stat().st_size
        if record is None:
            record = Report(scan_id=scan.id, format=fmt, file_path=str(path))
            db.add(record)
        record.file_path = str(path)
        record.content_hash = etag
        record.size_bytes = size
        record.generated_at = _utcnow()
        db.commit()
        artifacts[fmt] = ReportArtifact(path, etag, fmt, False, size)  # type: ignore[arg-type]
    return artifacts


def get_report(db: Session, scan: Scan, fmt: Format) -> ReportArtifact:
    if not settings.REPORT_CACHE_ENABLED:
        data = build_data(db, scan)
        path = report_path(scan.id, fmt)
        REPORT_DIR.mkdir(parents=True, exist_ok=True)
        if fmt == "html":
            path.write_text(report_generator.render_html(data), encoding="utf-8", newline="\n")
        else:
            report_generator.render_pdf(data, path)
        return ReportArtifact(path, content_etag(data), fmt, False, path.stat().st_size)
    return ensure_reports(db, scan)[fmt]


def purge_old_reports(db: Session, days: int | None = None) -> int:
    """Delete report artefacts and rows older than the retention window."""
    window = days or settings.RETENTION_REPORT_DAYS
    if window <= 0:
        return 0
    cutoff = _utcnow() - timedelta(days=window)
    stale = list(db.execute(select(Report).where(Report.generated_at < cutoff)).scalars())
    removed = 0
    for record in stale:
        try:
            Path(record.file_path).unlink(missing_ok=True)
        except OSError:  # pragma: no cover
            logger.warning("could not remove report file %s", record.file_path)
        db.delete(record)
        removed += 1
    if removed:
        db.commit()
    return removed
