"""Assessment ingestion: evidence document -> controls -> findings -> stored result.

This module is the single path from "a scanner produced a document" to "the database
holds an assessment", shared by the live job runner and the snapshot upload endpoint so
both produce identical results for identical evidence.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.db.models import (
    Device,
    DeviceExemption,
    Finding,
    Policy,
    Recommendation,
    Scan,
    ScanResult,
    User,
)
from app.services import scoring
from app.services.baseline import EffectiveSet, load_baseline, resolve_effective

logger = logging.getLogger("secureconfigai.ingest")


def utcnow() -> datetime:
    return datetime.now(UTC)


def effective_for_device(db: Session, device: Device | None) -> EffectiveSet:
    """Resolve baseline + global overrides + this device's exemptions."""
    baseline = load_baseline()
    overrides = list(db.execute(select(Policy)).scalars())
    exemptions: list[DeviceExemption] = []
    if device is not None:
        now = utcnow()
        exemptions = [
            e
            for e in db.execute(
                select(DeviceExemption).where(DeviceExemption.device_id == device.id)
            ).scalars()
            if e.expires_at is None or e.expires_at > now
        ]
    return resolve_effective(baseline, overrides, exemptions)


def criticality_for(device: Device | None, default: int = 3) -> int:
    return int(device.criticality) if device is not None and device.criticality else default


# --------------------------------------------------------------------------- health
HEALTH_BUCKETS = {
    "completed": ("completed", "success", "ok"),
    "error": ("error",),
    "timeout": ("timeout",),
    "unavailable": ("unavailable",),
    "skipped": ("skipped",),
}


def collector_health(document: Mapping[str, Any]) -> dict[str, Any]:
    """Summarise per-collector execution so a degraded scan cannot present as a clean one.

    The scanner already records a status per collector. Historically the backend dropped
    that map, which made a run with two timeouts indistinguishable from a complete run.
    This projection is stored on the scan result and returned by the results endpoint.
    """
    entries: dict[str, dict[str, Any]] = {}
    reported = document.get("collector_status")
    if isinstance(reported, Mapping):
        for name, entry in reported.items():
            if not isinstance(entry, Mapping):
                entries[str(name)] = {"status": str(entry)}
                continue
            entries[str(name)] = {
                "status": str(entry.get("status") or "unknown").lower(),
                "duration_ms": entry.get("duration_ms"),
                "error": (str(entry.get("error"))[:300] if entry.get("error") else None),
            }

    # Fall back to the checks map for documents that carry no collector_status block
    # (legacy uploads), so health is still derived from real evidence rather than assumed.
    checks = document.get("checks")
    if not entries and isinstance(checks, Mapping):
        for name, payload in checks.items():
            if isinstance(payload, Mapping):
                status = payload.get("status")
                entries[str(name)] = {
                    "status": (str(status).lower() if status else "reported"),
                    "duration_ms": payload.get("duration_ms"),
                    "error": None,
                }

    counts = {"completed": 0, "error": 0, "timeout": 0, "unavailable": 0, "skipped": 0, "unknown": 0}
    for entry in entries.values():
        status = str(entry.get("status") or "unknown").lower()
        bucket = next((name for name, aliases in HEALTH_BUCKETS.items() if status in aliases), "unknown")
        counts[bucket] += 1

    degraded = any(counts[key] for key in ("error", "timeout", "unavailable", "skipped"))
    return {
        "collectors": entries,
        "counts": counts,
        "total": len(entries),
        "degraded": degraded,
        "status": ("degraded" if degraded else ("complete" if entries else "unreported")),
    }


def ingest_document(
    db: Session,
    scan: Scan,
    document: Mapping[str, Any],
    *,
    device: Device | None,
    user: User | None = None,
) -> dict[str, Any]:
    """Score a document and persist controls, findings, recommendations and metrics."""
    payload = dict(document) if isinstance(document, Mapping) else {}
    criticality = criticality_for(device)
    effective = effective_for_device(db, device)

    controls = scoring.build_controls(payload, effective, criticality=criticality)
    findings = scoring.build_findings(controls)
    result = scoring.build_scan_result(controls, findings, effective, criticality=criticality)

    # Replace any previous findings for this scan (re-ingestion must be idempotent).
    for existing in list(
        db.execute(
            select(Finding).options(selectinload(Finding.recommendations)).where(Finding.scan_id == scan.id)
        ).scalars()
    ):
        db.delete(existing)
    db.flush()

    policy_map = {p.control_id: p for p in db.execute(select(Policy)).scalars()}
    control_map = {c.control_id: c for c in controls}

    for item in findings:
        control = control_map.get(item["control_id"])
        policy = policy_map.get(item["control_id"])
        finding = Finding(
            scan_id=scan.id,
            policy_id=policy.id if policy else None,
            control_id=item["control_id"],
            category=item["category"],
            title=item["title"],
            description=item["description"],
            current_value=_jsonable(item.get("current_value")),
            expected_value=_jsonable(item.get("expected_value")),
            severity=item["severity"],
            status=item["status"],
            evidence=_jsonable(item.get("evidence")),
        )
        db.add(finding)
        db.flush()

        remediation = dict(item.get("remediation") or {})
        db.add(
            Recommendation(
                finding_id=finding.id,
                what_is_wrong=remediation.get("what_is_wrong") or item["description"],
                why_it_matters=remediation.get("why_it_matters")
                or f"This weakens the {item['category']} posture of the endpoint.",
                what_should_be_done=remediation.get("what_should_be_done")
                or "Apply the recommended secure configuration and re-scan to verify.",
                verify_command=remediation.get("verify"),
                priority=item["severity"],
                remediation_type="manual",
                remediation_instruction=(
                    "Apply the change, then run a fresh assessment to confirm the control is compliant."
                ),
            )
        )
        if control is not None and control.exempted:
            finding.description = (finding.description or "") + " (exempted by policy)"
        finding.status = item["status"]

    existing_result = db.execute(select(ScanResult).where(ScanResult.scan_id == scan.id)).scalar_one_or_none()
    scan_result = existing_result or ScanResult(scan_id=scan.id)
    scan_result.security_score = result["security_score"]
    scan_result.compliance_score = result["compliance_score"]
    scan_result.assessment_coverage = result["assessment_coverage"]
    scan_result.risk_score = result["risk_score"]
    scan_result.risk_level = result["risk_level"]
    scan_result.evidence_quality = result["evidence_quality"]
    scan_result.controls = [_jsonable(c.as_dict()) for c in controls]
    scan_result.categories = result["categories"]
    assessment = dict(result["assessment"])
    assessment["collector_health"] = collector_health(payload)
    result["assessment"] = assessment
    scan_result.assessment = assessment
    scan_result.critical_count = result["critical_count"]
    scan_result.high_count = result["high_count"]
    scan_result.medium_count = result["medium_count"]
    scan_result.low_count = result["low_count"]
    scan_result.informational_count = result["informational_count"]
    scan_result.scoring_model_version = scoring.SCORING_MODEL_VERSION
    scan_result.baseline_version = effective.version()
    if existing_result is None:
        db.add(scan_result)

    scan.scoring_model_version = scoring.SCORING_MODEL_VERSION
    scan.baseline_version = effective.version()
    if device is not None:
        device.last_scan_at = scan.completed_at or utcnow()
        scan.device_id = device.id

    db.flush()
    logger.info(
        "ingested scan=%s posture=%s coverage=%s risk=%s findings=%d",
        scan.id,
        result["security_score"],
        result["assessment_coverage"],
        result["risk_score"],
        len(findings),
    )
    return {"result": result, "controls": controls, "findings": findings, "effective": effective}


def _jsonable(value: Any) -> Any:
    """Round-trip through plain JSON types so the ORM never receives a dataclass."""
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Mapping):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_jsonable(v) for v in value]
    return str(value)


#: Small collector fields that are always kept in the stored projection.
_PROJECTION_META_KEYS = ("status", "error", "evidence_metadata", "duration_ms", "source")


def project_document(document: Mapping[str, Any], effective: EffectiveSet) -> dict[str, Any]:
    """Reduce an evidence document to the control-relevant projection that is stored.

    The original scanner output can be tens of megabytes, of which a small fraction is
    read by any control. What is persisted is exactly the evidence the baseline declares
    plus collector health, which keeps the database small while remaining sufficient to
    reproduce every verdict. The full document is written to disk only when
    ``STORE_RAW_EVIDENCE`` is enabled.
    """
    checks = document.get("checks") if isinstance(document.get("checks"), Mapping) else {}

    wanted: dict[str, set[str]] = {}
    for control in effective.controls:
        names = wanted.setdefault(control.spec.collector, set())
        for path in (*control.spec.evidence_paths, *control.spec.paths):
            parts = str(path).split(".")
            if len(parts) >= 2 and parts[0] == "checks":
                names.add(parts[1].split("[*]")[0])

    projected_checks: dict[str, Any] = {}
    for collector, payload in checks.items():
        if not isinstance(payload, Mapping):
            projected_checks[collector] = payload  # preserve legacy scalars as-is
            continue
        kept: dict[str, Any] = {key: payload[key] for key in _PROJECTION_META_KEYS if key in payload}
        if collector in wanted:
            for key in wanted[collector]:
                if key in payload:
                    kept[key] = payload[key]
        else:
            kept.setdefault(
                "note", "collector payload omitted from the stored projection (no control consumes it)"
            )
        projected_checks[collector] = kept

    output: dict[str, Any] = {
        key: document[key]
        for key in (
            "schema_version",
            "format",
            "snapshot_id",
            "created_at",
            "scanner",
            "execution",
            "device",
            "collector_status",
            "integrity",
            "provenance",
            "baseline_target",
        )
        if key in document
    }
    output["checks"] = projected_checks
    output["projection"] = {
        "applied": True,
        "collectors_kept": sorted(wanted),
        "note": (
            "Only the evidence consumed by baseline controls is stored; the full "
            "document is available from the scanner output or the evidence store."
        ),
    }
    return output


def document_evidence_bytes(document: Mapping[str, Any]) -> int:
    import json as _json

    try:
        return len(_json.dumps(document, default=str, separators=(",", ":")))
    except (TypeError, ValueError):  # pragma: no cover - defensive
        return 0


def scan_summary(db: Session, scan: Scan, *, finding_count: int | None = None) -> dict[str, Any]:
    """Build the list/detail projection for one scan (never loads the document)."""
    result = db.execute(select(ScanResult).where(ScanResult.scan_id == scan.id)).scalar_one_or_none()
    device = db.get(Device, scan.device_id) if scan.device_id else None
    if finding_count is None:
        finding_count = db.query(Finding).filter(Finding.scan_id == scan.id).count()
    return summary_row(scan, result, device, int(finding_count))


def summary_row(
    scan: Scan, result: ScanResult | None, device: Device | None, finding_count: int
) -> dict[str, Any]:
    assessment = (result.assessment or {}) if result else {}
    return {
        "id": scan.id,
        "device_id": scan.device_id,
        "hostname": device.hostname if device else None,
        "status": scan.status,
        "stage": scan.stage,
        "progress": scan.progress,
        "source": scan.source,
        "started_at": scan.started_at,
        "completed_at": scan.completed_at,
        "duration_ms": scan.duration_ms,
        "security_score": result.security_score if result else None,
        "compliance_score": result.compliance_score if result else None,
        "assessment_coverage": result.assessment_coverage if result else None,
        "risk_score": result.risk_score if result else None,
        "risk_level": result.risk_level if result else None,
        "evidence_quality": result.evidence_quality if result else None,
        "critical_count": result.critical_count if result else None,
        "high_count": result.high_count if result else None,
        "medium_count": result.medium_count if result else None,
        "low_count": result.low_count if result else None,
        "informational_count": result.informational_count if result else None,
        "total_findings": finding_count,
        "controls_assessed": assessment.get("assessed_controls"),
        "controls_total": assessment.get("total_controls"),
        "scanner_version": scan.scanner_version,
        "scoring_model_version": scan.scoring_model_version,
        "baseline_version": scan.baseline_version,
        "error_message": scan.error_message,
    }
