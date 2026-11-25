"""Assessment ingestion: evidence document -> controls -> findings -> stored result.

This module is the single path from "a scanner produced a document" to "the database
holds an assessment". The live job runner and the snapshot upload endpoint both call it,
so identical evidence always produces an identical result.

Exemptions are applied by ``resolve_effective``, which ignores lapsed ones using the
current time. This module never re-filters them, so the expiry rule lives in one place.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

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

DEFAULT_CRITICALITY = 3

#: Collector fields that are always kept in the stored projection.
PROJECTION_META_KEYS = ("status", "error", "evidence_metadata", "duration_ms", "source")

#: Top-level document fields that are kept in the stored projection.
PROJECTION_DOCUMENT_KEYS = (
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

HEALTH_BUCKETS = {
    "completed": ("completed", "success", "ok"),
    "error": ("error",),
    "timeout": ("timeout",),
    "unavailable": ("unavailable",),
    "skipped": ("skipped",),
}
_STATUS_TO_BUCKET = {alias: bucket for bucket, aliases in HEALTH_BUCKETS.items() for alias in aliases}
DEGRADED_BUCKETS = ("error", "timeout", "unavailable", "skipped")


def utcnow() -> datetime:
    return datetime.now(UTC)


# --------------------------------------------------------------------------- resolution
def effective_for_device(db: Session, device: Device | None) -> EffectiveSet:
    """Resolve baseline, global overrides and this device's exemptions.

    Lapsed exemptions are excluded inside ``resolve_effective`` using ``now``.
    """
    baseline = load_baseline()
    overrides = list(db.execute(select(Policy)).scalars())
    exemptions: list[DeviceExemption] = []
    if device is not None:
        exemptions = list(
            db.execute(select(DeviceExemption).where(DeviceExemption.device_id == device.id)).scalars()
        )
    return resolve_effective(baseline, overrides, exemptions, now=utcnow())


def criticality_for(device: Device | None, default: int = DEFAULT_CRITICALITY) -> int:
    value = getattr(device, "criticality", None) if device is not None else None
    return int(value) if value is not None else default


# --------------------------------------------------------------------------- health
def collector_health(document: Mapping[str, Any]) -> dict[str, Any]:
    """Summarise per-collector execution, so a degraded scan cannot present as a clean one.

    The scanner reports a status for each collector. Without this projection, a run with
    two timeouts looks the same as a complete run.
    """
    entries: dict[str, dict[str, Any]] = {}
    reported = document.get("collector_status")
    if isinstance(reported, Mapping):
        for name, entry in reported.items():
            if not isinstance(entry, Mapping):
                entries[str(name)] = {"status": str(entry).lower()}
                continue
            entries[str(name)] = {
                "status": str(entry.get("status") or "unknown").lower(),
                "duration_ms": entry.get("duration_ms"),
                "error": str(entry["error"])[:300] if entry.get("error") else None,
            }

    # Legacy documents have no collector_status block. Derive health from the checks map
    # so the result still reflects real evidence and is not assumed.
    checks = document.get("checks")
    if not entries and isinstance(checks, Mapping):
        for name, payload in checks.items():
            if isinstance(payload, Mapping):
                status = payload.get("status")
                entries[str(name)] = {
                    "status": str(status).lower() if status else "reported",
                    "duration_ms": payload.get("duration_ms"),
                    "error": None,
                }

    counts = {bucket: 0 for bucket in (*HEALTH_BUCKETS, "unknown")}
    for entry in entries.values():
        counts[_STATUS_TO_BUCKET.get(str(entry.get("status") or "unknown").lower(), "unknown")] += 1

    degraded = any(counts[bucket] for bucket in DEGRADED_BUCKETS)
    return {
        "collectors": entries,
        "counts": counts,
        "total": len(entries),
        "degraded": degraded,
        "status": "degraded" if degraded else ("complete" if entries else "unreported"),
    }


# --------------------------------------------------------------------------- persistence helpers
def _jsonable(value: Any) -> Any:
    """Round-trip through plain JSON types so the ORM never receives a dataclass or set."""
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Mapping):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_jsonable(v) for v in value]
    return str(value)


def _recommendation_fields(item: Mapping[str, Any]) -> dict[str, str | None]:
    """Remediation text, with fallbacks for controls whose pack entry is incomplete."""
    remediation = dict(item.get("remediation") or {})
    return {
        "what_is_wrong": remediation.get("what_is_wrong") or item["description"],
        "why_it_matters": remediation.get("why_it_matters")
        or f"This weakens the {item['category']} posture of the endpoint.",
        "what_should_be_done": remediation.get("what_should_be_done")
        or "Apply the recommended secure configuration and re-scan to verify.",
        "verify_command": remediation.get("verify"),
    }


def _clear_previous_findings(db: Session, scan: Scan) -> None:
    """Remove findings and their recommendations from an earlier ingestion of this scan.

    Bulk deletes run explicitly, so the result does not depend on ORM cascade settings.
    """
    finding_ids = select(Finding.id).where(Finding.scan_id == scan.id)
    db.execute(delete(Recommendation).where(Recommendation.finding_id.in_(finding_ids)).execution_options(synchronize_session=False))
    db.execute(delete(Finding).where(Finding.scan_id == scan.id).execution_options(synchronize_session=False))
    db.flush()


# --------------------------------------------------------------------------- ingestion
def ingest_document(
    db: Session,
    scan: Scan,
    document: Mapping[str, Any],
    *,
    device: Device | None,
    user: User | None = None,
) -> dict[str, Any]:
    """Score a document and persist its controls, findings, recommendations and metrics.

    Re-ingesting the same scan replaces its findings, so the call is idempotent.
    """
    payload = dict(document) if isinstance(document, Mapping) else {}
    criticality = criticality_for(device)
    effective = effective_for_device(db, device)

    controls = scoring.build_controls(payload, effective, criticality=criticality)
    findings = scoring.build_findings(controls)
    result = scoring.build_scan_result(controls, findings, effective, criticality=criticality)

    _clear_previous_findings(db, scan)

    policy_ids = {p.control_id: p.id for p in db.execute(select(Policy)).scalars()}
    control_map = {c.control_id: c for c in controls}

    for item in findings:
        control = control_map.get(item["control_id"])
        evidence = _jsonable(item.get("evidence")) or {}
        if control is not None and control.exempted:
            # Keep the accepted deviation visible and attributable, rather than
            # appending text to the description.
            evidence = {
                **(evidence if isinstance(evidence, dict) else {"value": evidence}),
                "exemption": {
                    "reason": control.exemption_reason,
                    "expires_at": control.exemption_expires_at.isoformat()
                    if control.exemption_expires_at
                    else None,
                },
            }

        finding = Finding(
            scan_id=scan.id,
            policy_id=policy_ids.get(item["control_id"]),
            control_id=item["control_id"],
            category=item["category"],
            title=item["title"],
            description=item["description"],
            current_value=_jsonable(item.get("current_value")),
            expected_value=_jsonable(item.get("expected_value")),
            severity=item["severity"],
            status=item["status"],
            evidence=evidence,
        )
        db.add(finding)
        db.flush()

        fields = _recommendation_fields(item)
        db.add(
            Recommendation(
                finding_id=finding.id,
                what_is_wrong=fields["what_is_wrong"],
                why_it_matters=fields["why_it_matters"],
                what_should_be_done=fields["what_should_be_done"],
                verify_command=fields["verify_command"],
                priority=item["severity"],
                remediation_type="manual",
                remediation_instruction=(
                    "Apply the change, then run a fresh assessment to confirm the control is compliant."
                ),
            )
        )

    existing = db.execute(select(ScanResult).where(ScanResult.scan_id == scan.id)).scalar_one_or_none()
    scan_result = existing or ScanResult(scan_id=scan.id)
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
    scan.baseline_version = effective.version()
    if existing is None:
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


# --------------------------------------------------------------------------- projection
def project_document(document: Mapping[str, Any], effective: EffectiveSet) -> dict[str, Any]:
    """Reduce an evidence document to the control-relevant projection that is stored.

    Only the evidence that baseline controls declare is kept, plus collector health and
    provenance. That is enough to reproduce every verdict. The full document is written
    to disk only when raw evidence storage is enabled.
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
            projected_checks[collector] = payload  # legacy scalars are kept as they are
            continue
        kept: dict[str, Any] = {key: payload[key] for key in PROJECTION_META_KEYS if key in payload}
        if collector in wanted:
            for key in wanted[collector]:
                if key in payload:
                    kept[key] = payload[key]
        else:
            kept["note"] = "collector payload omitted from the stored projection (no control consumes it)"
        projected_checks[collector] = kept

    output: dict[str, Any] = {key: document[key] for key in PROJECTION_DOCUMENT_KEYS if key in document}
    output["checks"] = projected_checks
    output["projection"] = {
        "applied": True,
        "collectors_kept": sorted(wanted),
        "note": (
            "Only the evidence consumed by baseline controls is stored. "
            "The full document is available from the scanner output or the evidence store."
        ),
    }
    return output


def document_evidence_bytes(document: Mapping[str, Any]) -> int:
    try:
        return len(json.dumps(document, default=str, separators=(",", ":")))
    except (TypeError, ValueError):  # pragma: no cover - defensive
        return 0


# --------------------------------------------------------------------------- summaries
def scan_summary(db: Session, scan: Scan, *, finding_count: int | None = None) -> dict[str, Any]:
    """Build the list and detail projection for one scan. Never loads the evidence document."""
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