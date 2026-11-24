"""Retention enforcement and artefact cleanup.

Every retention window in the platform is configuration, and this module is the only
place that deletes anything. It is deliberately conservative:

* **Terminal scans only.** A scan that is `queued`, `running` or in any non-terminal
  state is never expired, so retention cannot delete work in progress.
* **Dry run is the default.** `run_retention()` plans first and deletes only when
  `dry_run=False`, so an operator can see exactly what an enforcement pass would remove
  before it happens.
* **Files follow rows.** A scan's report artefacts, gzipped evidence file and quarantine
  remnants are removed with the row that owns them; nothing is removed on a filename
  guess.
* **Every pass is observable.** The result is a plain dict (counts + byte totals) and an
  enforcement pass is written to the audit chain.

Windows are settings: ``RETENTION_SCAN_DAYS``, ``RETENTION_AUDIT_DAYS``,
``RETENTION_REPORT_DAYS`` and ``UPLOAD_QUARANTINE_TTL_MINUTES``. A window of ``0`` or
less disables that class rather than deleting everything.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core import audit
from app.core.config import EVIDENCE_DIR, UPLOAD_DIR, settings
from app.db.models import Scan, User

logger = logging.getLogger("secureconfigai.maintenance")

QUARANTINE_DIR = UPLOAD_DIR / "quarantine"

#: A scan in any of these states is finished and may be expired. The legacy
#: ``error`` vocabulary is included so pre-fix rows are not retained for ever.
TERMINAL_STATUSES = ("completed", "failed", "cancelled", "error")


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _as_utc(value: datetime | None) -> datetime | None:
    """Normalise a stored timestamp so comparisons never mix naive and aware values."""
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _file_bytes(path: Path) -> int:
    try:
        return path.stat().st_size if path.is_file() else 0
    except OSError:  # pragma: no cover - unreadable path
        return 0


def _safe_unlink(path: Path) -> int:
    """Remove one file, returning the bytes reclaimed. Never raises."""
    size = _file_bytes(path)
    try:
        path.unlink(missing_ok=True)
    except OSError:  # pragma: no cover - permissions / in use
        logger.warning("could not remove retention artefact %s", path)
        return 0
    return size


@dataclass
class RetentionPlan:
    """What one retention pass would do (or did)."""

    dry_run: bool = True
    scan_days: int = 0
    report_days: int = 0
    audit_days: int = 0
    quarantine_minutes: int = 0
    scans_expired: list[str] = field(default_factory=list)
    scan_files_removed: int = 0
    scan_bytes_reclaimed: int = 0
    reports_purged: int = 0
    audit_entries_purged: int = 0
    quarantine_files_removed: int = 0
    quarantine_bytes_reclaimed: int = 0
    evidence_files_removed: int = 0
    evidence_bytes_reclaimed: int = 0
    notes: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "dry_run": self.dry_run,
            "windows": {
                "scan_days": self.scan_days,
                "report_days": self.report_days,
                "audit_days": self.audit_days,
                "quarantine_minutes": self.quarantine_minutes,
            },
            "scans_expired": len(self.scans_expired),
            "scan_ids": self.scans_expired[:50],
            "scan_files_removed": self.scan_files_removed,
            "scan_bytes_reclaimed": self.scan_bytes_reclaimed,
            "reports_purged": self.reports_purged,
            "audit_entries_purged": self.audit_entries_purged,
            "quarantine_files_removed": self.quarantine_files_removed,
            "quarantine_bytes_reclaimed": self.quarantine_bytes_reclaimed,
            "evidence_files_removed": self.evidence_files_removed,
            "evidence_bytes_reclaimed": self.evidence_bytes_reclaimed,
            "notes": list(self.notes),
        }


# --------------------------------------------------------------------------- scans
def expire_scans(
    db: Session, days: int | None = None, *, dry_run: bool = True, plan: RetentionPlan | None = None
) -> RetentionPlan:
    """Delete terminal scans older than the scan retention window.

    Deleting a scan cascades to its result, findings, recommendations, reports and AI
    reports through the ORM relationships. The artefacts those rows point at are removed
    first so no orphaned files survive the row.
    """
    plan = plan or RetentionPlan(dry_run=dry_run)
    window = settings.RETENTION_SCAN_DAYS if days is None else days
    plan.scan_days = window
    plan.dry_run = dry_run
    if window <= 0:
        plan.notes.append("scan retention disabled (window <= 0)")
        return plan

    cutoff = _utcnow() - timedelta(days=window)
    candidates: list[Scan] = []
    for scan in db.execute(select(Scan).where(Scan.status.in_(TERMINAL_STATUSES))).scalars():
        finished = _as_utc(scan.completed_at) or _as_utc(scan.started_at)
        if finished is not None and finished < cutoff:
            candidates.append(scan)

    for scan in candidates:
        paths: list[Path] = []
        if scan.uploaded_file_path:
            paths.append(Path(scan.uploaded_file_path))
        for report in scan.reports:
            paths.append(Path(report.file_path))
        for path in paths:
            plan.scan_bytes_reclaimed += _file_bytes(path)
            if not dry_run:
                plan.scan_files_removed += 1 if _safe_unlink(path) or not path.exists() else 0
        plan.scans_expired.append(str(scan.id))
        if not dry_run:
            db.delete(scan)

    if not dry_run and candidates:
        db.commit()
        logger.warning("expired %d scan(s) older than %d day(s)", len(candidates), window)
    return plan


# --------------------------------------------------------------------------- reports
def purge_reports(
    db: Session, days: int | None = None, *, dry_run: bool = True, plan: RetentionPlan | None = None
) -> RetentionPlan:
    """Remove generated report artefacts (rows + files) past the report window."""
    from app.services.report_service import purge_old_reports

    plan = plan or RetentionPlan(dry_run=dry_run)
    window = settings.RETENTION_REPORT_DAYS if days is None else days
    plan.report_days = window
    plan.dry_run = dry_run
    if window <= 0:
        plan.notes.append("report retention disabled (window <= 0)")
        return plan
    if dry_run:
        from app.db.models import Report

        cutoff = _utcnow() - timedelta(days=window)
        stale = list(db.execute(select(Report).where(Report.generated_at < cutoff)).scalars())
        plan.reports_purged = len(stale)
        for record in stale:
            plan.scan_bytes_reclaimed += _file_bytes(Path(record.file_path))
        return plan
    plan.reports_purged = purge_old_reports(db, window)
    return plan


# --------------------------------------------------------------------------- audit
def purge_audit(
    db: Session, days: int | None = None, *, dry_run: bool = True, plan: RetentionPlan | None = None
) -> RetentionPlan:
    """Apply the audit retention window. Re-anchors the hash chain (see audit.py)."""
    plan = plan or RetentionPlan(dry_run=dry_run)
    window = settings.RETENTION_AUDIT_DAYS if days is None else days
    plan.audit_days = window
    plan.dry_run = dry_run
    if window <= 0:
        plan.notes.append("audit retention disabled (window <= 0)")
        return plan
    if dry_run:
        from app.db.models import AuditLog

        cutoff = _utcnow() - timedelta(days=window)
        plan.audit_entries_purged = db.query(AuditLog).filter(AuditLog.created_at < cutoff).count()
        return plan
    plan.audit_entries_purged = audit.purge_older_than(db, window)
    return plan


# --------------------------------------------------------------------------- files
def purge_quarantine(
    minutes: int | None = None, *, dry_run: bool = True, plan: RetentionPlan | None = None
) -> RetentionPlan:
    """Delete quarantine files left behind by interrupted or rejected uploads."""
    plan = plan or RetentionPlan(dry_run=dry_run)
    window = settings.UPLOAD_QUARANTINE_TTL_MINUTES if minutes is None else minutes
    plan.quarantine_minutes = window
    plan.dry_run = dry_run
    if window <= 0:
        plan.notes.append("quarantine cleanup disabled (window <= 0)")
        return plan
    if not QUARANTINE_DIR.exists():
        return plan
    cutoff = _utcnow() - timedelta(minutes=window)
    for path in sorted(QUARANTINE_DIR.iterdir()):
        if not path.is_file():
            continue
        try:
            modified = datetime.fromtimestamp(path.stat().st_mtime, tz=UTC)
        except OSError:  # pragma: no cover
            continue
        if modified >= cutoff:
            continue
        plan.quarantine_bytes_reclaimed += _file_bytes(path)
        if not dry_run:
            plan.quarantine_files_removed += 1
            _safe_unlink(path)
        else:
            plan.quarantine_files_removed += 1
    return plan


def purge_orphan_evidence(
    db: Session, *, dry_run: bool = True, plan: RetentionPlan | None = None
) -> RetentionPlan:
    """Remove stored evidence files whose scan row no longer exists."""
    plan = plan or RetentionPlan(dry_run=dry_run)
    plan.dry_run = dry_run
    if not EVIDENCE_DIR.exists():
        return plan
    known = {
        str(path)
        for path in db.execute(
            select(Scan.uploaded_file_path).where(Scan.uploaded_file_path.is_not(None))
        ).scalars()
        if path
    }
    for path in sorted(EVIDENCE_DIR.glob("*")):
        if not path.is_file() or str(path) in known:
            continue
        plan.evidence_bytes_reclaimed += _file_bytes(path)
        plan.evidence_files_removed += 1
        if not dry_run:
            _safe_unlink(path)
    return plan


# --------------------------------------------------------------------------- orchestration
def run_retention(
    db: Session, *, dry_run: bool = True, actor: User | None = None, request: Any | None = None
) -> dict[str, Any]:
    """Run one full retention pass and return a serialisable report.

    Order matters: scans first (their artefacts go with them), then orphan evidence,
    then reports, then the audit trail — so the purge itself is recorded after the
    rest of the work is known.
    """
    plan = RetentionPlan(dry_run=dry_run)
    expire_scans(db, dry_run=dry_run, plan=plan)
    purge_orphan_evidence(db, dry_run=dry_run, plan=plan)
    purge_reports(db, dry_run=dry_run, plan=plan)
    purge_quarantine(dry_run=dry_run, plan=plan)
    purge_audit(db, dry_run=dry_run, plan=plan)

    report = plan.as_dict()
    if not dry_run:
        audit.record(
            db,
            "admin.retention_purge",
            actor=actor,
            entity_type="retention",
            request=request,
            details={k: v for k, v in report.items() if k not in {"scan_ids"}},
        )
    return report
