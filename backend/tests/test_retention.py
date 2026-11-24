"""Retention enforcement: what expires, what must never expire, and what is audited.

Retention is the one place the platform deletes data, so it is tested in both directions:
a dry run must change nothing, an enforcement pass must remove exactly the expired
objects and their files, and work in progress must survive any window.
"""

from __future__ import annotations

import os
import time
from datetime import timedelta

import pytest

from app.core.config import EVIDENCE_DIR, settings
from app.core.timeutil import utcnow
from app.db.models import AuditLog, Report, Scan, User
from app.services import maintenance


@pytest.fixture
def owner(db) -> User:
    user = User(email="retention@example.com", password_hash="x", role="user")
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def _old_scan(db, owner, *, days: int, status: str = "completed") -> Scan:
    finished = utcnow() - timedelta(days=days)
    scan = Scan(
        user_id=owner.id,
        status=status,
        stage="Completed",
        started_at=finished,
        completed_at=finished,
        heartbeat_at=finished,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


def _write(path, payload: bytes = b"x") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)


# --------------------------------------------------------------------------- scans
def test_dry_run_reports_but_deletes_nothing(db, owner):
    scan = _old_scan(db, owner, days=settings.RETENTION_SCAN_DAYS + 30)
    report_path = settings.REPORT_CACHE_ENABLED and None  # noqa: F841 - readability
    from app.core.config import REPORT_DIR

    artefact = REPORT_DIR / f"{scan.id}.html"
    _write(artefact, b"<html></html>")
    db.add(Report(scan_id=scan.id, format="html", file_path=str(artefact)))
    db.commit()

    plan = maintenance.run_retention(db, dry_run=True)
    assert plan["dry_run"] is True
    assert plan["scans_expired"] == 1
    assert db.get(Scan, scan.id) is not None
    assert artefact.exists()
    assert db.query(Report).filter(Report.scan_id == scan.id).count() == 1


def test_enforcement_removes_expired_scans_and_their_files(db, owner):
    from app.core.config import REPORT_DIR

    scan = _old_scan(db, owner, days=settings.RETENTION_SCAN_DAYS + 30)
    artefact = REPORT_DIR / f"{scan.id}.html"
    evidence = EVIDENCE_DIR / f"{scan.id}.json.gz"
    _write(artefact, b"<html></html>")
    _write(evidence, b"evidence")
    db.add(Report(scan_id=scan.id, format="html", file_path=str(artefact)))
    scan.uploaded_file_path = str(evidence)
    db.commit()

    plan = maintenance.run_retention(db, dry_run=False)

    assert plan["scans_expired"] == 1
    assert db.get(Scan, scan.id) is None
    assert not artefact.exists()
    assert not evidence.exists()
    assert db.query(Report).filter(Report.scan_id == scan.id).count() == 0

    row = db.query(AuditLog).filter(AuditLog.action == "admin.retention_purge").one()
    assert row.details["scans_expired"] == 1
    assert row.details["dry_run"] is False


def test_work_in_progress_is_never_expired(db, owner):
    for status in ("queued", "running"):
        _old_scan(db, owner, days=settings.RETENTION_SCAN_DAYS + 400, status=status)

    plan = maintenance.run_retention(db, dry_run=False)
    assert plan["scans_expired"] == 0
    assert db.query(Scan).filter(Scan.status.in_(["queued", "running"])).count() == 2


def test_recent_terminal_scans_are_retained(db, owner):
    _old_scan(db, owner, days=1)
    plan = maintenance.run_retention(db, dry_run=False)
    assert plan["scans_expired"] == 0
    assert db.query(Scan).count() == 1


def test_a_disabled_window_deletes_nothing(db, owner, monkeypatch):
    monkeypatch.setattr(settings, "RETENTION_SCAN_DAYS", 0)
    _old_scan(db, owner, days=5000)
    plan = maintenance.run_retention(db, dry_run=False)
    assert plan["scans_expired"] == 0
    assert "scan retention disabled" in " ".join(plan["notes"])


# --------------------------------------------------------------------------- quarantine
def test_quarantine_files_past_their_ttl_are_removed():
    directory = maintenance.QUARANTINE_DIR
    directory.mkdir(parents=True, exist_ok=True)
    stale = directory / "stale_upload.json"
    fresh = directory / "fresh_upload.json"
    _write(stale, b"{}")
    _write(fresh, b"{}")
    old = time.time() - (settings.UPLOAD_QUARANTINE_TTL_MINUTES + 30) * 60
    os.utime(stale, (old, old))

    try:
        plan = maintenance.purge_quarantine(dry_run=False)
        assert plan.quarantine_files_removed >= 1
        assert not stale.exists()
        assert fresh.exists()
    finally:
        stale.unlink(missing_ok=True)
        fresh.unlink(missing_ok=True)


# --------------------------------------------------------------------------- audit
def test_audit_retention_purges_old_entries_and_reanchors_the_chain(db):
    from app.core import audit

    for index in range(3):
        audit.record(db, "auth.login.success", details={"n": index})

    old = db.query(AuditLog).order_by(AuditLog.seq.asc()).first()
    old.created_at = utcnow() - timedelta(days=settings.RETENTION_AUDIT_DAYS + 10)
    db.commit()

    preview = maintenance.purge_audit(db, dry_run=True)
    assert preview.audit_entries_purged == 1
    assert db.query(AuditLog).count() == 3

    applied = maintenance.purge_audit(db, dry_run=False)
    assert applied.audit_entries_purged == 1
    assert db.query(AuditLog).count() >= 2
    # A purge must leave a verifiable chain behind, not a broken one.
    assert audit.verify_chain(db)["chain_valid"] is True


# --------------------------------------------------------------------------- evidence
def test_orphan_evidence_files_are_removed(db, owner):
    scan = _old_scan(db, owner, days=1)
    orphan = EVIDENCE_DIR / "00000000-0000-0000-0000-000000000000.json.gz"
    _write(orphan, b"orphan")
    kept = EVIDENCE_DIR / f"{scan.id}.json.gz"
    _write(kept, b"kept")
    scan.uploaded_file_path = str(kept)
    db.commit()

    try:
        plan = maintenance.purge_orphan_evidence(db, dry_run=False)
        assert plan.evidence_files_removed >= 1
        assert not orphan.exists()
        assert kept.exists()
    finally:
        orphan.unlink(missing_ok=True)
        kept.unlink(missing_ok=True)


# --------------------------------------------------------------------------- endpoint
def test_retention_endpoint_defaults_to_a_dry_run(client, db, admin):
    response = client.post("/api/v1/admin/maintenance/retention", headers=admin["headers"])
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["dry_run"] is True
    assert body["actor"] == admin["email"]
    # A dry run must not be audited as an executed purge.
    assert db.query(AuditLog).filter(AuditLog.action == "admin.retention_purge").count() == 0


def test_retention_endpoint_enforces_when_asked(client, db, admin):
    response = client.post("/api/v1/admin/maintenance/retention?dry_run=false", headers=admin["headers"])
    assert response.status_code == 200, response.text
    assert response.json()["dry_run"] is False
    assert db.query(AuditLog).filter(AuditLog.action == "admin.retention_purge").count() == 1


def test_retention_endpoint_is_admin_only(client, user):
    assert client.post("/api/v1/admin/maintenance/retention", headers=user["headers"]).status_code == 403


def test_retention_windows_are_published_in_the_security_policy(client, admin):
    body = client.get("/api/v1/admin/security-policy", headers=admin["headers"]).json()
    retention = body["retention"]
    assert retention["scan_days"] == settings.RETENTION_SCAN_DAYS
    assert retention["audit_days"] == settings.RETENTION_AUDIT_DAYS
    assert retention["report_days"] == settings.RETENTION_REPORT_DAYS
