"""Asynchronous scan lifecycle: queued → running → completed / failed / cancelled.

The real Windows scanner is replaced by a tiny Python stub so the *queue mechanics* are
what is under test: the 202 response, the worker, progress mirroring, terminal states,
cancellation and interrupted-run recovery. Nothing here spawns PowerShell.
"""

from __future__ import annotations

import json
import sys
import time
from datetime import timedelta

import pytest

from app.core.timeutil import utcnow
from app.db.models import AuditLog, Finding, Scan, ScanResult
from app.services.jobs import ScanJobManager, manager

from .conftest import perfect_document

STUB = (
    "import json,pathlib,sys,time\n"
    "out=pathlib.Path(sys.argv[1])\n"
    "mode=sys.argv[2]\n"
    "if mode=='hang':\n"
    "    print(json.dumps({'stage':'Collecting','percent':10}),flush=True)\n"
    "    time.sleep(30)\n"
    "elif mode=='fail':\n"
    "    sys.stderr.write('collector exploded')\n"
    "    sys.exit(3)\n"
    "else:\n"
    "    print(json.dumps({'stage':'Collecting','percent':40}),flush=True)\n"
    "    doc=json.loads(sys.argv[3])\n"
    "    (out/'scan_result.json').write_text(json.dumps(doc),encoding='utf-8')\n"
    "    print(json.dumps({'event':'done','stage':'Analyzing','percent':100}),flush=True)\n"
)


def _stub_command(document, mode="ok"):
    payload = json.dumps(document)

    def _command(self, output_dir, inventory, collectors):  # noqa: ARG001
        return [sys.executable, "-c", STUB, str(output_dir), mode, payload]

    return _command


@pytest.fixture
def scanner_ok(monkeypatch):
    monkeypatch.setattr(ScanJobManager, "_command", _stub_command(perfect_document()))


@pytest.fixture
def scanner_fails(monkeypatch):
    monkeypatch.setattr(ScanJobManager, "_command", _stub_command({}, mode="fail"))


@pytest.fixture
def scanner_hangs(monkeypatch):
    monkeypatch.setattr(ScanJobManager, "_command", _stub_command({}, mode="hang"))


@pytest.fixture(autouse=True)
def drain_worker_pool():
    """Each test starts with an idle pool, so one test cannot starve the next."""
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline and manager.active_count:
        time.sleep(0.1)
    yield
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline and manager.active_count:
        time.sleep(0.1)


def _queue(client, headers) -> str:
    response = client.post("/api/v1/scans/start", headers=headers, json={})
    assert response.status_code == 202, response.text
    return response.json()["scan_id"]


def _wait(client, headers, scan_id, timeout=25.0) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        response = client.get(f"/api/v1/scans/{scan_id}/status", headers=headers)
        assert response.status_code == 200, response.text
        body = response.json()
        if body["status"] in {"completed", "failed", "cancelled"}:
            return body
        time.sleep(0.15)
    raise AssertionError(f"scan {scan_id} did not reach a terminal state in {timeout}s")


# --------------------------------------------------------------------------- happy path
def test_scan_runs_to_completion_and_persists_a_result(client, db, user, scanner_ok):
    scan_id = _queue(client, user["headers"])
    status = _wait(client, user["headers"], scan_id)
    assert status["status"] == "completed", status
    assert status["progress"] == 100
    assert status["duration_ms"] is not None and status["duration_ms"] >= 0

    results = client.get(f"/api/v1/scans/{scan_id}/results", headers=user["headers"])
    assert results.status_code == 200, results.text
    body = results.json()
    assert body["results"]["security_score"] == 100
    assert body["results"]["assessment_coverage"] == 100
    assert body["results"]["scoring_model_current"] is True
    assert len(body["results"]["controls"]) == 28

    scan = db.get(Scan, _as_uuid(scan_id))
    db.refresh(scan)
    assert scan.scoring_model_version and scan.baseline_version and scan.scanner_version


def test_scan_records_collector_health(client, db, user, scanner_ok):
    scan_id = _queue(client, user["headers"])
    _wait(client, user["headers"], scan_id)

    body = client.get(f"/api/v1/scans/{scan_id}/results", headers=user["headers"]).json()
    health = body["results"]["collector_health"]
    assert health["total"] == len(perfect_document()["checks"])
    assert health["status"] == "complete"
    assert health["counts"]["completed"] == health["total"]
    assert body["results"]["evidence_quality_explained"].endswith("all collectors reported.")


def test_progress_is_mirrored_from_the_scanner(client, db, user, scanner_ok):
    scan_id = _queue(client, user["headers"])
    _wait(client, user["headers"], scan_id)
    scan = db.get(Scan, _as_uuid(scan_id))
    db.refresh(scan)
    # The worker writes the stage from the scanner's progress stream.
    assert scan.stage in {"Completed", "Completed with degraded evidence", "Analyzing"}


def test_completion_and_start_are_audited(client, db, user, scanner_ok):
    scan_id = _queue(client, user["headers"])
    _wait(client, user["headers"], scan_id)
    actions = [row.action for row in db.query(AuditLog).order_by(AuditLog.seq).all()]
    assert "scan.start" in actions
    assert "scan.complete" in actions


# --------------------------------------------------------------------------- failure
def test_worker_failure_marks_the_scan_failed(client, db, user, scanner_fails):
    scan_id = _queue(client, user["headers"])
    status = _wait(client, user["headers"], scan_id)
    assert status["status"] == "failed", status
    assert "exited with code 3" in (status["error_message"] or "")

    actions = [row.action for row in db.query(AuditLog).all()]
    assert "scan.fail" in actions


# --------------------------------------------------------------------------- cancellation
def test_cancellation_terminates_the_worker_and_wins_the_race(client, db, user, scanner_hangs):
    scan_id = _queue(client, user["headers"])
    # Wait until the worker is actually running so cancel has something to terminate.
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        scan = db.get(Scan, _as_uuid(scan_id))
        db.refresh(scan)
        if scan.status == "running":
            break
        time.sleep(0.1)

    response = client.post(f"/api/v1/scans/{scan_id}/cancel", headers=user["headers"])
    assert response.status_code == 202, response.text
    assert response.json()["status"] == "cancelled"

    time.sleep(0.5)
    scan = db.get(Scan, _as_uuid(scan_id))
    db.refresh(scan)
    # The worker must not overwrite the operator's cancellation with a failure.
    assert scan.status == "cancelled"
    assert "cancelled" in (scan.stage or "").lower() or scan.error_message


def test_cancelling_a_finished_scan_is_a_conflict(client, user, scanner_ok):
    scan_id = _queue(client, user["headers"])
    _wait(client, user["headers"], scan_id)
    response = client.post(f"/api/v1/scans/{scan_id}/cancel", headers=user["headers"])
    assert response.status_code == 409


# --------------------------------------------------------------------------- recovery
def test_interrupted_scans_are_recovered_at_startup(db):
    """A scan abandoned by a dead process must never stay "running" for ever."""
    from app.db.models import User

    owner = db.query(User).first()
    if owner is None:
        owner = User(email="recovery@example.com", password_hash="x", role="user")
        db.add(owner)
        db.commit()
        db.refresh(owner)

    stale = Scan(
        user_id=owner.id,
        status="running",
        stage="Starting collector",
        started_at=utcnow() - timedelta(hours=3),
        heartbeat_at=None,
    )
    fresh = Scan(
        user_id=owner.id,
        status="running",
        stage="Starting collector",
        started_at=utcnow(),
        heartbeat_at=utcnow(),
    )
    db.add_all([stale, fresh])
    db.commit()

    recovered = manager.recover_stale(db)
    assert recovered == 1

    db.refresh(stale)
    db.refresh(fresh)
    assert stale.status == "failed"
    assert stale.completed_at is not None
    assert "stopped" in (stale.error_message or "")
    assert fresh.status == "running"


# --------------------------------------------------------------------------- idempotency
def test_reassessment_does_not_duplicate_findings(client, db, user):
    document = perfect_document("IDEMPOTENT-PC")
    from .conftest import snapshot_from

    uploaded = client.post(
        "/api/v1/scans/upload",
        headers=user["headers"],
        files={
            "file": (
                "configuration_snapshot.json",
                json.dumps(snapshot_from(document)).encode(),
                "application/json",
            )
        },
    )
    assert uploaded.status_code == 200, uploaded.text
    scan_id = uploaded.json()["scan_id"]

    first = client.post(f"/api/v1/scans/{scan_id}/reassess", headers=user["headers"])
    assert first.status_code == 200, first.text
    second = client.post(f"/api/v1/scans/{scan_id}/reassess", headers=user["headers"])
    assert second.status_code == 200, second.text

    db.expire_all()
    assert db.query(Finding).filter(Finding.scan_id == _as_uuid(scan_id)).count() == 0
    assert db.query(ScanResult).filter(ScanResult.scan_id == _as_uuid(scan_id)).count() == 1


def _as_uuid(value: str):
    import uuid

    return uuid.UUID(value)
