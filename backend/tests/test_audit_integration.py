"""Proof that real operations write audit rows — and that the chain detects tampering.

The research report's F-10 finding was that the audit table, model, endpoint and UI all
existed while nothing ever wrote a row. These tests are the regression guard: they
perform the operations through the HTTP API and then read the chain back.
"""

from __future__ import annotations

import json

import pytest

from app.core import audit
from app.db.models import AuditLog, User
from app.services.jobs import manager

from .conftest import (
    login,
    perfect_document,
    register,
    snapshot_from,
)


@pytest.fixture(autouse=True)
def no_real_scans(monkeypatch):
    """Queueing must be exercised without spawning the Windows scanner."""
    monkeypatch.setattr(manager, "submit", lambda scan_id: None)


def _actions(db) -> list[str]:
    db.expire_all()
    return [row.action for row in db.query(AuditLog).order_by(AuditLog.seq.asc()).all()]


def _upload(client, headers, document):
    payload = snapshot_from(document)
    return client.post(
        "/api/v1/scans/upload",
        headers=headers,
        files={
            "file": ("configuration_snapshot.json", json.dumps(payload).encode("utf-8"), "application/json")
        },
    )


# --------------------------------------------------------------------------- auth
def test_registration_and_sign_in_are_audited(client, db):
    email, password = register(client)
    login(client, email, password)
    client.post("/api/v1/auth/login", json={"email": email, "password": "WrongPassword123"})

    actions = _actions(db)
    assert "auth.register" in actions
    assert "auth.login.success" in actions
    assert "auth.login.failure" in actions


def test_successful_login_row_carries_actor_and_request_metadata(client, db):
    email, password = register(client)
    response = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200

    row = db.query(AuditLog).filter(AuditLog.action == "auth.login.success").one()
    assert row.user_id is not None
    assert row.outcome == "success"
    assert row.request_id
    assert row.prev_hash == audit.GENESIS_HASH or len(row.prev_hash) == 64
    assert len(row.entry_hash) == 64


def test_refresh_and_logout_are_audited(client, db, user):
    client.post("/api/v1/auth/refresh", json={"refresh_token": user["tokens"]["refresh_token"]})
    client.post(
        "/api/v1/auth/logout",
        headers=user["headers"],
        json={"refresh_token": user["tokens"]["refresh_token"]},
    )

    actions = _actions(db)
    assert "auth.refresh" in actions
    assert "auth.logout" in actions


# --------------------------------------------------------------------------- admin
def test_role_and_status_changes_are_audited(client, db, admin):
    email, _ = register(client, prefix="target")
    target = db.query(User).filter(User.email == email).one()

    assert (
        client.patch(
            f"/api/v1/admin/users/{target.id}/role", headers=admin["headers"], json={"role": "admin"}
        ).status_code
        == 200
    )
    assert (
        client.patch(
            f"/api/v1/admin/users/{target.id}/status", headers=admin["headers"], json={"is_active": False}
        ).status_code
        == 200
    )

    actions = _actions(db)
    assert "user.role_change" in actions
    assert "user.status_change" in actions


# --------------------------------------------------------------------------- policies
def test_policy_lifecycle_is_audited_and_disabled_policies_stay_visible(client, db, admin):
    created = client.post(
        "/api/v1/policies",
        headers=admin["headers"],
        json={"control_id": "FW-001", "name": "Paused firewall", "weight": 12, "severity": "high"},
    )
    assert created.status_code == 201, created.text
    policy_id = created.json()["id"]

    assert client.patch(f"/api/v1/policies/{policy_id}/toggle", headers=admin["headers"]).status_code == 200

    # The toggle bug: a disabled override must still be listed so it can be re-enabled.
    listed = client.get("/api/v1/policies", headers=admin["headers"])
    assert listed.status_code == 200
    assert [item["id"] for item in listed.json()["items"]] == [policy_id]
    assert listed.json()["items"][0]["is_enabled"] is False

    assert client.delete(f"/api/v1/policies/{policy_id}", headers=admin["headers"]).status_code == 204

    actions = _actions(db)
    assert "policy.create" in actions
    assert "policy.toggle" in actions
    assert "policy.delete" in actions


# --------------------------------------------------------------------------- devices
def test_device_registration_and_deletion_are_audited(client, db, user):
    created = client.post(
        "/api/v1/devices/register", headers=user["headers"], json={"hostname": "AUDIT-PC", "criticality": 4}
    )
    assert created.status_code == 201, created.text
    device_id = created.json()["id"]

    assert client.delete(f"/api/v1/devices/{device_id}", headers=user["headers"]).status_code == 204

    actions = _actions(db)
    assert "device.create" in actions
    assert "device.delete" in actions


# --------------------------------------------------------------------------- scans
def test_scan_queueing_is_audited_and_returns_202(client, db, user):
    response = client.post("/api/v1/scans/start", headers=user["headers"], json={})
    assert response.status_code == 202, response.text
    body = response.json()
    assert body["status"] == "queued"

    row = db.query(AuditLog).filter(AuditLog.action == "scan.start").one()
    assert row.entity_type == "scan"
    assert row.entity_id == body["scan_id"]


def test_upload_and_rejection_are_both_audited(client, db, user):
    ok = _upload(client, user["headers"], perfect_document("AUDIT-HOST"))
    assert ok.status_code == 200, ok.text
    assert "scan.upload" in _actions(db)

    rejected = client.post(
        "/api/v1/scans/upload",
        headers=user["headers"],
        files={"file": ("evidence.json", b"not json", "application/json")},
    )
    assert rejected.status_code == 400

    row = db.query(AuditLog).filter(AuditLog.action == "scan.upload.rejected").one()
    assert row.outcome == "failure"
    assert row.details["filename"] == "evidence.json"


def test_ai_report_generation_is_audited_without_a_provider(client, db, user):
    uploaded = _upload(client, user["headers"], perfect_document("AI-HOST"))
    scan_id = uploaded.json()["scan_id"]

    response = client.post(f"/api/v1/ai/report/{scan_id}", headers=user["headers"])
    assert response.status_code == 200, response.text
    assert response.json()["model_used"] == "local-rule-engine"

    assert "ai.report" in _actions(db)


# --------------------------------------------------------------------------- chain
def test_chain_verifies_and_detects_tampering(client, db, admin):
    email, password = register(client)
    login(client, email, password)

    verified = client.get("/api/v1/admin/audit-logs/verify", headers=admin["headers"])
    assert verified.status_code == 200
    assert verified.json()["chain_valid"] is True

    # Edit one row behind the application's back: the chain must break.
    row = db.query(AuditLog).filter(AuditLog.action == "auth.register").first()
    row.details = {"email": "tampered@example.com"}
    db.commit()

    broken = client.get("/api/v1/admin/audit-logs/verify", headers=admin["headers"])
    assert broken.status_code == 200
    assert broken.json()["chain_valid"] is False


def test_audit_rows_are_listed_with_actor_email(client, db, admin):
    email, password = register(client)
    login(client, email, password)

    response = client.get("/api/v1/admin/audit-logs?action=auth.login.success", headers=admin["headers"])
    assert response.status_code == 200
    items = response.json()["items"]
    assert items
    assert items[0]["actor_email"] == email
    assert items[0]["outcome"] == "success"


def test_audit_endpoint_is_admin_only(client, user):
    assert client.get("/api/v1/admin/audit-logs", headers=user["headers"]).status_code == 403


def test_every_registered_action_has_a_description():
    """The action registry is a contract; a blank description is a documentation bug."""
    assert audit.ACTIONS
    assert all(description.strip() for description in audit.ACTIONS.values())


def test_deleting_a_user_cannot_rewrite_audit_history(client, db, admin):
    """The trail is immutable: an actor may not be deleted out from under its own rows.

    Without ``passive_deletes`` SQLAlchemy would null ``audit_logs.user_id`` on delete,
    silently changing a row the hash chain has already committed to and breaking
    verification for ever. The foreign key now refuses the delete instead.
    """
    from sqlalchemy.exc import IntegrityError

    email, _ = register(client)
    user_row = db.query(User).filter(User.email == email).one()

    with pytest.raises(IntegrityError):
        db.delete(user_row)
        db.commit()
    db.rollback()

    verified = client.get("/api/v1/admin/audit-logs/verify", headers=admin["headers"])
    assert verified.json()["chain_valid"] is True
