"""Upload security: adversarial archives, oversize bodies, tampering and cleanup.

Everything here is exercised through the real endpoint with real bytes. No network or
external service is involved, so the negative paths are safe to run in CI.
"""

from __future__ import annotations

import io
import json
import zipfile

from app.core.config import settings
from app.db.models import AuditLog

from .conftest import empty_document, legacy_document, perfect_document, snapshot_from


def _json_upload(client, headers, payload, name="configuration_snapshot.json"):
    body = json.dumps(payload).encode("utf-8") if not isinstance(payload, bytes) else payload
    return client.post(
        "/api/v1/scans/upload", headers=headers, files={"file": (name, body, "application/json")}
    )


def _zip_bytes(entries: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in entries.items():
            archive.writestr(name, data)
    return buffer.getvalue()


# --------------------------------------------------------------------------- accepted
def test_a_valid_snapshot_is_accepted_and_fully_assessed(client, user):
    response = _json_upload(client, user["headers"], snapshot_from(perfect_document("UPLOAD-OK")))
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["integrity_verified"] is True
    assert body["finding_count"] == 0
    assert body["summary"]["security_score"] == 100
    assert body["summary"]["assessment_coverage"] == 100
    assert body["authenticity_verified"] is False  # checksum only, stated honestly


def test_a_zip_wrapped_snapshot_is_accepted(client, user):
    payload = json.dumps(snapshot_from(perfect_document("ZIP-OK"))).encode()
    response = client.post(
        "/api/v1/scans/upload",
        headers=user["headers"],
        files={
            "file": ("evidence.zip", _zip_bytes({"configuration_snapshot.json": payload}), "application/zip")
        },
    )
    assert response.status_code == 200, response.text
    assert response.json()["integrity_verified"] is True


def test_legacy_documents_are_converted_and_reported_as_unverified(client, user):
    response = _json_upload(client, user["headers"], legacy_document("LEGACY-OK"), name="legacy.json")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["integrity_verified"] is False
    assert any("Legacy" in warning or "legacy" in warning for warning in (body["message"] or "").split("."))
    assert body["finding_count"] >= 1


def test_degraded_evidence_yields_no_findings(client, user):
    """Collectors that could not read anything must not fabricate a failure."""
    document = perfect_document("UNREADABLE")
    document["checks"] = {
        name: {"status": "unavailable", "error": "requires elevation"} for name in document["checks"]
    }
    response = _json_upload(client, user["headers"], snapshot_from(document))
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["finding_count"] == 0
    assert body["summary"]["risk_score"] == 0
    assert body["summary"]["evidence_quality"] == "unavailable"


def test_a_snapshot_with_no_collectors_at_all_is_rejected(client, user):
    """Zero collectors is not evidence — accepting it would be a silent empty assessment."""
    response = _json_upload(client, user["headers"], snapshot_from(empty_document()))
    assert response.status_code == 400
    assert "no collected checks" in response.json()["detail"]


# --------------------------------------------------------------------------- rejected
def test_wrong_extension_is_rejected(client, user, db):
    response = _json_upload(client, user["headers"], b"{}", name="malware.exe")
    assert response.status_code == 400
    assert "supported" in response.json()["detail"]


def test_empty_file_is_rejected(client, user):
    response = _json_upload(client, user["headers"], b"", name="empty.json")
    assert response.status_code == 400


def test_invalid_json_is_rejected(client, user, db):
    response = _json_upload(client, user["headers"], b"{not json", name="broken.json")
    assert response.status_code == 400
    assert "not valid JSON" in response.json()["detail"]
    assert db.query(AuditLog).filter(AuditLog.action == "scan.upload.rejected").count() == 1


def test_non_utf8_body_is_rejected(client, user):
    response = _json_upload(
        client, user["headers"], b'{"device": {"hostname": "\xff\xfe"}}', name="latin1.json"
    )
    assert response.status_code == 400
    assert "UTF-8" in response.json()["detail"]


def test_oversize_upload_is_rejected_by_the_body_length(client, user, monkeypatch):
    monkeypatch.setattr(settings, "MAX_UPLOAD_BYTES", 2048)
    payload = json.dumps({"device": {"hostname": "BIG"}, "padding": "x" * 4096}).encode()
    response = _json_upload(client, user["headers"], payload, name="big.json")
    assert response.status_code == 413
    assert "limit" in response.json()["detail"].lower()


def test_zip_path_traversal_is_rejected(client, user):
    payload = json.dumps(snapshot_from(perfect_document("TRAVERSAL"))).encode()
    archive = _zip_bytes({"../../evil.json": payload})
    response = client.post(
        "/api/v1/scans/upload",
        headers=user["headers"],
        files={"file": ("traversal.zip", archive, "application/zip")},
    )
    assert response.status_code == 400
    assert "Unsafe ZIP archive paths" in response.json()["detail"]


def test_zip_without_json_is_rejected(client, user):
    archive = _zip_bytes({"readme.txt": b"hello", "nested/": b""})
    response = client.post(
        "/api/v1/scans/upload",
        headers=user["headers"],
        files={"file": ("nojson.zip", archive, "application/zip")},
    )
    assert response.status_code == 400
    assert "No JSON file" in response.json()["detail"]


def test_corrupt_zip_is_rejected(client, user):
    response = client.post(
        "/api/v1/scans/upload",
        headers=user["headers"],
        files={"file": ("corrupt.zip", b"PK\x03\x04garbage", "application/zip")},
    )
    assert response.status_code == 400
    assert "invalid" in response.json()["detail"].lower()


def test_tampered_integrity_hash_is_rejected(client, user):
    payload = snapshot_from(perfect_document("TAMPERED"))
    payload["checks"]["system_hardening"]["bitlocker"]["enabled"] = False
    response = _json_upload(client, user["headers"], payload)
    assert response.status_code == 400
    assert "integrity check failed" in response.json()["detail"]


def test_snapshot_without_checks_is_rejected(client, user):
    payload = snapshot_from(perfect_document("NOCHECKS"))
    payload["checks"] = {}
    from app.services.configuration_snapshot import calculate_snapshot_hash

    payload["integrity"]["sha256"] = calculate_snapshot_hash(payload)
    response = _json_upload(client, user["headers"], payload)
    assert response.status_code == 400
    assert "no collected checks" in response.json()["detail"]


def test_unsupported_schema_version_is_rejected(client, user):
    payload = snapshot_from(perfect_document("V99"))
    payload["schema_version"] = "99.0"
    from app.services.configuration_snapshot import calculate_snapshot_hash

    payload["integrity"]["sha256"] = calculate_snapshot_hash(payload)
    response = _json_upload(client, user["headers"], payload)
    assert response.status_code == 400
    assert "Unsupported snapshot schema" in response.json()["detail"]


def test_unrecognisable_document_is_rejected(client, user):
    response = _json_upload(client, user["headers"], {"hello": "world"}, name="junk.json")
    assert response.status_code == 400
    assert "no recognisable collected evidence" in response.json()["detail"]


def test_rejected_uploads_do_not_accumulate_on_disk(client, user):
    from app.services.maintenance import QUARANTINE_DIR

    before = set(QUARANTINE_DIR.iterdir()) if QUARANTINE_DIR.exists() else set()
    for _ in range(3):
        _json_upload(client, user["headers"], b"{broken", name="bad.json")
    after = set(QUARANTINE_DIR.iterdir()) if QUARANTINE_DIR.exists() else set()
    assert after == before


def test_uploads_require_authentication(client):
    response = client.post("/api/v1/scans/upload", files={"file": ("x.json", b"{}", "application/json")})
    assert response.status_code == 401
