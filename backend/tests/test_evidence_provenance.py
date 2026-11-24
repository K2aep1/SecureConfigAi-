"""Evidence provenance: integrity is a checksum, authenticity needs a key.

The research report's F-14 finding was that a client-computed SHA-256 proves nothing
about origin. The platform now supports an opt-in HMAC envelope that the **server**
verifies with a key the endpoint signs with, and it never claims authenticity when no key
is configured.

The snapshot in these tests is produced by the real scanner module, so the test also
proves that the scanner and the backend agree on the envelope format.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from app.core.config import settings
from app.services import configuration_snapshot as cs

from .conftest import perfect_document, snapshot_from

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scanner.snapshot import build_configuration_snapshot  # noqa: E402

KEY = "unit-test-signing-key-0123456789abcdef"


def _scanner_snapshot(signing_key: str | None) -> dict:
    document = perfect_document("PROVENANCE-PC")
    return build_configuration_snapshot(document, scanner_version="1.2", signing_key=signing_key)


def _upload(client, headers, payload):
    return client.post(
        "/api/v1/scans/upload",
        headers=headers,
        files={"file": ("snapshot.json", json.dumps(payload).encode("utf-8"), "application/json")},
    )


def test_scanner_snapshot_with_a_key_carries_a_verifiable_envelope(configured_key):
    snapshot = _scanner_snapshot(KEY)
    assert snapshot["provenance"]["algorithm"] == "HMAC-SHA-256"
    verified, reason, block = cs.verify_provenance(snapshot)
    assert verified is True, reason
    assert block["scan_id"] == snapshot["snapshot_id"]


def test_signed_snapshot_is_accepted_as_authenticated(client, user, configured_key):
    response = _upload(client, user["headers"], _scanner_snapshot(KEY))
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["integrity_verified"] is True
    assert body["authenticity_verified"] is True
    assert "provenance verified" in body["message"]


def test_tampered_signed_payload_is_rejected(client, user, configured_key):
    snapshot = _scanner_snapshot(KEY)
    # Change the evidence *and* recompute the checksum, exactly as an attacker would.
    snapshot["checks"]["system_hardening"]["bitlocker"]["enabled"] = False
    snapshot["integrity"]["sha256"] = cs.calculate_snapshot_hash(snapshot)

    response = _upload(client, user["headers"], snapshot)
    assert response.status_code == 400
    assert "provenance check failed" in response.json()["detail"]


def test_envelope_signed_with_another_key_is_rejected(client, user, configured_key):
    snapshot = _scanner_snapshot("a-completely-different-key-0123456789")
    response = _upload(client, user["headers"], snapshot)
    assert response.status_code == 400
    assert "provenance check failed" in response.json()["detail"]


def test_unsigned_snapshot_is_integrity_only_and_says_so(client, user, configured_key):
    snapshot = snapshot_from(perfect_document("UNSIGNED"))
    response = _upload(client, user["headers"], snapshot)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["integrity_verified"] is True
    assert body["authenticity_verified"] is False
    assert "not authenticated" in body["message"]


def test_signed_snapshot_without_a_server_key_is_accepted_as_unverified(client, user, monkeypatch):
    """A misconfigured server must not reject valid evidence; it must be honest about it."""
    monkeypatch.setattr(settings, "EVIDENCE_SIGNING_KEY", None)
    response = _upload(client, user["headers"], _scanner_snapshot(KEY))
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["integrity_verified"] is True
    assert body["authenticity_verified"] is False
    assert "no signing key" in body["message"]


def test_a_server_digest_is_never_taken_from_the_client(configured_key):
    """The reference digest is recomputed locally, so a forged one changes nothing."""
    snapshot = _scanner_snapshot(KEY)
    snapshot["provenance"]["evidence_digest"] = "0" * 64
    verified, reason, _ = cs.verify_provenance(snapshot)
    # The forged field is ignored: the locally recomputed digest still produces a match.
    assert verified is True, reason


def test_provenance_helper_is_deterministic():
    message = cs.provenance_message(
        evidence_digest="a" * 64,
        scan_id="SCFG-1",
        timestamp="2026-01-01T00:00:00+00:00",
        scanner_version="1.2",
        nonce="n",
    )
    assert message == (("a" * 64) + "|SCFG-1|2026-01-01T00:00:00+00:00|1.2|n").encode()
    first = cs.compute_provenance_hmac(
        evidence_digest="a" * 64,
        scan_id="SCFG-1",
        timestamp="2026-01-01T00:00:00+00:00",
        scanner_version="1.2",
        nonce="n",
        key=KEY,
    )
    second = cs.compute_provenance_hmac(
        evidence_digest="a" * 64,
        scan_id="SCFG-1",
        timestamp="2026-01-01T00:00:00+00:00",
        scanner_version="1.2",
        nonce="n",
        key=KEY,
    )
    assert first == second
    assert len(first) == 64


def test_a_short_key_is_not_treated_as_configured(monkeypatch):
    monkeypatch.setattr(settings, "EVIDENCE_SIGNING_KEY", "short")
    assert settings.evidence_signing_configured is False


@pytest.fixture
def configured_key(monkeypatch):
    monkeypatch.setattr(settings, "EVIDENCE_SIGNING_KEY", KEY)
    return KEY
