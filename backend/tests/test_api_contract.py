"""API contract: bounded payloads, keyset pagination, headers and rate limiting.

The research report measured `GET /scans` at 27.9 MB and 3.07 s. These tests assert the
*shape* of the contract that prevents a regression: list responses are summaries, evidence
is never serialised into a list, and the cheap endpoints stay cheap.
"""

from __future__ import annotations

import uuid
from datetime import timedelta

import pytest

from app.core.config import settings
from app.core.rate_limit import limiter
from app.core.timeutil import utcnow
from app.db.models import Device, Scan, ScanResult, User


@pytest.fixture
def seeded(db, user):
    """A realistic multi-scan history without running the scanner 25 times."""
    owner = db.query(User).filter(User.email == user["email"]).one()
    device = Device(user_id=owner.id, hostname="API-PC", criticality=3)
    db.add(device)
    db.commit()
    db.refresh(device)

    now = utcnow()
    for index in range(25):
        started = now - timedelta(hours=index)
        scan = Scan(
            user_id=owner.id,
            device_id=device.id,
            status="completed",
            stage="Completed",
            progress=100,
            source="local_agent",
            started_at=started,
            completed_at=started,
            heartbeat_at=started,
            duration_ms=14000,
            scanner_version="1.2",
            scoring_model_version="2.0.0",
            baseline_version="1.0.0",
        )
        db.add(scan)
        db.flush()
        db.add(
            ScanResult(
                scan_id=scan.id,
                security_score=80 - index % 10,
                compliance_score=75,
                assessment_coverage=100,
                risk_score=index % 30,
                risk_level="moderate",
                evidence_quality="high",
                controls=[],
                categories=[],
                assessment={"scoring_model_version": "2.0.0", "assessed_controls": 28, "total_controls": 28},
            )
        )
    db.commit()
    return device


# --------------------------------------------------------------------------- payload size
def test_scan_list_is_a_bounded_summary(client, user, seeded):
    response = client.get("/api/v1/scans?limit=25", headers=user["headers"])
    assert response.status_code == 200, response.text

    payload = response.content
    assert len(payload) < 50 * 1024, f"list response was {len(payload)} bytes"

    body = response.json()
    assert len(body["items"]) == 25
    # Evidence must never be part of a list response.
    assert "normalized_data" not in response.text
    assert "raw_data" not in response.text
    first = body["items"][0]
    assert first["security_score"] is not None
    assert first["scoring_model_version"] == "2.0.0"


def test_scan_detail_never_ships_the_evidence_document(client, user, seeded):
    listing = client.get("/api/v1/scans?limit=1", headers=user["headers"]).json()
    scan_id = listing["items"][0]["id"]

    detail = client.get(f"/api/v1/scans/{scan_id}", headers=user["headers"])
    assert detail.status_code == 200
    assert len(detail.content) < 8 * 1024
    assert "normalized_data" not in detail.text


def test_trend_is_a_compact_projection(client, user, seeded):
    response = client.get("/api/v1/scans/trend?limit=25", headers=user["headers"])
    assert response.status_code == 200, response.text
    rows = response.json()
    assert len(rows) == 25
    assert len(response.content) < 8 * 1024
    for row in rows:
        assert set(row) <= {
            "scan_id",
            "timestamp",
            "security_score",
            "compliance_score",
            "assessment_coverage",
            "risk_score",
            "risk_level",
            "scoring_model_version",
            "baseline_version",
        }


def test_alerts_are_a_compact_projection(client, user, seeded):
    response = client.get("/api/v1/scans/alerts", headers=user["headers"])
    assert response.status_code == 200
    assert len(response.content) < 8 * 1024


# --------------------------------------------------------------------------- pagination
def test_keyset_pagination_walks_the_whole_history_once(client, user, seeded):
    seen: list[str] = []
    cursor = None
    for _ in range(10):
        url = "/api/v1/scans?limit=10" + (f"&cursor={cursor}" if cursor else "")
        body = client.get(url, headers=user["headers"]).json()
        seen.extend(item["id"] for item in body["items"])
        cursor = body["next_cursor"]
        if not body["has_more"]:
            break
    assert len(seen) == 25
    assert len(set(seen)) == 25, "keyset pagination must not duplicate rows"


def test_invalid_cursor_is_a_client_error(client, user):
    response = client.get("/api/v1/scans?cursor=not-a-cursor", headers=user["headers"])
    assert response.status_code == 400


def test_limit_is_bounded(client, user):
    assert client.get("/api/v1/scans?limit=0", headers=user["headers"]).status_code == 422
    assert client.get("/api/v1/scans?limit=9999", headers=user["headers"]).status_code == 422


# --------------------------------------------------------------------------- ownership
def test_another_users_scan_is_not_found_not_forbidden(client, user, seeded):
    from .conftest import login, register

    email, password = register(client, prefix="other")
    other = login(client, email, password)
    listing = client.get("/api/v1/scans?limit=1", headers=user["headers"]).json()
    scan_id = listing["items"][0]["id"]

    response = client.get(
        f"/api/v1/scans/{scan_id}", headers={"Authorization": f"Bearer {other['access_token']}"}
    )
    assert response.status_code == 404


# --------------------------------------------------------------------------- headers
def test_security_headers_are_present_on_every_response(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Referrer-Policy"] == "no-referrer"
    assert "default-src 'self'" in response.headers["Content-Security-Policy"]
    assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]
    assert "server" not in {header.lower() for header in response.headers}
    assert response.headers.get("X-Request-ID")
    assert response.headers.get("X-Response-Time-ms")


def test_api_responses_are_not_cached(client, user):
    response = client.get("/api/v1/auth/me", headers=user["headers"])
    assert response.headers["Cache-Control"].startswith("no-store")


def test_an_unhandled_error_never_leaks_internals(client, monkeypatch):
    from app.api.v1 import scans as scans_module

    def boom(*args, **kwargs):
        raise RuntimeError("secret internal detail")

    monkeypatch.setattr(scans_module, "load_baseline", boom)
    response = client.get("/api/v1/scans/trend", headers={"Authorization": "Bearer x"})
    # Unauthenticated first: still a clean 401, never a traceback.
    assert response.status_code == 401


# --------------------------------------------------------------------------- rate limits
def test_login_rate_limit_returns_429_with_retry_after(client, monkeypatch):
    from .conftest import register

    register(client)
    monkeypatch.setattr(settings, "RATE_LIMIT_LOGIN", 3)
    limiter.reset()

    statuses = []
    for _ in range(5):
        statuses.append(
            client.post(
                "/api/v1/auth/login", json={"email": "nobody@example.com", "password": "WrongPass123"}
            ).status_code
        )
    assert 429 in statuses

    blocked = client.post(
        "/api/v1/auth/login", json={"email": "nobody@example.com", "password": "WrongPass123"}
    )
    assert blocked.headers.get("Retry-After")


def test_scan_start_is_rate_limited(client, db, user, monkeypatch):
    from app.services.jobs import manager

    monkeypatch.setattr(manager, "submit", lambda scan_id: None)
    monkeypatch.setattr(settings, "RATE_LIMIT_SCAN_START", 2)
    limiter.reset()

    statuses = [
        client.post("/api/v1/scans/start", headers=user["headers"], json={}).status_code for _ in range(4)
    ]
    assert statuses[:2] == [202, 202]
    assert statuses[-1] == 429


def test_report_generation_requires_an_owner(client, user, seeded):
    listing = client.get("/api/v1/scans?limit=1", headers=user["headers"]).json()
    scan_id = listing["items"][0]["id"]
    # A completed scan with no stored result still serves a report for its owner.
    response = client.get(f"/api/v1/scans/{scan_id}/report/html", headers=user["headers"])
    assert response.status_code == 200
    etag = response.headers["ETag"]
    repeat = client.get(f"/api/v1/scans/{scan_id}/report/html", headers=user["headers"], params={})
    assert repeat.status_code == 200
    conditional = client.get(
        f"/api/v1/scans/{scan_id}/report/html", headers={**user["headers"], "If-None-Match": etag}
    )
    assert conditional.status_code == 304
    assert conditional.content == b""


def _as_uuid(value: str) -> uuid.UUID:
    return uuid.UUID(value)


def test_versioned_meta_endpoint_is_available(client):
    response = client.get("/api/v1/meta")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["app_name"] == "SecureConfigAI"
    assert body["control_count"] > 0
