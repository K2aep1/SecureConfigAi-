"""AI must be optional, lazy, bounded and unable to influence any verdict.

Every test here runs with no network: the provider client is either unconfigured or
replaced with a stub that fails in a controlled way. The deterministic path is asserted
to be unaffected in each case.
"""

from __future__ import annotations

import json

import pytest

from app.db.models import AICache
from app.services import ai_client as ai_module
from app.services.ai_client import LOCAL_MODEL, ProviderUnavailable

from .conftest import failing_document, perfect_document, snapshot_from


def _upload(client, headers, document, name="h"):
    response = client.post(
        "/api/v1/scans/upload",
        headers=headers,
        files={"file": (f"{name}.json", json.dumps(snapshot_from(document)).encode(), "application/json")},
    )
    assert response.status_code == 200, response.text
    return response.json()


def _finding_id(client, headers, scan_id):
    results = client.get(f"/api/v1/scans/{scan_id}/results", headers=headers)
    assert results.status_code == 200
    findings = client.get(f"/api/v1/scans/{scan_id}/results", headers=headers).json()["findings"]
    assert findings, "the failing fixture must produce findings"
    return findings[0]["id"]


@pytest.fixture(autouse=True)
def fresh_status_cache():
    """The provider status is cached in-process for a minute; tests must not inherit it."""
    ai_module.ai_client._status_cache = None
    yield
    ai_module.ai_client._status_cache = None


# --------------------------------------------------------------------------- unconfigured
def test_status_reports_that_ai_is_disabled(client, user):
    response = client.get("/api/v1/ai/status", headers=user["headers"])
    assert response.status_code == 200
    body = response.json()
    assert body["enabled"] is False  # the suite disables AI globally
    assert body["configured"] is False
    assert body["connected"] is False
    assert body["advisory"] is True
    assert "disabled" in body["error"].lower()


def test_status_explains_a_missing_key_when_ai_is_enabled(client, user, monkeypatch):
    monkeypatch.setattr(ai_module.settings, "AI_ENABLED", True)
    monkeypatch.setattr(ai_module.settings, "OPENAI_API_KEY", None)
    monkeypatch.setattr(ai_module.settings, "DEEPSEEK_API_KEY", None)
    monkeypatch.setattr(ai_module.settings, "GEMINI_API_KEY", None)

    body = client.get("/api/v1/ai/status", headers=user["headers"]).json()
    assert body["configured"] is False
    assert "No provider key" in body["error"]


def test_report_generation_falls_back_to_the_local_engine(client, user):
    scan = _upload(client, user["headers"], failing_document("AI-LOCAL"))
    response = client.post(f"/api/v1/ai/report/{scan['scan_id']}", headers=user["headers"])
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["model_used"] == LOCAL_MODEL
    assert body["summary"].strip()
    assert body["cached"] is False


def test_finding_explanation_and_recommendation_fall_back(client, user):
    scan = _upload(client, user["headers"], failing_document("AI-FIND"))
    finding_id = _finding_id(client, user["headers"], scan["scan_id"])

    explained = client.post(f"/api/v1/ai/findings/{finding_id}/explain", headers=user["headers"])
    assert explained.status_code == 200, explained.text
    assert explained.json()["model_used"] == LOCAL_MODEL
    assert explained.json()["explanation"].strip()

    recommended = client.post(f"/api/v1/ai/findings/{finding_id}/recommend", headers=user["headers"])
    assert recommended.status_code == 200, recommended.text
    assert recommended.json()["model_used"] == LOCAL_MODEL


def test_ai_disabled_by_configuration_still_serves_deterministic_results(client, user, monkeypatch):
    monkeypatch.setattr(ai_module.settings, "AI_ENABLED", False)
    scan = _upload(client, user["headers"], failing_document("AI-OFF"))

    status = client.get("/api/v1/ai/status", headers=user["headers"]).json()
    assert status["enabled"] is False
    assert status["configured"] is False

    # The assessment itself is unaffected by AI being off.
    results = client.get(f"/api/v1/scans/{scan['scan_id']}/results", headers=user["headers"]).json()
    assert results["status"] == "completed"
    assert results["results"]["security_score"] == 0
    assert results["results"]["scoring_model_current"] is True

    report = client.post(f"/api/v1/ai/report/{scan['scan_id']}", headers=user["headers"])
    assert report.status_code == 200
    assert report.json()["model_used"] == LOCAL_MODEL


# --------------------------------------------------------------------------- provider failure
@pytest.fixture
def configured_provider(monkeypatch):
    """Pretend a key exists without ever touching the network."""
    monkeypatch.setattr(ai_module.settings, "AI_ENABLED", True)
    monkeypatch.setattr(ai_module.settings, "AI_PROVIDER", "openai")
    monkeypatch.setattr(ai_module.settings, "OPENAI_API_KEY", "sk-test-not-a-real-key")


def test_provider_error_falls_back_and_the_assessment_is_unchanged(
    client, user, configured_provider, monkeypatch
):
    def boom(messages, max_tokens=700):  # noqa: ARG001
        raise ProviderUnavailable("429 rate limited")

    monkeypatch.setattr(ai_module.ai_client, "_call", boom)

    scan = _upload(client, user["headers"], failing_document("AI-ERR"))
    before = client.get(f"/api/v1/scans/{scan['scan_id']}/results", headers=user["headers"]).json()

    finding_id = _finding_id(client, user["headers"], scan["scan_id"])
    explained = client.post(f"/api/v1/ai/findings/{finding_id}/explain", headers=user["headers"])
    assert explained.status_code == 200
    assert explained.json()["model_used"] == LOCAL_MODEL

    after = client.get(f"/api/v1/scans/{scan['scan_id']}/results", headers=user["headers"]).json()
    assert before["results"]["security_score"] == after["results"]["security_score"]
    assert before["results"]["risk_score"] == after["results"]["risk_score"]
    assert before["results"]["compliance_score"] == after["results"]["compliance_score"]


def test_provider_timeout_falls_back(client, user, configured_provider, monkeypatch):
    def timeout(messages, max_tokens=700):  # noqa: ARG001
        raise TimeoutError("read timeout after 30s")

    monkeypatch.setattr(ai_module.ai_client, "_call", timeout)

    scan = _upload(client, user["headers"], perfect_document("AI-TIMEOUT"))
    response = client.post(f"/api/v1/ai/report/{scan['scan_id']}", headers=user["headers"])
    assert response.status_code == 200
    assert response.json()["model_used"] == LOCAL_MODEL


# --------------------------------------------------------------------------- caching
def test_model_output_is_cached_by_evidence_digest(client, user, db, configured_provider, monkeypatch):
    calls = {"n": 0}

    def fake_call(messages, max_tokens=700):  # noqa: ARG001
        calls["n"] += 1
        return "Model-authored explanation."

    monkeypatch.setattr(ai_module.ai_client, "_call", fake_call)

    scan = _upload(client, user["headers"], failing_document("AI-CACHE"))
    finding_id = _finding_id(client, user["headers"], scan["scan_id"])

    first = client.post(f"/api/v1/ai/findings/{finding_id}/explain", headers=user["headers"]).json()
    second = client.post(f"/api/v1/ai/findings/{finding_id}/explain", headers=user["headers"]).json()

    assert first["model_used"] != LOCAL_MODEL
    assert first["text" if "text" in first else "explanation"] == "Model-authored explanation."
    assert calls["n"] == 1, "the second identical request must be served from cache"
    assert second["cached"] is True
    assert db.query(AICache).count() == 1


def test_fallbacks_are_never_cached_as_model_output(client, user, db, monkeypatch):
    scan = _upload(client, user["headers"], failing_document("AI-NOCACHE"))
    finding_id = _finding_id(client, user["headers"], scan["scan_id"])
    response = client.post(f"/api/v1/ai/findings/{finding_id}/explain", headers=user["headers"])
    assert response.status_code == 200
    assert response.json()["model_used"] == LOCAL_MODEL
    assert db.query(AICache).count() == 0


# --------------------------------------------------------------------------- safety
def test_ai_input_sanitisation_strips_control_characters_and_redacts_email():
    dirty = "evil\x00\x1b[31m service admin@example.com " + "A" * 5000
    cleaned = ai_module.sanitise(dirty)
    assert "\x00" not in cleaned
    assert "\x1b" not in cleaned
    assert "admin@example.com" not in cleaned
    assert len(cleaned) < 1000


def test_ai_cannot_write_to_the_authoritative_assessment(client, user, db):
    
    """No AI endpoint may alter a stored control, score or finding."""
    from app.db.models import ScanResult

    scan = _upload(client, user["headers"], failing_document("AI-WRITE"))
    scan_id = scan["scan_id"]
    before = client.get(f"/api/v1/scans/{scan_id}/results", headers=user["headers"]).json()["results"]
    before_model_version = before["stored_scoring_model_version"]
    client.post(f"/api/v1/ai/report/{scan_id}", headers=user["headers"])
    client.post(
        f"/api/v1/ai/findings/{_finding_id(client, user['headers'], scan_id)}/recommend",
        headers=user["headers"],
    )

    db.expire_all()
    import uuid

    stored = db.query(ScanResult).filter(ScanResult.scan_id == uuid.UUID(scan_id)).one()
    assert stored.security_score == before["security_score"]
    assert stored.risk_score == before["risk_score"]
    assert stored.compliance_score == before["compliance_score"]
    assert stored.assessment["scoring_model_version"] == before_model_version


def test_chat_can_attach_owned_scan_context(client, user, monkeypatch):
    scan = _upload(client, user["headers"], failing_document("AI-CHAT-CONTEXT"))

    def fake_call(messages, max_tokens=700):  # noqa: ARG001
        prompt = messages[-1]["content"]
        assert scan["scan_id"] in prompt
        assert "security_score" in prompt
        assert "highest_severity_findings" in prompt
        return "Answer grounded in the selected scan."

    monkeypatch.setattr(ai_module.settings, "AI_ENABLED", True)
    monkeypatch.setattr(ai_module.settings, "OPENAI_API_KEY", "sk-test-not-a-real-key")
    monkeypatch.setattr(ai_module.ai_client, "_call", fake_call)

    response = client.post(
        "/api/v1/ai/chat",
        headers=user["headers"],
        json={"content": "What should I fix first?", "scan_id": scan["scan_id"]},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["model_used"] != LOCAL_MODEL

    sessions = client.get("/api/v1/ai/chat/sessions", headers=user["headers"]).json()
    assert sessions["items"][0]["scan_id"] == scan["scan_id"]


def test_chat_cannot_attach_another_users_scan(client, user):
    from .conftest import login, register

    scan = _upload(client, user["headers"], failing_document("AI-CHAT-OWNERSHIP"))
    email, password = register(client, prefix="chatother")
    other = login(client, email, password)
    response = client.post(
        "/api/v1/ai/chat",
        headers={"Authorization": f"Bearer {other['access_token']}"},
        json={"content": "Summarise this scan", "scan_id": scan["scan_id"]},
    )
    assert response.status_code == 404


def test_ai_recommendation_does_not_overwrite_recorded_remediation(
    client, user, configured_provider, monkeypatch
):
    scan = _upload(client, user["headers"], failing_document("AI-REC-PRESERVE"))
    finding_id = _finding_id(client, user["headers"], scan["scan_id"])
    before = client.get(f"/api/v1/scans/{scan['scan_id']}/results", headers=user["headers"]).json()
    finding_before = next(item for item in before["findings"] if item["id"] == finding_id)
    original_guidance = finding_before["recommendation"]["what_should_be_done"]

    monkeypatch.setattr(
        ai_module.ai_client, "_call", lambda messages, max_tokens=700: "Fresh advisory wording."
    )
    response = client.post(f"/api/v1/ai/findings/{finding_id}/recommend", headers=user["headers"])
    assert response.status_code == 200, response.text
    assert response.json()["recommendation"]["what_should_be_done"] == "Fresh advisory wording."

    after = client.get(f"/api/v1/scans/{scan['scan_id']}/results", headers=user["headers"]).json()
    finding_after = next(item for item in after["findings"] if item["id"] == finding_id)
    assert finding_after["recommendation"]["what_should_be_done"] == original_guidance


def test_ai_fallback_explains_exhausted_api_credits():
    message = ai_module._fallback_response(
        "Local advice.", "RateLimitError (HTTP 429): insufficient_quota credit_balance_exhausted"
    )
    assert "LOCAL FALLBACK" in message
    assert "credits" in message.lower()
    assert "NOT AI-GENERATED" in message
