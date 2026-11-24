"""Gemini must use the Google OpenAI-compatible endpoint and its own credentials."""

from __future__ import annotations

import sys
from types import SimpleNamespace

from app.core.config import settings
from app.services.ai_client import AIClient


def test_gemini_key_and_model_are_selected(monkeypatch):
    monkeypatch.setattr(settings, "AI_PROVIDER", "gemini")
    monkeypatch.setattr(settings, "GEMINI_API_KEY", "gemini-test-key")
    monkeypatch.setattr(settings, "GEMINI_MODEL", "gemini-3.8-flash")
    # V4 fix: the shared test environment disables AI globally (conftest sets
    # AI_ENABLED=false), so this test must enable it explicitly before asserting
    # the provider is "configured". Without this the test could only ever pass on
    # a machine whose environment happened to re-enable AI.
    monkeypatch.setattr(settings, "AI_ENABLED", True)

    assert settings.ai_api_key == "gemini-test-key"
    assert settings.ai_model == "gemini-3.8-flash"
    assert settings.ai_configured is True


def test_gemini_client_uses_google_openai_compatibility_endpoint(monkeypatch):
    captured: dict[str, object] = {}

    class FakeOpenAI:
        def __init__(self, **kwargs):
            captured.update(kwargs)

    monkeypatch.setattr(settings, "AI_ENABLED", True)  # V4: conftest disables AI globally
    monkeypatch.setattr(settings, "AI_PROVIDER", "gemini")
    monkeypatch.setattr(settings, "GEMINI_API_KEY", "gemini-test-key")
    monkeypatch.setattr(
        settings,
        "GEMINI_BASE_URL",
        "https://generativelanguage.googleapis.com/v1beta/openai/",
    )
    monkeypatch.setitem(sys.modules, "openai", SimpleNamespace(OpenAI=FakeOpenAI))

    client = AIClient()
    assert client._get_client() is not None
    assert captured["api_key"] == "gemini-test-key"
    assert captured["base_url"] == "https://generativelanguage.googleapis.com/v1beta/openai/"
    assert captured["timeout"] == float(settings.AI_TIMEOUT_SECONDS)
    assert captured["max_retries"] == 0
