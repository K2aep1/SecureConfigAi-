"""Platform security policy: the service's own posture, not the assessed endpoint's.

These tests pin the behaviour that must not regress: no SQLite outside tests, a
production deployment refuses trivial secrets, the password policy cannot be bypassed,
and the published policy matches the enforced one.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.core import security
from app.core.config import Settings
from app.core.security_policy import PasswordPolicyError, PlatformSecurityPolicy, settings

BASE = {
    "APP_ENV": "development",
    "DATABASE_URL": "postgresql+psycopg://u:p@localhost:5432/db",
    "JWT_SECRET_KEY": "a" * 48,
}


def _settings(**overrides) -> Settings:
    return Settings(**{**BASE, **overrides})


# --------------------------------------------------------------------------- database
@pytest.mark.parametrize("url", ["sqlite:///./dev.db", "mysql://u:p@h/db", "sqlite://"])
def test_only_postgresql_is_accepted_outside_tests(url):
    for env in ("development", "production"):
        with pytest.raises(ValidationError):
            _settings(APP_ENV=env, DATABASE_URL=url)


def test_a_missing_database_url_is_a_configuration_error():
    with pytest.raises(ValidationError):
        _settings(DATABASE_URL="")


def test_the_legacy_postgresql_scheme_is_normalised_to_psycopg():
    assert _settings(DATABASE_URL="postgresql://u:p@h/db").DATABASE_URL.startswith("postgresql+psycopg://")


# --------------------------------------------------------------------------- secrets
@pytest.mark.parametrize("secret", ["", "change-me", "secret", "short"])
def test_a_trivial_jwt_secret_is_flagged(secret):
    assert _settings(JWT_SECRET_KEY=secret).jwt_secret_is_placeholder is True


def test_a_long_random_jwt_secret_is_accepted():
    assert _settings(JWT_SECRET_KEY="a" * 48).jwt_secret_is_placeholder is False


def test_production_refuses_to_start_with_a_placeholder_secret():
    config = _settings(APP_ENV="production", JWT_SECRET_KEY="change-me")
    policy = PlatformSecurityPolicy(config)
    blocking = policy.blocking_failures()
    assert [check.name for check in blocking] == ["jwt_secret"]


def test_production_disables_interactive_docs():
    assert _settings(APP_ENV="production").docs_enabled is False
    assert _settings(APP_ENV="development").docs_enabled is True


def test_a_wildcard_cors_origin_is_flagged():
    config = _settings(CORS_ORIGINS="*")
    policy = PlatformSecurityPolicy(config)
    checks = {check.name: check for check in policy.startup_checks()}
    assert checks["cors_origins"].ok is False


def test_the_published_policy_matches_the_effective_configuration():
    policy = PlatformSecurityPolicy(settings)
    published = policy.as_dict()
    assert published["password"]["max_length"] == settings.PASSWORD_MAX_LENGTH
    assert published["lockout"]["max_failed_logins"] == settings.MAX_FAILED_LOGINS
    assert published["tokens"]["algorithm"] == settings.JWT_ALGORITHM
    assert published["database"]["dialect"] == "postgresql" or settings.is_test
    assert published["ai"]["advisory_only"] is True
    assert published["secrets"]["jwt_secret_strength"] in {"placeholder", "adequate", "strong"}


def test_the_policy_never_publishes_secret_values():
    payload = repr(PlatformSecurityPolicy(settings).as_dict())
    if settings.JWT_SECRET_KEY and len(settings.JWT_SECRET_KEY) >= 12:
        assert settings.JWT_SECRET_KEY not in payload
    if settings.ai_api_key:
        assert settings.ai_api_key not in payload


# --------------------------------------------------------------------------- passwords
def test_the_password_policy_rejects_over_length_input_without_truncating():
    policy = PlatformSecurityPolicy(settings)
    with pytest.raises(PasswordPolicyError) as excinfo:
        policy.validate_password("A1" + "b" * (settings.PASSWORD_MAX_LENGTH + 10))
    assert "at most" in str(excinfo.value)


def test_the_password_policy_enforces_minimum_length_and_classes():
    policy = PlatformSecurityPolicy(settings)
    with pytest.raises(PasswordPolicyError):
        policy.validate_password("short1")
    with pytest.raises(PasswordPolicyError):
        policy.validate_password("alllettersnodigits")
    with pytest.raises(PasswordPolicyError):
        policy.validate_password(" leading-space-1")
    with pytest.raises(PasswordPolicyError):
        policy.validate_password("password")


def test_hashing_never_truncates_an_over_length_password():
    with pytest.raises(ValueError):
        security.hash_password("A1" + "b" * (settings.PASSWORD_MAX_LENGTH + 1))


def test_two_hashes_of_the_same_password_differ_and_both_verify():
    first = security.hash_password("CorrectHorse42")
    second = security.hash_password("CorrectHorse42")
    assert first != second
    assert security.verify_password("CorrectHorse42", first) is True
    assert security.verify_password("CorrectHorse42", second) is True
    assert security.verify_password("wrong", first) is False


# --------------------------------------------------------------------------- uploads
def test_the_upload_limit_is_shared_by_the_route_and_the_parser():
    """One limit, one owner: the endpoint and the snapshot validator cannot diverge."""
    from app.services import configuration_snapshot

    assert configuration_snapshot.settings is settings


def test_access_tokens_and_refresh_tokens_are_not_interchangeable():
    with pytest.raises(security.TokenError):
        security.decode_token(
            security.issue_refresh_token("user@example.com", "uid").token, expected_type="access"
        )
    with pytest.raises(security.TokenError):
        security.decode_token(
            security.issue_access_token("user@example.com", "uid", "user").token, expected_type="refresh"
        )
