"""Authentication, session and lockout tests."""

from __future__ import annotations

import pytest

from app.core import security
from app.core.config import settings
from app.db.models import User

from .conftest import PASSWORD, login, register, unique_email


def test_auth_policy_is_public_and_describes_the_rules(client):
    response = client.get("/api/v1/auth/policy")
    assert response.status_code == 200
    body = response.json()
    assert body["password"]["min_length"] == settings.PASSWORD_MIN_LENGTH
    assert body["max_failed_logins"] == settings.MAX_FAILED_LOGINS
    assert "at least" in body["password_hint"]


def test_register_login_and_me(client):
    email, password = register(client)
    tokens = login(client, email, password)
    assert tokens["token_type"] == "bearer"
    assert tokens["expires_in"] > 0

    me = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {tokens['access_token']}"})
    assert me.status_code == 200
    assert me.json()["role"] == "user"
    assert me.json()["email"] == email


@pytest.mark.parametrize(
    "password,reason",
    [
        ("Short1", "too short"),
        ("alllettersonly", "no digit"),
        ("1234567890123", "no letter"),
        ("         Pass1", "whitespace"),
        (PASSWORD, None),
    ],
)
def test_password_policy_is_enforced_at_the_schema(client, password, reason):
    response = client.post("/api/v1/auth/register", json={"email": unique_email(), "password": password})
    if reason is None:
        assert response.status_code == 201, response.text
    else:
        assert response.status_code == 422, f"{reason}: {response.text}"


def test_password_longer_than_bcrypt_limit_is_rejected_not_crashed(client):
    """Regression: a 100-character password used to raise inside the endpoint (HTTP 500)."""
    response = client.post(
        "/api/v1/auth/register", json={"email": unique_email(), "password": "Aa1" + "x" * 100}
    )
    assert response.status_code == 422
    assert "72" in response.text


def test_self_registration_cannot_grant_admin(client, db):
    email = unique_email("sneaky")
    response = client.post(
        "/api/v1/auth/register", json={"email": email, "password": PASSWORD, "role": "admin"}
    )
    assert response.status_code == 201
    assert response.json()["role"] == "user"
    db.expire_all()
    assert db.query(User).filter(User.email == email).one().role == "user"


def test_duplicate_registration_and_generic_login_errors(client):
    email, password = register(client)
    duplicate = client.post("/api/v1/auth/register", json={"email": email, "password": password})
    assert duplicate.status_code == 400

    wrong = client.post("/api/v1/auth/login", json={"email": email, "password": "WrongPass123"})
    unknown = client.post("/api/v1/auth/login", json={"email": unique_email(), "password": "WrongPass123"})
    assert wrong.status_code == unknown.status_code == 401
    assert wrong.json()["detail"] == unknown.json()["detail"]


def test_account_lockout_and_admin_unlock(client, admin, db):
    email, password = register(client, prefix="locked")
    for _ in range(settings.MAX_FAILED_LOGINS):
        assert (
            client.post("/api/v1/auth/login", json={"email": email, "password": "WrongPass123"}).status_code
            == 401
        )

    locked = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert locked.status_code == 423
    assert "locked" in locked.json()["detail"].lower()

    db.expire_all()
    user = db.query(User).filter(User.email == email).one()
    target_id = str(user.id)
    assert user.failed_login_count >= settings.MAX_FAILED_LOGINS

    listed_users = client.get("/api/v1/admin/users", headers=admin["headers"])
    assert listed_users.status_code == 200
    listed_user = next(item for item in listed_users.json()["items"] if item["id"] == target_id)
    assert listed_user["is_locked"] is True

    unlock = client.post(f"/api/v1/admin/users/{target_id}/unlock", headers=admin["headers"])
    assert unlock.status_code == 200
    assert client.post("/api/v1/auth/login", json={"email": email, "password": password}).status_code == 200


def test_refresh_rotation_and_reuse_detection(client):
    email, password = register(client, prefix="rotate")
    first = login(client, email, password)

    rotated = client.post("/api/v1/auth/refresh", json={"refresh_token": first["refresh_token"]})
    assert rotated.status_code == 200
    second = rotated.json()
    assert second["refresh_token"] != first["refresh_token"]

    # Replaying the consumed token must be treated as theft and revoke the family.
    replay = client.post("/api/v1/auth/refresh", json={"refresh_token": first["refresh_token"]})
    assert replay.status_code == 401
    assert "reuse" in replay.json()["detail"].lower()

    after = client.post("/api/v1/auth/refresh", json={"refresh_token": second["refresh_token"]})
    assert after.status_code == 401, "the whole family must be revoked"


def test_refresh_accepts_a_json_body_only(client):
    email, password = register(client, prefix="body")
    tokens = login(client, email, password)
    assert client.post(f"/api/v1/auth/refresh?token={tokens['refresh_token']}").status_code in (404, 405, 422)
    assert (
        client.post("/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]}).status_code
        == 200
    )


def test_token_types_are_not_interchangeable(client):
    email, password = register(client, prefix="types")
    tokens = login(client, email, password)

    access_as_refresh = client.post("/api/v1/auth/refresh", json={"refresh_token": tokens["access_token"]})
    assert access_as_refresh.status_code == 401

    refresh_as_bearer = client.get(
        "/api/v1/auth/me", headers={"Authorization": f"Bearer {tokens['refresh_token']}"}
    )
    assert refresh_as_bearer.status_code == 401


def test_logout_revokes_the_refresh_token(client):
    email, password = register(client, prefix="logout")
    tokens = login(client, email, password)
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}
    assert (
        client.post(
            "/api/v1/auth/logout", json={"refresh_token": tokens["refresh_token"]}, headers=headers
        ).status_code
        == 200
    )
    assert (
        client.post("/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]}).status_code
        == 401
    )


def test_disabled_account_loses_access(client, admin, db):
    email, password = register(client, prefix="disable")
    tokens = login(client, email, password)
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}
    assert client.get("/api/v1/auth/me", headers=headers).status_code == 200

    db.expire_all()
    target = db.query(User).filter(User.email == email).one()
    disabled = client.patch(
        f"/api/v1/admin/users/{target.id}/status", params={"is_active": False}, headers=admin["headers"]
    )
    assert disabled.status_code == 200
    assert client.get("/api/v1/auth/me", headers=headers).status_code == 401
    assert client.post("/api/v1/auth/login", json={"email": email, "password": password}).status_code == 403


def test_password_hashing_is_bcrypt_and_verifies():
    hashed = security.hash_password("CorrectHorse42")
    assert hashed.startswith("$2")
    assert security.verify_password("CorrectHorse42", hashed)
    assert not security.verify_password("wrong", hashed)
    assert not security.verify_password("x" * 200, hashed)
    with pytest.raises(ValueError):
        security.hash_password("x" * 200)


def test_access_token_carries_issuer_audience_and_short_expiry():
    issued = security.issue_access_token("someone@example.com", "uid", "user")
    payload = security.decode_token(issued.token, expected_type="access")
    assert payload["iss"] == settings.JWT_ISSUER
    assert payload["aud"] == settings.JWT_AUDIENCE
    assert payload["type"] == "access"
    assert payload["exp"] - payload["iat"] == settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60


def test_token_signed_with_another_secret_is_rejected(monkeypatch):
    issued = security.issue_access_token("someone@example.com", "uid", "user")
    monkeypatch.setattr(settings, "JWT_SECRET_KEY", "a-completely-different-secret-value")
    with pytest.raises(security.TokenError):
        security.decode_token(issued.token, expected_type="access")
