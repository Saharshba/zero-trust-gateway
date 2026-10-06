"""Authentication, MFA, session revocation and RBAC."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import jwt
from sqlalchemy import select

from tests.conftest import TEST_USERS
from zta.common.config import settings
from zta.common.models import Session as SessionRow
from zta.common.models import User
from zta.common.security import create_access_token, totp_now, verify_totp


def test_login_returns_tokens_and_a_trust_score(client):
    body = client.post(
        "/api/auth/login",
        json={"username": "employee", "password": TEST_USERS["employee"][0], "device_id": "laptop-employee"},
    ).json()
    assert body["token_type"] == "bearer"
    assert body["user"]["role"] == "EMPLOYEE"
    assert body["trust_score"] > 0
    assert "hashed_password" not in body["user"]


def test_managed_device_raises_the_trust_score_at_login(client):
    password = TEST_USERS["employee"][0]
    without = client.post("/api/auth/login", json={"username": "employee", "password": password}).json()
    with_device = client.post(
        "/api/auth/login",
        json={"username": "employee", "password": password, "device_id": "laptop-employee"},
    ).json()
    assert with_device["trust_score"] > without["trust_score"]


def test_quarantined_device_lowers_the_trust_score(client):
    password = TEST_USERS["employee"][0]
    healthy = client.post(
        "/api/auth/login", json={"username": "employee", "password": password, "device_id": "laptop-employee"}
    ).json()
    quarantined = client.post(
        "/api/auth/login",
        json={"username": "employee", "password": password, "device_id": "laptop-quarantined"},
    ).json()
    assert quarantined["trust_score"] < healthy["trust_score"]


def test_wrong_password_and_unknown_user_are_indistinguishable(client):
    wrong = client.post("/api/auth/login", json={"username": "admin", "password": "nope-nope-nope"})
    unknown = client.post("/api/auth/login", json={"username": "nobody", "password": "nope-nope-nope"})
    assert wrong.status_code == unknown.status_code == 401
    assert wrong.json()["detail"] == unknown.json()["detail"]


def test_account_locks_after_repeated_failures(client):
    for _ in range(settings.max_failed_logins):
        client.post("/api/auth/login", json={"username": "guest", "password": "wrong-password"})
    blocked = client.post(
        "/api/auth/login", json={"username": "guest", "password": TEST_USERS["guest"][0]}
    )
    assert blocked.status_code == 429
    assert "locked" in blocked.json()["detail"].lower()


def test_successful_login_resets_the_failure_counter(client, db):
    client.post("/api/auth/login", json={"username": "guest", "password": "wrong-password"})
    client.post("/api/auth/login", json={"username": "guest", "password": TEST_USERS["guest"][0]})
    assert db.scalar(select(User).where(User.username == "guest")).failed_logins == 0


# --- tokens --------------------------------------------------------------
def test_expired_token_is_rejected(client, monkeypatch):
    monkeypatch.setattr(settings, "access_token_ttl_minutes", -1)
    token = create_access_token("admin", "ADMIN")
    response = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401
    assert "expired" in response.json()["detail"].lower()


def test_token_signed_with_another_key_is_rejected(client):
    forged = jwt.encode(
        {"sub": "admin", "role": "ADMIN", "type": "access", "aud": settings.jwt_audience,
         "iss": settings.jwt_issuer, "exp": datetime.now(timezone.utc) + timedelta(hours=1)},
        "not-the-real-key",
        algorithm="HS256",
    )
    assert client.get("/api/auth/me", headers={"Authorization": f"Bearer {forged}"}).status_code == 401


def test_refresh_token_cannot_be_used_as_an_access_token(client):
    tokens = client.post(
        "/api/auth/login", json={"username": "admin", "password": TEST_USERS["admin"][0]}
    ).json()
    response = client.get("/api/auth/me", headers={"Authorization": f"Bearer {tokens['refresh_token']}"})
    assert response.status_code == 401


def test_refresh_rotates_and_invalidates_the_old_token(client):
    tokens = client.post(
        "/api/auth/login", json={"username": "admin", "password": TEST_USERS["admin"][0]}
    ).json()
    refreshed = client.post("/api/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert refreshed.status_code == 200
    # Replaying the original refresh token must now fail.
    replay = client.post("/api/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert replay.status_code == 401


def test_logout_revokes_the_session_immediately(client):
    tokens = client.post(
        "/api/auth/login", json={"username": "admin", "password": TEST_USERS["admin"][0]}
    ).json()
    header = {"Authorization": f"Bearer {tokens['access_token']}"}
    assert client.get("/api/auth/me", headers=header).status_code == 200

    assert client.post("/api/auth/logout", headers=header).status_code == 204
    # The access token is still cryptographically valid but its session is gone.
    assert client.get("/api/auth/me", headers=header).status_code == 401
    assert client.post("/api/auth/refresh", json={"refresh_token": tokens["refresh_token"]}).status_code == 401


def test_sessions_record_where_the_login_came_from(client, db):
    client.post(
        "/api/auth/login",
        json={"username": "employee", "password": TEST_USERS["employee"][0], "device_id": "laptop-employee"},
    )
    session_row = db.scalars(select(SessionRow)).all()[-1]
    assert session_row.device_id == "laptop-employee"
    assert session_row.is_active


# --- MFA -----------------------------------------------------------------
def test_totp_verification_accepts_the_current_code_and_rejects_others():
    secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
    assert verify_totp(secret, totp_now(secret))
    assert not verify_totp(secret, "000000")


def test_mfa_enrolment_then_login_requires_a_code(client, auth_header):
    header = auth_header("employee")
    enrolled = client.post("/api/auth/mfa/enroll", headers=header).json()
    assert enrolled["otpauth_uri"].startswith("otpauth://totp/")

    activated = client.post(
        "/api/auth/mfa/activate", json={"code": totp_now(enrolled["secret"])}, headers=header
    )
    assert activated.status_code == 200 and activated.json()["mfa_enabled"] is True

    password = TEST_USERS["employee"][0]
    without_code = client.post("/api/auth/login", json={"username": "employee", "password": password})
    assert without_code.status_code == 401
    assert without_code.headers.get("X-MFA-Required") == "true"

    wrong_code = client.post(
        "/api/auth/login", json={"username": "employee", "password": password, "totp_code": "123456"}
    )
    assert wrong_code.status_code == 401

    good = client.post(
        "/api/auth/login",
        json={"username": "employee", "password": password, "totp_code": totp_now(enrolled["secret"])},
    )
    assert good.status_code == 200 and good.json()["mfa_satisfied"] is True


def test_mfa_raises_the_trust_score(client, auth_header):
    header = auth_header("employee")
    secret = client.post("/api/auth/mfa/enroll", headers=header).json()["secret"]
    client.post("/api/auth/mfa/activate", json={"code": totp_now(secret)}, headers=header)
    password = TEST_USERS["employee"][0]
    with_mfa = client.post(
        "/api/auth/login",
        json={"username": "employee", "password": password, "totp_code": totp_now(secret),
              "device_id": "laptop-employee"},
    ).json()
    assert with_mfa["trust_score"] >= 90


# --- RBAC ----------------------------------------------------------------
def test_only_admins_may_create_users(client, auth_header):
    payload = {"username": "intruder", "email": "i@example.com", "password": "Str0ng!Password1",
               "role": "ADMIN"}
    assert client.post("/api/auth/register", json=payload, headers=auth_header("employee")).status_code == 403
    assert client.post("/api/auth/register", json=payload, headers=auth_header("admin")).status_code == 201


def test_weak_passwords_are_rejected(client, auth_header):
    payload = {"username": "weakling", "email": "w@example.com", "password": "passwordpassword"}
    assert client.post("/api/auth/register", json=payload, headers=auth_header("admin")).status_code == 422


def test_only_admins_may_read_the_audit_trail(client, auth_header):
    assert client.get("/api/audit", headers=auth_header("employee")).status_code == 403
    assert client.get("/api/audit", headers=auth_header("admin")).status_code == 200


def test_role_change_is_audited(client, auth_header):
    admin = auth_header("admin")
    assert client.patch("/api/auth/users/guest/role?role=EMPLOYEE", headers=admin).status_code == 200
    entries = client.get("/api/audit?action=CHANGE_ROLE", headers=admin).json()
    assert entries and entries[0]["detail"]["to"] == "EMPLOYEE"


def test_failed_logins_are_audited(client, auth_header):
    client.post("/api/auth/login", json={"username": "admin", "password": "wrong-password"})
    entries = client.get("/api/audit?action=LOGIN", headers=auth_header("admin")).json()
    assert any(e["outcome"] == "FAILURE" for e in entries)


def test_security_headers_and_request_id(client):
    response = client.get("/health")
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["X-Request-ID"]


def test_login_rate_limit(client, monkeypatch):
    from zta.common import ratelimit

    ratelimit.reset()
    monkeypatch.setattr(settings, "login_rate_limit_requests", 4)
    codes = [
        client.post("/api/auth/login", json={"username": "admin", "password": "x"}).status_code
        for _ in range(7)
    ]
    assert 429 in codes
    ratelimit.reset()
