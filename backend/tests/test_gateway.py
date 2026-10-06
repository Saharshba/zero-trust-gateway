"""End-to-end tests through the gateway.

These drive the real enforcement path: gateway → signed PDP call → policy
evaluation → signed upstream call, with only the transport swapped for an
in-process one.
"""
from __future__ import annotations

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from tests.conftest import TEST_USERS
from zta.common.models import AccessLog, Decision
from zta.common.security import sign_request, totp_now


def bearer(token: str, device_id: str | None = None, source_ip: str = "10.0.0.5") -> dict[str, str]:
    """Auth headers for a gateway call.

    TestClient reports a source of "testclient", so the forwarded-for header
    stands in for the real client address the way a TLS terminator would set
    it. Policies that gate on the corporate network need a plausible one.
    """
    headers = {"Authorization": f"Bearer {token}", "X-Forwarded-For": source_ip}
    if device_id:
        headers["X-Device-Id"] = device_id
    return headers


@pytest.fixture
def employee_token(client):
    return client.post(
        "/api/auth/login",
        json={"username": "employee", "password": TEST_USERS["employee"][0], "device_id": "laptop-employee"},
    ).json()["access_token"]


@pytest.fixture
def guest_token(client):
    return client.post(
        "/api/auth/login", json={"username": "guest", "password": TEST_USERS["guest"][0]}
    ).json()["access_token"]


@pytest.fixture
def admin_mfa_token(client, auth_header):
    """An admin who has completed MFA on a managed device: maximum trust."""
    header = auth_header("admin")
    secret = client.post("/api/auth/mfa/enroll", headers=header).json()["secret"]
    client.post("/api/auth/mfa/activate", json={"code": totp_now(secret)}, headers=header)
    return client.post(
        "/api/auth/login",
        json={"username": "admin", "password": TEST_USERS["admin"][0], "totp_code": totp_now(secret),
              "device_id": "laptop-admin"},
    ).json()["access_token"]


# --- the default is deny -------------------------------------------------
def test_request_without_a_token_is_denied(gateway):
    response = gateway.get("/reports/q1")
    assert response.status_code == 401
    assert response.headers["X-ZTA-Decision"] == "DENY"
    assert "token" in response.json()["reason"].lower()


def test_invalid_token_is_denied(gateway):
    response = gateway.get("/reports/q1", headers=bearer("clearly-not-a-jwt"))
    assert response.status_code == 401
    assert "invalid" in response.json()["reason"].lower()


def test_unknown_path_is_denied_rather_than_proxied(gateway, employee_token):
    response = gateway.get("/not-a-registered-resource", headers=bearer(employee_token))
    assert response.status_code == 403
    assert "No resource is registered" in response.json()["reason"]


# --- allow paths ---------------------------------------------------------
def test_employee_on_a_managed_device_reaches_reports(gateway, employee_token):
    response = gateway.get("/reports/q1", headers=bearer(employee_token))
    assert response.status_code == 200
    assert response.headers["X-ZTA-Decision"] == "ALLOW"
    assert response.headers["X-ZTA-Policy"] == "allow-employee-reports"

    body = response.json()
    assert body["service"] == "reports"
    # The path the upstream sees has the resource prefix stripped.
    assert body["path"] == "/q1"
    # The upstream is told who the caller is, without ever seeing their token.
    assert body["caller"]["user"] == "employee"
    assert body["caller"]["role"] == "EMPLOYEE"


def test_guest_may_read_the_public_service(gateway, guest_token):
    assert gateway.get("/public/status", headers=bearer(guest_token)).status_code == 200


def test_admin_with_mfa_reaches_the_restricted_console(gateway, admin_mfa_token):
    response = gateway.get("/admin/users", headers=bearer(admin_mfa_token))
    assert response.status_code == 200, response.json()
    assert response.headers["X-ZTA-Policy"] == "allow-admin-console"
    assert int(response.headers["X-ZTA-Trust-Score"]) >= 80


# --- deny paths ----------------------------------------------------------
def test_guest_cannot_reach_internal_reports(gateway, guest_token):
    response = gateway.get("/reports/q1", headers=bearer(guest_token))
    assert response.status_code == 403
    assert response.json()["reason"]


def test_guest_cannot_write_anywhere(gateway, guest_token):
    response = gateway.post("/public/status", headers=bearer(guest_token), json={})
    assert response.status_code == 403
    assert response.headers.get("X-ZTA-Policy") == "deny-guest-writes"


def test_admin_without_mfa_is_denied_the_restricted_console(gateway, client, auth_header):
    token = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": TEST_USERS["admin"][0], "device_id": "laptop-admin"},
    ).json()["access_token"]
    response = gateway.get("/admin/users", headers=bearer(token))
    assert response.status_code == 403
    assert "MFA" in response.json()["reason"]


def test_employee_on_an_unmanaged_device_is_denied(gateway, client):
    token = client.post(
        "/api/auth/login", json={"username": "employee", "password": TEST_USERS["employee"][0]}
    ).json()["access_token"]
    response = gateway.get("/reports/q1", headers=bearer(token))
    assert response.status_code == 403
    assert "device registration" in response.json()["reason"] or "trust" in response.json()["reason"]


def test_quarantining_a_device_cuts_access_off(gateway, client, auth_header):
    token = client.post(
        "/api/auth/login",
        json={"username": "employee", "password": TEST_USERS["employee"][0], "device_id": "laptop-employee"},
    ).json()["access_token"]
    assert gateway.get("/reports/q1", headers=bearer(token)).status_code == 200

    client.patch("/api/devices/laptop-employee", json={"status": "QUARANTINED"}, headers=auth_header("admin"))
    gateway.app.state.pdp.cache.clear()      # the cached ALLOW would otherwise stand for a few seconds

    denied = gateway.get("/reports/q1", headers=bearer(token))
    assert denied.status_code == 403


def test_logout_stops_the_gateway_from_forwarding(gateway, client, employee_token):
    assert gateway.get("/reports/q1", headers=bearer(employee_token)).status_code == 200
    client.post("/api/auth/logout", headers=bearer(employee_token))
    gateway.app.state.pdp.cache.clear()
    assert gateway.get("/reports/q1", headers=bearer(employee_token)).status_code == 401


def test_a_new_deny_policy_takes_effect(gateway, client, auth_header, employee_token):
    assert gateway.get("/reports/q1", headers=bearer(employee_token)).status_code == 200

    client.post(
        "/api/policies",
        json={"name": "incident-freeze", "effect": "DENY", "priority": 1, "resources": ["reports"],
              "description": "Temporary freeze during an incident."},
        headers=auth_header("admin"),
    )
    gateway.app.state.pdp.cache.clear()

    denied = gateway.get("/reports/q1", headers=bearer(employee_token))
    assert denied.status_code == 403
    assert denied.headers["X-ZTA-Policy"] == "incident-freeze"


# --- the gateway is the only way in --------------------------------------
def test_internal_service_rejects_unsigned_requests(internal_app):
    """Reaching the internal network is not enough to reach the service."""
    with TestClient(internal_app) as direct:
        response = direct.get("/q1")
    assert response.status_code == 403
    assert "gateway" in response.json()["detail"].lower()


def test_internal_service_rejects_a_forged_signature(internal_app):
    with TestClient(internal_app) as direct:
        response = direct.get(
            "/q1", headers={"X-Gateway-Signature": "deadbeef", "X-Gateway-Timestamp": "1700000000"}
        )
    assert response.status_code == 403


def test_internal_service_rejects_a_replayed_signature(internal_app):
    """A valid signature from long ago is outside the replay window."""
    signature, _ = sign_request("GET", "/q1", timestamp=1_700_000_000)
    with TestClient(internal_app) as direct:
        response = direct.get(
            "/q1", headers={"X-Gateway-Signature": signature, "X-Gateway-Timestamp": "1700000000"}
        )
    assert response.status_code == 403


def test_pdp_rejects_calls_that_are_not_from_the_gateway(client):
    """The decision endpoint is not a public API."""
    response = client.post("/internal/authorize", json={"method": "GET", "path": "/public"})
    assert response.status_code == 401
    assert "signature" in response.json()["detail"].lower()


# --- failure behaviour ---------------------------------------------------
def test_gateway_fails_closed_when_the_pdp_is_unreachable(gateway, employee_token):
    class Broken:
        async def post(self, *args, **kwargs):
            raise httpx.ConnectError("control plane is down")

        async def aclose(self):
            pass

    gateway.app.state.pdp.cache.clear()
    gateway.app.state.pdp._client = Broken()

    response = gateway.get("/reports/q1", headers=bearer(employee_token))
    assert response.status_code == 503
    assert "denied" in response.json()["detail"].lower()


def test_gateway_reports_upstream_failure_as_502(gateway, employee_token):
    class Broken:
        async def request(self, *args, **kwargs):
            raise httpx.ConnectError("upstream is down")

        async def aclose(self):
            pass

    gateway.app.state.upstream = Broken()
    assert gateway.get("/reports/q1", headers=bearer(employee_token)).status_code == 502


# --- evidence ------------------------------------------------------------
def test_every_decision_is_written_to_the_access_log(gateway, db, employee_token, guest_token):
    gateway.get("/reports/q1", headers=bearer(employee_token))
    gateway.get("/reports/q1", headers=bearer(guest_token))
    gateway.get("/reports/q1")

    logs = db.scalars(select(AccessLog).order_by(AccessLog.id)).all()
    decisions = [(log.username, log.decision, log.resource) for log in logs]
    assert ("employee", Decision.ALLOW, "reports") in decisions
    assert ("guest", Decision.DENY, "reports") in decisions
    assert ("anonymous", Decision.DENY, "reports") in decisions
    assert all(log.reason for log in logs), "a decision without a reason is not auditable"
    assert all(log.latency_ms >= 0 for log in logs)


def test_access_log_is_queryable_and_feeds_the_dashboard(gateway, client, auth_header, employee_token,
                                                         guest_token):
    gateway.get("/reports/q1", headers=bearer(employee_token))
    gateway.get("/admin/users", headers=bearer(guest_token))

    admin = auth_header("admin")
    denied = client.get("/api/access-logs?decision=DENY", headers=admin).json()
    assert denied["meta"]["total"] >= 1
    assert all(item["decision"] == "DENY" for item in denied["items"])

    stats = client.get("/api/statistics?window_minutes=60", headers=admin).json()
    assert stats["total_requests"] >= 2
    assert stats["allowed"] + stats["denied"] == stats["total_requests"]
    assert 0 <= stats["deny_rate"] <= 1
    assert stats["registered_devices"] >= 2
    assert stats["decisions_over_time"]
    assert stats["top_deny_reasons"]


def test_decision_cache_avoids_a_second_pdp_call(gateway, db, employee_token):
    """Repeated identical requests are served from the cache within its TTL."""
    gateway.get("/reports/q1", headers=bearer(employee_token))
    first = db.scalar(select(AccessLog).order_by(AccessLog.id.desc()))
    gateway.get("/reports/q1", headers=bearer(employee_token))
    second = db.scalar(select(AccessLog).order_by(AccessLog.id.desc()))
    assert first.id == second.id, "the cached decision should not have hit the PDP again"


def test_denials_are_never_cached(gateway, db, guest_token):
    """A denial must be recomputed every time, so a policy fix applies at once."""
    gateway.get("/reports/q1", headers=bearer(guest_token))
    first_count = len(db.scalars(select(AccessLog)).all())
    gateway.get("/reports/q1", headers=bearer(guest_token))
    assert len(db.scalars(select(AccessLog)).all()) == first_count + 1


def test_request_id_is_propagated_end_to_end(gateway, employee_token, db):
    response = gateway.get(
        "/reports/q1", headers={**bearer(employee_token), "X-Request-ID": "trace-me-123"}
    )
    assert response.headers["X-Request-ID"] == "trace-me-123"
    log = db.scalar(select(AccessLog).order_by(AccessLog.id.desc()))
    assert log.request_id == "trace-me-123"


def test_gateway_health_needs_no_authentication(gateway):
    assert gateway.get("/health").json()["component"] == "gateway"


def test_admin_off_the_corporate_network_is_denied(gateway, admin_mfa_token):
    """Same identity, same device, same MFA - but the wrong network."""
    response = gateway.get("/admin/users", headers=bearer(admin_mfa_token, source_ip="203.0.113.9"))
    assert response.status_code == 403
    assert "source network" in response.json()["reason"]
