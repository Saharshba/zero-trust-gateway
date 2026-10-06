"""Policy, resource and device administration through the API."""
from __future__ import annotations

from sqlalchemy import select

from zta.common.models import Device, DeviceStatus, Policy

NEW_POLICY = {
    "name": "allow-contractors-reports",
    "description": "Contractors may read reports during business hours.",
    "effect": "ALLOW",
    "priority": 30,
    "roles": ["EMPLOYEE"],
    "resources": ["reports"],
    "methods": ["GET"],
    "source_cidrs": ["10.10.0.0/16"],
    "require_registered_device": True,
    "require_mfa": False,
    "min_trust_score": 70,
    "time_start_hour": 9,
    "time_end_hour": 18,
    "weekdays": [0, 1, 2, 3, 4],
}


def test_policies_are_listed_in_evaluation_order(client, auth_header):
    policies = client.get("/api/policies", headers=auth_header("employee")).json()
    priorities = [p["priority"] for p in policies]
    assert priorities == sorted(priorities)
    assert {p["name"] for p in policies} >= {"allow-public-read", "deny-guest-writes"}


def test_create_policy_requires_admin(client, auth_header):
    assert client.post("/api/policies", json=NEW_POLICY, headers=auth_header("employee")).status_code == 403
    created = client.post("/api/policies", json=NEW_POLICY, headers=auth_header("admin"))
    assert created.status_code == 201
    assert created.json()["version"] == 1


def test_duplicate_policy_names_are_rejected(client, auth_header):
    admin = auth_header("admin")
    client.post("/api/policies", json=NEW_POLICY, headers=admin)
    assert client.post("/api/policies", json=NEW_POLICY, headers=admin).status_code == 409


def test_policy_validation(client, auth_header):
    admin = auth_header("admin")
    bad_cidr = {**NEW_POLICY, "name": "bad-cidr", "source_cidrs": ["10.0.0.0/64"]}
    bad_method = {**NEW_POLICY, "name": "bad-method", "methods": ["FETCH"]}
    bad_trust = {**NEW_POLICY, "name": "bad-trust", "min_trust_score": 500}
    bad_weekday = {**NEW_POLICY, "name": "bad-day", "weekdays": [9]}
    for payload in (bad_cidr, bad_method, bad_trust, bad_weekday):
        assert client.post("/api/policies", json=payload, headers=admin).status_code == 422


def test_updating_a_policy_bumps_the_version_and_records_a_revision(client, auth_header):
    admin = auth_header("admin")
    policy = client.post("/api/policies", json=NEW_POLICY, headers=admin).json()

    updated = client.patch(
        f"/api/policies/{policy['id']}", json={"min_trust_score": 85, "enabled": False}, headers=admin
    ).json()
    assert updated["version"] == 2
    assert updated["min_trust_score"] == 85

    revisions = client.get(f"/api/policies/{policy['id']}/revisions", headers=admin).json()
    assert [r["version"] for r in revisions] == [2, 1]
    assert revisions[0]["snapshot"]["min_trust_score"] == 85
    assert revisions[0]["changed_by"] == "admin"


def test_policies_are_disabled_not_deleted(client, auth_header, db):
    admin = auth_header("admin")
    policy = client.post("/api/policies", json=NEW_POLICY, headers=admin).json()
    assert client.delete(f"/api/policies/{policy['id']}", headers=admin).status_code == 204

    row = db.get(Policy, policy["id"])
    assert row is not None and row.enabled is False
    assert client.get(f"/api/policies/{policy['id']}/revisions", headers=admin).json()


def test_policy_changes_are_audited(client, auth_header):
    admin = auth_header("admin")
    client.post("/api/policies", json=NEW_POLICY, headers=admin)
    entries = client.get("/api/audit?action=CREATE_POLICY", headers=admin).json()
    assert entries and entries[0]["resource"] == "policy:allow-contractors-reports"


# --- resources -----------------------------------------------------------
def test_resources_are_seeded_and_creatable_by_admins(client, auth_header):
    admin = auth_header("admin")
    names = {r["name"] for r in client.get("/api/resources", headers=admin).json()}
    assert names == {"public", "reports", "admin"}

    payload = {"name": "wiki", "path_prefix": "/wiki", "upstream_url": "http://internal-wiki:9004"}
    assert client.post("/api/resources", json=payload, headers=auth_header("guest")).status_code == 403
    assert client.post("/api/resources", json=payload, headers=admin).status_code == 201
    assert client.post("/api/resources", json=payload, headers=admin).status_code == 409


# --- devices -------------------------------------------------------------
def test_enrolled_devices_start_pending(client, auth_header, db):
    payload = {
        "device_id": "new-laptop-01",
        "name": "Dev laptop",
        "platform": "Linux",
        "disk_encrypted": True,
        "screen_lock": True,
        "os_up_to_date": True,
        "endpoint_protection": True,
    }
    created = client.post("/api/devices", json=payload, headers=auth_header("employee"))
    assert created.status_code == 201
    assert created.json()["status"] == "PENDING"

    device = db.scalar(select(Device).where(Device.device_id == "new-laptop-01"))
    assert device.status == DeviceStatus.PENDING


def test_users_only_see_their_own_devices(client, auth_header):
    employee_devices = {d["device_id"] for d in client.get("/api/devices", headers=auth_header("employee")).json()}
    admin_devices = {d["device_id"] for d in client.get("/api/devices", headers=auth_header("admin")).json()}
    assert "laptop-admin" not in employee_devices
    assert admin_devices > employee_devices     # admins see the whole fleet


def test_a_device_cannot_be_claimed_by_a_second_user(client, auth_header):
    payload = {"device_id": "laptop-employee", "name": "stolen"}
    assert client.post("/api/devices", json=payload, headers=auth_header("guest")).status_code == 409


def test_admins_approve_and_quarantine_devices(client, auth_header):
    admin = auth_header("admin")
    client.post("/api/devices", json={"device_id": "new-laptop-02"}, headers=auth_header("employee"))

    approved = client.patch("/api/devices/new-laptop-02", json={"status": "REGISTERED"}, headers=admin)
    assert approved.status_code == 200 and approved.json()["status"] == "REGISTERED"

    assert client.patch(
        "/api/devices/new-laptop-02", json={"status": "QUARANTINED"}, headers=auth_header("employee")
    ).status_code == 403
    assert client.patch("/api/devices/unknown-device", json={"status": "REGISTERED"},
                        headers=admin).status_code == 404


def test_device_id_format_is_validated(client, auth_header):
    assert client.post(
        "/api/devices", json={"device_id": "bad id with spaces"}, headers=auth_header("employee")
    ).status_code == 422


# --- simulator -----------------------------------------------------------
def test_simulator_explains_what_would_happen(client, auth_header):
    admin = auth_header("admin")
    denied = client.post(
        "/api/simulate",
        json={"username": "guest", "path": "/admin/users", "method": "GET", "source_ip": "10.0.0.5"},
        headers=admin,
    ).json()
    assert denied["decision"] == "DENY"

    allowed = client.post(
        "/api/simulate",
        json={"username": "guest", "path": "/public/status", "method": "GET", "source_ip": "10.0.0.5"},
        headers=admin,
    ).json()
    assert allowed["decision"] == "ALLOW"
    assert allowed["matched_policy"] == "allow-public-read"


def test_simulator_does_not_write_to_the_access_log(client, auth_header):
    admin = auth_header("admin")
    before = client.get("/api/access-logs", headers=admin).json()["meta"]["total"]
    client.post("/api/simulate", json={"username": "guest", "path": "/public/status"}, headers=admin)
    after = client.get("/api/access-logs", headers=admin).json()["meta"]["total"]
    assert before == after


def test_simulator_rejects_unknown_users(client, auth_header):
    response = client.post(
        "/api/simulate", json={"username": "ghost", "path": "/public"}, headers=auth_header("admin")
    )
    assert response.status_code == 404
