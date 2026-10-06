"""Fixtures.

The environment is set before importing `zta`, because settings and the
SQLAlchemy engine are created at import time.
"""
from __future__ import annotations

import os

os.environ.setdefault("DATABASE_URL", "sqlite://")
os.environ.setdefault("REDIS_ENABLED", "false")
os.environ.setdefault("SECRET_KEY", "test-secret-key-that-is-long-enough-000")
os.environ.setdefault("GATEWAY_SIGNING_KEY", "test-gateway-signing-key")
os.environ.setdefault("BCRYPT_ROUNDS", "4")
os.environ.setdefault("RATE_LIMIT_REQUESTS", "100000")
os.environ.setdefault("LOGIN_RATE_LIMIT_REQUESTS", "100000")
os.environ.setdefault("SEED_DEMO_DATA", "false")

from contextlib import asynccontextmanager  # noqa: E402

import httpx  # noqa: E402
import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import (
    create_engine,  # noqa: E402
    select,  # noqa: E402
)
from sqlalchemy.orm import sessionmaker  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402

from zta.common.database import Base, get_db  # noqa: E402
from zta.common.models import Device, DeviceStatus, Policy, Role, User  # noqa: E402
from zta.common.security import hash_password  # noqa: E402
from zta.control_plane.app import create_app as create_control_plane  # noqa: E402
from zta.control_plane.bootstrap import seed_policies, seed_resources  # noqa: E402
from zta.gateway.app import create_app as create_gateway  # noqa: E402
from zta.services.internal_service import create_app as create_internal  # noqa: E402

TEST_USERS = {
    "admin": ("AdminPassw0rd!42", Role.ADMIN),
    "employee": ("EmployeePassw0rd!42", Role.EMPLOYEE),
    "guest": ("GuestPassw0rd!42", Role.GUEST),
}

# Devices used across the suite: one healthy managed laptop per user role,
# plus a quarantined one.
TEST_DEVICES = {
    "laptop-admin": ("admin", DeviceStatus.REGISTERED, True),
    "laptop-employee": ("employee", DeviceStatus.REGISTERED, True),
    "laptop-quarantined": ("employee", DeviceStatus.QUARANTINED, True),
    "laptop-pending": ("employee", DeviceStatus.PENDING, False),
}


@asynccontextmanager
async def _noop_lifespan(app):
    yield


@pytest.fixture
def db_engine():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    yield engine
    Base.metadata.drop_all(engine)
    engine.dispose()


@pytest.fixture
def session_factory(db_engine):
    return sessionmaker(bind=db_engine, autoflush=False, expire_on_commit=False)


@pytest.fixture
def db(session_factory):
    session = session_factory()
    try:
        yield session
    finally:
        session.close()


def _seed(session_factory) -> None:
    with session_factory() as session:
        for username, (password, role) in TEST_USERS.items():
            session.add(
                User(
                    username=username,
                    email=f"{username}@example.com",
                    hashed_password=hash_password(password),
                    role=role,
                )
            )
        session.commit()

        owners = {u.username: u.id for u in session.query(User).all()}
        for device_id, (owner, status, healthy) in TEST_DEVICES.items():
            session.add(
                Device(
                    device_id=device_id,
                    name=device_id,
                    owner_id=owners[owner],
                    status=status,
                    platform="macOS",
                    disk_encrypted=healthy,
                    screen_lock=healthy,
                    os_up_to_date=healthy,
                    endpoint_protection=healthy,
                )
            )
        seed_resources(session)
        seed_policies(session)

        # The seeded weekend rule would make every gateway test pass or fail
        # depending on the day it runs. Time-of-day and weekday evaluation is
        # covered deterministically in test_policy_engine.py with explicit
        # timestamps, so it is disabled for the API-level suite.
        weekend = session.scalar(select(Policy).where(Policy.name == "deny-weekend-reports"))
        if weekend is not None:
            weekend.enabled = False
        session.commit()


@pytest.fixture
def control_plane_app(session_factory):
    from zta.common import ratelimit

    ratelimit.reset()
    app = create_control_plane()
    app.router.lifespan_context = _noop_lifespan

    def override_get_db():
        session = session_factory()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_db] = override_get_db
    _seed(session_factory)
    return app


@pytest.fixture
def client(control_plane_app):
    with TestClient(control_plane_app) as test_client:
        yield test_client


@pytest.fixture
def internal_app():
    """One stand-in upstream, standing for all three internal services."""
    return create_internal("reports")


@pytest.fixture
def gateway(control_plane_app, internal_app):
    """The real gateway, with its two HTTP clients pointed at in-process apps.

    Nothing about the gateway itself is stubbed: it still signs its PDP calls,
    caches decisions and signs what it forwards upstream.
    """
    app = create_gateway()
    with TestClient(app) as test_client:
        app.state.pdp._client = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=control_plane_app), timeout=5.0
        )
        app.state.pdp.cache.clear()
        app.state.upstream = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=internal_app), timeout=5.0
        )
        yield test_client


def login(client: TestClient, username: str = "admin", **extra) -> dict:
    password, _ = TEST_USERS[username]
    response = client.post(
        "/api/auth/login", json={"username": username, "password": password, **extra}
    )
    assert response.status_code == 200, response.text
    return response.json()


@pytest.fixture
def auth_header(client):
    def _header(username: str = "admin", **extra) -> dict[str, str]:
        return {"Authorization": f"Bearer {login(client, username, **extra)['access_token']}"}

    return _header


@pytest.fixture
def token_for(client):
    def _token(username: str = "admin", **extra) -> str:
        return login(client, username, **extra)["access_token"]

    return _token
