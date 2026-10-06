"""First-run seeding: the admin account, the demo resources and a policy set.

The seeded policies are a worked example of the model, not a recommendation to
copy verbatim: they show role, device, MFA, network, trust-score and time
conditions all being used.
"""
from __future__ import annotations

import logging

from sqlalchemy import select
from sqlalchemy.orm import Session

from zta.common.config import settings
from zta.common.models import Classification, Effect, Policy, PolicyRevision, Resource, Role, User
from zta.common.security import hash_password

logger = logging.getLogger(__name__)

DEMO_RESOURCES = [
    {
        "name": "public",
        "path_prefix": "/public",
        "upstream_url": "http://internal-public:9001",
        "classification": Classification.PUBLIC,
        "description": "Status page. Reachable by any authenticated identity.",
    },
    {
        "name": "reports",
        "path_prefix": "/reports",
        "upstream_url": "http://internal-reports:9002",
        "classification": Classification.INTERNAL,
        "description": "Internal reporting service. Employees on managed devices.",
    },
    {
        "name": "admin",
        "path_prefix": "/admin",
        "upstream_url": "http://internal-admin:9003",
        "classification": Classification.RESTRICTED,
        "description": "Administrative console. Admins, MFA, corporate network only.",
    },
]

DEMO_POLICIES = [
    {
        "name": "deny-guest-writes",
        "description": "Guests may read, never modify. Evaluated before any allow rule.",
        "effect": Effect.DENY,
        "priority": 5,
        "roles": [Role.GUEST.value],
        "methods": ["POST", "PUT", "PATCH", "DELETE"],
    },
    {
        "name": "deny-weekend-reports",
        "description": "Internal reporting is closed at the weekend.",
        "effect": Effect.DENY,
        "priority": 8,
        "roles": [Role.EMPLOYEE.value],
        "resources": ["reports"],
        "weekdays": [5, 6],
    },
    {
        "name": "allow-admin-console",
        "description": "Admins, from the corporate network, on a managed device, with MFA.",
        "effect": Effect.ALLOW,
        "priority": 10,
        "roles": [Role.ADMIN.value],
        "resources": ["admin"],
        "source_cidrs": ["10.0.0.0/8", "192.168.0.0/16"],
        "require_registered_device": True,
        "require_mfa": True,
        "min_trust_score": 80,
    },
    {
        "name": "allow-employee-reports",
        "description": "Employees and admins may use reporting from a managed device.",
        "effect": Effect.ALLOW,
        "priority": 20,
        "roles": [Role.EMPLOYEE.value, Role.ADMIN.value],
        "resources": ["reports"],
        "require_registered_device": True,
        "min_trust_score": 60,
    },
    {
        "name": "allow-public-read",
        "description": "Any authenticated identity may read the public service.",
        "effect": Effect.ALLOW,
        "priority": 50,
        "roles": [Role.GUEST.value, Role.EMPLOYEE.value, Role.ADMIN.value],
        "resources": ["public"],
        "methods": ["GET", "HEAD"],
    },
]


def seed_admin(db: Session) -> User:
    user = db.scalar(select(User).where(User.username == settings.bootstrap_admin_username))
    if user is not None:
        return user
    user = User(
        username=settings.bootstrap_admin_username,
        email=settings.bootstrap_admin_email,
        hashed_password=hash_password(settings.bootstrap_admin_password),
        role=Role.ADMIN,
    )
    db.add(user)
    db.commit()
    logger.warning("created bootstrap admin %r - change this password now", user.username)
    return user


def seed_resources(db: Session) -> int:
    created = 0
    for spec in DEMO_RESOURCES:
        if db.scalar(select(Resource).where(Resource.name == spec["name"])):
            continue
        db.add(Resource(**spec))
        created += 1
    if created:
        db.commit()
    return created


def seed_policies(db: Session) -> int:
    created = 0
    for spec in DEMO_POLICIES:
        if db.scalar(select(Policy).where(Policy.name == spec["name"])):
            continue
        policy = Policy(**spec, version=1)
        db.add(policy)
        db.flush()
        db.add(
            PolicyRevision(
                policy_id=policy.id,
                version=1,
                changed_by="system",
                snapshot={"seeded": True, **{k: str(v) for k, v in spec.items()}},
            )
        )
        created += 1
    if created:
        db.commit()
        logger.info("seeded %d policies", created)
    return created


def bootstrap(db: Session) -> None:
    seed_admin(db)
    if settings.seed_demo_data:
        seed_resources(db)
        seed_policies(db)
