"""The policy decision point.

Everything the gateway asks about a request funnels through `authorize`:
resolve the resource, identify the caller, score the device, evaluate the
policies, and hand back a decision plus the upstream to forward to.
"""
from __future__ import annotations

from dataclasses import dataclass

import jwt
from sqlalchemy import select
from sqlalchemy.orm import Session

from zta.common.models import Device, DeviceStatus, Policy, Resource, User
from zta.common.models import Session as SessionRow
from zta.common.security import decode_token
from zta.policy import AccessContext, DecisionResult, DevicePosture, evaluate, policy_from_orm, trust_score

# Networks the organisation controls. Being on one raises the trust score a
# little - it never grants access by itself, which is the zero-trust part.
KNOWN_NETWORKS = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]


@dataclass
class Identity:
    authenticated: bool = False
    username: str = "anonymous"
    role: str = ""
    device_id: str | None = None
    mfa_satisfied: bool = False
    failure_reason: str = ""


def identify(db: Session, access_token: str | None) -> Identity:
    """Validate the bearer token and confirm its session is still live."""
    if not access_token:
        return Identity(failure_reason="No access token presented")
    try:
        claims = decode_token(access_token)
    except jwt.ExpiredSignatureError:
        return Identity(failure_reason="Access token has expired")
    except jwt.PyJWTError:
        return Identity(failure_reason="Access token is invalid")

    sid = claims.get("sid")
    if sid:
        session_row = db.scalar(select(SessionRow).where(SessionRow.jti == sid))
        if session_row is None or not session_row.is_active:
            return Identity(failure_reason="Session has been revoked")

    user = db.scalar(select(User).where(User.username == claims.get("sub")))
    if user is None or not user.is_active:
        return Identity(failure_reason="User is unknown or disabled")

    return Identity(
        authenticated=True,
        username=user.username,
        role=user.role.value,
        device_id=claims.get("device_id"),
        mfa_satisfied=bool(claims.get("mfa")),
    )


def posture_for(db: Session, device_id: str | None) -> DevicePosture:
    if not device_id:
        return DevicePosture()
    device = db.scalar(select(Device).where(Device.device_id == device_id))
    if device is None:
        return DevicePosture(device_id=device_id)
    return DevicePosture(
        device_id=device.device_id,
        registered=device.status == DeviceStatus.REGISTERED,
        quarantined=device.status in (DeviceStatus.QUARANTINED, DeviceStatus.REVOKED),
        disk_encrypted=device.disk_encrypted,
        screen_lock=device.screen_lock,
        os_up_to_date=device.os_up_to_date,
        endpoint_protection=device.endpoint_protection,
    )


def resolve_resource(db: Session, path: str) -> Resource | None:
    """Longest matching path prefix wins, so /admin beats /."""
    resources = db.scalars(select(Resource).where(Resource.enabled.is_(True))).all()
    matches = [r for r in resources if path == r.path_prefix or path.startswith(r.path_prefix.rstrip("/") + "/")]
    if not matches:
        return None
    return max(matches, key=lambda r: len(r.path_prefix))


def upstream_path(resource: Resource, path: str) -> str:
    if not resource.strip_prefix:
        return path
    trimmed = path[len(resource.path_prefix.rstrip("/")):] or "/"
    return trimmed if trimmed.startswith("/") else f"/{trimmed}"


@dataclass
class AuthorizationOutcome:
    result: DecisionResult
    identity: Identity
    resource: Resource | None
    context: AccessContext


def authorize(
    db: Session,
    *,
    method: str,
    path: str,
    source_ip: str = "",
    access_token: str | None = None,
    device_id_header: str | None = None,
) -> AuthorizationOutcome:
    identity = identify(db, access_token)
    # The header is only a hint; the token's device binding wins when present,
    # otherwise a caller could claim any device id.
    device_id = identity.device_id or device_id_header
    posture = posture_for(db, device_id)
    score = trust_score(
        authenticated=identity.authenticated,
        mfa_satisfied=identity.mfa_satisfied,
        posture=posture,
        source_ip=source_ip,
        known_networks=KNOWN_NETWORKS,
    )
    resource = resolve_resource(db, path)

    context = AccessContext(
        method=method.upper(),
        path=path,
        resource=resource.name if resource else "",
        classification=resource.classification.value if resource else "INTERNAL",
        authenticated=identity.authenticated,
        username=identity.username,
        role=identity.role,
        mfa_satisfied=identity.mfa_satisfied,
        source_ip=source_ip,
        posture=posture,
        trust_score=score,
    )

    if not identity.authenticated:
        result = DecisionResult(decision="DENY", reason=identity.failure_reason, trust_score=score)
    elif resource is None:
        # Unknown paths are denied rather than passed through: the gateway
        # exposes exactly the resources that were registered, nothing else.
        result = DecisionResult(
            decision="DENY", reason=f"No resource is registered for path {path}", trust_score=score
        )
    else:
        policies = [policy_from_orm(p) for p in db.scalars(select(Policy)).all()]
        result = evaluate(context, policies)

    return AuthorizationOutcome(result=result, identity=identity, resource=resource, context=context)
