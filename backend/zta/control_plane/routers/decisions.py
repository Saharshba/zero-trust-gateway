"""The PDP endpoint the gateway calls, plus a policy simulator."""
from __future__ import annotations

import time

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from zta.common import audit
from zta.common.database import get_db
from zta.common.models import Policy, User
from zta.common.schemas import AuthorizeRequest, AuthorizeResponse, SimulateRequest
from zta.control_plane.authorization import authorize, posture_for, resolve_resource, upstream_path
from zta.control_plane.deps import get_current_user, require_gateway
from zta.policy import AccessContext, evaluate, policy_from_orm, trust_score

router = APIRouter(tags=["decisions"])


@router.post("/internal/authorize", response_model=AuthorizeResponse, dependencies=[Depends(require_gateway)])
def authorize_request(
    payload: AuthorizeRequest, request: Request, db: Session = Depends(get_db)
) -> AuthorizeResponse:
    """Decide one request. Called only by the gateway, which signs its calls.

    Every decision - allowed or denied - is written to `access_logs` before the
    response is returned, so the evidence trail cannot be skipped by a gateway
    that crashes mid-request.
    """
    started = time.perf_counter()
    outcome = authorize(
        db,
        method=payload.method,
        path=payload.path,
        source_ip=payload.source_ip or audit.client_ip(request),
        access_token=payload.access_token,
        device_id_header=payload.device_id,
    )
    latency_ms = (time.perf_counter() - started) * 1000

    audit.record_decision(
        db,
        request_id=payload.request_id,
        username=outcome.identity.username,
        role=outcome.identity.role,
        device_id=outcome.context.posture.device_id or "",
        source_ip=outcome.context.source_ip,
        method=outcome.context.method,
        path=outcome.context.path,
        resource=outcome.context.resource,
        decision=outcome.result.decision,
        reason=outcome.result.reason,
        matched_policy=outcome.result.matched_policy,
        policy_version=outcome.result.policy_version,
        trust_score=outcome.result.trust_score,
        latency_ms=latency_ms,
    )

    resource = outcome.resource
    return AuthorizeResponse(
        decision=outcome.result.decision,
        reason=outcome.result.reason,
        matched_policy=outcome.result.matched_policy,
        policy_version=outcome.result.policy_version,
        trust_score=outcome.result.trust_score,
        username=outcome.identity.username,
        role=outcome.identity.role,
        resource=resource.name if resource else None,
        upstream_url=resource.upstream_url if (resource and outcome.result.allowed) else None,
        upstream_path=upstream_path(resource, payload.path) if (resource and outcome.result.allowed) else None,
        classification=resource.classification.value if resource else None,
    )


@router.post("/api/simulate", response_model=AuthorizeResponse)
def simulate(
    payload: SimulateRequest, db: Session = Depends(get_db), actor: User = Depends(get_current_user)
) -> AuthorizeResponse:
    """Answer "would this succeed?" without issuing the request.

    Useful when writing a policy: it reports the same reason string the real
    decision would produce, and it is not written to the access log because no
    access actually happened.
    """
    user = db.scalar(select(User).where(User.username == payload.username))
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    resource = resolve_resource(db, payload.path)
    posture = posture_for(db, payload.device_id)
    score = trust_score(
        authenticated=True,
        mfa_satisfied=payload.mfa_satisfied,
        posture=posture,
        source_ip=payload.source_ip,
    )
    context = AccessContext(
        method=payload.method.upper(),
        path=payload.path,
        resource=resource.name if resource else "",
        classification=resource.classification.value if resource else "INTERNAL",
        authenticated=True,
        username=user.username,
        role=user.role.value,
        mfa_satisfied=payload.mfa_satisfied,
        source_ip=payload.source_ip,
        posture=posture,
        trust_score=score,
    )

    if resource is None:
        return AuthorizeResponse(
            decision="DENY",
            reason=f"No resource is registered for path {payload.path}",
            trust_score=score,
            username=user.username,
            role=user.role.value,
        )

    result = evaluate(context, [policy_from_orm(p) for p in db.scalars(select(Policy)).all()])
    return AuthorizeResponse(
        decision=result.decision,
        reason=result.reason,
        matched_policy=result.matched_policy,
        policy_version=result.policy_version,
        trust_score=result.trust_score,
        username=user.username,
        role=user.role.value,
        resource=resource.name,
        classification=resource.classification.value,
    )
