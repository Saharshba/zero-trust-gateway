"""Audit trail for administrative actions, and the access-decision log."""
from __future__ import annotations

import logging

from fastapi import Request
from sqlalchemy.orm import Session

from zta.common.models import AccessLog, AuditLog, Decision

logger = logging.getLogger("audit")


def client_ip(request: Request | None) -> str:
    """Source IP, honouring X-Forwarded-For when a proxy sits in front."""
    if request is None:
        return ""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else ""


def record(
    db: Session,
    *,
    username: str,
    action: str,
    resource: str = "",
    outcome: str = "SUCCESS",
    request: Request | None = None,
    detail: dict | None = None,
    commit: bool = True,
) -> AuditLog:
    entry = AuditLog(
        username=username,
        action=action,
        resource=resource,
        outcome=outcome,
        source_ip=client_ip(request),
        detail=detail or {},
    )
    db.add(entry)
    if commit:
        db.commit()
    logger.info("%s %s %s -> %s", username, action, resource, outcome)
    return entry


def record_decision(
    db: Session,
    *,
    request_id: str,
    username: str,
    role: str,
    device_id: str,
    source_ip: str,
    method: str,
    path: str,
    resource: str,
    decision: str,
    reason: str,
    matched_policy: str | None = None,
    policy_version: int | None = None,
    trust_score: float = 0.0,
    latency_ms: float = 0.0,
    upstream_status: int | None = None,
    commit: bool = True,
) -> AccessLog:
    """Write one row per authorisation decision - allow and deny alike."""
    entry = AccessLog(
        request_id=request_id,
        username=username or "anonymous",
        role=role,
        device_id=device_id or "",
        source_ip=source_ip,
        method=method,
        path=path,
        resource=resource,
        decision=Decision(decision),
        reason=reason[:255],
        matched_policy=matched_policy,
        policy_version=policy_version,
        trust_score=trust_score,
        latency_ms=latency_ms,
        upstream_status=upstream_status,
    )
    db.add(entry)
    if commit:
        db.commit()
    logger.info(
        "%s %s %s %s -> %s (%s)", username or "anonymous", method, path, source_ip, decision, reason
    )
    return entry
