"""Access-log queries, the dashboard aggregate and the admin audit trail."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from zta.common.database import get_db
from zta.common.models import (
    AccessLog,
    AuditLog,
    Decision,
    Device,
    DeviceStatus,
    Policy,
    User,
)
from zta.common.models import (
    Session as SessionRow,
)
from zta.common.schemas import (
    AccessLogOut,
    AccessLogPage,
    AuditOut,
    DecisionPoint,
    NamedCount,
    PageMeta,
    StatisticsOut,
)
from zta.control_plane.deps import get_current_user, require_admin

router = APIRouter(prefix="/api", tags=["insights"])


@router.get("/access-logs", response_model=AccessLogPage)
def access_logs(
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
    decision: Decision | None = None,
    username: str | None = None,
    resource: str | None = None,
    source_ip: str | None = None,
    since_hours: int | None = Query(default=None, ge=1, le=24 * 90),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> AccessLogPage:
    filters = []
    if decision:
        filters.append(AccessLog.decision == decision)
    if username:
        filters.append(AccessLog.username == username)
    if resource:
        filters.append(AccessLog.resource == resource)
    if source_ip:
        filters.append(AccessLog.source_ip == source_ip)
    if since_hours:
        filters.append(AccessLog.timestamp >= datetime.now(timezone.utc) - timedelta(hours=since_hours))

    total = db.scalar(select(func.count()).select_from(AccessLog).where(*filters)) or 0
    rows = db.scalars(
        select(AccessLog).where(*filters).order_by(AccessLog.timestamp.desc()).limit(limit).offset(offset)
    ).all()
    return AccessLogPage(
        items=[AccessLogOut.model_validate(r) for r in rows],
        meta=PageMeta(total=total, limit=limit, offset=offset),
    )


def _counts(db: Session, column, *filters, limit: int = 8) -> list[NamedCount]:
    rows = db.execute(
        select(column, func.count(AccessLog.id))
        .where(*filters)
        .group_by(column)
        .order_by(func.count(AccessLog.id).desc())
        .limit(limit)
    ).all()
    return [NamedCount(name=str(name or "—"), count=count) for name, count in rows]


@router.get("/statistics", response_model=StatisticsOut)
def statistics(
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
    window_minutes: int = Query(default=60, ge=5, le=60 * 24 * 30),
) -> StatisticsOut:
    """Everything the dashboard needs, in one query round."""
    now = datetime.now(timezone.utc)
    since = now - timedelta(minutes=window_minutes)
    in_window = (AccessLog.timestamp >= since,)

    total = db.scalar(select(func.count()).select_from(AccessLog).where(*in_window)) or 0
    allowed = (
        db.scalar(
            select(func.count()).select_from(AccessLog)
            .where(*in_window, AccessLog.decision == Decision.ALLOW)
        )
        or 0
    )
    denied = total - allowed

    average_trust = db.scalar(select(func.avg(AccessLog.trust_score)).where(*in_window)) or 0.0
    average_latency = db.scalar(select(func.avg(AccessLog.latency_ms)).where(*in_window)) or 0.0

    # Bucket by hour for the timeline. Doing it in Python keeps the query
    # portable between SQLite (tests) and PostgreSQL (deployment).
    rows = db.execute(
        select(AccessLog.timestamp, AccessLog.decision).where(*in_window).order_by(AccessLog.timestamp)
    ).all()
    buckets: dict[datetime, dict[str, int]] = {}
    granularity = timedelta(minutes=1 if window_minutes <= 120 else 60)
    for timestamp, verdict in rows:
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)
        seconds = int(granularity.total_seconds())
        epoch = int(timestamp.timestamp()) // seconds * seconds
        key = datetime.fromtimestamp(epoch, tz=timezone.utc)
        bucket = buckets.setdefault(key, {"allowed": 0, "denied": 0})
        bucket["allowed" if verdict == Decision.ALLOW else "denied"] += 1

    recent_denials = db.scalars(
        select(AccessLog)
        .where(AccessLog.decision == Decision.DENY)
        .order_by(AccessLog.timestamp.desc())
        .limit(10)
    ).all()

    return StatisticsOut(
        generated_at=now,
        window_minutes=window_minutes,
        total_requests=total,
        allowed=allowed,
        denied=denied,
        deny_rate=round(denied / total, 4) if total else 0.0,
        unique_users=db.scalar(
            select(func.count(func.distinct(AccessLog.username))).where(*in_window)
        ) or 0,
        active_sessions=db.scalar(
            select(func.count()).select_from(SessionRow)
            .where(SessionRow.revoked_at.is_(None), SessionRow.expires_at > now)
        ) or 0,
        registered_devices=db.scalar(
            select(func.count()).select_from(Device).where(Device.status == DeviceStatus.REGISTERED)
        ) or 0,
        quarantined_devices=db.scalar(
            select(func.count()).select_from(Device).where(Device.status == DeviceStatus.QUARANTINED)
        ) or 0,
        active_policies=db.scalar(
            select(func.count()).select_from(Policy).where(Policy.enabled.is_(True))
        ) or 0,
        average_trust_score=round(float(average_trust), 1),
        average_latency_ms=round(float(average_latency), 2),
        top_denied_resources=_counts(db, AccessLog.resource, *in_window, AccessLog.decision == Decision.DENY),
        top_deny_reasons=_counts(db, AccessLog.reason, *in_window, AccessLog.decision == Decision.DENY),
        top_users=_counts(db, AccessLog.username, *in_window),
        top_source_ips=_counts(db, AccessLog.source_ip, *in_window),
        decisions_over_time=[
            DecisionPoint(bucket=key, allowed=value["allowed"], denied=value["denied"])
            for key, value in sorted(buckets.items())
        ],
        recent_denials=[AccessLogOut.model_validate(r) for r in recent_denials],
    )


@router.get("/audit", response_model=list[AuditOut])
def audit_trail(
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
    action: str | None = None,
    username: str | None = None,
    limit: int = Query(default=100, ge=1, le=1000),
) -> list[AuditOut]:
    filters = []
    if action:
        filters.append(AuditLog.action == action)
    if username:
        filters.append(AuditLog.username == username)
    rows = db.scalars(
        select(AuditLog).where(*filters).order_by(AuditLog.timestamp.desc()).limit(limit)
    ).all()
    return [AuditOut.model_validate(r) for r in rows]
