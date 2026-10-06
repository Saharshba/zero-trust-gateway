"""Domain model for the zero-trust control plane.

The tables fall into four groups:
  identity  - users, sessions
  device    - devices and their posture
  policy    - resources, policies (versioned), policy revisions
  evidence  - access_logs (every decision) and audit_logs (admin actions)
"""
from __future__ import annotations

import enum
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import JSON

from zta.common.database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def as_utc(value: datetime | None) -> datetime | None:
    """Attach UTC to a naive timestamp.

    SQLite (used by the test suite) drops the timezone on the way out, so any
    value read back from the database is normalised before it is compared with
    an aware `utcnow()`.
    """
    if value is None or value.tzinfo is not None:
        return value
    return value.replace(tzinfo=timezone.utc)


class Role(str, enum.Enum):
    ADMIN = "ADMIN"
    EMPLOYEE = "EMPLOYEE"
    GUEST = "GUEST"


class Effect(str, enum.Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"


class Decision(str, enum.Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"


class DeviceStatus(str, enum.Enum):
    REGISTERED = "REGISTERED"
    PENDING = "PENDING"
    QUARANTINED = "QUARANTINED"
    REVOKED = "REVOKED"


class Classification(str, enum.Enum):
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    RESTRICTED = "RESTRICTED"


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    email: Mapped[str] = mapped_column(String(255), unique=True)
    hashed_password: Mapped[str] = mapped_column(String(255))
    role: Mapped[Role] = mapped_column(Enum(Role, native_enum=False), default=Role.GUEST)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)

    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    mfa_secret: Mapped[str | None] = mapped_column(String(64), nullable=True)

    failed_logins: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    devices: Mapped[list[Device]] = relationship(back_populates="owner")
    sessions: Mapped[list[Session]] = relationship(back_populates="user")


class Session(Base):
    """One row per issued refresh token, so logout can actually revoke."""

    __tablename__ = "sessions"

    id: Mapped[int] = mapped_column(primary_key=True)
    jti: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    device_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    source_ip: Mapped[str] = mapped_column(String(45), default="")
    user_agent: Mapped[str] = mapped_column(String(255), default="")
    mfa_satisfied: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    user: Mapped[User] = relationship(back_populates="sessions")

    @property
    def is_active(self) -> bool:
        return self.revoked_at is None and as_utc(self.expires_at) > utcnow()


class Device(Base):
    """A device must be enrolled before it can reach anything but PUBLIC."""

    __tablename__ = "devices"

    id: Mapped[int] = mapped_column(primary_key=True)
    device_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(128), default="")
    owner_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    status: Mapped[DeviceStatus] = mapped_column(
        Enum(DeviceStatus, native_enum=False), default=DeviceStatus.PENDING
    )
    platform: Mapped[str] = mapped_column(String(64), default="")
    # Posture signals reported at enrolment; they feed the trust score.
    disk_encrypted: Mapped[bool] = mapped_column(Boolean, default=False)
    screen_lock: Mapped[bool] = mapped_column(Boolean, default=False)
    os_up_to_date: Mapped[bool] = mapped_column(Boolean, default=False)
    endpoint_protection: Mapped[bool] = mapped_column(Boolean, default=False)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen_ip: Mapped[str] = mapped_column(String(45), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    owner: Mapped[User | None] = relationship(back_populates="devices")


class Resource(Base):
    """An upstream the gateway can route to, and how sensitive it is."""

    __tablename__ = "resources"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True)
    path_prefix: Mapped[str] = mapped_column(String(128), unique=True)
    upstream_url: Mapped[str] = mapped_column(String(255))
    classification: Mapped[Classification] = mapped_column(
        Enum(Classification, native_enum=False), default=Classification.INTERNAL
    )
    description: Mapped[str] = mapped_column(Text, default="")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    strip_prefix: Mapped[bool] = mapped_column(Boolean, default=True)


class Policy(Base):
    """One access rule.

    Evaluation is ordered by `priority` (low first) and the first match wins.
    Anything that matches nothing is denied: there is no implicit allow.
    """

    __tablename__ = "policies"
    __table_args__ = (Index("ix_policy_priority", "priority"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True)
    description: Mapped[str] = mapped_column(Text, default="")
    effect: Mapped[Effect] = mapped_column(Enum(Effect, native_enum=False), default=Effect.DENY)
    priority: Mapped[int] = mapped_column(Integer, default=100)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    version: Mapped[int] = mapped_column(Integer, default=1)

    # --- conditions (all present ones must hold) ------------------------
    roles: Mapped[list] = mapped_column(JSON, default=list)              # ["EMPLOYEE", ...]
    resources: Mapped[list] = mapped_column(JSON, default=list)          # resource names
    methods: Mapped[list] = mapped_column(JSON, default=list)            # ["GET", "POST"]
    path_globs: Mapped[list] = mapped_column(JSON, default=list)         # ["/admin/*"]
    source_cidrs: Mapped[list] = mapped_column(JSON, default=list)       # ["10.0.0.0/8"]
    require_registered_device: Mapped[bool] = mapped_column(Boolean, default=False)
    require_mfa: Mapped[bool] = mapped_column(Boolean, default=False)
    min_trust_score: Mapped[int] = mapped_column(Integer, default=0)
    # Local-time window, inclusive start, exclusive end; 0/0 means "always".
    time_start_hour: Mapped[int] = mapped_column(Integer, default=0)
    time_end_hour: Mapped[int] = mapped_column(Integer, default=0)
    weekdays: Mapped[list] = mapped_column(JSON, default=list)           # 0=Mon … 6=Sun

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    revisions: Mapped[list[PolicyRevision]] = relationship(back_populates="policy")


class PolicyRevision(Base):
    """Immutable snapshot of a policy each time it changes."""

    __tablename__ = "policy_revisions"

    id: Mapped[int] = mapped_column(primary_key=True)
    policy_id: Mapped[int] = mapped_column(ForeignKey("policies.id"), index=True)
    version: Mapped[int] = mapped_column(Integer)
    changed_by: Mapped[str] = mapped_column(String(64), default="")
    changed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    snapshot: Mapped[dict] = mapped_column(JSON, default=dict)

    policy: Mapped[Policy] = relationship(back_populates="revisions")

    __table_args__ = (UniqueConstraint("policy_id", "version", name="uq_policy_version"),)


class AccessLog(Base):
    """Every authorisation decision the PDP made. This is the ZTA evidence trail."""

    __tablename__ = "access_logs"
    __table_args__ = (
        Index("ix_access_ts_decision", "timestamp", "decision"),
        Index("ix_access_user_resource", "username", "resource"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    request_id: Mapped[str] = mapped_column(String(32), default="", index=True)
    username: Mapped[str] = mapped_column(String(64), default="anonymous", index=True)
    role: Mapped[str] = mapped_column(String(16), default="")
    device_id: Mapped[str] = mapped_column(String(64), default="")
    source_ip: Mapped[str] = mapped_column(String(45), default="", index=True)
    method: Mapped[str] = mapped_column(String(8), default="GET")
    path: Mapped[str] = mapped_column(String(255), default="")
    resource: Mapped[str] = mapped_column(String(64), default="", index=True)
    decision: Mapped[Decision] = mapped_column(Enum(Decision, native_enum=False), index=True)
    reason: Mapped[str] = mapped_column(String(255), default="")
    matched_policy: Mapped[str | None] = mapped_column(String(128), nullable=True)
    policy_version: Mapped[int | None] = mapped_column(Integer, nullable=True)
    trust_score: Mapped[float] = mapped_column(Float, default=0.0)
    latency_ms: Mapped[float] = mapped_column(Float, default=0.0)
    upstream_status: Mapped[int | None] = mapped_column(Integer, nullable=True)


class AuditLog(Base):
    """Administrative actions on the control plane itself."""

    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    username: Mapped[str] = mapped_column(String(64), index=True)
    action: Mapped[str] = mapped_column(String(64), index=True)
    resource: Mapped[str] = mapped_column(String(255), default="")
    source_ip: Mapped[str] = mapped_column(String(45), default="")
    outcome: Mapped[str] = mapped_column(String(16), default="SUCCESS")
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
