"""API contract for the control plane."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

from zta.common.models import Classification, Decision, DeviceStatus, Effect, Role

ORM = ConfigDict(from_attributes=True)


# --- identity -----------------------------------------------------------
class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$")
    email: EmailStr
    password: str = Field(min_length=12, max_length=128)
    role: Role = Role.GUEST

    @field_validator("password")
    @classmethod
    def _strength(cls, value: str) -> str:
        classes = (
            any(c.islower() for c in value),
            any(c.isupper() for c in value),
            any(c.isdigit() for c in value),
            any(not c.isalnum() for c in value),
        )
        if sum(classes) < 3:
            raise ValueError("password must combine at least three of: lowercase, uppercase, digits, symbols")
        return value


class UserOut(BaseModel):
    model_config = ORM
    id: int
    username: str
    email: EmailStr
    role: Role
    is_active: bool
    mfa_enabled: bool
    created_at: datetime
    last_login_at: datetime | None = None


class LoginRequest(BaseModel):
    username: str
    password: str
    totp_code: str | None = Field(default=None, max_length=8)
    device_id: str | None = Field(default=None, max_length=64)


class TokenPair(BaseModel):
    access_token: str
    refresh_token: str
    token_type: Literal["bearer"] = "bearer"
    expires_in: int
    mfa_satisfied: bool
    trust_score: int
    user: UserOut


class RefreshRequest(BaseModel):
    refresh_token: str


class MfaEnrollOut(BaseModel):
    secret: str
    otpauth_uri: str


class MfaActivateRequest(BaseModel):
    code: str = Field(min_length=6, max_length=8)


# --- devices ------------------------------------------------------------
class DeviceEnroll(BaseModel):
    device_id: str = Field(min_length=6, max_length=64, pattern=r"^[A-Za-z0-9_.:-]+$")
    name: str = Field(default="", max_length=128)
    platform: str = Field(default="", max_length=64)
    disk_encrypted: bool = False
    screen_lock: bool = False
    os_up_to_date: bool = False
    endpoint_protection: bool = False


class DeviceUpdate(BaseModel):
    status: DeviceStatus | None = None
    disk_encrypted: bool | None = None
    screen_lock: bool | None = None
    os_up_to_date: bool | None = None
    endpoint_protection: bool | None = None


class DeviceOut(BaseModel):
    model_config = ORM
    id: int
    device_id: str
    name: str
    status: DeviceStatus
    platform: str
    disk_encrypted: bool
    screen_lock: bool
    os_up_to_date: bool
    endpoint_protection: bool
    last_seen_at: datetime | None
    last_seen_ip: str
    created_at: datetime


# --- resources & policies ----------------------------------------------
class ResourceOut(BaseModel):
    model_config = ORM
    id: int
    name: str
    path_prefix: str
    upstream_url: str
    classification: Classification
    description: str
    enabled: bool


class ResourceCreate(BaseModel):
    name: str = Field(min_length=2, max_length=64)
    path_prefix: str = Field(min_length=1, max_length=128, pattern=r"^/[A-Za-z0-9/_-]*$")
    upstream_url: str = Field(min_length=7, max_length=255)
    classification: Classification = Classification.INTERNAL
    description: str = ""
    strip_prefix: bool = True


class PolicyBase(BaseModel):
    name: str = Field(min_length=3, max_length=128)
    description: str = ""
    effect: Effect = Effect.DENY
    priority: int = Field(default=100, ge=0, le=10_000)
    enabled: bool = True
    roles: list[Role] = Field(default_factory=list)
    resources: list[str] = Field(default_factory=list)
    methods: list[str] = Field(default_factory=list)
    path_globs: list[str] = Field(default_factory=list)
    source_cidrs: list[str] = Field(default_factory=list)
    require_registered_device: bool = False
    require_mfa: bool = False
    min_trust_score: int = Field(default=0, ge=0, le=100)
    time_start_hour: int = Field(default=0, ge=0, le=23)
    time_end_hour: int = Field(default=0, ge=0, le=23)
    weekdays: list[int] = Field(default_factory=list)

    @field_validator("methods")
    @classmethod
    def _methods(cls, value: list[str]) -> list[str]:
        allowed = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
        upper = [m.upper() for m in value]
        unknown = set(upper) - allowed
        if unknown:
            raise ValueError(f"unsupported HTTP methods: {', '.join(sorted(unknown))}")
        return upper

    @field_validator("source_cidrs")
    @classmethod
    def _cidrs(cls, value: list[str]) -> list[str]:
        import ipaddress

        for cidr in value:
            try:
                ipaddress.ip_network(cidr, strict=False)
            except ValueError as exc:
                raise ValueError(f"invalid CIDR {cidr!r}") from exc
        return value

    @field_validator("weekdays")
    @classmethod
    def _weekdays(cls, value: list[int]) -> list[int]:
        if any(day < 0 or day > 6 for day in value):
            raise ValueError("weekdays must be 0 (Monday) through 6 (Sunday)")
        return value


class PolicyCreate(PolicyBase):
    pass


class PolicyUpdate(BaseModel):
    description: str | None = None
    effect: Effect | None = None
    priority: int | None = Field(default=None, ge=0, le=10_000)
    enabled: bool | None = None
    roles: list[Role] | None = None
    resources: list[str] | None = None
    methods: list[str] | None = None
    path_globs: list[str] | None = None
    source_cidrs: list[str] | None = None
    require_registered_device: bool | None = None
    require_mfa: bool | None = None
    min_trust_score: int | None = Field(default=None, ge=0, le=100)
    time_start_hour: int | None = Field(default=None, ge=0, le=23)
    time_end_hour: int | None = Field(default=None, ge=0, le=23)
    weekdays: list[int] | None = None


class PolicyOut(PolicyBase):
    model_config = ORM
    id: int
    version: int
    created_at: datetime
    updated_at: datetime


class PolicyRevisionOut(BaseModel):
    model_config = ORM
    id: int
    version: int
    changed_by: str
    changed_at: datetime
    snapshot: dict[str, Any]


# --- decisions ----------------------------------------------------------
class AuthorizeRequest(BaseModel):
    """What the gateway sends the PDP."""

    request_id: str = Field(default="", max_length=32)
    method: str
    path: str
    source_ip: str = ""
    access_token: str | None = None
    device_id: str | None = None
    user_agent: str = ""


class AuthorizeResponse(BaseModel):
    decision: Decision
    reason: str
    matched_policy: str | None = None
    policy_version: int | None = None
    trust_score: int = 0
    username: str = "anonymous"
    role: str = ""
    resource: str | None = None
    upstream_url: str | None = None
    upstream_path: str | None = None
    classification: str | None = None


class SimulateRequest(BaseModel):
    """Ask "what would happen if…" without making the request."""

    username: str
    method: str = "GET"
    path: str
    source_ip: str = "10.0.0.5"
    device_id: str | None = None
    mfa_satisfied: bool = False


class AccessLogOut(BaseModel):
    model_config = ORM
    id: int
    timestamp: datetime
    request_id: str
    username: str
    role: str
    device_id: str
    source_ip: str
    method: str
    path: str
    resource: str
    decision: Decision
    reason: str
    matched_policy: str | None
    policy_version: int | None
    trust_score: float
    latency_ms: float
    upstream_status: int | None


class AuditOut(BaseModel):
    model_config = ORM
    id: int
    timestamp: datetime
    username: str
    action: str
    resource: str
    source_ip: str
    outcome: str
    detail: dict[str, Any]


class PageMeta(BaseModel):
    total: int
    limit: int
    offset: int


class AccessLogPage(BaseModel):
    items: list[AccessLogOut]
    meta: PageMeta


class NamedCount(BaseModel):
    name: str
    count: int


class DecisionPoint(BaseModel):
    bucket: datetime
    allowed: int
    denied: int


class StatisticsOut(BaseModel):
    generated_at: datetime
    window_minutes: int
    total_requests: int
    allowed: int
    denied: int
    deny_rate: float
    unique_users: int
    active_sessions: int
    registered_devices: int
    quarantined_devices: int
    active_policies: int
    average_trust_score: float
    average_latency_ms: float
    top_denied_resources: list[NamedCount]
    top_deny_reasons: list[NamedCount]
    top_users: list[NamedCount]
    top_source_ips: list[NamedCount]
    decisions_over_time: list[DecisionPoint]
    recent_denials: list[AccessLogOut]
