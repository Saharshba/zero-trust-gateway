"""The policy decision point.

Pure functions over dataclasses: no database, no HTTP, no framework. The
control plane loads policies from SQL and hands them here, which is what makes
the whole decision path unit-testable.

Evaluation order:
  1. policies sorted by priority (lowest number first), then by id
  2. the first policy whose conditions all match decides the request
  3. if nothing matches, the request is DENIED - there is no implicit allow
"""
from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from fnmatch import fnmatch
from typing import Any

from zta.policy.trust import DevicePosture, in_any_network


@dataclass(frozen=True)
class PolicySpec:
    """A policy, decoupled from the ORM row it came from."""

    name: str
    effect: str                       # ALLOW | DENY
    priority: int = 100
    version: int = 1
    enabled: bool = True
    roles: Sequence[str] = ()
    resources: Sequence[str] = ()
    methods: Sequence[str] = ()
    path_globs: Sequence[str] = ()
    source_cidrs: Sequence[str] = ()
    require_registered_device: bool = False
    require_mfa: bool = False
    min_trust_score: int = 0
    time_start_hour: int = 0
    time_end_hour: int = 0
    weekdays: Sequence[int] = ()


@dataclass(frozen=True)
class AccessContext:
    """Everything known about one request at decision time."""

    method: str
    path: str
    resource: str = ""
    classification: str = "INTERNAL"
    authenticated: bool = False
    username: str = "anonymous"
    role: str = ""
    mfa_satisfied: bool = False
    source_ip: str = ""
    posture: DevicePosture = field(default_factory=DevicePosture)
    trust_score: int = 0
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass(frozen=True)
class DecisionResult:
    decision: str                     # ALLOW | DENY
    reason: str
    matched_policy: str | None = None
    policy_version: int | None = None
    trust_score: int = 0

    @property
    def allowed(self) -> bool:
        return self.decision == "ALLOW"


def policy_from_orm(row: Any) -> PolicySpec:
    """Build a PolicySpec from a `Policy` ORM row."""
    effect = getattr(row.effect, "value", row.effect)
    return PolicySpec(
        name=row.name,
        effect=effect,
        priority=row.priority,
        version=row.version,
        enabled=row.enabled,
        roles=tuple(row.roles or ()),
        resources=tuple(row.resources or ()),
        methods=tuple(row.methods or ()),
        path_globs=tuple(row.path_globs or ()),
        source_cidrs=tuple(row.source_cidrs or ()),
        require_registered_device=row.require_registered_device,
        require_mfa=row.require_mfa,
        min_trust_score=row.min_trust_score,
        time_start_hour=row.time_start_hour,
        time_end_hour=row.time_end_hour,
        weekdays=tuple(row.weekdays or ()),
    )


# --- individual conditions ----------------------------------------------
def _matches_role(policy: PolicySpec, context: AccessContext) -> bool:
    return not policy.roles or context.role in policy.roles


def _matches_resource(policy: PolicySpec, context: AccessContext) -> bool:
    return not policy.resources or context.resource in policy.resources


def _matches_method(policy: PolicySpec, context: AccessContext) -> bool:
    return not policy.methods or context.method.upper() in {m.upper() for m in policy.methods}


def _matches_path(policy: PolicySpec, context: AccessContext) -> bool:
    return not policy.path_globs or any(fnmatch(context.path, glob) for glob in policy.path_globs)


def _matches_network(policy: PolicySpec, context: AccessContext) -> bool:
    return not policy.source_cidrs or in_any_network(context.source_ip, list(policy.source_cidrs))


def _matches_time(policy: PolicySpec, context: AccessContext) -> bool:
    moment = context.timestamp
    if policy.weekdays and moment.weekday() not in policy.weekdays:
        return False
    start, end = policy.time_start_hour, policy.time_end_hour
    if start == end:                      # 0/0 (or any equal pair) means "always"
        return True
    hour = moment.hour
    if start < end:
        return start <= hour < end
    # A window that wraps midnight, e.g. 22:00-06:00.
    return hour >= start or hour < end


def _matches_device(policy: PolicySpec, context: AccessContext) -> bool:
    if not policy.require_registered_device:
        return True
    return context.posture.registered and not context.posture.quarantined


def _matches_mfa(policy: PolicySpec, context: AccessContext) -> bool:
    return not policy.require_mfa or context.mfa_satisfied


def _matches_trust(policy: PolicySpec, context: AccessContext) -> bool:
    return context.trust_score >= policy.min_trust_score


CONDITIONS = (
    ("role", _matches_role),
    ("resource", _matches_resource),
    ("method", _matches_method),
    ("path", _matches_path),
    ("source network", _matches_network),
    ("time window", _matches_time),
    ("device registration", _matches_device),
    ("MFA", _matches_mfa),
    ("trust score", _matches_trust),
)


def unmet_conditions(policy: PolicySpec, context: AccessContext) -> list[str]:
    """Which of the policy's conditions this request fails. Empty means it matches."""
    return [label for label, check in CONDITIONS if not check(policy, context)]


def evaluate(context: AccessContext, policies: Iterable[PolicySpec]) -> DecisionResult:
    """Return the decision for `context`. Default is deny."""
    if not context.authenticated:
        return DecisionResult(
            decision="DENY",
            reason="Unauthenticated request",
            trust_score=context.trust_score,
        )

    ordered = sorted(
        (p for p in policies if p.enabled),
        key=lambda p: (p.priority, p.name),
    )

    near_misses: list[tuple[PolicySpec, list[str]]] = []
    for policy in ordered:
        unmet = unmet_conditions(policy, context)
        if not unmet:
            reason = (
                f"Matched policy '{policy.name}' (v{policy.version})"
                if policy.effect == "ALLOW"
                else f"Explicitly denied by policy '{policy.name}' (v{policy.version})"
            )
            return DecisionResult(
                decision=policy.effect,
                reason=reason,
                matched_policy=policy.name,
                policy_version=policy.version,
                trust_score=context.trust_score,
            )
        # Remember allow-policies that were close, so the denial can explain
        # *what* the user would need rather than just "denied".
        if policy.effect == "ALLOW" and _matches_role(policy, context) and _matches_resource(policy, context):
            near_misses.append((policy, unmet))

    if near_misses:
        policy, unmet = min(near_misses, key=lambda item: len(item[1]))
        return DecisionResult(
            decision="DENY",
            reason=f"Failed {', '.join(unmet)} for policy '{policy.name}'",
            matched_policy=None,
            trust_score=context.trust_score,
        )

    return DecisionResult(
        decision="DENY",
        reason="No policy grants this role access to this resource",
        trust_score=context.trust_score,
    )
