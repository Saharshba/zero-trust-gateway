"""Policy and resource administration, with a revision history."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from zta.common import audit
from zta.common.database import get_db
from zta.common.models import Policy, PolicyRevision, Resource, User
from zta.common.schemas import (
    PolicyCreate,
    PolicyOut,
    PolicyRevisionOut,
    PolicyUpdate,
    ResourceCreate,
    ResourceOut,
)
from zta.control_plane.deps import get_current_user, require_admin

router = APIRouter(prefix="/api", tags=["policies"])

SNAPSHOT_FIELDS = (
    "name", "description", "effect", "priority", "enabled", "roles", "resources", "methods",
    "path_globs", "source_cidrs", "require_registered_device", "require_mfa", "min_trust_score",
    "time_start_hour", "time_end_hour", "weekdays",
)


def snapshot(policy: Policy) -> dict:
    out = {}
    for field in SNAPSHOT_FIELDS:
        value = getattr(policy, field)
        out[field] = getattr(value, "value", value)
    return out


def _record_revision(db: Session, policy: Policy, username: str) -> None:
    db.add(
        PolicyRevision(
            policy_id=policy.id, version=policy.version, changed_by=username, snapshot=snapshot(policy)
        )
    )


@router.get("/policies", response_model=list[PolicyOut])
def list_policies(db: Session = Depends(get_db), _: User = Depends(get_current_user)) -> list[PolicyOut]:
    """Ordered exactly as the engine evaluates them: priority first."""
    rows = db.scalars(select(Policy).order_by(Policy.priority, Policy.name)).all()
    return [PolicyOut.model_validate(r) for r in rows]


@router.post("/policies", response_model=PolicyOut, status_code=status.HTTP_201_CREATED)
def create_policy(
    payload: PolicyCreate,
    request: Request,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
) -> PolicyOut:
    if db.scalar(select(Policy).where(Policy.name == payload.name)):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="A policy with that name exists")

    data = payload.model_dump()
    data["roles"] = [getattr(r, "value", r) for r in data.get("roles", [])]
    policy = Policy(**data, version=1)
    db.add(policy)
    db.commit()
    db.refresh(policy)

    _record_revision(db, policy, admin.username)
    db.commit()
    audit.record(db, username=admin.username, action="CREATE_POLICY", resource=f"policy:{policy.name}",
                 request=request, detail={"effect": policy.effect.value, "priority": policy.priority})
    return PolicyOut.model_validate(policy)


@router.patch("/policies/{policy_id}", response_model=PolicyOut)
def update_policy(
    policy_id: int,
    payload: PolicyUpdate,
    request: Request,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
) -> PolicyOut:
    """Every change bumps the version and stores a snapshot of the result."""
    policy = db.get(Policy, policy_id)
    if policy is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Policy not found")

    changes = payload.model_dump(exclude_unset=True)
    if "roles" in changes and changes["roles"] is not None:
        changes["roles"] = [getattr(r, "value", r) for r in changes["roles"]]
    for field, value in changes.items():
        setattr(policy, field, value)
    policy.version += 1
    db.commit()
    db.refresh(policy)

    _record_revision(db, policy, admin.username)
    db.commit()
    audit.record(db, username=admin.username, action="UPDATE_POLICY", resource=f"policy:{policy.name}",
                 request=request, detail={"version": policy.version,
                                          "fields": sorted(changes)})
    return PolicyOut.model_validate(policy)


@router.delete("/policies/{policy_id}", status_code=status.HTTP_204_NO_CONTENT)
def disable_policy(
    policy_id: int,
    request: Request,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
) -> None:
    """Policies are disabled, never deleted: the revision history must survive."""
    policy = db.get(Policy, policy_id)
    if policy is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Policy not found")
    policy.enabled = False
    policy.version += 1
    db.commit()
    _record_revision(db, policy, admin.username)
    db.commit()
    audit.record(db, username=admin.username, action="DISABLE_POLICY", resource=f"policy:{policy.name}",
                 request=request)


@router.get("/policies/{policy_id}/revisions", response_model=list[PolicyRevisionOut])
def policy_revisions(
    policy_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
    limit: int = Query(default=50, ge=1, le=200),
) -> list[PolicyRevisionOut]:
    rows = db.scalars(
        select(PolicyRevision)
        .where(PolicyRevision.policy_id == policy_id)
        .order_by(PolicyRevision.version.desc())
        .limit(limit)
    ).all()
    return [PolicyRevisionOut.model_validate(r) for r in rows]


@router.get("/resources", response_model=list[ResourceOut])
def list_resources(db: Session = Depends(get_db), _: User = Depends(get_current_user)) -> list[ResourceOut]:
    rows = db.scalars(select(Resource).order_by(Resource.path_prefix)).all()
    return [ResourceOut.model_validate(r) for r in rows]


@router.post("/resources", response_model=ResourceOut, status_code=status.HTTP_201_CREATED)
def create_resource(
    payload: ResourceCreate,
    request: Request,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
) -> ResourceOut:
    clash = db.scalar(
        select(Resource).where((Resource.name == payload.name) | (Resource.path_prefix == payload.path_prefix))
    )
    if clash is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Name or path prefix already in use")
    resource = Resource(**payload.model_dump())
    db.add(resource)
    db.commit()
    db.refresh(resource)
    audit.record(db, username=admin.username, action="CREATE_RESOURCE", resource=f"resource:{resource.name}",
                 request=request, detail={"upstream": resource.upstream_url})
    return ResourceOut.model_validate(resource)
