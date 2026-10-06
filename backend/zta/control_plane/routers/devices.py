"""Device enrolment and posture. A device is an identity too."""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from zta.common import audit
from zta.common.database import get_db
from zta.common.models import Device, DeviceStatus, Role, User
from zta.common.schemas import DeviceEnroll, DeviceOut, DeviceUpdate
from zta.control_plane.deps import get_current_user, require_admin

router = APIRouter(prefix="/api/devices", tags=["devices"])


@router.post("", response_model=DeviceOut, status_code=status.HTTP_201_CREATED)
def enroll(
    payload: DeviceEnroll,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> DeviceOut:
    """Enrol a device for the calling user.

    Enrolment does not grant trust: the device starts PENDING and an admin
    must approve it before any policy requiring a registered device matches.
    """
    existing = db.scalar(select(Device).where(Device.device_id == payload.device_id))
    if existing is not None and existing.owner_id != user.id:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Device is enrolled to another user")

    device = existing or Device(device_id=payload.device_id, owner_id=user.id, status=DeviceStatus.PENDING)
    device.name = payload.name or device.name
    device.platform = payload.platform or device.platform
    device.disk_encrypted = payload.disk_encrypted
    device.screen_lock = payload.screen_lock
    device.os_up_to_date = payload.os_up_to_date
    device.endpoint_protection = payload.endpoint_protection
    device.last_seen_at = datetime.now(timezone.utc)
    device.last_seen_ip = audit.client_ip(request)
    db.add(device)
    db.commit()
    db.refresh(device)

    audit.record(db, username=user.username, action="ENROLL_DEVICE", resource=f"device:{device.device_id}",
                 request=request, detail={"status": device.status.value})
    return DeviceOut.model_validate(device)


@router.get("", response_model=list[DeviceOut])
def list_devices(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    status_filter: DeviceStatus | None = None,
) -> list[DeviceOut]:
    """Admins see the fleet; everyone else sees only their own devices."""
    filters = []
    if user.role != Role.ADMIN:
        filters.append(Device.owner_id == user.id)
    if status_filter:
        filters.append(Device.status == status_filter)
    rows = db.scalars(select(Device).where(*filters).order_by(Device.created_at.desc())).all()
    return [DeviceOut.model_validate(r) for r in rows]


@router.patch("/{device_id}", response_model=DeviceOut)
def update_device(
    device_id: str,
    payload: DeviceUpdate,
    request: Request,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
) -> DeviceOut:
    """Approve, quarantine or revoke a device, or correct its posture."""
    device = db.scalar(select(Device).where(Device.device_id == device_id))
    if device is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")

    changes = payload.model_dump(exclude_unset=True)
    before = device.status.value
    for field, value in changes.items():
        setattr(device, field, value)
    db.commit()
    db.refresh(device)

    audit.record(db, username=admin.username, action="UPDATE_DEVICE", resource=f"device:{device_id}",
                 request=request, detail={"from": before, "changes": {k: str(v) for k, v in changes.items()}})
    return DeviceOut.model_validate(device)
