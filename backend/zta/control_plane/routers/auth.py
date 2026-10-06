"""Authentication: login (with optional TOTP), refresh, logout, MFA enrolment."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import jwt
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from zta.common import audit
from zta.common.config import settings
from zta.common.database import get_db
from zta.common.models import Device, DeviceStatus, Role, User, as_utc
from zta.common.models import Session as SessionRow
from zta.common.schemas import (
    LoginRequest,
    MfaActivateRequest,
    MfaEnrollOut,
    RefreshRequest,
    TokenPair,
    UserCreate,
    UserOut,
)
from zta.common.security import (
    REFRESH,
    create_access_token,
    create_refresh_token,
    decode_token,
    generate_totp_secret,
    hash_password,
    new_session_id,
    provisioning_uri,
    verify_password,
    verify_totp,
)
from zta.control_plane.deps import get_current_user, require_admin
from zta.policy import DevicePosture, trust_score

router = APIRouter(prefix="/api/auth", tags=["auth"])


def _posture_for(db: Session, device_id: str | None) -> DevicePosture:
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


def _issue(db: Session, user: User, request: Request, *, device_id: str | None, mfa: bool) -> TokenPair:
    sid = new_session_id()
    now = datetime.now(timezone.utc)
    db.add(
        SessionRow(
            jti=sid,
            user_id=user.id,
            device_id=device_id,
            source_ip=audit.client_ip(request),
            user_agent=request.headers.get("user-agent", "")[:255],
            mfa_satisfied=mfa,
            created_at=now,
            expires_at=now + timedelta(days=settings.refresh_token_ttl_days),
        )
    )
    db.commit()

    score = trust_score(
        authenticated=True,
        mfa_satisfied=mfa,
        posture=_posture_for(db, device_id),
        source_ip=audit.client_ip(request),
    )
    return TokenPair(
        access_token=create_access_token(
            user.username, user.role.value, device_id=device_id, mfa=mfa, sid=sid
        ),
        refresh_token=create_refresh_token(user.username, jti=sid, device_id=device_id),
        expires_in=settings.access_token_ttl_minutes * 60,
        mfa_satisfied=mfa,
        trust_score=score,
        user=UserOut.model_validate(user),
    )


@router.post("/login", response_model=TokenPair)
def login(payload: LoginRequest, request: Request, db: Session = Depends(get_db)) -> TokenPair:
    user = db.scalar(select(User).where(User.username == payload.username))
    now = datetime.now(timezone.utc)

    if user is not None and user.locked_until and as_utc(user.locked_until) > now:
        audit.record(db, username=user.username, action="LOGIN", outcome="FAILURE", request=request,
                     detail={"reason": "locked"})
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Account temporarily locked after repeated failures",
        )

    if user is None or not verify_password(payload.password, user.hashed_password):
        if user is not None:
            # Lockout is per-account, on top of the per-IP rate limit, so an
            # attacker rotating IPs still hits a wall.
            user.failed_logins += 1
            if user.failed_logins >= settings.max_failed_logins:
                user.locked_until = now + timedelta(minutes=settings.lockout_minutes)
                user.failed_logins = 0
            db.commit()
        audit.record(db, username=payload.username, action="LOGIN", outcome="FAILURE", request=request,
                     detail={"reason": "invalid_credentials"})
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password")

    if not user.is_active:
        audit.record(db, username=user.username, action="LOGIN", outcome="FAILURE", request=request,
                     detail={"reason": "disabled"})
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account is disabled")

    mfa_satisfied = False
    if user.mfa_enabled:
        if not payload.totp_code:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="MFA code required",
                headers={"X-MFA-Required": "true"},
            )
        if not verify_totp(user.mfa_secret or "", payload.totp_code):
            audit.record(db, username=user.username, action="LOGIN", outcome="FAILURE", request=request,
                         detail={"reason": "invalid_mfa"})
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid MFA code")
        mfa_satisfied = True

    user.failed_logins = 0
    user.locked_until = None
    user.last_login_at = now

    if payload.device_id:
        device = db.scalar(select(Device).where(Device.device_id == payload.device_id))
        if device is not None:
            device.last_seen_at = now
            device.last_seen_ip = audit.client_ip(request)

    tokens = _issue(db, user, request, device_id=payload.device_id, mfa=mfa_satisfied)
    audit.record(
        db,
        username=user.username,
        action="LOGIN",
        request=request,
        detail={"role": user.role.value, "mfa": mfa_satisfied, "device_id": payload.device_id or ""},
    )
    return tokens


@router.post("/refresh", response_model=TokenPair)
def refresh(payload: RefreshRequest, request: Request, db: Session = Depends(get_db)) -> TokenPair:
    try:
        claims = decode_token(payload.refresh_token, expected_type=REFRESH)
    except jwt.PyJWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token") from None

    session_row = db.scalar(select(SessionRow).where(SessionRow.jti == claims.get("jti")))
    if session_row is None or not session_row.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session is no longer valid")

    user = db.scalar(select(User).where(User.username == claims.get("sub")))
    if user is None or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")

    # Rotate: the old session is revoked as the new one is issued, so a stolen
    # refresh token is usable at most once.
    session_row.revoked_at = datetime.now(timezone.utc)
    db.commit()
    return _issue(db, user, request, device_id=session_row.device_id, mfa=session_row.mfa_satisfied)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(request: Request, db: Session = Depends(get_db), user: User = Depends(get_current_user)) -> None:
    """Revoke every session for this user; their access tokens stop working."""
    sessions = db.scalars(
        select(SessionRow).where(SessionRow.user_id == user.id, SessionRow.revoked_at.is_(None))
    ).all()
    now = datetime.now(timezone.utc)
    for session_row in sessions:
        session_row.revoked_at = now
    db.commit()
    audit.record(db, username=user.username, action="LOGOUT", request=request,
                 detail={"sessions_revoked": len(sessions)})


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(get_current_user)) -> UserOut:
    return UserOut.model_validate(user)


@router.post("/mfa/enroll", response_model=MfaEnrollOut)
def mfa_enroll(db: Session = Depends(get_db), user: User = Depends(get_current_user)) -> MfaEnrollOut:
    """Generate a TOTP secret. MFA is not active until a code is verified."""
    if user.mfa_enabled:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="MFA is already enabled")
    secret = generate_totp_secret()
    user.mfa_secret = secret
    db.commit()
    return MfaEnrollOut(secret=secret, otpauth_uri=provisioning_uri(secret, user.username))


@router.post("/mfa/activate", response_model=UserOut)
def mfa_activate(
    payload: MfaActivateRequest,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> UserOut:
    if not user.mfa_secret:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Start with /api/auth/mfa/enroll")
    if not verify_totp(user.mfa_secret, payload.code):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid MFA code")
    user.mfa_enabled = True
    db.commit()
    db.refresh(user)
    audit.record(db, username=user.username, action="ENABLE_MFA", request=request)
    return UserOut.model_validate(user)


@router.post("/register", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def register(
    payload: UserCreate,
    request: Request,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
) -> UserOut:
    clash = db.scalar(select(User).where((User.username == payload.username) | (User.email == payload.email)))
    if clash is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Username or email already in use")
    user = User(
        username=payload.username,
        email=payload.email,
        hashed_password=hash_password(payload.password),
        role=payload.role,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    audit.record(db, username=admin.username, action="CREATE_USER", resource=f"user:{user.username}",
                 request=request, detail={"role": user.role.value})
    return UserOut.model_validate(user)


@router.get("/users", response_model=list[UserOut])
def list_users(db: Session = Depends(get_db), admin: User = Depends(require_admin)) -> list[UserOut]:
    return [UserOut.model_validate(u) for u in db.scalars(select(User).order_by(User.id)).all()]


@router.patch("/users/{username}/role", response_model=UserOut)
def set_role(
    username: str,
    role: Role,
    request: Request,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
) -> UserOut:
    user = db.scalar(select(User).where(User.username == username))
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    before = user.role.value
    user.role = role
    db.commit()
    db.refresh(user)
    audit.record(db, username=admin.username, action="CHANGE_ROLE", resource=f"user:{username}",
                 request=request, detail={"from": before, "to": role.value})
    return UserOut.model_validate(user)
