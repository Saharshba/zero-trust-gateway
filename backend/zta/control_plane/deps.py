"""Dependencies: the current user, role gates, and the gateway's own identity."""
from __future__ import annotations

import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from zta.common.database import get_db
from zta.common.models import Role, User
from zta.common.models import Session as SessionRow
from zta.common.security import decode_token, verify_signature

bearer = HTTPBearer(auto_error=False)

CREDENTIALS_ERROR = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Could not validate credentials",
    headers={"WWW-Authenticate": "Bearer"},
)


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
    db: Session = Depends(get_db),
) -> User:
    if credentials is None or not credentials.credentials:
        raise CREDENTIALS_ERROR
    try:
        payload = decode_token(credentials.credentials)
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        ) from None
    except jwt.PyJWTError:
        raise CREDENTIALS_ERROR from None

    # An access token whose session was revoked (logout) must stop working
    # immediately; that is the whole point of tracking sessions.
    sid = payload.get("sid")
    if sid:
        session_row = db.scalar(select(SessionRow).where(SessionRow.jti == sid))
        if session_row is None or not session_row.is_active:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session has been revoked")

    user = db.scalar(select(User).where(User.username == payload.get("sub")))
    if user is None or not user.is_active:
        raise CREDENTIALS_ERROR
    return user


class RequireRole:
    """ADMIN implies every other role, so admin routes are listed once."""

    def __init__(self, *roles: Role) -> None:
        self.roles = set(roles) | {Role.ADMIN}

    def __call__(self, user: User = Depends(get_current_user)) -> User:
        if user.role not in self.roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires one of: {', '.join(sorted(r.value for r in self.roles))}",
            )
        return user


require_admin = RequireRole(Role.ADMIN)
require_employee = RequireRole(Role.EMPLOYEE)


def require_gateway(request: Request) -> None:
    """Authenticate the gateway itself on the PDP endpoint.

    The decision endpoint is not user-facing: only the gateway may call it, and
    it proves that with the same HMAC it uses toward the internal services.
    """
    signature = request.headers.get("x-gateway-signature", "")
    timestamp = request.headers.get("x-gateway-timestamp", "")
    if not verify_signature(request.method, request.url.path, signature, timestamp):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or missing gateway signature"
        )
