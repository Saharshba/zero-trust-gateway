"""Passwords, TOTP and the JWTs the gateway validates."""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import bcrypt
import jwt

from zta.common.config import settings

ACCESS = "access"
REFRESH = "refresh"
BCRYPT_MAX_BYTES = 72


# --- passwords -----------------------------------------------------------
def hash_password(password: str) -> str:
    return bcrypt.hashpw(
        password.encode("utf-8")[:BCRYPT_MAX_BYTES], bcrypt.gensalt(rounds=settings.bcrypt_rounds)
    ).decode()


def verify_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8")[:BCRYPT_MAX_BYTES], hashed.encode("utf-8"))
    except (ValueError, TypeError):
        return False


# --- tokens --------------------------------------------------------------
def _encode(claims: dict[str, Any], expires: timedelta) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        **claims,
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
        "iat": now,
        "exp": now + expires,
    }
    payload.setdefault("jti", uuid.uuid4().hex)
    return jwt.encode(payload, settings.secret_key, algorithm=settings.jwt_algorithm)


def create_access_token(
    username: str, role: str, *, device_id: str | None = None, mfa: bool = False, sid: str | None = None
) -> str:
    """The access token carries the claims the gateway needs to build a context."""
    return _encode(
        {
            "sub": username,
            "role": role,
            "type": ACCESS,
            "device_id": device_id,
            "mfa": mfa,
            "sid": sid,
        },
        timedelta(minutes=settings.access_token_ttl_minutes),
    )


def create_refresh_token(username: str, *, jti: str, device_id: str | None = None) -> str:
    return _encode(
        {"sub": username, "type": REFRESH, "jti": jti, "device_id": device_id},
        timedelta(days=settings.refresh_token_ttl_days),
    )


def decode_token(token: str, expected_type: str = ACCESS) -> dict[str, Any]:
    payload = jwt.decode(
        token,
        settings.secret_key,
        algorithms=[settings.jwt_algorithm],
        audience=settings.jwt_audience,
        issuer=settings.jwt_issuer,
    )
    if payload.get("type") != expected_type:
        raise jwt.InvalidTokenError(f"expected a {expected_type} token")
    return payload


def new_session_id() -> str:
    return uuid.uuid4().hex


# --- TOTP (RFC 6238), implemented here to avoid another dependency --------
def generate_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode("utf-8").rstrip("=")


def totp_now(secret: str, at: float | None = None, step: int = 30, digits: int = 6) -> str:
    counter = int((at if at is not None else time.time()) // step)
    key = base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(code % (10**digits)).zfill(digits)


def verify_totp(secret: str, code: str, *, window: int = 1, at: float | None = None) -> bool:
    """Accept the current code and `window` steps either side of it (clock skew)."""
    if not secret or not code:
        return False
    now = at if at is not None else time.time()
    candidate = code.strip().replace(" ", "")
    for drift in range(-window, window + 1):
        if hmac.compare_digest(totp_now(secret, at=now + drift * 30), candidate):
            return True
    return False


def provisioning_uri(secret: str, username: str, issuer: str = "ZTA Gateway") -> str:
    from urllib.parse import quote

    return (
        f"otpauth://totp/{quote(issuer)}:{quote(username)}"
        f"?secret={secret}&issuer={quote(issuer)}&algorithm=SHA1&digits=6&period=30"
    )


# --- gateway -> internal service signing ---------------------------------
def sign_request(method: str, path: str, timestamp: int | None = None) -> tuple[str, str]:
    """HMAC over method+path+timestamp.

    The internal services verify this, so a request that skips the gateway -
    for example from another container on the same network - is rejected even
    though the service has no authentication of its own.
    """
    ts = str(timestamp if timestamp is not None else int(time.time()))
    message = f"{method.upper()}|{path}|{ts}".encode()
    signature = hmac.new(settings.gateway_signing_key.encode(), message, hashlib.sha256).hexdigest()
    return signature, ts


def verify_signature(method: str, path: str, signature: str, timestamp: str) -> bool:
    try:
        age = abs(int(time.time()) - int(timestamp))
    except (TypeError, ValueError):
        return False
    if age > settings.gateway_signature_ttl_seconds:
        return False          # replay window
    expected, _ = sign_request(method, path, timestamp=int(timestamp))
    return hmac.compare_digest(expected, signature or "")
