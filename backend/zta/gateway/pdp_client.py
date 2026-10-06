"""Client for the policy decision point, with a short-lived decision cache."""
from __future__ import annotations

import hashlib
import logging
import time
from dataclasses import dataclass
from typing import Any

import httpx

from zta.common.config import settings
from zta.common.security import sign_request

logger = logging.getLogger("gateway.pdp")

AUTHORIZE_PATH = "/internal/authorize"


@dataclass
class CachedDecision:
    payload: dict[str, Any]
    expires_at: float


class DecisionCache:
    """Tiny in-process TTL cache.

    Caching an authorisation decision is a deliberate trade: it removes a PDP
    round-trip per request at the cost of a few seconds' staleness after a
    policy change or a revocation. The TTL is therefore seconds, not minutes,
    and only ALLOW decisions are cached - a denial is cheap to recompute and
    must react the moment a policy is fixed.
    """

    def __init__(self, ttl_seconds: int) -> None:
        self.ttl = ttl_seconds
        self._entries: dict[str, CachedDecision] = {}

    @staticmethod
    def key(method: str, path: str, token: str | None, device_id: str | None, source_ip: str) -> str:
        digest = hashlib.sha256(
            f"{method}|{path}|{token or ''}|{device_id or ''}|{source_ip}".encode()
        ).hexdigest()
        return digest

    def get(self, key: str) -> dict[str, Any] | None:
        entry = self._entries.get(key)
        if entry is None:
            return None
        if entry.expires_at < time.time():
            del self._entries[key]
            return None
        return entry.payload

    def put(self, key: str, payload: dict[str, Any]) -> None:
        if not self.ttl or payload.get("decision") != "ALLOW":
            return
        self._entries[key] = CachedDecision(payload=payload, expires_at=time.time() + self.ttl)

    def clear(self) -> None:
        self._entries.clear()


class PdpClient:
    def __init__(self, base_url: str | None = None, cache: DecisionCache | None = None) -> None:
        self.base_url = (base_url or settings.control_plane_url).rstrip("/")
        self.cache = cache if cache is not None else DecisionCache(settings.decision_cache_seconds)
        self._client = httpx.AsyncClient(timeout=settings.pdp_timeout_seconds)

    async def authorize(self, payload: dict[str, Any]) -> dict[str, Any]:
        cache_key = self.cache.key(
            payload["method"], payload["path"], payload.get("access_token"),
            payload.get("device_id"), payload.get("source_ip", ""),
        )
        cached = self.cache.get(cache_key)
        if cached is not None:
            return {**cached, "cached": True}

        signature, timestamp = sign_request("POST", AUTHORIZE_PATH)
        response = await self._client.post(
            f"{self.base_url}{AUTHORIZE_PATH}",
            json=payload,
            headers={"X-Gateway-Signature": signature, "X-Gateway-Timestamp": timestamp},
        )
        response.raise_for_status()
        decision = response.json()
        self.cache.put(cache_key, decision)
        return {**decision, "cached": False}

    async def aclose(self) -> None:
        await self._client.aclose()
