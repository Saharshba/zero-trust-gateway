"""Fixed-window rate limiting.

Backed by Redis when it is reachable so limits hold across API replicas, with
an in-process fallback that keeps single-node dev and the test suite working.
"""
from __future__ import annotations

import logging
import threading
import time
from collections import defaultdict, deque

from zta.common.config import settings

logger = logging.getLogger(__name__)

_local_hits: dict[str, deque[float]] = defaultdict(deque)
_lock = threading.Lock()
_redis = None
_redis_checked = False


def _get_redis():
    global _redis, _redis_checked
    if _redis_checked:
        return _redis
    _redis_checked = True
    if not settings.redis_enabled:
        return None
    try:
        import redis

        client = redis.Redis.from_url(settings.redis_url, socket_connect_timeout=0.5)
        client.ping()
        _redis = client
    except Exception as exc:  # pragma: no cover - depends on deployment
        logger.warning("redis unavailable (%s); using in-process rate limiting", exc)
        _redis = None
    return _redis


def hit(key: str, limit: int, window_seconds: int) -> tuple[bool, int]:
    """Record one hit. Returns (allowed, remaining)."""
    client = _get_redis()
    if client is not None:
        try:
            bucket = f"rl:{key}:{int(time.time() // window_seconds)}"
            count = client.incr(bucket)
            if count == 1:
                client.expire(bucket, window_seconds)
            return count <= limit, max(0, limit - count)
        except Exception as exc:  # pragma: no cover
            logger.warning("redis rate limit failed (%s); falling back", exc)

    now = time.time()
    with _lock:
        hits = _local_hits[key]
        cutoff = now - window_seconds
        while hits and hits[0] < cutoff:
            hits.popleft()
        hits.append(now)
        count = len(hits)
    return count <= limit, max(0, limit - count)


def reset() -> None:
    """Test helper."""
    with _lock:
        _local_hits.clear()
