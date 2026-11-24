"""In-process sliding-window rate limiting.

Deliberately dependency-free: the platform is a single-node service by design, so a
process-local limiter is the right size of solution. It is thread-safe because FastAPI
runs sync endpoints in a worker pool. If the deployment is ever scaled horizontally the
limiter must move to the shared cache/edge — the interface is intentionally narrow so
that swap is small.

Account lockout is handled separately in the database (``users.failed_login_count`` /
``users.locked_until``) because it must survive a restart and must be visible to
administrators.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass

from fastapi import HTTPException, Request, status

from app.core.config import settings


@dataclass(frozen=True)
class RateLimitRule:
    name: str
    limit: int
    window_seconds: int


class SlidingWindowLimiter:
    """Counts events per key inside a sliding time window."""

    def __init__(self, clock=time.monotonic) -> None:
        self._events: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()
        self._clock = clock

    def check(self, key: str, rule: RateLimitRule) -> tuple[bool, int]:
        """Register an event. Returns ``(allowed, retry_after_seconds)``."""
        if rule.limit <= 0:
            return True, 0
        now = self._clock()
        cutoff = now - rule.window_seconds
        with self._lock:
            bucket = self._events[key]
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()
            if len(bucket) >= rule.limit:
                retry_after = max(1, int(rule.window_seconds - (now - bucket[0])) + 1)
                return False, retry_after
            bucket.append(now)
            return True, 0

    def peek(self, key: str, rule: RateLimitRule) -> int:
        """Remaining allowance without consuming an event (for headers/tests)."""
        now = self._clock()
        cutoff = now - rule.window_seconds
        with self._lock:
            bucket = self._events[key]
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()
            return max(0, rule.limit - len(bucket))

    def reset(self, key: str | None = None) -> None:
        with self._lock:
            if key is None:
                self._events.clear()
            else:
                self._events.pop(key, None)

    def prune(self) -> None:
        """Drop empty buckets; called periodically by the maintenance task."""
        with self._lock:
            for key in [k for k, v in self._events.items() if not v]:
                self._events.pop(key, None)


limiter = SlidingWindowLimiter()


def client_ip(request: Request) -> str:
    """Best-effort client address, honouring proxy headers only when configured."""
    if settings.TRUST_PROXY_HEADERS:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()
        real = request.headers.get("x-real-ip")
        if real:
            return real.strip()
    return request.client.host if request.client else "unknown"


def rule(name: str) -> RateLimitRule:
    """Look up a named rule from the effective platform policy."""
    from app.core.security_policy import platform_policy

    for entry in platform_policy.rate_limits:
        if entry["name"] == name:
            return RateLimitRule(entry["name"], entry["limit"], entry["window_seconds"])
    raise KeyError(f"unknown rate limit rule: {name}")


def enforce(name: str, *keys: str, detail: str = "Too many requests.") -> None:
    """Consume one event for ``keys``; raise HTTP 429 when the rule is exceeded."""
    if not settings.RATE_LIMIT_ENABLED:
        return
    r = rule(name)
    for key in keys:
        allowed, retry_after = limiter.check(f"{name}:{key}", r)
        if not allowed:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"{detail} Try again in {retry_after} seconds.",
                headers={"Retry-After": str(retry_after)},
            )


def enforce_request(name: str, request: Request, *extra_keys: str) -> None:
    """Convenience wrapper: rate limit per client address plus optional extra keys."""
    keys = [f"ip:{client_ip(request)}", *extra_keys]
    enforce(name, *keys)
