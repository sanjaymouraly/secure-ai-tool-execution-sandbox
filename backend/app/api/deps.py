"""API dependencies: authentication, authorisation, rate limiting and CSRF."""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from collections.abc import Callable
from dataclasses import dataclass

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..core.config import Settings, get_settings
from ..core.container import Container, get_container
from ..core.security import AuthError, constant_time_compare, decode_access_token
from ..db.models import User
from ..db.session import get_db

__all__ = [
    "RateLimiter",
    "client_ip",
    "enforce_csrf",
    "get_container_dep",
    "get_current_user",
    "get_db",
    "get_optional_user",
    "get_settings_dep",
    "rate_limiter",
    "require_admin",
    "require_approver",
    "require_role",
]


# --------------------------------------------------------------------- users
def get_container_dep() -> Container:
    """Return the application container."""
    return get_container()


def get_settings_dep() -> Settings:
    """Return the application settings."""
    return get_settings()


def client_ip(request: Request) -> str:
    """Best effort client address.

    ``X-Forwarded-For`` is only consulted when the deployment explicitly
    trusts a proxy; otherwise a client could spoof its own address and bypass
    the rate limiter.
    """
    if getattr(request.state, "trust_proxy_headers", False):
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _extract_token(request: Request) -> tuple[str, str]:
    """Return ``(token, source)`` where source is 'bearer' or 'cookie'."""
    header = request.headers.get("authorization", "")
    if header.lower().startswith("bearer "):
        return header[7:].strip(), "bearer"
    cookie = request.cookies.get(get_settings().session_cookie_name)
    if cookie:
        return cookie, "cookie"
    return "", "none"


def enforce_csrf(request: Request, token: str, source: str) -> None:
    """Enforce the CSRF double submit check for cookie based requests."""
    if source != "cookie":
        return
    if request.method in {"GET", "HEAD", "OPTIONS", "TRACE"}:
        return
    settings = get_settings()
    header_value = request.headers.get(settings.csrf_header_name, "")
    if not header_value:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Missing {settings.csrf_header_name} header for cookie authenticated requests.",
        )
    try:
        payload = decode_access_token(settings, token)
    except AuthError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc
    expected = str(payload.get("csrf") or "")
    if not expected or not constant_time_compare(header_value, expected):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="CSRF token mismatch.")


def get_optional_user(request: Request, db: Session = Depends(get_db)) -> User | None:
    """Return the authenticated user, or ``None``."""
    token, source = _extract_token(request)
    if not token:
        return None
    try:
        payload = decode_access_token(get_settings(), token)
    except AuthError:
        return None
    enforce_csrf(request, token, source)
    user = db.execute(select(User).where(User.id == payload.get("sub"))).scalars().first()
    if user is None or not user.is_active:
        return None
    return user


def get_current_user(request: Request, db: Session = Depends(get_db)) -> User:
    """Return the authenticated user or raise 401."""
    settings = get_settings()
    token, source = _extract_token(request)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        payload = decode_access_token(settings, token)
    except AuthError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc
    enforce_csrf(request, token, source)
    user = db.execute(select(User).where(User.id == payload.get("sub"))).scalars().first()
    if user is None or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User is not active.")
    return user


def require_role(*roles: str) -> Callable[[User], User]:
    """Build a dependency that requires one of the given roles."""

    def _dependency(current_user: User = Depends(get_current_user)) -> User:
        if current_user.role not in roles and not current_user.is_superuser:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"This action requires one of the roles: {', '.join(roles)}.",
            )
        return current_user

    return _dependency


def require_admin(current_user: User = Depends(get_current_user)) -> User:
    """Require an administrator."""
    if not (current_user.is_superuser or current_user.role == "admin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrator privileges are required.",
        )
    return current_user


def require_approver(current_user: User = Depends(get_current_user)) -> User:
    """Require an administrator or an approver."""
    if not (current_user.is_superuser or current_user.role in {"admin", "approver"}):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Approver privileges are required for this action.",
        )
    return current_user


# -------------------------------------------------------------- rate limits
@dataclass
class RateLimitRule:
    """A simple token bucket rule."""

    requests: int
    window_seconds: int


class RateLimiter:
    """In-process sliding window rate limiter.

    .. note::

       The limiter is per process.  A multi-replica deployment needs a shared
       store (Redis) to enforce a global limit; this limitation is recorded
       in ``docs/limitations.md``.
    """

    def __init__(self) -> None:
        self._buckets: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def check(self, key: str, rule: RateLimitRule) -> tuple[bool, int, int]:
        """Return ``(allowed, remaining, retry_after_seconds)``."""
        now = time.monotonic()
        with self._lock:
            bucket = self._buckets[key]
            cutoff = now - rule.window_seconds
            while bucket and bucket[0] < cutoff:
                bucket.popleft()
            if len(bucket) >= rule.requests:
                retry_after = int(bucket[0] + rule.window_seconds - now) + 1
                return False, 0, max(1, retry_after)
            bucket.append(now)
            return True, rule.requests - len(bucket), 0

    def reset(self) -> None:
        with self._lock:
            self._buckets.clear()


rate_limiter = RateLimiter()


def enforce_rate_limit(
    request: Request,
    settings: Settings = Depends(get_settings_dep),
) -> None:
    """Apply the global rate limit to a request."""
    if not settings.rate_limit_enabled:
        return
    user = getattr(request.state, "user", None)
    identity = f"user:{user.id}" if user else f"ip:{client_ip(request)}"
    allowed, _remaining, retry_after = rate_limiter.check(
        identity, RateLimitRule(settings.rate_limit_requests, settings.rate_limit_window_seconds)
    )
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded. Slow down and try again shortly.",
            headers={"Retry-After": str(retry_after)},
        )
