"""Authentication primitives: password hashing, JWT sessions and CSRF tokens."""

from __future__ import annotations

import hashlib
import hmac
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from .config import Settings

_password_hasher = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2)


class AuthError(Exception):
    """Raised when authentication material is invalid."""


# --------------------------------------------------------------- passwords
def hash_password(password: str) -> str:
    """Hash a password with Argon2id."""
    if not password or len(password) < 8:
        raise ValueError("Password must be at least 8 characters long")
    return _password_hasher.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    """Verify a password against an Argon2id hash."""
    if not password or not hashed:
        return False
    try:
        _password_hasher.verify(hashed, password)
        return True
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False
    except Exception:  # pragma: no cover - defensive
        return False


def needs_rehash(hashed: str) -> bool:
    """Return True when the stored hash should be upgraded."""
    try:
        return _password_hasher.check_needs_rehash(hashed)
    except Exception:  # pragma: no cover - defensive
        return False


# -------------------------------------------------------------------- jwt
def create_access_token(
    settings: Settings,
    *,
    subject: str,
    role: str,
    username: str,
    expires_minutes: int | None = None,
    extra_claims: dict[str, Any] | None = None,
) -> tuple[str, datetime]:
    """Create a signed access token. Returns ``(token, expires_at)``."""
    now = datetime.now(UTC)
    expires_at = now + timedelta(minutes=expires_minutes or settings.access_token_expire_minutes)
    payload: dict[str, Any] = {
        "sub": subject,
        "role": role,
        "username": username,
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int(expires_at.timestamp()),
        "jti": uuid.uuid4().hex,
        "typ": "access",
    }
    if extra_claims:
        payload.update(extra_claims)
    token = jwt.encode(payload, settings.secret_key, algorithm=settings.jwt_algorithm)
    return token, expires_at


def decode_access_token(settings: Settings, token: str) -> dict[str, Any]:
    """Decode and validate an access token."""
    try:
        payload = jwt.decode(
            token,
            settings.secret_key,
            algorithms=[settings.jwt_algorithm],
            options={"require": ["exp", "sub", "iat"]},
        )
    except jwt.ExpiredSignatureError as exc:
        raise AuthError("Access token has expired") from exc
    except jwt.InvalidTokenError as exc:
        raise AuthError("Access token is invalid") from exc
    return payload


def create_refresh_token(settings: Settings, *, subject: str) -> tuple[str, datetime]:
    """Create a long lived refresh token."""
    now = datetime.now(UTC)
    expires_at = now + timedelta(days=settings.refresh_token_expire_days)
    payload = {
        "sub": subject,
        "iat": int(now.timestamp()),
        "exp": int(expires_at.timestamp()),
        "jti": uuid.uuid4().hex,
        "typ": "refresh",
    }
    return jwt.encode(payload, settings.secret_key, algorithm=settings.jwt_algorithm), expires_at


# ------------------------------------------------------------------- csrf
def generate_csrf_token() -> str:
    """Generate a cryptographically random CSRF token."""
    return secrets.token_urlsafe(32)


def constant_time_compare(left: str, right: str) -> bool:
    """Compare two strings in constant time."""
    return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))


def hash_token(token: str) -> str:
    """Return a SHA-256 hash of a bearer/session token for safe storage."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def new_session_id() -> str:
    """Return a new opaque session identifier."""
    return secrets.token_urlsafe(24)
