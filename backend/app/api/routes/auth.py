"""Authentication routes."""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ...core.config import get_settings
from ...core.security import (
    constant_time_compare,
    create_access_token,
    generate_csrf_token,
    hash_password,
    verify_password,
)
from ...db.models import User
from ...db.session import get_db
from ..deps import RateLimitRule, client_ip, get_current_user, rate_limiter

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/auth", tags=["authentication"])


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=12, max_length=256)


class RegisterRequest(BaseModel):
    username: str = Field(min_length=3, max_length=64, pattern=r"^[A-Za-z0-9._-]+$")
    email: str | None = Field(default=None, max_length=255)
    password: str = Field(min_length=12, max_length=256)


def _public_user(user: User) -> dict[str, Any]:
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "role": user.role,
        "is_superuser": user.is_superuser,
        "is_active": user.is_active,
    }


def _issue_session(response: Response, request: Request, user: User) -> dict[str, Any]:
    """Create a session and set the authentication cookies."""
    settings = get_settings()
    csrf = generate_csrf_token()
    token, expires_at = create_access_token(
        settings,
        subject=user.id,
        role=user.role,
        username=user.username,
        extra_claims={"csrf": csrf},
    )
    max_age = max(0, int((expires_at - datetime.now(UTC)).total_seconds()))
    response.set_cookie(
        settings.session_cookie_name,
        token,
        httponly=True,
        samesite="lax",
        secure=settings.is_production,
        max_age=max_age,
        path="/",
    )
    response.set_cookie(
        settings.csrf_cookie_name,
        csrf,
        httponly=False,
        samesite="lax",
        secure=settings.is_production,
        max_age=max_age,
        path="/",
    )
    request.state.csrf_token = csrf
    return {
        "access_token": token,
        "token_type": "bearer",  # nosec B105 - the OAuth token type, not a credential
        "expires_at": expires_at.isoformat(),
        "csrf_token": csrf,
        "user": _public_user(user),
    }


@router.post("/login")
async def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Authenticate a user and open a session."""
    settings = get_settings()

    allowed, _remaining, retry_after = (True, 0, 0)
    if settings.rate_limit_enabled:
        allowed, _remaining, retry_after = rate_limiter.check(
            f"login:{client_ip(request)}:{payload.username.lower()}",
            RateLimitRule(settings.rate_limit_login_requests, settings.rate_limit_login_window_seconds),
        )
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts. Try again later.",
            headers={"Retry-After": str(retry_after)},
        )

    user = db.execute(select(User).where(User.username == payload.username)).scalars().first()
    if user is None:
        # Constant work regardless of whether the user exists.
        hash_password("placeholder-not-a-real-password")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password.")
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="The account is disabled.")
    if user.locked_until and user.locked_until.replace(tzinfo=UTC) > datetime.now(UTC):
        raise HTTPException(status_code=status.HTTP_423_LOCKED, detail="The account is temporarily locked.")
    if not verify_password(payload.password, user.hashed_password):
        user.failed_login_count = (user.failed_login_count or 0) + 1
        if user.failed_login_count >= 10:
            user.locked_until = datetime.now(UTC).replace(microsecond=0)
            user.failed_login_count = 0
        db.commit()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password.")

    user.failed_login_count = 0
    user.locked_until = None
    user.last_login_at = datetime.now(UTC)
    db.commit()
    db.refresh(user)

    result = _issue_session(response, request, user)
    return result


@router.post("/logout")
async def logout(response: Response) -> dict[str, Any]:
    """Terminate the current session."""
    settings = get_settings()
    response.delete_cookie(settings.session_cookie_name, path="/")
    response.delete_cookie(settings.csrf_cookie_name, path="/")
    return {"status": "logged_out"}


@router.get("/me")
async def me(current_user: User = Depends(get_current_user)) -> dict[str, Any]:
    """Return the authenticated user."""
    settings = get_settings()
    return {
        "user": _public_user(current_user),
        "auth_mode": settings.auth_mode,
        "permissions": {
            "can_approve": current_user.role in {"admin", "approver"} or current_user.is_superuser,
            "can_edit_policy": current_user.role == "admin" or current_user.is_superuser,
            "can_run_attack_lab": current_user.role in {"admin", "approver", "analyst"}
            or current_user.is_superuser,
        },
    }


@router.post("/change-password")
async def change_password(
    payload: ChangePasswordRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Change the password of the authenticated user."""
    if not verify_password(payload.current_password, current_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="The current password is incorrect."
        )
    if not constant_time_compare(payload.current_password, payload.current_password):  # pragma: no cover
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid password.")
    current_user.hashed_password = hash_password(payload.new_password)
    db.commit()
    return {"status": "password_updated"}


@router.post("/register", status_code=status.HTTP_201_CREATED)
async def register(
    payload: RegisterRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Register a new user (disabled by default)."""
    settings = get_settings()
    if not settings.allow_registration:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Registration is disabled. An administrator must create the account.",
        )
    existing = db.execute(select(User).where(User.username == payload.username)).scalars().first()
    if existing is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="The username is taken.")
    user = User(
        username=payload.username,
        email=payload.email,
        hashed_password=hash_password(payload.password),
        role="analyst",
        is_active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return _issue_session(response, request, user)
