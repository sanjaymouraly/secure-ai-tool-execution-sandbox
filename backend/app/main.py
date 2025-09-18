"""FastAPI application entry point.

The application wires together the trusted control plane (this process), the
policy engine, the execution broker, the sandbox workers (separate
containers) and the database.  The Docker daemon is used **only** by the
broker; its socket is never exposed to an agent or to the frontend.
"""

from __future__ import annotations

import logging
import time
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from .api.routes import (
    approvals,
    attack_lab,
    audit,
    auth,
    executions,
    policies,
    providers,
    sessions,
    system,
    tools,
    workspace,
)
from .core.config import get_settings
from .core.container import get_container
from .core.logging_config import configure_logging
from .core.security import hash_password
from .db.models import User
from .db.session import SessionLocal, init_db

logger = logging.getLogger(__name__)

settings = get_settings()
configure_logging(settings.log_level, settings.log_json)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Initialise and tear down the application."""
    settings.ensure_directories()
    init_db()
    _bootstrap_users()
    container = get_container()
    sandbox_status = await container.sandbox.status()
    if not sandbox_status.available:
        logger.error(
            "The configured sandbox backend (%s) is not available: %s",
            settings.sandbox_backend,
            sandbox_status.detail,
        )
    else:
        logger.info(
            "Sandbox backend '%s' is available (isolated=%s, image=%s)",
            sandbox_status.name,
            sandbox_status.isolated,
            sandbox_status.image,
        )
    logger.info("%s %s ready", settings.app_name, settings.app_version)
    try:
        yield
    finally:
        await container.sandbox.cleanup()
        logger.info("Shutdown complete")


def _bootstrap_users() -> None:
    """Create the bootstrap administrator when no user exists yet."""
    db = SessionLocal()
    try:
        existing = db.query(User).count()
        if existing == 0:
            db.add(
                User(
                    username=settings.bootstrap_admin_username,
                    email="admin@localhost",
                    hashed_password=hash_password(settings.bootstrap_admin_password),
                    role="admin",
                    is_superuser=True,
                    is_active=True,
                )
            )
            db.commit()
            logger.warning(
                "Created the bootstrap administrator '%s'. Change the password immediately "
                "and set SAXIS_BOOTSTRAP_ADMIN_PASSWORD before exposing this service.",
                settings.bootstrap_admin_username,
            )
        if settings.auth_mode == "local":
            local = db.query(User).filter(User.username == "local").first()
            if local is None:
                db.add(
                    User(
                        username="local",
                        email="local@localhost",
                        hashed_password=hash_password("local-single-user-mode"),
                        role="admin",
                        is_superuser=True,
                        is_active=True,
                    )
                )
                db.commit()
    finally:
        db.close()


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add conservative security headers to every response."""

    async def dispatch(self, request: Request, call_next: Any) -> Any:
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        response.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
            "script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'",
        )
        return response


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Attach a request id and the client address to every request."""

    async def dispatch(self, request: Request, call_next: Any) -> Any:
        request_id = request.headers.get("x-request-id") or uuid.uuid4().hex[:16]
        request.state.request_id = request_id
        request.state.trust_proxy_headers = False
        started = time.perf_counter()
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        duration = (time.perf_counter() - started) * 1000
        logger.info(
            "request",
            extra={
                "request_id": request_id,
                "method": request.method,
                "path": request.url.path,
                "status": response.status_code,
                "duration_ms": round(duration, 2),
                "client": request.client.host if request.client else "unknown",
            },
        )
        return response


app = FastAPI(
    title=settings.app_name,
    description=(
        "A secure platform where AI agents can propose tool calls but never grant "
        "themselves permission. Every action passes a deterministic, deny-by-default "
        "policy engine and an isolated sandbox before it runs."
    ),
    version=settings.app_version,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
    lifespan=lifespan,
)

app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RequestContextMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=settings.cors_allow_credentials,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["X-Request-ID"],
)

app.include_router(system.router)
app.include_router(auth.router, prefix=settings.api_prefix)
app.include_router(tools.router, prefix=settings.api_prefix)
app.include_router(executions.router, prefix=settings.api_prefix)
app.include_router(workspace.router, prefix=settings.api_prefix)
app.include_router(sessions.router, prefix=settings.api_prefix)
app.include_router(approvals.router, prefix=settings.api_prefix)
app.include_router(policies.router, prefix=settings.api_prefix)
app.include_router(audit.router, prefix=settings.api_prefix)
app.include_router(providers.router, prefix=settings.api_prefix)
app.include_router(attack_lab.router, prefix=settings.api_prefix)


@app.get("/", include_in_schema=False)
async def root() -> dict[str, Any]:
    """Root endpoint with service information."""
    return {
        "name": settings.app_name,
        "version": settings.app_version,
        "docs": "/api/docs",
        "health": "/health",
        "ready": "/ready",
        "api": settings.api_prefix,
    }


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    """Return a consistent error payload for validation failures."""
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"detail": "The request payload is invalid.", "errors": exc.errors()},
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Return a sanitised error payload for unexpected failures."""
    logger.exception("Unhandled error on %s %s", request.method, request.url.path)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "An internal error occurred."},
    )
