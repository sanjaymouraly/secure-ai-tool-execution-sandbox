"""SQLAlchemy declarative base and shared column helpers."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import DateTime, String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def utcnow() -> datetime:
    """Return an aware UTC timestamp."""
    return datetime.now(UTC)


def new_id() -> str:
    """Return a short random identifier."""
    return uuid.uuid4().hex


class Base(DeclarativeBase):
    """Base class for all ORM models."""


class TimestampMixin:
    """Adds creation/update timestamps to a model."""

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False, index=True
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )


class IdMixin:
    """Adds a string primary key to a model."""

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=new_id)
