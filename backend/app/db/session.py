"""Database engine and session management."""

from __future__ import annotations

import logging
from collections.abc import Generator
from pathlib import Path

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from ..core.config import get_settings

logger = logging.getLogger(__name__)

_settings = get_settings()
_db_path = _settings.database_url.replace("sqlite:///", "")

if _settings.database_url.startswith("sqlite"):
    Path(_db_path).parent.mkdir(parents=True, exist_ok=True)

engine: Engine = create_engine(
    _settings.database_url,
    echo=_settings.sql_echo,
    future=True,
    connect_args={"check_same_thread": False, "timeout": 30}
    if _settings.database_url.startswith("sqlite")
    else {"pool_pre_ping": True},
)

if _settings.database_url.startswith("sqlite"):

    @event.listens_for(engine, "connect")
    def _set_sqlite_pragmas(dbapi_connection, _connection_record):  # pragma: no cover - driver hook
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.close()


SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency yielding a database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """Create all tables and register the model metadata."""
    from app.db import models

    models.Base.metadata.create_all(bind=engine)
    logger.info("Database initialised at %s", _settings.database_url)
