"""Structured application logging."""

from __future__ import annotations

import json
import logging
import sys
from datetime import UTC, datetime
from typing import Any

from .redaction import redact_text

#: Attributes that are always masked in log records.
_SENSITIVE_ATTRIBUTES = {
    "password",
    "api_key",
    "apikey",
    "token",
    "access_token",
    "refresh_token",
    "secret",
    "authorization",
    "csrf",
    "session",
}


class JsonFormatter(logging.Formatter):
    """Format log records as single line JSON."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": redact_text(record.getMessage()),
        }
        if record.exc_info:
            payload["exception"] = redact_text(self.formatException(record.exc_info))
        for key, value in record.__dict__.items():
            if key.startswith("_") or key in logging.LogRecord("", 0, "", 0, "", (), None).__dict__:
                continue
            if key in {
                "args",
                "msg",
                "exc_info",
                "exc_text",
                "stack_info",
                "levelname",
                "levelno",
                "pathname",
                "filename",
                "module",
                "lineno",
                "funcName",
                "created",
                "msecs",
                "relativeCreated",
                "thread",
                "threadName",
                "process",
                "processName",
                "name",
                "taskName",
            }:
                continue
            if key in _SENSITIVE_ATTRIBUTES:
                payload[key] = "[REDACTED]"
            else:
                payload[key] = redact_text(str(value))
        return json.dumps(payload, default=str)


def configure_logging(level: str = "INFO", json_output: bool = True) -> None:
    """Configure the root logger."""
    root = logging.getLogger()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    for handler in list(root.handlers):
        root.removeHandler(handler)

    handler = logging.StreamHandler(sys.stdout)
    if json_output:
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)-8s %(name)s: %(message)s"))
    root.addHandler(handler)

    # These libraries are noisy at INFO level.
    for noisy in ("uvicorn.access", "httpx", "httpcore", "sqlalchemy.engine.Engine"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
