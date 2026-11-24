"""Logging setup with secret redaction.

Structured (JSON) logs by default so the output is machine-parseable, plus a redaction
filter that removes anything that looks like a credential before it reaches a handler.
Error paths are exactly where secrets leak, so redaction is centralised rather than
left to each call site.
"""

from __future__ import annotations

import json
import logging
import re
import sys
from datetime import UTC, datetime

from app.core.config import settings

REDACT_KEYS = (
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "authorization",
    "credential",
    "jwt",
    "cookie",
)

_PATTERNS = [
    re.compile(r"(?i)\b(sk-[a-z0-9]{8,})\b"),
    re.compile(r"(?i)\b(bearer\s+)[A-Za-z0-9._\-]{12,}"),
    re.compile(r"(?i)(password\"?\s*[:=]\s*\"?)([^\",}\s]+)"),
]


def redact(text: str) -> str:
    """Best-effort removal of credential-shaped substrings from a log message."""
    if not text:
        return text
    for pattern in _PATTERNS:
        if pattern.groups >= 2:
            text = pattern.sub(lambda m: m.group(1) + "***REDACTED***", text)
        else:
            text = pattern.sub("***REDACTED***", text)
    return text


class RedactionFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:  # pragma: no cover
            return True
        if any(k in message.lower() for k in REDACT_KEYS) or "sk-" in message:
            record.msg = redact(str(record.msg))
            record.args = ()
        return True


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": redact(record.getMessage()),
        }
        for key in (
            "request_id",
            "method",
            "path",
            "status",
            "duration_ms",
            "user_id",
            "action",
            "outcome",
            "client",
        ):
            value = getattr(record, key, None)
            if value is not None:
                payload[key] = value
        if record.exc_info:
            payload["exception"] = redact(self.formatException(record.exc_info))
        return json.dumps(payload, ensure_ascii=False, default=str)


def configure_logging() -> None:
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(
        JsonFormatter() if settings.LOG_JSON else logging.Formatter("%(levelname)s %(name)s %(message)s")
    )
    handler.addFilter(RedactionFilter())
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(settings.LOG_LEVEL.upper())
    for noisy in ("uvicorn.access", "uvicorn.error"):
        logging.getLogger(noisy).handlers = [handler]
        logging.getLogger(noisy).propagate = False
    logging.getLogger("sqlalchemy.engine").setLevel(logging.INFO if settings.DB_ECHO else logging.WARNING)
