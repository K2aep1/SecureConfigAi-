"""Time helpers.

SQLite returns *naive* datetimes for ``DateTime(timezone=True)`` columns while
PostgreSQL returns aware ones. Comparing the two raises ``TypeError``, so every
comparison in the codebase goes through :func:`ensure_utc` (or the small predicates
here) rather than touching ``.tzinfo`` directly. This was the cause of a real bug in
token expiry and account lockout handling.
"""

from __future__ import annotations

from datetime import UTC, datetime


def utcnow() -> datetime:
    """Current time as an aware UTC datetime."""
    return datetime.now(UTC)


def ensure_utc(value: datetime | None) -> datetime | None:
    """Return an aware UTC datetime, treating naive values as UTC (which they are)."""
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def is_future(value: datetime | None) -> bool:
    """True when ``value`` is in the future (naive values are treated as UTC)."""
    resolved = ensure_utc(value)
    return bool(resolved and resolved > utcnow())


def is_past(value: datetime | None) -> bool:
    resolved = ensure_utc(value)
    return bool(resolved and resolved <= utcnow())


def elapsed_ms(start: datetime | None, end: datetime | None) -> int | None:
    """Milliseconds between two stored timestamps, tolerating mixed naive/aware values.

    A value that has been round-tripped through SQLite comes back naive while a freshly
    computed one is aware; subtracting them directly raises ``TypeError``. Every duration
    in the application goes through this helper instead.
    """
    started, finished = ensure_utc(start), ensure_utc(end)
    if started is None or finished is None:
        return None
    return max(0, int((finished - started).total_seconds() * 1000))
