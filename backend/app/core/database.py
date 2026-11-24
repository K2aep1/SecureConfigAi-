"""PostgreSQL engine and session factory, with isolated SQLite test support.

The normal application requires PostgreSQL. SQLite is accepted only when
``APP_ENV=test`` and an explicit test database URL is provided. For those isolated tests,
connection pragmas are set on every pooled connection (they are per-connection, not
per-database):

* ``journal_mode=WAL`` — readers stop blocking the writer.
* ``synchronous=NORMAL`` — the standard WAL durability/throughput trade.
* ``foreign_keys=ON`` — SQLite has foreign key enforcement **off** by default.
* ``busy_timeout`` — wait instead of failing immediately under contention.
* ``temp_store=MEMORY`` — keep sort/temporary b-trees off disk.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import settings
from app.db.base import Base  # noqa: F401  (re-exported for convenience)

logger = logging.getLogger("secureconfigai.db")

_connect_args: dict[str, object] = {}
_engine_kwargs: dict[str, object] = {"echo": settings.DB_ECHO, "future": True}

if settings.is_sqlite:
    _connect_args["check_same_thread"] = False
    _connect_args["timeout"] = settings.SQLITE_BUSY_TIMEOUT_MS / 1000
else:
    _engine_kwargs.update(
        pool_size=settings.DB_POOL_SIZE,
        max_overflow=settings.DB_MAX_OVERFLOW,
        pool_timeout=settings.DB_POOL_TIMEOUT,
        pool_recycle=settings.DB_POOL_RECYCLE,
    )

engine: Engine = create_engine(
    settings.DATABASE_URL,
    connect_args=_connect_args,
    pool_pre_ping=True,
    **_engine_kwargs,
)


if settings.is_sqlite:

    @event.listens_for(engine, "connect")
    def _sqlite_pragmas(dbapi_connection, _record):  # pragma: no cover - driver hook
        cursor = dbapi_connection.cursor()
        try:
            if settings.SQLITE_WAL:
                cursor.execute("PRAGMA journal_mode=WAL")
                cursor.execute("PRAGMA synchronous=NORMAL")
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute(f"PRAGMA busy_timeout={settings.SQLITE_BUSY_TIMEOUT_MS}")
            cursor.execute("PRAGMA temp_store=MEMORY")
            cursor.execute("PRAGMA cache_size=-32768")
        finally:
            cursor.close()


SessionLocal = sessionmaker(
    bind=engine,
    autocommit=False,
    autoflush=False,
    expire_on_commit=False,  # avoids a re-SELECT per attribute after commit
)


def get_db() -> Iterator[Session]:
    """FastAPI dependency: one session per request."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@contextmanager
def session_scope() -> Iterator[Session]:
    """Session for background work (job runner, maintenance tasks)."""
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def healthcheck() -> dict[str, object]:
    """Cheap database liveness probe used by /health."""
    info: dict[str, object] = {"dialect": "sqlite" if settings.is_sqlite else "postgresql"}
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
            info["reachable"] = True
            if settings.is_sqlite:
                info["journal_mode"] = connection.execute(text("PRAGMA journal_mode")).scalar()
    except Exception as exc:  # pragma: no cover - depends on the environment
        # V4 fix (L-4): the raw exception text (psycopg messages include host, port and
        # database names) used to be echoed by the unauthenticated /health endpoint.
        # The full detail now stays in the server log; the public body reports a
        # generic reason only.
        logger.warning("database health probe failed: %s", exc)
        info["reachable"] = False
        info["error"] = "database unreachable"
    return info
