"""Application entry point.

Startup is where configuration becomes verifiable: the platform security policy runs its
checks, the baseline pack is validated (a malformed baseline stops the service rather
than producing wrong verdicts), interrupted scans are reconciled, and the background
maintenance task is started. In production a critical configuration failure prevents the
process from serving at all.
"""

from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.gzip import GZipMiddleware

import app.db.models  # noqa: F401  (register models with the metadata)
from app.api.v1.router import api_router, root_router
from app.core.config import settings
from app.core.database import session_scope
from app.core.logging import configure_logging
from app.core.middleware import RequestContextMiddleware, SecurityHeadersMiddleware
from app.core.rate_limit import limiter
from app.core.security_policy import platform_policy
from app.db.models import Scan
from app.services import maintenance
from app.services.baseline import BaselineError, load_baseline
from app.services.jobs import manager
from app.services.token_service import prune_expired

logger = logging.getLogger("secureconfigai.main")

MAINTENANCE_INTERVAL_SECONDS = 900


async def _maintenance_loop() -> None:
    """Periodic housekeeping: rate-limit buckets, stale tokens, retention."""
    while True:
        try:
            await asyncio.sleep(MAINTENANCE_INTERVAL_SECONDS)
            limiter.prune()
            with session_scope() as db:
                prune_expired(db)
                # Rejected/interrupted uploads are always swept: they are temporary by
                # definition and never carry assessment data.
                maintenance.purge_quarantine(dry_run=False)
                if settings.RETENTION_ENFORCEMENT_ENABLED:
                    report = maintenance.run_retention(db, dry_run=False)
                    logger.info("retention pass: %s", {k: v for k, v in report.items() if k != "scan_ids"})
        except asyncio.CancelledError:  # pragma: no cover - shutdown path
            raise
        except Exception:  # pragma: no cover - maintenance must not kill the app
            logger.warning("maintenance cycle failed", exc_info=True)


@asynccontextmanager
async def lifespan(app: FastAPI):
    configure_logging()
    logger.info("starting %s %s (env=%s)", settings.APP_NAME, settings.APP_VERSION, settings.APP_ENV)

    # 1. Baseline must be valid before anything can be assessed.
    try:
        baseline = load_baseline()
        logger.info(
            "baseline %s v%s loaded: %d controls, total weight %d",
            baseline.baseline_id,
            baseline.version,
            len(baseline.controls),
            baseline.total_weight,
        )
    except BaselineError:
        logger.critical("the security baseline could not be loaded", exc_info=True)
        raise

    # 2. Platform security policy checks.
    checks = platform_policy.startup_checks()
    for check in checks:
        log = logger.info if check.ok else (logger.error if check.severity == "critical" else logger.warning)
        log(
            "security check %s: %s%s",
            check.name,
            check.message,
            f" Remedy: {check.remedy}" if not check.ok and check.remedy else "",
        )
    blocking = platform_policy.blocking_failures()
    if blocking:
        raise RuntimeError(
            "refusing to start: critical security configuration problems: "
            + "; ".join(c.name for c in blocking)
        )

    # 3. Reconcile scans interrupted by a previous shutdown.
    try:
        with session_scope() as db:
            manager.recover_stale(db)
            # Drop the private evidence of scans that no longer exist (defensive).
            stale_running = db.query(Scan).filter(Scan.status == "running").count()
            if stale_running:
                logger.warning("%d scan(s) still marked running", stale_running)
    except Exception:  # pragma: no cover
        logger.warning("scan recovery failed", exc_info=True)

    # 4. Optional retention enforcement at boot.
    if settings.RETENTION_ENFORCEMENT_ENABLED:
        try:
            with session_scope() as db:
                report = maintenance.run_retention(db, dry_run=False)
                logger.info(
                    "startup retention pass: %s", {k: v for k, v in report.items() if k != "scan_ids"}
                )
        except Exception:  # pragma: no cover - never block serving on housekeeping
            logger.warning("startup retention pass failed", exc_info=True)

    # 5. Background maintenance.
    task = asyncio.create_task(_maintenance_loop())
    try:
        yield
    finally:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        manager.shutdown(wait=False)
        logger.info("shutdown complete")


app = FastAPI(
    title=settings.APP_NAME,
    description=(
        "Endpoint security configuration assessment: deterministic weighted controls "
        "mapped to CIS, Microsoft and NIST baselines, with advisory-only AI explanation."
    ),
    version=settings.APP_VERSION,
    docs_url="/docs" if settings.docs_enabled else None,
    redoc_url="/redoc" if settings.docs_enabled else None,
    openapi_url="/openapi.json" if settings.docs_enabled else None,
    lifespan=lifespan,
)

# Middleware order: the last added is the outermost, so request context wraps headers.
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=settings.CORS_ALLOW_CREDENTIALS,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Request-ID", "If-None-Match"],
    expose_headers=["ETag", "X-Request-ID", "X-Response-Time-ms", "Retry-After"],
    max_age=settings.CORS_MAX_AGE,
)
app.add_middleware(GZipMiddleware, minimum_size=1024, compresslevel=5)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RequestContextMiddleware)

app.include_router(root_router)
app.include_router(api_router)


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Never leak internals; the request id ties the response to the server log."""
    request_id = getattr(request.state, "request_id", None)
    logger.exception("unhandled exception", extra={"request_id": request_id, "path": request.url.path})
    return JSONResponse(
        status_code=500,
        content={"detail": "An internal error occurred.", "request_id": request_id},
    )


@app.get("/", include_in_schema=False)
def index() -> dict[str, str]:
    return {
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "docs": "/docs" if settings.docs_enabled else "disabled",
        "health": "/health",
        "api": settings.API_PREFIX,
    }
