"""Middleware: request correlation, access logging and security headers.

Ordering matters. ``add_middleware`` inserts at the front of the stack, so the last
middleware added is the outermost. Registration order in ``main.py`` therefore reads
bottom-up: RequestContext (outermost, so every response gets a request id and timing)
then SecurityHeaders (so even error responses carry the headers).
"""

from __future__ import annotations

import logging
import re
import time
import uuid

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp

from app.core.config import settings
from app.core.security_policy import platform_policy

logger = logging.getLogger("secureconfigai.access")

#: Paths that should never be cached by an intermediary or the browser.
_NO_STORE_PREFIXES = ("/api/",)
#: Paths that manage their own validators (ETag) and must not be overridden.
_VALIDATOR_PREFIXES = ("/api/v1/scans/",)

#: V4 fix (L-3): a client-supplied request id is reflected into responses, logs and
#: audit rows, so it is constrained to a safe shape instead of being echoed verbatim.
_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


def _safe_request_id(raw: str | None) -> str:
    """Accept a client-supplied request id only when it is well-formed; else mint one."""
    if raw and _REQUEST_ID_RE.fullmatch(raw):
        return raw
    return uuid.uuid4().hex[:16]


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Assign a request id, time the request, and emit one structured access log line."""

    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)

    async def dispatch(self, request: Request, call_next):
        request_id = _safe_request_id(request.headers.get("x-request-id"))
        request.state.request_id = request_id
        started = time.perf_counter()
        try:
            response = await call_next(request)
        except Exception:
            duration_ms = round((time.perf_counter() - started) * 1000, 1)
            logger.exception(
                "unhandled error",
                extra={
                    "request_id": request_id,
                    "method": request.method,
                    "path": request.url.path,
                    "status": 500,
                    "duration_ms": duration_ms,
                },
            )
            raise
        duration_ms = round((time.perf_counter() - started) * 1000, 1)
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Response-Time-ms"] = str(duration_ms)
        if request.url.path.startswith(_NO_STORE_PREFIXES):
            if not (request.url.path.startswith(_VALIDATOR_PREFIXES) and "report" in request.url.path):
                response.headers.setdefault("Cache-Control", "no-store")
        logger.info(
            "request",
            extra={
                "request_id": request_id,
                "method": request.method,
                "path": request.url.path,
                "status": response.status_code,
                "duration_ms": duration_ms,
                "user_id": getattr(request.state, "user_id", None),
                "client": request.client.host if request.client else None,
            },
        )
        return response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Apply the platform header policy to every response.

    V4 fix (L-2): an unhandled exception used to bypass this middleware entirely —
    Starlette's ``ServerErrorMiddleware`` sits outside it — so 500 responses shipped
    without CSP, nosniff or the rest of the header policy. When the inner call raises,
    the generic JSON 500 body is produced here (with the full header set applied)
    and the exception is re-raised so server-side logging still happens.
    """

    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)
        self.policy = platform_policy.header_policy

    async def dispatch(self, request: Request, call_next) -> Response:
        try:
            response = await call_next(request)
        except Exception:
            logger.exception(
                "unhandled error inside security-headers middleware",
                extra={"path": request.url.path, "request_id": getattr(request.state, "request_id", None)},
            )
            response = JSONResponse(
                {"detail": "Internal server error", "request_id": getattr(request.state, "request_id", None)},
                status_code=500,
            )
        if not settings.SECURITY_HEADERS_ENABLED:
            return response
        headers = response.headers
        headers.setdefault("X-Content-Type-Options", self.policy["x_content_type_options"])
        headers.setdefault("X-Frame-Options", self.policy["x_frame_options"])
        headers.setdefault("Referrer-Policy", self.policy["referrer_policy"])
        headers.setdefault("Permissions-Policy", self.policy["permissions_policy"])
        headers.setdefault("Cross-Origin-Opener-Policy", self.policy["cross_origin_opener_policy"])
        headers.setdefault("Cross-Origin-Resource-Policy", self.policy["cross_origin_resource_policy"])
        headers.setdefault("Content-Security-Policy", self.policy["content_security_policy"])
        if self.policy["hsts"]:
            headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        # The interactive API documentation is served from the same origin and needs
        # its own inline assets, so relax the CSP there only.
        if request.url.path.startswith(("/docs", "/redoc")):
            headers["Content-Security-Policy"] = (
                "default-src 'self'; img-src 'self' data: https://fastapi.tiangolo.com; "
                "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
                "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
                "connect-src 'self'; frame-ancestors 'none'"
            )
        # Do not advertise the server implementation.
        if "server" in headers:
            del headers["server"]
        return response
