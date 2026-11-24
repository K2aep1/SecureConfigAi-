"""Platform security policy: the effective, auditable security posture of the service.

Two distinct things are called "policy" in this project and they must not be confused:

* **Platform security policy** (this module) — how the *service* protects itself:
  password rules, lockout, token lifetimes, rate limits, upload limits, response
  headers, retention and secret handling.
* **Global security baseline** (``app/services/baseline.py``) — the endpoint
  hardening controls the service *assesses*.

Both are exposed read-only through the API so an auditor or an operator can see the
effective values without reading code. Startup checks turn "we think it is configured"
into "it was verified at boot".
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Literal

from app.core.config import Settings, settings

Severity = Literal["critical", "high", "medium", "low", "info"]

_SYMBOL_RE = re.compile(r"[^A-Za-z0-9]")


@dataclass(frozen=True)
class StartupCheck:
    name: str
    ok: bool
    severity: Severity
    message: str
    remedy: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "ok": self.ok,
            "severity": self.severity,
            "message": self.message,
            "remedy": self.remedy,
        }


class PasswordPolicyError(ValueError):
    """Raised when a candidate password violates the platform password policy."""


class PlatformSecurityPolicy:
    """Effective platform security policy, derived from settings."""

    def __init__(self, config: Settings | None = None) -> None:
        self.config = config or settings

    # ---------------------------------------------------------------- password
    @property
    def password_rules(self) -> dict[str, Any]:
        c = self.config
        return {
            "min_length": c.PASSWORD_MIN_LENGTH,
            "max_length": c.PASSWORD_MAX_LENGTH,
            "require_letter": c.PASSWORD_REQUIRE_LETTER,
            "require_digit": c.PASSWORD_REQUIRE_DIGIT,
            "require_symbol": c.PASSWORD_REQUIRE_SYMBOL,
            "max_failed_logins": c.MAX_FAILED_LOGINS,
            "lockout_minutes": c.LOCKOUT_MINUTES,
            "access_token_minutes": c.ACCESS_TOKEN_EXPIRE_MINUTES,
            "refresh_token_days": c.REFRESH_TOKEN_EXPIRE_DAYS,
        }

    def describe_password_rules(self) -> str:
        rules = self.password_rules
        parts = [f"at least {rules['min_length']} characters"]
        if rules["require_letter"]:
            parts.append("one letter")
        if rules["require_digit"]:
            parts.append("one digit")
        if rules["require_symbol"]:
            parts.append("one symbol")
        return "Password must contain " + ", ".join(parts) + "."

    def validate_password(self, password: str) -> None:
        """Raise :class:`PasswordPolicyError` with a user-safe message."""
        c = self.config
        if not isinstance(password, str) or not password:
            raise PasswordPolicyError("Password is required.")
        raw = password.encode("utf-8")
        if len(password) < c.PASSWORD_MIN_LENGTH:
            raise PasswordPolicyError(f"Password must be at least {c.PASSWORD_MIN_LENGTH} characters long.")
        if len(raw) > c.PASSWORD_MAX_LENGTH:
            # bcrypt silently truncates beyond 72 bytes; refusing is the honest option.
            raise PasswordPolicyError(f"Password must be at most {c.PASSWORD_MAX_LENGTH} bytes long.")
        if c.PASSWORD_REQUIRE_LETTER and not re.search(r"[A-Za-z]", password):
            raise PasswordPolicyError("Password must contain at least one letter.")
        if c.PASSWORD_REQUIRE_DIGIT and not re.search(r"\d", password):
            raise PasswordPolicyError("Password must contain at least one digit.")
        if c.PASSWORD_REQUIRE_SYMBOL and not _SYMBOL_RE.search(password):
            raise PasswordPolicyError("Password must contain at least one symbol.")
        if password.strip() != password:
            raise PasswordPolicyError("Password must not start or end with whitespace.")
        if password.lower() in {"password", "changeme", "letmein", "admin123"}:
            raise PasswordPolicyError("Password is too common.")

    # ---------------------------------------------------------------- rate limits
    @property
    def rate_limits(self) -> list[dict[str, Any]]:
        c = self.config
        return [
            {
                "name": "auth.login",
                "limit": c.RATE_LIMIT_LOGIN,
                "window_seconds": c.RATE_LIMIT_LOGIN_WINDOW,
                "scope": "ip+email",
                "description": "Failed and successful sign-in attempts per address and account.",
            },
            {
                "name": "auth.register",
                "limit": c.RATE_LIMIT_REGISTER,
                "window_seconds": c.RATE_LIMIT_REGISTER_WINDOW,
                "scope": "ip",
                "description": "New account registrations per address.",
            },
            {
                "name": "auth.refresh",
                "limit": c.RATE_LIMIT_REGISTER * 6,
                "window_seconds": c.RATE_LIMIT_REGISTER_WINDOW,
                "scope": "ip",
                "description": "Token refresh calls per address.",
            },
            {
                "name": "scans.start",
                "limit": c.RATE_LIMIT_SCAN_START,
                "window_seconds": c.RATE_LIMIT_SCAN_START_WINDOW,
                "scope": "user",
                "description": "Assessment runs queued per user.",
            },
            {
                "name": "scans.upload",
                "limit": c.RATE_LIMIT_UPLOAD,
                "window_seconds": c.RATE_LIMIT_UPLOAD_WINDOW,
                "scope": "user",
                "description": "Snapshot uploads per user.",
            },
            {
                "name": "reports.generate",
                "limit": c.RATE_LIMIT_REPORT,
                "window_seconds": c.RATE_LIMIT_REPORT_WINDOW,
                "scope": "user",
                "description": "Report renders per user.",
            },
            {
                "name": "ai.invoke",
                "limit": c.RATE_LIMIT_AI,
                "window_seconds": c.RATE_LIMIT_AI_WINDOW,
                "scope": "user",
                "description": "AI explanations and summaries per user.",
            },
        ]

    # ---------------------------------------------------------------- headers
    @property
    def header_policy(self) -> dict[str, Any]:
        c = self.config
        return {
            "content_security_policy": c.CONTENT_SECURITY_POLICY,
            "x_frame_options": "DENY",
            "x_content_type_options": "nosniff",
            "referrer_policy": "no-referrer",
            "permissions_policy": (
                "accelerometer=(), camera=(), geolocation=(), "
                "gyroscope=(), magnetometer=(), microphone=(), "
                "payment=(), usb=()"
            ),
            "cross_origin_opener_policy": "same-origin",
            "cross_origin_resource_policy": "same-origin",
            "hsts": c.HSTS_ENABLED,
            "cache_control_api": "no-store",
        }

    # ---------------------------------------------------------------- full view
    def as_dict(self) -> dict[str, Any]:
        c = self.config
        secret_state = (
            "placeholder"
            if c.jwt_secret_is_placeholder
            else ("strong" if len(c.JWT_SECRET_KEY) >= 48 else "adequate")
        )
        return {
            "environment": c.APP_ENV,
            "password": {
                "min_length": c.PASSWORD_MIN_LENGTH,
                "max_length": c.PASSWORD_MAX_LENGTH,
                "require_letter": c.PASSWORD_REQUIRE_LETTER,
                "require_digit": c.PASSWORD_REQUIRE_DIGIT,
                "require_symbol": c.PASSWORD_REQUIRE_SYMBOL,
            },
            "lockout": {
                "max_failed_logins": c.MAX_FAILED_LOGINS,
                "lockout_minutes": c.LOCKOUT_MINUTES,
                "window_minutes": c.LOGIN_WINDOW_MINUTES,
            },
            "tokens": {
                "algorithm": c.JWT_ALGORITHM,
                "issuer": c.JWT_ISSUER,
                "audience": c.JWT_AUDIENCE,
                "access_token_minutes": c.ACCESS_TOKEN_EXPIRE_MINUTES,
                "refresh_token_days": c.REFRESH_TOKEN_EXPIRE_DAYS,
                "refresh_rotation": c.REFRESH_ROTATION,
                "reuse_detection": c.REFRESH_REUSE_DETECTION,
            },
            "rate_limits": self.rate_limits,
            "uploads": {
                "max_bytes": c.MAX_UPLOAD_BYTES,
                "allowed_extensions": sorted(c.allowed_upload_extensions),
                "quarantine_ttl_minutes": c.UPLOAD_QUARANTINE_TTL_MINUTES,
                "store_raw_evidence": c.STORE_RAW_EVIDENCE,
            },
            "headers": self.header_policy,
            "cors": {
                "origins": c.cors_origin_list,
                "allow_credentials": c.CORS_ALLOW_CREDENTIALS,
                "wildcard": "*" in c.cors_origin_list,
            },
            "retention": {
                "scan_days": c.RETENTION_SCAN_DAYS,
                "audit_days": c.RETENTION_AUDIT_DAYS,
                "report_days": c.RETENTION_REPORT_DAYS,
            },
            "database": {
                "dialect": "sqlite" if c.is_sqlite else "postgresql",
                "pool_size": c.DB_POOL_SIZE,
                "max_overflow": c.DB_MAX_OVERFLOW,
                "wal": c.SQLITE_WAL if c.is_sqlite else None,
            },
            "scanning": {
                "job_workers": c.SCAN_JOB_WORKERS,
                "max_queue": c.SCAN_MAX_QUEUE,
                "budget_seconds": c.SCAN_BUDGET_SECONDS,
                "parallel_collectors": c.SCAN_PARALLEL,
                "inventory_collectors": c.SCAN_INVENTORY,
                "elevate_scanner": c.SCANNER_ELEVATE,
                "stale_after_seconds": c.SCAN_STALE_AFTER_SECONDS,
            },
            "secrets": {
                "jwt_secret_configured": not c.jwt_secret_is_placeholder,
                "jwt_secret_strength": secret_state,
                "ai_key_configured": bool(c.ai_api_key),
                "database_password_in_url": ("://" in c.DATABASE_URL and "@" in c.DATABASE_URL),
            },
            "ai": {
                "enabled": c.AI_ENABLED,
                "provider": c.AI_PROVIDER,
                "model": c.ai_model,
                "configured": c.ai_configured,
                "timeout_seconds": c.AI_TIMEOUT_SECONDS,
                "max_retries": c.AI_MAX_RETRIES,
                "cache_ttl_minutes": c.AI_CACHE_TTL_MINUTES,
                "redact_pii": c.AI_REDACT_PII,
                "advisory_only": True,
            },
            "docs_enabled": c.docs_enabled,
            "startup_checks": [c_.as_dict() for c_ in self.startup_checks()],
        }

    # ---------------------------------------------------------------- startup
    def startup_checks(self) -> list[StartupCheck]:
        """Verify the deployment's security configuration. Runs at boot and on demand."""
        c = self.config
        checks: list[StartupCheck] = []

        placeholder = c.jwt_secret_is_placeholder
        checks.append(
            StartupCheck(
                name="jwt_secret",
                ok=not placeholder or not c.is_production,
                severity="critical" if c.is_production else "high",
                message=(
                    "JWT secret is a placeholder or shorter than 32 characters."
                    if placeholder
                    else "JWT secret is configured and long enough."
                ),
                remedy=(
                    "Set JWT_SECRET_KEY to a random value of at least 48 characters from a "
                    'secret manager: python -c "import secrets;print(secrets.token_urlsafe(48))"'
                ),
            )
        )
        checks.append(
            StartupCheck(
                name="cors_origins",
                ok=("*" not in c.cors_origin_list),
                severity="high",
                message=(
                    "CORS allows every origin."
                    if "*" in c.cors_origin_list
                    else f"CORS is restricted to {len(c.cors_origin_list)} origin(s)."
                ),
                remedy="List explicit origins in CORS_ORIGINS; never combine '*' with credentials.",
            )
        )
        checks.append(
            StartupCheck(
                name="docs_exposure",
                ok=not (c.is_production and c.docs_enabled),
                severity="medium",
                message=(
                    "Interactive API documentation is disabled in production."
                    if not c.docs_enabled
                    else "Interactive API documentation is enabled (fine outside production)."
                ),
                remedy="Set APP_ENV=production to disable /docs and /openapi.json.",
            )
        )
        checks.append(
            StartupCheck(
                name="database_password",
                ok=not (c.is_production and c.is_sqlite),
                severity="medium",
                message=(
                    "Using SQLite in production."
                    if (c.is_production and c.is_sqlite)
                    else f"Database dialect: {'sqlite' if c.is_sqlite else 'postgresql'}."
                ),
                remedy="Point DATABASE_URL at PostgreSQL for multi-user or multi-worker deployments.",
            )
        )
        checks.append(
            StartupCheck(
                name="ai_key",
                ok=True,
                severity="info",
                message=(
                    "AI provider is configured; advisory features are available."
                    if c.ai_configured
                    else "No AI provider key configured; the deterministic analysis path is used."
                ),
                remedy="Set OPENAI_API_KEY or DEEPSEEK_API_KEY to enable AI explanations.",
            )
        )
        checks.append(
            StartupCheck(
                name="scanner_elevation",
                ok=True,
                severity="info",
                message=(
                    "Scanner will request UAC elevation."
                    if c.SCANNER_ELEVATE
                    else "Scanner runs with the privileges of the service account."
                ),
                remedy=(
                    "Run the service as a dedicated account with the minimum privileges "
                    "needed; leave SCANNER_ELEVATE=false for unattended deployments."
                ),
            )
        )
        checks.append(
            StartupCheck(
                name="raw_evidence_storage",
                ok=True,
                severity="info",
                message=(
                    "Full raw evidence is stored on disk."
                    if c.STORE_RAW_EVIDENCE
                    else "Only the control evidence projection is stored in the database."
                ),
                remedy="Enable STORE_RAW_EVIDENCE only when the deployment has a retention policy.",
            )
        )
        return checks

    def blocking_failures(self) -> list[StartupCheck]:
        """Checks that must stop the process: critical failures in production only."""
        return [c for c in self.startup_checks() if not c.ok and c.severity == "critical"]


platform_policy = PlatformSecurityPolicy()
