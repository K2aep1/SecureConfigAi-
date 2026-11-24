"""Application configuration.

Every security-relevant value is configuration, not a constant, so a deployment can be
audited by reading one object. Defaults are secure: the application refuses to start in
production with a placeholder JWT secret, wildcard CORS or docs enabled.

Environment variables are case-sensitive and loaded from ``backend/.env``.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

BACKEND_DIR = Path(__file__).resolve().parents[2]
PROJECT_ROOT = BACKEND_DIR.parent
DATA_DIR = BACKEND_DIR / "app" / "data"
UPLOAD_DIR = BACKEND_DIR / "uploads"
REPORT_DIR = UPLOAD_DIR / "reports"
EVIDENCE_DIR = BACKEND_DIR / "uploads" / "evidence"
SCANNER_DIR = PROJECT_ROOT / "scanner"

PLACEHOLDER_SECRETS = {
    "",
    "change-me",
    "changeme",
    "secret",
    "development-secret-key-change-me",
    "CHANGE_THIS_TO_A_LONG_RANDOM_SECRET",
    "replace-with-a-long-random-secret",
    "test-secret-key-for-tests",
}


class Settings(BaseSettings):
    """Effective application settings."""

    model_config = SettingsConfigDict(
        env_file=BACKEND_DIR / ".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    # ---- application -------------------------------------------------------
    APP_NAME: str = "SecureConfigAI"
    APP_VERSION: str = "4.0.0"
    APP_ENV: str = Field(default="development", pattern="^(development|test|production)$")
    LOG_LEVEL: str = "INFO"
    LOG_JSON: bool = True
    TRUST_PROXY_HEADERS: bool = False
    API_PREFIX: str = "/api/v1"

    # ---- database ----------------------------------------------------------
    DATABASE_URL: str = Field(default="", validate_default=True)
    DB_ECHO: bool = False
    DB_POOL_SIZE: int = 5
    DB_MAX_OVERFLOW: int = 10
    DB_POOL_TIMEOUT: int = 30
    DB_POOL_RECYCLE: int = 1800
    SQLITE_BUSY_TIMEOUT_MS: int = 5000
    SQLITE_WAL: bool = True

    # ---- secrets and tokens ------------------------------------------------
    JWT_SECRET_KEY: str = "development-secret-key-change-me"
    JWT_ALGORITHM: str = Field(default="HS256", pattern="^(HS256|HS384|HS512)$")
    JWT_ISSUER: str = "secureconfigai"
    JWT_AUDIENCE: str = "secureconfigai-api"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    REFRESH_ROTATION: bool = True
    REFRESH_REUSE_DETECTION: bool = True

    # ---- password and lockout policy ---------------------------------------
    PASSWORD_MIN_LENGTH: int = 12
    PASSWORD_MAX_LENGTH: int = 72
    PASSWORD_REQUIRE_LETTER: bool = True
    PASSWORD_REQUIRE_DIGIT: bool = True
    PASSWORD_REQUIRE_SYMBOL: bool = False
    MAX_FAILED_LOGINS: int = 5
    LOCKOUT_MINUTES: int = 15
    LOGIN_WINDOW_MINUTES: int = 15

    # ---- rate limits (count / window seconds) ------------------------------
    RATE_LIMIT_LOGIN: int = 10
    RATE_LIMIT_LOGIN_WINDOW: int = 300
    RATE_LIMIT_REGISTER: int = 5
    RATE_LIMIT_REGISTER_WINDOW: int = 3600
    RATE_LIMIT_SCAN_START: int = 6
    RATE_LIMIT_SCAN_START_WINDOW: int = 3600
    RATE_LIMIT_UPLOAD: int = 20
    RATE_LIMIT_UPLOAD_WINDOW: int = 3600
    RATE_LIMIT_REPORT: int = 60
    RATE_LIMIT_REPORT_WINDOW: int = 3600
    RATE_LIMIT_AI: int = 30
    RATE_LIMIT_AI_WINDOW: int = 3600
    RATE_LIMIT_ENABLED: bool = True

    # ---- CORS and headers --------------------------------------------------
    CORS_ORIGINS: str = "http://localhost:5173,http://127.0.0.1:5173"
    CORS_ALLOW_CREDENTIALS: bool = True
    CORS_MAX_AGE: int = 600
    SECURITY_HEADERS_ENABLED: bool = True
    HSTS_ENABLED: bool = False
    CONTENT_SECURITY_POLICY: str = (
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; font-src 'self' data:; connect-src 'self' "
        "http://127.0.0.1:8001 http://localhost:8001; frame-ancestors 'none'; "
        "base-uri 'self'; form-action 'self'; object-src 'none'"
    )

    # ---- uploads and evidence ---------------------------------------------
    MAX_UPLOAD_BYTES: int = 64 * 1024 * 1024
    ALLOWED_UPLOAD_EXTENSIONS: str = ".json,.zip"
    UPLOAD_QUARANTINE_TTL_MINUTES: int = 60
    STORE_RAW_EVIDENCE: bool = False
    MAX_STORED_EVIDENCE_BYTES: int = 2 * 1024 * 1024

    # ---- scanning ----------------------------------------------------------
    SCAN_JOB_WORKERS: int = 2
    SCAN_MAX_QUEUE: int = 20
    SCAN_BUDGET_SECONDS: int = 120
    SCAN_PARALLEL: int = 4
    SCAN_INVENTORY: bool = False
    SCANNER_ELEVATE: bool = False
    SCAN_STALE_AFTER_SECONDS: int = 900
    SCAN_DEFAULT_CRITICALITY: int = 3
    STARTUP_RECOVER_SCANS: bool = True

    # ---- reports and retention --------------------------------------------
    REPORT_CACHE_ENABLED: bool = True
    RETENTION_SCAN_DAYS: int = 365
    RETENTION_AUDIT_DAYS: int = 730
    RETENTION_REPORT_DAYS: int = 180
    #: Enforce retention automatically (startup + every maintenance cycle). Off by
    #: default: destructive housekeeping is an explicit operator decision.
    RETENTION_ENFORCEMENT_ENABLED: bool = False
    RETENTION_PURGE_ON_STARTUP: bool = False

    # ---- evidence provenance ----------------------------------------------
    #: Optional shared secret. When set on both the scanner and the backend, a snapshot
    #: may carry a server-verifiable HMAC provenance envelope; when unset, evidence is
    #: reported as checksum-only and no authenticity claim is made.
    EVIDENCE_SIGNING_KEY: str | None = None

    # ---- audit chain --------------------------------------------------------
    #: V4 (M-1): optional server-side key for the audit hash chain. When set, entries
    #: are committed with keyed HMAC-SHA-256 instead of plain SHA-256, so an attacker
    #: with database write access can no longer recompute the chain after rewriting
    #: history. The key lives in configuration only — never in the database. When
    #: unset, the V3 behaviour (plain, self-attestable chain) is preserved.
    AUDIT_CHAIN_HMAC_KEY: str | None = None

    # ---- AI (advisory only) ------------------------------------------------
    AI_ENABLED: bool = True
    AI_PROVIDER: str = "openai"
    OPENAI_API_KEY: str | None = None
    OPENAI_MODEL: str = "gpt-4o-mini"
    DEEPSEEK_API_KEY: str | None = None
    DEEPSEEK_BASE_URL: str = "https://api.deepseek.com/v1"
    DEEPSEEK_MODEL: str = "deepseek-chat"
    GEMINI_API_KEY: str | None = None
    GEMINI_BASE_URL: str = "https://generativelanguage.googleapis.com/v1beta/openai/"
    GEMINI_MODEL: str = "gemini-3.8-flash"
    AI_TIMEOUT_SECONDS: int = 30
    AI_MAX_RETRIES: int = 2
    #: V4 (M-2): maximum concurrent in-flight provider calls across the process.
    #: Requests beyond this fail fast into the deterministic fallback instead of
    #: pinning the request thread pool.
    AI_MAX_CONCURRENT_CALLS: int = 4
    AI_CACHE_TTL_MINUTES: int = 60
    AI_REDACT_PII: bool = True
    AI_STATUS_CACHE_SECONDS: int = 60

    @field_validator("APP_ENV", mode="before")
    @classmethod
    def _normalise_env(cls, value: str) -> str:
        return str(value).strip().lower()

    @field_validator("DATABASE_URL", mode="before")
    @classmethod
    def _require_database_url(cls, value: object) -> str:
        url = str(value or "").strip()
        if not url:
            raise ValueError(
                "DATABASE_URL is required. Configure a PostgreSQL connection in "
                "backend/.env; SQLite is allowed only for APP_ENV=test."
            )
        if url.startswith("postgresql://"):
            url = "postgresql+psycopg://" + url[len("postgresql://") :]
        return url

    @model_validator(mode="after")
    def _enforce_database_backend(self) -> Settings:
        scheme = self.DATABASE_URL.partition("://")[0].lower()
        if scheme == "postgresql+psycopg":
            return self
        if self.is_test and scheme in {"sqlite", "sqlite+pysqlite"}:
            return self
        raise ValueError(
            "DATABASE_URL must use PostgreSQL (postgresql+psycopg://) outside "
            "APP_ENV=test. No SQLite development or production fallback is configured."
        )

    # ---- derived helpers ---------------------------------------------------
    @property
    def is_production(self) -> bool:
        return self.APP_ENV == "production"

    @property
    def is_test(self) -> bool:
        return self.APP_ENV == "test"

    @property
    def docs_enabled(self) -> bool:
        return not self.is_production

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.CORS_ORIGINS.split(",") if o.strip()]

    @property
    def allowed_upload_extensions(self) -> set[str]:
        return {e.strip().lower() for e in self.ALLOWED_UPLOAD_EXTENSIONS.split(",") if e.strip()}

    @property
    def ai_api_key(self) -> str | None:
        provider = (self.AI_PROVIDER or "openai").strip().lower()
        if provider == "deepseek":
            return (self.DEEPSEEK_API_KEY or "").strip() or None
        if provider == "gemini":
            return (self.GEMINI_API_KEY or "").strip() or None
        return (self.OPENAI_API_KEY or "").strip() or None

    @property
    def ai_model(self) -> str:
        provider = (self.AI_PROVIDER or "openai").strip().lower()
        if provider == "deepseek":
            return self.DEEPSEEK_MODEL
        if provider == "gemini":
            return self.GEMINI_MODEL
        return self.OPENAI_MODEL

    @property
    def ai_configured(self) -> bool:
        return bool(self.AI_ENABLED and self.ai_api_key)

    @property
    def is_sqlite(self) -> bool:
        return self.DATABASE_URL.startswith("sqlite:")

    @property
    def evidence_signing_configured(self) -> bool:
        """True only when a usable key is present; an empty value is 'not configured'."""
        key = (self.EVIDENCE_SIGNING_KEY or "").strip()
        return len(key) >= 32

    @property
    def jwt_secret_is_placeholder(self) -> bool:
        secret = (self.JWT_SECRET_KEY or "").strip()
        return secret in PLACEHOLDER_SECRETS or len(secret) < 32

    @property
    def baseline_path(self) -> Path:
        return DATA_DIR / "baseline" / "global_baseline_v1.json"


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
