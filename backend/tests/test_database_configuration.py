"""Database backend policy tests."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.core.config import Settings


def test_development_requires_postgresql():
    with pytest.raises(ValidationError, match="must use PostgreSQL"):
        Settings(_env_file=None, APP_ENV="development", DATABASE_URL="sqlite:///./secureconfigai.db")


def test_production_requires_postgresql():
    with pytest.raises(ValidationError, match="must use PostgreSQL"):
        Settings(_env_file=None, APP_ENV="production", DATABASE_URL="sqlite:///./secureconfigai.db")


def test_test_environment_allows_explicit_sqlite_database():
    config = Settings(_env_file=None, APP_ENV="test", DATABASE_URL="sqlite:///./isolated-test.db")
    assert config.is_sqlite


def test_postgresql_url_uses_installed_psycopg_driver():
    config = Settings(
        _env_file=None, APP_ENV="development", DATABASE_URL="postgresql://user:password@localhost:5432/app"
    )
    assert config.DATABASE_URL == ("postgresql+psycopg://user:password@localhost:5432/app")


def test_database_url_is_required():
    with pytest.raises(ValidationError, match="DATABASE_URL is required"):
        Settings(_env_file=None, APP_ENV="development", DATABASE_URL="")
