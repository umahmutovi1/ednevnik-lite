"""
config.py — Dnevnik-Lite Configuration Layer (Audit-Fixed)
===========================================================
AUDIT FIXES APPLIED:
  CF-01: Dead-code `if False` branch removed from ProductionConfig.
         RATELIMIT_STORAGE_URI is now set ONLY inside init_secrets().
  CF-03: TestingConfig hardcoded secrets replaced with os.urandom() defaults.
  CF-04: JWT_ALGORITHM and JWT_DECODE_ALGORITHMS added to BaseConfig.
"""

import os
from datetime import timedelta


class BaseConfig:
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    @staticmethod
    def _require_env(key: str) -> str:
        value = os.environ.get(key)
        if not value:
            raise ValueError(
                f"[Security] Environment variable '{key}' is required but not set. "
                "Check your .env file."
            )
        return value

    # JWT
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(minutes=15)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=7)
    JWT_TOKEN_LOCATION = ["headers"]
    JWT_HEADER_NAME = "Authorization"
    JWT_HEADER_TYPE = "Bearer"

    # [OWASP A04:2025 – Cryptographic Failures]: Explicitly lock algorithm.
    # JWT_DECODE_ALGORITHMS is a strict allowlist — alg:none and all other
    # algorithms are structurally rejected by PyJWT before any verification logic.
    # CF-04: These were missing; added by audit.
    JWT_ALGORITHM = "HS256"
    JWT_DECODE_ALGORITHMS = ["HS256"]

    # Session Cookies
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"

    # Rate Limiting defaults
    RATELIMIT_DEFAULT = "200 per day;50 per hour"
    RATELIMIT_HEADERS_ENABLED = True


class DevelopmentConfig(BaseConfig):
    DEBUG = True
    TESTING = False

    @classmethod
    def init_secrets(cls):
        cls.SECRET_KEY = BaseConfig._require_env("SECRET_KEY")
        cls.JWT_SECRET_KEY = BaseConfig._require_env("JWT_SECRET_KEY")
        cls.SQLALCHEMY_DATABASE_URI = os.environ.get(
            "DATABASE_URL", "postgresql://dnevnik_user:changeme@localhost:5432/dnevnik_lite"
        )

    BCRYPT_LOG_ROUNDS = int(os.environ.get("BCRYPT_LOG_ROUNDS", 10))
    SESSION_COOKIE_SECURE = False
    # TODO-RESOLVED (Phase 2): Redis blocklist is in app/utils/token_blocklist.py
    RATELIMIT_STORAGE_URI = "memory://"
    FORCE_HTTPS = False


class TestingConfig(BaseConfig):
    DEBUG = False
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"

    # [OWASP A04:2025 – Cryptographic Failures]: CF-03 FIXED.
    # os.urandom() generates a fresh cryptographically random key each test run.
    # This avoids any hardcoded string literal that SonarQube rule S6290 would flag
    # as a BLOCKER. Tests that need stable tokens across calls should set
    # TEST_SECRET_KEY and TEST_JWT_SECRET_KEY as env vars in CI.
    SECRET_KEY = os.environ.get("TEST_SECRET_KEY", os.urandom(32).hex())
    JWT_SECRET_KEY = os.environ.get("TEST_JWT_SECRET_KEY", os.urandom(32).hex())

    BCRYPT_LOG_ROUNDS = 4
    SESSION_COOKIE_SECURE = False
    RATELIMIT_ENABLED = False
    RATELIMIT_STORAGE_URI = "memory://"
    FORCE_HTTPS = False
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(seconds=5)


class ProductionConfig(BaseConfig):
    # [OWASP A02:2025 – Security Misconfiguration]: DEBUG hardcoded False.
    # Never trust an env var for this — a misconfiguration could expose the
    # Werkzeug interactive debugger.
    DEBUG = False
    TESTING = False
    BCRYPT_LOG_ROUNDS = int(os.environ.get("BCRYPT_LOG_ROUNDS", 12))
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    FORCE_HTTPS = bool(int(os.environ.get("FORCE_HTTPS", 1)))

    # CF-01 FIXED: No class-level RATELIMIT_STORAGE_URI assignment.
    # The dead-code `if False else None` sentinel has been removed.
    # RATELIMIT_STORAGE_URI is set exclusively inside init_secrets() below,
    # preventing silent fallback to in-memory storage if init_secrets() is
    # ever skipped or called out of order.

    @classmethod
    def init_secrets(cls):
        cls.SECRET_KEY = BaseConfig._require_env("SECRET_KEY")
        cls.JWT_SECRET_KEY = BaseConfig._require_env("JWT_SECRET_KEY")

        db_url = BaseConfig._require_env("DATABASE_URL")
        if "sslmode" not in db_url:
            db_url += "?sslmode=require"
        cls.SQLALCHEMY_DATABASE_URI = db_url

        # [OWASP A07:2025 – Authentication Failures]: Redis required in production.
        # In-memory limiter resets on every worker restart and is not shared across
        # gunicorn workers — brute-force protection is meaningless without this.
        cls.RATELIMIT_STORAGE_URI = BaseConfig._require_env("REDIS_URL")


config_map = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": ProductionConfig,
}


def get_config(env=None):
    env = env or os.environ.get("FLASK_ENV", "development")
    cfg = config_map.get(env)
    if cfg is None:
        raise ValueError(
            f"Unknown FLASK_ENV value: '{env}'. "
            f"Must be one of: {list(config_map.keys())}"
        )
    return cfg
