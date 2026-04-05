"""
config.py — Dnevnik-Lite Configuration Layer
=============================================
Three config classes cover the full deployment lifecycle:
  - DevelopmentConfig  : local dev, DEBUG on, relaxed cookie/HTTPS settings
  - TestingConfig      : pytest runs, in-memory SQLite, fast bcrypt
  - ProductionConfig   : hardened, HTTPS-only, Redis, strict cookies

SECURITY NOTE: SECRET_KEY and JWT_SECRET_KEY are read exclusively from
environment variables. The application raises ValueError at startup if
either is missing — this prevents silent fallback to weak defaults.
"""

import os
from datetime import timedelta


class BaseConfig:
    """
    Shared settings inherited by all environments.
    Defaults here are the MOST RESTRICTIVE values; child classes
    may only relax them when explicitly justified.
    """

    # -------------------------------------------------------------------------
    # Secrets — MUST come from environment; no hardcoded fallbacks
    # -------------------------------------------------------------------------
    @staticmethod
    def _require_env(key: str) -> str:
        """Raise loudly at startup if a required secret is absent."""
        value = os.environ.get(key)
        if not value:
            raise ValueError(
                f"[Security] Environment variable '{key}' is required but not set. "
                "Check your .env file. The application will not start without it."
            )
        return value

    # -------------------------------------------------------------------------
    # SQLAlchemy
    # -------------------------------------------------------------------------
    SQLALCHEMY_TRACK_MODIFICATIONS = False  # Disable event system overhead

    # -------------------------------------------------------------------------
    # JWT — Flask-JWT-Extended
    # Access tokens expire in 15 minutes:
    #   - Limits damage window if a token is stolen or leaked in logs/headers.
    #   - Short enough to reduce exposure; client must use refresh token to renew.
    # Refresh tokens expire in 7 days:
    #   - UX tradeoff: users don't have to re-login daily.
    #   - Refresh tokens are longer-lived but can be revoked server-side (blocklist).
    #   - Rotating refresh tokens (new refresh token on each use) prevents replay attacks.
    # -------------------------------------------------------------------------
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(minutes=15)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=7)
    JWT_TOKEN_LOCATION = ["headers"]          # Accept tokens only in Authorization header
    JWT_HEADER_NAME = "Authorization"
    JWT_HEADER_TYPE = "Bearer"

    # -------------------------------------------------------------------------
    # Session Cookies
    # SECURE: cookie is only sent over HTTPS — prevents cleartext sniffing.
    # HTTPONLY: JavaScript cannot read the cookie — mitigates XSS token theft.
    # SAMESITE='Lax': blocks cross-site request forgery (CSRF) in most cases
    #   without breaking normal navigation links.
    # -------------------------------------------------------------------------
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"

    # -------------------------------------------------------------------------
    # Rate Limiting defaults (Flask-Limiter)
    # Production MUST override RATELIMIT_STORAGE_URI with Redis.
    # -------------------------------------------------------------------------
    RATELIMIT_DEFAULT = "200 per day;50 per hour"
    RATELIMIT_HEADERS_ENABLED = True          # Expose X-RateLimit-* headers to clients


class DevelopmentConfig(BaseConfig):
    """
    Local development — convenience over maximum security.
    DEBUG is True; HTTPS is not enforced; cookies are non-secure
    so plain HTTP (localhost) works without cert setup.
    """
    DEBUG = True
    TESTING = False

    # Secrets — still read from .env, never hardcoded
    @classmethod
    def init_secrets(cls):
        cls.SECRET_KEY = BaseConfig._require_env("SECRET_KEY")
        cls.JWT_SECRET_KEY = BaseConfig._require_env("JWT_SECRET_KEY")
        cls.SQLALCHEMY_DATABASE_URI = os.environ.get(
            "DATABASE_URL", "postgresql://dnevnik_user:changeme@localhost:5432/dnevnik_lite"
        )

    # bcrypt work factor — lower in dev to speed up login during development
    # MUST be 12+ in production
    BCRYPT_LOG_ROUNDS = int(os.environ.get("BCRYPT_LOG_ROUNDS", 10))

    # Relax cookie security for HTTP localhost
    SESSION_COOKIE_SECURE = False

    # TODO: Production — switch storage to Redis
    RATELIMIT_STORAGE_URI = "memory://"

    FORCE_HTTPS = False


class TestingConfig(BaseConfig):
    """
    pytest test suite — fast, isolated, no real DB or network.
    """
    DEBUG = False
    TESTING = True

    # In-memory SQLite — fast, isolated, destroyed after each test run
    # No SSL mode needed (not PostgreSQL)
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"

    # Placeholder secrets for tests — tests must not use real credentials
    SECRET_KEY = "test-secret-key-not-for-production"          # noqa: S105
    JWT_SECRET_KEY = "test-jwt-secret-key-not-for-production"  # noqa: S105

    # bcrypt work factor 4: absolute minimum, only acceptable in tests
    # Makes hashing near-instant so test suites don't time out
    BCRYPT_LOG_ROUNDS = 4

    SESSION_COOKIE_SECURE = False

    # Disable rate limiting in tests so fixtures don't trip limits
    RATELIMIT_ENABLED = False

    # TODO: Production — switch storage to Redis
    RATELIMIT_STORAGE_URI = "memory://"

    FORCE_HTTPS = False

    # JWT very short in tests — we want to test expiry behavior easily
    # Override per-test with app.config.update() where needed
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(seconds=5)


class ProductionConfig(BaseConfig):
    """
    Production — maximum security. No DEBUG, HTTPS enforced, Redis required.
    This class will RAISE at startup if required environment variables are absent.
    """

    # DEBUG is HARDCODED False — never trust an env var for this alone.
    # A misconfigured environment variable could accidentally enable debug mode,
    # exposing stack traces, the interactive debugger, and internal state.
    DEBUG = False
    TESTING = False

    @classmethod
    def init_secrets(cls):
        cls.SECRET_KEY = BaseConfig._require_env("SECRET_KEY")
        cls.JWT_SECRET_KEY = BaseConfig._require_env("JWT_SECRET_KEY")

        db_url = BaseConfig._require_env("DATABASE_URL")
        # Enforce SSL on all production DB connections to prevent
        # cleartext credential and data exposure in transit
        if "sslmode" not in db_url:
            db_url += "?sslmode=require"
        cls.SQLALCHEMY_DATABASE_URI = db_url

    # bcrypt work factor 12: NIST-recommended minimum for production.
    # ~300ms per hash — slow enough to deter brute force, fast enough for UX.
    BCRYPT_LOG_ROUNDS = int(os.environ.get("BCRYPT_LOG_ROUNDS", 12))

    # Strict cookies — HTTPS only, not readable by JS
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"

    # Redis for distributed rate limiting — in-memory is single-process only
    # and resets on restart (useless for production brute-force defense)
    RATELIMIT_STORAGE_URI = BaseConfig._require_env.__func__(
        None  # evaluated lazily in init_app
    ) if False else None  # Sentinel — real value set in init_secrets

    @classmethod
    def init_secrets(cls):  # type: ignore[override]
        cls.SECRET_KEY = BaseConfig._require_env("SECRET_KEY")
        cls.JWT_SECRET_KEY = BaseConfig._require_env("JWT_SECRET_KEY")

        db_url = BaseConfig._require_env("DATABASE_URL")
        if "sslmode" not in db_url:
            db_url += "?sslmode=require"
        cls.SQLALCHEMY_DATABASE_URI = db_url

        # Redis for Flask-Limiter — required in production
        cls.RATELIMIT_STORAGE_URI = BaseConfig._require_env("REDIS_URL")

    FORCE_HTTPS = bool(int(os.environ.get("FORCE_HTTPS", 1)))


# ---------------------------------------------------------------------------
# Config registry — referenced by create_app() via FLASK_ENV
# ---------------------------------------------------------------------------
config_map = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": ProductionConfig,
}


def get_config(env: str | None = None) -> type:
    """
    Return the config class for the given environment string.
    Falls back to DevelopmentConfig if FLASK_ENV is not set.
    """
    env = env or os.environ.get("FLASK_ENV", "development")
    cfg = config_map.get(env)
    if cfg is None:
        raise ValueError(
            f"Unknown FLASK_ENV value: '{env}'. "
            f"Must be one of: {list(config_map.keys())}"
        )
    return cfg
