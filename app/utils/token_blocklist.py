"""
app/utils/token_blocklist.py — Redis JWT Blocklist
===================================================
Implements server-side JWT revocation via Redis JTI (JWT ID) storage.

WHY STATELESS JWTs NEED A BLOCKLIST:
  A JWT is self-contained — it carries its own validity proof (the signature).
  Without a server-side check, the server has NO way to invalidate an issued token
  before its natural expiry. This means:
    - Logout is a lie: the client discards the token but the server would accept it for
      up to 15 more minutes (access token TTL).
    - Privilege revocation is impossible: if an admin downgrades a teacher to a student,
      the teacher's access token still passes the "nastavnik" role check until it expires.
    - Account deactivation has a delay: `is_active=False` is checked on DB re-query,
      but a cached route (one that doesn't re-query) would still honor the token.

  A blocklist solves this by making every protected request ask: "is this JTI dead?"
  [OWASP A07:2025 – Authentication Failures]
  [OWASP A04:2025 – Cryptographic Failures]

GRACEFUL DEGRADATION — FAIL CLOSED:
  If Redis is unreachable, we DO NOT fall back to "assume the token is valid."
  Failing open (accepting tokens when the blocklist is unavailable) completely defeats
  the purpose of the blocklist — an attacker who can disrupt Redis connectivity would
  be able to reuse revoked tokens indefinitely.

  Fail-closed behavior: if Redis raises an exception, we treat the token as BLOCKLISTED
  and return 401. This is the conservative choice — a brief Redis outage causes
  authentication failures (recoverable), not a security bypass (unrecoverable).
  [OWASP A10:2025 – Mishandling of Exceptional Conditions]

KEY NAMING:
  Redis key: `jti_blocklist:{jti}`
  - Namespaced to avoid collision with other Redis data in the same instance
  - TTL set to remaining token lifetime so Redis auto-expires entries (no manual cleanup)

TTL LOGIC:
  We set TTL = max(0, exp_timestamp - now). This means:
    - A token with 5 minutes left: TTL = 300 seconds
    - An already-expired token: TTL = 0 → Redis won't store it (already invalid naturally)
  This prevents unbounded Redis growth without any scheduled cleanup jobs.
"""

import sys
import time
from typing import Optional

import redis
from flask import current_app

# Module-level Redis client — initialized lazily on first use
_redis_client: Optional[redis.Redis] = None

# Key prefix for all blocklist entries
_KEY_PREFIX = "jti_blocklist:"


def _get_redis() -> redis.Redis:
    """
    Return the Redis client, creating it on first call.
    Uses REDIS_URL from app config; falls back to localhost:6379 for dev.
    [OWASP A02:2025 – Security Misconfiguration]: Redis URL must be set in production config.
    """
    global _redis_client
    if _redis_client is None:
        redis_url = current_app.config.get("REDIS_URL", "redis://localhost:6379/0")
        _redis_client = redis.from_url(redis_url, decode_responses=True)
    return _redis_client


def blocklist_token(jti: str, exp_timestamp: Optional[int], token_type: str = "access") -> bool:
    """
    Write a JWT JTI to the Redis blocklist with TTL = remaining token lifetime.

    Parameters
    ----------
    jti           : JWT ID claim — unique identifier for this specific token
    exp_timestamp : Unix timestamp of token expiry (from the 'exp' JWT claim)
    token_type    : 'access' or 'refresh' — for logging only

    Returns
    -------
    True if the token was successfully blocklisted, False if Redis was unreachable.

    FAIL CLOSED NOTE: This function returns False on Redis failure rather than raising.
    The CALLER is responsible for treating False as a hard failure (return 401).
    We never silently accept a token we couldn't verify against the blocklist.
    """
    try:
        r = _get_redis()
        key = f"{_KEY_PREFIX}{jti}"

        if exp_timestamp is None:
            # No expiry claim — blocklist with a safe default TTL (7 days = max refresh TTL)
            ttl_seconds = 7 * 24 * 3600
        else:
            # TTL = remaining lifetime, floored at 1 second
            # [OWASP A04:2025 – Cryptographic Failures]: TTL must exactly match token lifetime
            ttl_seconds = max(1, int(exp_timestamp - time.time()))

        r.setex(key, ttl_seconds, token_type)
        return True

    except redis.RedisError as exc:
        # [OWASP A10:2025 – Mishandling of Exceptional Conditions]:
        # Log the failure loudly but return False — caller must treat this as failure
        print(
            f"[CRITICAL] Redis blocklist write FAILED for JTI {jti}: {exc}",
            file=sys.stderr,
        )
        return False


def is_token_blocklisted(jti: str) -> bool:
    """
    Check whether a JTI is in the Redis blocklist.

    Returns True if blocklisted OR if Redis is unreachable (fail-closed).
    Returns False only if Redis confirms the key does NOT exist.

    FAIL CLOSED:
      Redis unavailable → return True (reject the token).
      This means a Redis outage causes 401s, not security bypasses.
      [OWASP A10:2025 – Mishandling of Exceptional Conditions]
    """
    try:
        r = _get_redis()
        key = f"{_KEY_PREFIX}{jti}"
        return r.exists(key) == 1

    except redis.RedisError as exc:
        # [OWASP A10:2025 – Mishandling of Exceptional Conditions]: fail closed
        print(
            f"[CRITICAL] Redis blocklist check FAILED for JTI {jti}: {exc}. "
            "Rejecting token (fail-closed).",
            file=sys.stderr,
        )
        return True  # Fail CLOSED — reject the token if we can't verify


def register_blocklist_loader(jwt_manager) -> None:
    """
    Register the blocklist check with Flask-JWT-Extended.

    This function is called once in create_app(). After registration, every
    request that uses @jwt_required() will automatically call is_token_blocklisted()
    before reaching the route handler.

    [OWASP A07:2025 – Authentication Failures]: The loader runs on EVERY protected
    request — a token issued before logout/rotation is rejected here before any
    route logic runs, regardless of which decorator protects the route.
    """
    @jwt_manager.token_in_blocklist_loader
    def check_if_token_in_blocklist(jwt_header, jwt_payload: dict) -> bool:
        jti = jwt_payload.get("jti")
        if not jti:
            # No JTI claim — this is an unusual token; reject it conservatively
            return True
        return is_token_blocklisted(jti)
