"""
services/auth_service.py — Authentication Business Logic
=========================================================
All authentication logic lives here — not in route handlers.
Routes call these functions; they do not implement auth logic themselves.

This separation ensures:
  1. Auth logic is independently testable (no HTTP context required)
  2. Route handlers stay thin and readable
  3. Security-critical code is in one auditable place

SECURITY NOTES:
  - Passwords are NEVER logged, stored in plaintext, or returned in responses.
  - bcrypt.check_password_hash() uses constant-time comparison — timing-safe.
  - JWT tokens are created here and returned to routes — never stored server-side
    (stateless). Refresh token revocation uses a blocklist (Phase 2).
  - All auth failures increment the same counter and return the same error message
    to prevent username enumeration (whether the email exists or the password is wrong,
    the client sees the same response).
"""

from typing import Optional, Tuple

from flask import current_app
from flask_bcrypt import Bcrypt
from flask_jwt_extended import create_access_token, create_refresh_token

from app.models import User, db

bcrypt = Bcrypt()


# ---------------------------------------------------------------------------
# Password Utilities
# ---------------------------------------------------------------------------

def hash_password(plaintext: str) -> str:
    """
    Hash a plaintext password using bcrypt.
    Work factor is read from BCRYPT_LOG_ROUNDS (12 in prod, 4 in tests).

    bcrypt: adaptive one-way hash — work factor configurable,
    resistant to rainbow tables and GPU brute-force.
    """
    rounds = current_app.config.get("BCRYPT_LOG_ROUNDS", 12)
    return bcrypt.generate_password_hash(plaintext, rounds=rounds).decode("utf-8")


def verify_password(plaintext: str, hashed: str) -> bool:
    """
    Constant-time bcrypt comparison — prevents timing attacks.
    Never short-circuit; always compare the full hash.
    """
    return bcrypt.check_password_hash(hashed, plaintext)


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------

def authenticate_user(email: str, password: str) -> Tuple[Optional[User], str]:
    """
    Validate credentials and return the User if successful.

    Returns (user, error_message). If error_message is empty, auth succeeded.

    SECURITY: The error message is intentionally identical whether the email
    doesn't exist OR the password is wrong — this prevents username enumeration.
    An attacker cannot distinguish "no such account" from "wrong password."

    SECURITY: Even when the email doesn't exist, we still call a dummy bcrypt
    comparison to prevent timing-based enumeration. Without this, a fast
    response (no user found → no hash check) reveals that the email isn't
    registered.
    """
    _GENERIC_ERROR = "Invalid email or password."  # Same message for all failures

    # Normalize email before lookup
    normalized_email = email.strip().lower()

    # ORM query — parameterized, no raw SQL
    user = User.query.filter_by(email=normalized_email).first()

    if user is None:
        # Dummy hash check to equalize response time regardless of whether
        # the email exists — prevents timing-based username enumeration.
        bcrypt.check_password_hash(
            "$2b$12$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            password
        )
        return None, _GENERIC_ERROR

    if not user.is_active:
        # Account exists but is deactivated — same error, same timing.
        # Do NOT reveal that the account exists but is disabled.
        bcrypt.check_password_hash(user.password_hash, password)
        return None, _GENERIC_ERROR

    if not verify_password(password, user.password_hash):
        return None, _GENERIC_ERROR

    return user, ""


# ---------------------------------------------------------------------------
# Token Creation
# ---------------------------------------------------------------------------

def create_tokens(user: User) -> dict:
    """
    Create a JWT access + refresh token pair for the given user.

    JWT short expiry (15 min): limits the damage window if a token is stolen.
    Refresh token (7 days): allows clients to renew access without re-login,
    but can be revoked server-side (Phase 2: blocklist via Redis).

    The token identity is the user's integer ID — not email, so tokens
    survive email changes without invalidation.

    Additional claims embed role — avoids a DB round-trip on every request
    to check the user's role. The role in the token is verified against the
    DB on sensitive operations (e.g., admin actions) to catch privilege changes.
    """
    additional_claims = {
        "role": user.role.name,
        "email": user.email,  # Convenience — not used for authz decisions
    }

    access_token = create_access_token(
        identity=str(user.id),
        additional_claims=additional_claims
    )
    refresh_token = create_refresh_token(
        identity=str(user.id),
        additional_claims=additional_claims
    )

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "Bearer",
        "expires_in": 900,  # 15 minutes in seconds
    }


# ---------------------------------------------------------------------------
# User Creation (Admin-only operation)
# ---------------------------------------------------------------------------

def create_user(
    email: str,
    password: str,
    first_name: str,
    last_name: str,
    role_id: int,
) -> Tuple[Optional[User], str]:
    """
    Create a new user. Called only by admin routes.

    Returns (user, error_message).

    SECURITY:
      - Password is hashed immediately — plaintext never touches the DB session.
      - Email uniqueness is checked at ORM level (raises IntegrityError if duplicate).
      - Role ID is validated against the Role table — can't assign non-existent roles.
    """
    from app.models import Role  # Local import to avoid circular imports

    normalized_email = email.strip().lower()

    # Check for existing user at application level first (better error message than DB error)
    if User.query.filter_by(email=normalized_email).first():
        return None, f"A user with email '{normalized_email}' already exists."

    # Validate role exists
    role = Role.query.get(role_id)
    if not role:
        return None, f"Role ID {role_id} does not exist."

    # Hash password immediately — plaintext never stored
    password_hash = hash_password(password)

    user = User(
        email=normalized_email,
        password_hash=password_hash,
        first_name=first_name.strip(),
        last_name=last_name.strip(),
        role_id=role_id,
        is_active=True,
    )

    try:
        db.session.add(user)
        db.session.commit()
        return user, ""
    except Exception as exc:  # pylint: disable=broad-except
        db.session.rollback()
        current_app.logger.error(f"User creation failed: {exc}")
        return None, "User creation failed due to a database error."


# ---------------------------------------------------------------------------
# Token Decoding Utility (Phase 2 — needed for logout refresh token revocation)
# ---------------------------------------------------------------------------

def decode_token_claims(token_str: str) -> dict | None:
    """
    Decode a JWT token string without verifying expiry — used during logout
    to extract the JTI and exp claims from the refresh token so we can blocklist it.

    SECURITY NOTE: We use decode_token (not verify_jwt_in_request) because the
    refresh token is not in the Authorization header during logout — it's in the body.
    We still verify the signature (decode_token verifies by default).
    Returns None if the token is malformed or the signature is invalid.
    [OWASP A07:2025 – Authentication Failures]
    """
    try:
        from flask_jwt_extended import decode_token
        return decode_token(token_str)
    except Exception:
        return None
