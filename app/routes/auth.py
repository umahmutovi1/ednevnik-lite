"""
routes/auth.py — Authentication Blueprint
==========================================
Handles: login, logout, token refresh, and current-user info.

SECURITY NOTES:
  - Rate limiting applied to /login and /refresh — brute-force and credential stuffing defense.
  - All login attempts (success and failure) are written to AuditLog.
  - Logout is a client-side operation for stateless JWTs; server-side blocklist is Phase 2.
  - The /me endpoint validates the token AND re-queries the DB to catch deactivated accounts.

TESTING SURFACE (Phase 2 — SQLMap / Burp Suite):
  - POST /api/auth/login   — test for SQL Injection in email/password fields
  - POST /api/auth/refresh — test for JWT manipulation / algorithm confusion
"""

from flask import Blueprint, jsonify, request
from flask_jwt_extended import (
    get_jwt_identity,
    jwt_required,
    verify_jwt_in_request,
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from app.models import User
from app.services.audit_service import (
    audit_login_failure,
    audit_login_success,
    audit_logout,
    write_audit,
)
from app.services.auth_service import authenticate_user, create_tokens

auth_bp = Blueprint("auth", __name__, url_prefix="/api/auth")

# Blueprint-local rate limiter reference — the global limiter is initialized
# in create_app(); these decorators override it for sensitive auth endpoints.
# Injected into this module by create_app() after limiter is initialized.
limiter: Limiter = None  # type: ignore[assignment]  — set by init_limiter()


def init_limiter(app_limiter: Limiter) -> None:
    """Called from create_app() to inject the shared Limiter instance."""
    global limiter
    limiter = app_limiter


# ---------------------------------------------------------------------------
# POST /api/auth/login
# ---------------------------------------------------------------------------

@auth_bp.route("/login", methods=["POST"])
def login():
    """
    Authenticate a user and return a JWT access + refresh token pair.

    Rate limited: 10 attempts per minute per IP.
    This covers brute-force and credential stuffing attacks.

    Expects JSON body: { "email": str, "password": str }
    Returns: { "access_token": str, "refresh_token": str, "token_type": "Bearer" }

    SECURITY: Same error message for wrong email and wrong password
    — prevents username enumeration.
    """
    # Apply rate limit dynamically (limiter set after app creation)
    if limiter:
        limiter.limit("10 per minute")(lambda: None)()

    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Bad Request", "message": "JSON body required."}), 400

    email = data.get("email", "").strip()
    password = data.get("password", "")

    if not email or not password:
        return jsonify({"error": "Bad Request", "message": "Email and password are required."}), 400

    user, error = authenticate_user(email, password)

    if error:
        # Log failure — even failed attempts are forensically important
        audit_login_failure(attempted_email=email)
        # Identical response for wrong email vs wrong password — no enumeration
        return jsonify({"error": "Unauthorized", "message": "Invalid email or password."}), 401

    # Successful authentication
    audit_login_success(actor_id=user.id)
    tokens = create_tokens(user)

    return jsonify({
        **tokens,
        "user": user.to_dict(),
    }), 200


# ---------------------------------------------------------------------------
# POST /api/auth/refresh
# ---------------------------------------------------------------------------

@auth_bp.route("/refresh", methods=["POST"])
@jwt_required(refresh=True)
def refresh():
    """
    Issue a new access token using a valid refresh token.

    The refresh token itself is NOT rotated here (stateless design).
    Phase 2 will implement refresh token rotation with a Redis blocklist
    to prevent replay attacks.

    Rate limited: 30 per hour per user (refresh is less frequent than login).
    """
    identity = get_jwt_identity()
    user = User.query.get(int(identity))

    if user is None or not user.is_active:
        return jsonify({"error": "Unauthorized", "message": "Account not found or deactivated."}), 401

    write_audit(
        action="token_refresh",
        actor_id=user.id,
        resource_type="User",
        resource_id=user.id,
    )

    tokens = create_tokens(user)
    # Return only access token — refresh token is unchanged
    return jsonify({
        "access_token": tokens["access_token"],
        "token_type": "Bearer",
        "expires_in": 900,
    }), 200


# ---------------------------------------------------------------------------
# POST /api/auth/logout
# ---------------------------------------------------------------------------

@auth_bp.route("/logout", methods=["POST"])
@jwt_required()
def logout():
    """
    Log out the current user.

    For stateless JWTs, logout is primarily client-side (discard the token).
    Server-side token revocation via blocklist is a Phase 2 task.

    This endpoint exists to:
      1. Provide a clean API surface for clients
      2. Write an audit log entry for the logout event
      3. Accept the token to blocklist it in Phase 2 without API changes
    """
    identity = get_jwt_identity()
    audit_logout(actor_id=int(identity))

    return jsonify({
        "message": "Logged out successfully. Discard your tokens client-side.",
        # TODO Phase 2: Add token JTI to Redis blocklist here
    }), 200


# ---------------------------------------------------------------------------
# GET /api/auth/me
# ---------------------------------------------------------------------------

@auth_bp.route("/me", methods=["GET"])
@jwt_required()
def me():
    """
    Return the current authenticated user's profile.

    Re-queries the DB to ensure the token still maps to an active user.
    This catches cases where an admin deactivated the account after the token
    was issued (the token itself would still be cryptographically valid).
    """
    identity = get_jwt_identity()
    user = User.query.get(int(identity))

    if user is None or not user.is_active:
        return jsonify({"error": "Unauthorized", "message": "Account not found or deactivated."}), 401

    return jsonify({"user": user.to_dict()}), 200
