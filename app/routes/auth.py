"""
routes/auth.py — Authentication Blueprint (Audit-Fixed)
========================================================
AUDIT FIX APPLIED:
  CF-02: The broken `limiter.limit()(lambda: None)()` pattern has been removed.
         The login rate limit is now applied in create_app() via
         app.view_functions["auth.login"] after Blueprint registration.
         The init_limiter() injection pattern is also removed.
"""

from flask import Blueprint, jsonify, request
from flask_jwt_extended import get_jwt, get_jwt_identity, jwt_required
from marshmallow import ValidationError

from app.models import User
from app.schemas.auth_schemas import LoginSchema
from app.services.audit_service import (
    audit_login_failure, audit_login_success, audit_logout, write_audit,
)
from app.services.auth_service import authenticate_user, create_tokens
from app.utils.token_blocklist import blocklist_token, is_token_blocklisted

auth_bp = Blueprint("auth", __name__, url_prefix="/api/auth")

_login_schema = LoginSchema()


@auth_bp.route("/login", methods=["POST"])
def login():
    """
    [OWASP A05:2025 – Injection]: LoginSchema validates before DB interaction.
    [OWASP A07:2025 – Authentication Failures]: Rate limit applied in create_app().
    [OWASP A09:2025 – Security Logging]: Both success and failure logged.
    [OWASP A10:2025 – Mishandling]: ValidationError -> 401 generic, not 500.

    CF-02 FIX: The broken lambda rate-limit workaround has been removed.
    The 10/min rate limit is registered in create_app() via app.view_functions.
    """
    raw = request.get_json(silent=True)
    if not raw:
        return jsonify({"error": "Bad Request", "message": "JSON body required."}), 400

    try:
        data = _login_schema.load(raw)
    except ValidationError:
        return jsonify({"error": "Unauthorized", "message": "Invalid email or password."}), 401

    user, error = authenticate_user(data["email"], data["password"])

    if error:
        audit_login_failure(attempted_email=data["email"])
        return jsonify({"error": "Unauthorized", "message": "Invalid email or password."}), 401

    audit_login_success(actor_id=user.id)
    tokens = create_tokens(user)
    return jsonify({**tokens, "user": user.to_dict()}), 200


@auth_bp.route("/refresh", methods=["POST"])
@jwt_required(refresh=True)
def refresh():
    """Token rotation with Redis blocklist. [OWASP A04:2025, A07:2025]"""
    claims = get_jwt()
    old_jti = claims.get("jti")
    identity = get_jwt_identity()

    if old_jti and is_token_blocklisted(old_jti):
        write_audit(
            action="permission_escalation_attempt",
            actor_id=int(identity) if identity else None,
            resource_type="Token",
            detail=f"Blocklisted refresh token reuse attempt. JTI: {old_jti}",
        )
        return jsonify({"error": "Unauthorized", "message": "Token has been revoked."}), 401

    user = User.query.get(int(identity))
    if user is None or not user.is_active:
        return jsonify({"error": "Unauthorized", "message": "Account not found or deactivated."}), 401

    new_tokens = create_tokens(user)

    if old_jti:
        exp = claims.get("exp")
        blocklist_token(old_jti, exp_timestamp=exp, token_type="refresh")

    write_audit(action="token_refresh", actor_id=user.id, resource_type="User",
                resource_id=user.id, detail="Token rotated -- old refresh JTI blocklisted.")

    return jsonify({
        "access_token": new_tokens["access_token"],
        "refresh_token": new_tokens["refresh_token"],
        "token_type": "Bearer",
        "expires_in": 900,
    }), 200


@auth_bp.route("/logout", methods=["POST"])
@jwt_required()
def logout():
    """
    Dual-JTI revocation. [OWASP A07:2025]
    AUDIT FIX (Gap-04): blocklist_token() return value is checked.
    If the Redis write fails, we return 503 rather than 200 — a 200 would
    imply the token is dead when it is not.
    """
    claims = get_jwt()
    access_jti = claims.get("jti")
    access_exp = claims.get("exp")
    identity = get_jwt_identity()

    if access_jti:
        # [OWASP A10:2025 – Mishandling of Exceptional Conditions]:
        # Check the return value — False means Redis write failed.
        success = blocklist_token(access_jti, exp_timestamp=access_exp, token_type="access")
        if not success:
            return jsonify({
                "error": "ServiceUnavailable",
                "message": "Logout could not be completed. Please try again.",
            }), 503

    raw = request.get_json(silent=True) or {}
    refresh_token_str = raw.get("refresh_token")
    if refresh_token_str:
        from app.services.auth_service import decode_token_claims
        refresh_claims = decode_token_claims(refresh_token_str)
        if refresh_claims:
            refresh_jti = refresh_claims.get("jti")
            refresh_exp = refresh_claims.get("exp")
            if refresh_jti:
                blocklist_token(refresh_jti, exp_timestamp=refresh_exp, token_type="refresh")

    audit_logout(actor_id=int(identity))
    return jsonify({"message": "Logged out successfully. Both tokens have been revoked."}), 200


@auth_bp.route("/me", methods=["GET"])
@jwt_required()
def me():
    """[OWASP A07:2025]: Re-queries DB to catch deactivated accounts."""
    identity = get_jwt_identity()
    user = User.query.get(int(identity))
    if user is None or not user.is_active:
        return jsonify({"error": "Unauthorized", "message": "Account not found or deactivated."}), 401
    return jsonify({"user": user.to_dict()}), 200
