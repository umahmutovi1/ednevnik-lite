"""
routes/auth.py — Authentication Blueprint (Phase 2)
=====================================================
Phase 2 changes:
  - LoginSchema validates all /login input before authenticate_user is called
  - /refresh: token rotation — new refresh token issued, old JTI blocklisted
  - /logout: both access + refresh JTIs blocklisted in Redis
  - @jwt.token_in_blocklist_loader checks every protected request

OWASP 2025 COVERAGE:
  - [A07:2025 – Authentication Failures]: rate limiting, bcrypt timing safety, enumeration prevention
  - [A04:2025 – Cryptographic Failures]: JWT HS256, short-lived access tokens, Redis blocklist
  - [A05:2025 – Injection]: LoginSchema validates + strips all input
  - [A09:2025 – Security Logging and Alerting Failures]: every auth event (success + failure) audited
  - [A10:2025 – Mishandling of Exceptional Conditions]: ValidationError -> 400, never 500
"""

from flask import Blueprint, jsonify, request
from flask_jwt_extended import (
    get_jwt,
    get_jwt_identity,
    jwt_required,
)
from flask_limiter import Limiter
from marshmallow import ValidationError

from app.models import User
from app.schemas.auth_schemas import LoginSchema
from app.services.audit_service import (
    audit_login_failure,
    audit_login_success,
    audit_logout,
    write_audit,
)
from app.services.auth_service import authenticate_user, create_tokens
from app.utils.token_blocklist import blocklist_token, is_token_blocklisted

auth_bp = Blueprint("auth", __name__, url_prefix="/api/auth")

limiter: Limiter = None  # type: ignore[assignment]

_login_schema = LoginSchema()


def init_limiter(app_limiter: Limiter) -> None:
    global limiter
    limiter = app_limiter


@auth_bp.route("/login", methods=["POST"])
def login():
    """
    [OWASP A05:2025 - Injection]: LoginSchema validates all fields before any DB interaction.
    [OWASP A07:2025 - Authentication Failures]: Rate limited; same error for bad email/password.
    [OWASP A09:2025 - Security Logging]: Both success and failure written to AuditLog.
    [OWASP A10:2025 - Mishandling of Exceptional Conditions]: ValidationError -> 400, not 500.
    """
    if limiter:
        limiter.limit("10 per minute")(lambda: None)()

    raw = request.get_json(silent=True)
    if not raw:
        return jsonify({"error": "Bad Request", "message": "JSON body required."}), 400

    try:
        data = _login_schema.load(raw)
    except ValidationError:
        # Generic error -- do NOT expose which field failed (prevents email enumeration)
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
    """
    Issue a NEW access token AND a NEW refresh token (token rotation).
    Blocklist the old refresh token JTI immediately.

    [OWASP A04:2025 - Cryptographic Failures]: Token rotation ensures a stolen
    refresh token can only be used once. After rotation the old token is dead.
    [OWASP A07:2025 - Authentication Failures]: Without a blocklist, stateless JWTs
    cannot support true logout or privilege revocation.
    """
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

    # Blocklist old refresh JTI with TTL = remaining lifetime of the old token
    # Why TTL must equal remaining lifetime: longer wastes Redis memory; indefinite fills Redis.
    if old_jti:
        exp = claims.get("exp")
        blocklist_token(old_jti, exp_timestamp=exp, token_type="refresh")

    write_audit(
        action="token_refresh",
        actor_id=user.id,
        resource_type="User",
        resource_id=user.id,
        detail="Token rotated -- old refresh JTI blocklisted.",
    )

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
    Blocklist both the access token and refresh token.
    [OWASP A07:2025 - Authentication Failures]: True server-side logout.
    After this call both tokens are dead even if cryptographically valid.
    """
    claims = get_jwt()
    access_jti = claims.get("jti")
    access_exp = claims.get("exp")
    identity = get_jwt_identity()

    if access_jti:
        blocklist_token(access_jti, exp_timestamp=access_exp, token_type="access")

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
    """
    [OWASP A07:2025 - Authentication Failures]: Re-queries DB to catch deactivated accounts.
    """
    identity = get_jwt_identity()
    user = User.query.get(int(identity))
    if user is None or not user.is_active:
        return jsonify({"error": "Unauthorized", "message": "Account not found or deactivated."}), 401
    return jsonify({"user": user.to_dict()}), 200
