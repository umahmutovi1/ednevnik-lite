"""
utils/decorators.py — Role-Based Access Control (RBAC) Decorators
==================================================================
All route-level access control lives here.

RBAC DESIGN (Defense in Depth):
  - Layer 1: JWT token required (@jwt_required()) — unauthenticated requests rejected
  - Layer 2: Role claim in JWT — quick rejection without DB hit
  - Layer 3: Role verified against DB — catches privilege changes after token issuance
  - Layer 4: ORM-level scoping in service layer — data access further restricted

All access denials write to AuditLog — failed attempts are forensically important.

PRINCIPLE OF LEAST PRIVILEGE:
  - @admin_required rejects teacher AND student tokens (not just students)
  - @teacher_required rejects admin AND student tokens
  - @student_required rejects admin AND teacher tokens
  This prevents unintended privilege bleeding between roles.

USAGE:
    @teacher_bp.route("/grades", methods=["POST"])
    @teacher_required
    def create_grade():
        teacher_id = get_current_user_id()
        ...
"""

import functools
from typing import Callable

from flask import jsonify, request
from flask_jwt_extended import get_jwt, get_jwt_identity, verify_jwt_in_request

from app.models import User


# ---------------------------------------------------------------------------
# Internal helper
# ---------------------------------------------------------------------------

def _get_current_user_and_role() -> tuple[User | None, str | None]:
    """
    Retrieve the current authenticated user from DB and their role.

    We re-verify the role against the DB (not just the JWT claim) to handle
    cases where an admin changes a user's role after the token was issued.
    The JWT role claim is a cache — the DB is the source of truth.
    """
    identity = get_jwt_identity()
    user = User.query.get(int(identity))
    if user is None or not user.is_active:
        return None, None
    role_name = user.role.name if user.role else None
    return user, role_name


def _deny_access(actor_id: int | None, reason: str):
    """Write audit entry and return a 403 response."""
    from app.services.audit_service import audit_access_denied

    attempted_route = request.path
    audit_access_denied(actor_id=actor_id, attempted_resource=f"{request.method} {attempted_route}")

    return jsonify({
        "error": "Forbidden",
        "message": reason,
    }), 403


# ---------------------------------------------------------------------------
# Public decorator factory
# ---------------------------------------------------------------------------

def _role_required(*allowed_roles: str) -> Callable:
    """
    Decorator factory: enforce that the current JWT identity has one of the allowed roles.

    SECURITY NOTE: We check BOTH the JWT claim (fast, no DB) AND the DB (authoritative).
    If they differ, we trust the DB — the token may be stale.
    """
    def decorator(fn: Callable) -> Callable:
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            # Step 1: Validate JWT signature and expiry
            try:
                verify_jwt_in_request()
            except Exception:
                return jsonify({
                    "error": "Unauthorized",
                    "message": "A valid Bearer token is required.",
                }), 401

            # Step 2: Quick check — role claim in JWT
            claims = get_jwt()
            jwt_role = claims.get("role")
            identity = get_jwt_identity()

            if jwt_role not in allowed_roles:
                return _deny_access(
                    actor_id=int(identity) if identity else None,
                    reason=f"This endpoint requires role: {' or '.join(allowed_roles)}."
                )

            # Step 3: Authoritative check — verify role in DB
            # (handles role changes after token issuance, deactivated accounts)
            user, db_role = _get_current_user_and_role()

            if user is None:
                return jsonify({
                    "error": "Unauthorized",
                    "message": "Account not found or deactivated.",
                }), 401

            if db_role not in allowed_roles:
                return _deny_access(
                    actor_id=user.id,
                    reason=f"Insufficient privileges. Required: {' or '.join(allowed_roles)}."
                )

            # Step 4: Attach user to kwargs so route handlers don't re-query DB
            kwargs["current_user"] = user
            return fn(*args, **kwargs)

        return wrapper
    return decorator


# ---------------------------------------------------------------------------
# Public role decorators
# ---------------------------------------------------------------------------

def admin_required(fn: Callable) -> Callable:
    """
    Restrict endpoint to Admin role only.
    Rejects nastavnik AND ucenik tokens — not just ucenik.
    """
    return _role_required("admin")(fn)


def teacher_required(fn: Callable) -> Callable:
    """
    Restrict endpoint to Nastavnik (Teacher) role only.
    Admins must use admin endpoints; teachers cannot access admin endpoints.
    """
    return _role_required("nastavnik")(fn)


def student_required(fn: Callable) -> Callable:
    """
    Restrict endpoint to Učenik (Student) role only — read-only access.
    """
    return _role_required("ucenik")(fn)


def admin_or_teacher_required(fn: Callable) -> Callable:
    """
    Allow both Admin and Nastavnik — used for shared read endpoints (e.g., viewing classes).
    """
    return _role_required("admin", "nastavnik")(fn)


# ---------------------------------------------------------------------------
# Utility: get current user ID without re-querying DB
# ---------------------------------------------------------------------------

def get_current_user_id() -> int:
    """Extract and return the integer user ID from the current JWT identity."""
    return int(get_jwt_identity())
