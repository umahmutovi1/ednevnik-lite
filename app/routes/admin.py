"""
routes/admin.py — Admin Blueprint
===================================
Endpoints accessible only to users with role='admin'.

RBAC:
  - Every route decorated with @admin_required
  - @admin_required checks JWT signature → JWT role claim → DB role (3 layers)
  - All sensitive operations written to AuditLog

AVAILABLE ENDPOINTS:
  GET    /api/admin/users            — List all users
  POST   /api/admin/users            — Create a new user
  GET    /api/admin/users/<id>       — Get one user
  PATCH  /api/admin/users/<id>       — Update user (role, name, active status)
  DELETE /api/admin/users/<id>       — Soft-delete (deactivate) user
  GET    /api/admin/audit-logs       — Paginated audit log viewer

TESTING SURFACE (Phase 2):
  - All endpoints: Burp Suite auth flow testing (attempt access with teacher/student tokens)
  - POST /api/admin/users: marshmallow schema validation testing (Phase 2)
  - GET /api/admin/audit-logs: test pagination parameters for injection
"""

from flask import Blueprint, jsonify, request

from app.models import AuditLog, Role, User, db
from app.services.audit_service import (
    audit_user_created,
    audit_user_deactivated,
    write_audit,
)
from app.services.auth_service import create_user
from app.utils.decorators import admin_required, get_current_user_id

admin_bp = Blueprint("admin", __name__, url_prefix="/api/admin")


# ---------------------------------------------------------------------------
# GET /api/admin/users — List all users
# ---------------------------------------------------------------------------

@admin_bp.route("/users", methods=["GET"])
@admin_required
def list_users(current_user):
    """
    Return all users (paginated).

    Query params:
      - page (int, default 1)
      - per_page (int, default 20, max 100)
      - role (str, optional filter: admin | nastavnik | ucenik)
      - active (bool, optional filter)
    """
    page = request.args.get("page", 1, type=int)
    per_page = min(request.args.get("per_page", 20, type=int), 100)
    role_filter = request.args.get("role")
    active_filter = request.args.get("active")

    # ORM query — all filters parameterized, no raw SQL
    query = User.query

    if role_filter:
        role = Role.query.filter_by(name=role_filter).first()
        if role:
            query = query.filter_by(role_id=role.id)

    if active_filter is not None:
        is_active = active_filter.lower() in ("true", "1", "yes")
        query = query.filter_by(is_active=is_active)

    pagination = query.order_by(User.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )

    return jsonify({
        "users": [u.to_dict() for u in pagination.items],
        "total": pagination.total,
        "page": pagination.page,
        "pages": pagination.pages,
        "per_page": per_page,
    }), 200


# ---------------------------------------------------------------------------
# POST /api/admin/users — Create a new user
# ---------------------------------------------------------------------------

@admin_bp.route("/users", methods=["POST"])
@admin_required
def create_user_endpoint(current_user):
    """
    Create a new user. Admin only.

    NOTE: Full marshmallow schema validation is a Phase 2 task.
    Current validation is minimal — expand before production.

    Expects JSON: {
        "email": str,
        "password": str,
        "first_name": str,
        "last_name": str,
        "role_id": int
    }
    """
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Bad Request", "message": "JSON body required."}), 400

    required = ["email", "password", "first_name", "last_name", "role_id"]
    missing = [f for f in required if not data.get(f)]
    if missing:
        return jsonify({
            "error": "Bad Request",
            "message": f"Missing required fields: {', '.join(missing)}"
        }), 400

    # TODO Phase 2: Replace manual field extraction with marshmallow schema validation
    user, error = create_user(
        email=data["email"],
        password=data["password"],
        first_name=data["first_name"],
        last_name=data["last_name"],
        role_id=data["role_id"],
    )

    if error:
        return jsonify({"error": "Conflict", "message": error}), 409

    audit_user_created(
        actor_id=current_user.id,
        new_user_id=user.id,
        email=user.email,
    )

    return jsonify({"message": "User created.", "user": user.to_dict()}), 201


# ---------------------------------------------------------------------------
# GET /api/admin/users/<user_id> — Get one user
# ---------------------------------------------------------------------------

@admin_bp.route("/users/<int:user_id>", methods=["GET"])
@admin_required
def get_user(current_user, user_id: int):
    """Return a single user by ID."""
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "Not Found", "message": f"User {user_id} not found."}), 404

    return jsonify({"user": user.to_dict()}), 200


# ---------------------------------------------------------------------------
# PATCH /api/admin/users/<user_id> — Update user
# ---------------------------------------------------------------------------

@admin_bp.route("/users/<int:user_id>", methods=["PATCH"])
@admin_required
def update_user(current_user, user_id: int):
    """
    Partially update a user. Admin only.

    Updateable fields: first_name, last_name, role_id, is_active.
    Email and password changes require dedicated endpoints (Phase 2).

    SECURITY: Admins cannot change their own role (prevents accidental self-demotion).
    """
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "Not Found", "message": f"User {user_id} not found."}), 404

    data = request.get_json(silent=True) or {}
    changes = []

    if "first_name" in data:
        user.first_name = data["first_name"].strip()
        changes.append("first_name")

    if "last_name" in data:
        user.last_name = data["last_name"].strip()
        changes.append("last_name")

    if "role_id" in data:
        # Prevent admins from changing their own role
        if user_id == current_user.id:
            return jsonify({
                "error": "Forbidden",
                "message": "Admins cannot change their own role."
            }), 403
        role = Role.query.get(data["role_id"])
        if not role:
            return jsonify({"error": "Bad Request", "message": "Invalid role_id."}), 400
        user.role_id = data["role_id"]
        changes.append(f"role → {role.name}")

    if "is_active" in data:
        if user_id == current_user.id and not data["is_active"]:
            return jsonify({
                "error": "Forbidden",
                "message": "Admins cannot deactivate their own account."
            }), 403
        user.is_active = bool(data["is_active"])
        action = "user_activated" if user.is_active else "user_deactivated"
        write_audit(
            action=action,
            actor_id=current_user.id,
            resource_type="User",
            resource_id=user_id,
            detail=f"{action} by admin {current_user.email}",
        )
        changes.append(f"is_active → {user.is_active}")

    if not changes:
        return jsonify({"message": "No changes provided."}), 200

    db.session.commit()

    write_audit(
        action="user_updated",
        actor_id=current_user.id,
        resource_type="User",
        resource_id=user_id,
        detail=f"Fields changed: {', '.join(changes)}",
    )

    return jsonify({"message": "User updated.", "user": user.to_dict()}), 200


# ---------------------------------------------------------------------------
# DELETE /api/admin/users/<user_id> — Soft-delete (deactivate)
# ---------------------------------------------------------------------------

@admin_bp.route("/users/<int:user_id>", methods=["DELETE"])
@admin_required
def deactivate_user(current_user, user_id: int):
    """
    Soft-delete a user by deactivating them.

    SECURITY: We never hard-delete users — doing so would orphan AuditLog
    entries and destroy the forensic trail. Deactivated accounts cannot log in
    but their history is preserved.
    """
    if user_id == current_user.id:
        return jsonify({
            "error": "Forbidden",
            "message": "Admins cannot deactivate their own account."
        }), 403

    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "Not Found", "message": f"User {user_id} not found."}), 404

    if not user.is_active:
        return jsonify({"message": "User is already deactivated."}), 200

    user.is_active = False
    db.session.commit()

    audit_user_deactivated(
        actor_id=current_user.id,
        target_user_id=user_id,
        email=user.email,
    )

    return jsonify({"message": f"User {user.email} has been deactivated."}), 200


# ---------------------------------------------------------------------------
# GET /api/admin/audit-logs — Audit log viewer
# ---------------------------------------------------------------------------

@admin_bp.route("/audit-logs", methods=["GET"])
@admin_required
def view_audit_logs(current_user):
    """
    Paginated audit log viewer. Admin only.

    Query params:
      - page (int, default 1)
      - per_page (int, default 50, max 200)
      - action (str, optional filter)
      - actor_id (int, optional filter)
    """
    page = request.args.get("page", 1, type=int)
    per_page = min(request.args.get("per_page", 50, type=int), 200)
    action_filter = request.args.get("action")
    actor_filter = request.args.get("actor_id", type=int)

    query = AuditLog.query

    if action_filter:
        query = query.filter_by(action=action_filter)

    if actor_filter:
        query = query.filter_by(actor_id=actor_filter)

    pagination = query.order_by(AuditLog.timestamp.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )

    return jsonify({
        "logs": [log.to_dict() for log in pagination.items],
        "total": pagination.total,
        "page": pagination.page,
        "pages": pagination.pages,
    }), 200
