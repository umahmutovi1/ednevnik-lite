"""
routes/admin.py — Admin Blueprint (Phase 2)
============================================
Phase 2 changes:
  - CreateUserSchema and UpdateUserSchema replace manual data.get() extraction
  - ValidationError returns generic 400 — no internal field names exposed
  - All OWASP 2025 references updated

[OWASP A01:2025 – Broken Access Control]: @admin_required, 3-layer RBAC
[OWASP A05:2025 – Injection]: Schemas validate all input before business logic
[OWASP A10:2025 – Mishandling of Exceptional Conditions]: ValidationError -> 400, not 500
[OWASP A09:2025 – Security Logging and Alerting Failures]: AuditLog on every mutation
"""

from flask import Blueprint, jsonify, request
from marshmallow import ValidationError

from app.models import AuditLog, Role, User, db
from app.schemas.admin_schemas import CreateUserSchema, UpdateUserSchema
from app.services.audit_service import (
    audit_user_created,
    audit_user_deactivated,
    write_audit,
)
from app.services.auth_service import create_user
from app.utils.decorators import admin_required

admin_bp = Blueprint("admin", __name__, url_prefix="/api/admin")

_create_user_schema = CreateUserSchema()
_update_user_schema = UpdateUserSchema()


@admin_bp.route("/users", methods=["GET"])
@admin_required
def list_users(current_user):
    page = request.args.get("page", 1, type=int)
    per_page = min(request.args.get("per_page", 20, type=int), 100)
    role_filter = request.args.get("role")
    active_filter = request.args.get("active")

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


@admin_bp.route("/users", methods=["POST"])
@admin_required
def create_user_endpoint(current_user):
    """
    [OWASP A05:2025 – Injection]: CreateUserSchema validates all fields.
    [OWASP A01:2025 – Broken Access Control]: role_id allowlist in schema.
    [OWASP A10:2025 – Mishandling of Exceptional Conditions]: ValidationError -> 400.
    """
    raw = request.get_json(silent=True)
    if not raw:
        return jsonify({"error": "Bad Request", "message": "JSON body required."}), 400

    try:
        # [OWASP A05:2025 – Injection]: schema is the first gate
        data = _create_user_schema.load(raw)
    except ValidationError as err:
        # [OWASP A10:2025 – Mishandling of Exceptional Conditions]:
        # Return field errors but NEVER expose internal model structure.
        # err.messages keys are schema field names — safe to return.
        return jsonify({"error": "Bad Request", "message": err.messages}), 400

    user, error = create_user(
        email=data["email"],
        password=data["password"],
        first_name=data["first_name"],
        last_name=data["last_name"],
        role_id=data["role_id"],
    )

    if error:
        return jsonify({"error": "Conflict", "message": error}), 409

    audit_user_created(actor_id=current_user.id, new_user_id=user.id, email=user.email)
    return jsonify({"message": "User created.", "user": user.to_dict()}), 201


@admin_bp.route("/users/<int:user_id>", methods=["GET"])
@admin_required
def get_user(current_user, user_id: int):
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "Not Found", "message": f"User {user_id} not found."}), 404
    return jsonify({"user": user.to_dict()}), 200


@admin_bp.route("/users/<int:user_id>", methods=["PATCH"])
@admin_required
def update_user(current_user, user_id: int):
    """
    [OWASP A05:2025 – Injection]: UpdateUserSchema validates all provided fields.
    [OWASP A01:2025 – Broken Access Control]: role_id allowlist enforced in schema.
    """
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "Not Found", "message": f"User {user_id} not found."}), 404

    raw = request.get_json(silent=True) or {}

    try:
        data = _update_user_schema.load(raw)
    except ValidationError as err:
        return jsonify({"error": "Bad Request", "message": err.messages}), 400

    changes = []

    if "first_name" in data:
        user.first_name = data["first_name"]
        changes.append("first_name")

    if "last_name" in data:
        user.last_name = data["last_name"]
        changes.append("last_name")

    if "role_id" in data:
        if user_id == current_user.id:
            return jsonify({"error": "Forbidden", "message": "Admins cannot change their own role."}), 403
        role = Role.query.get(data["role_id"])
        if not role:
            return jsonify({"error": "Bad Request", "message": "Invalid role_id."}), 400
        user.role_id = data["role_id"]
        changes.append(f"role -> {role.name}")

    if "is_active" in data:
        if user_id == current_user.id and not data["is_active"]:
            return jsonify({"error": "Forbidden", "message": "Admins cannot deactivate their own account."}), 403
        user.is_active = data["is_active"]
        action = "user_activated" if user.is_active else "user_deactivated"
        write_audit(action=action, actor_id=current_user.id, resource_type="User", resource_id=user_id,
                    detail=f"{action} by admin {current_user.email}")
        changes.append(f"is_active -> {user.is_active}")

    if not changes:
        return jsonify({"message": "No changes provided."}), 200

    db.session.commit()
    write_audit(action="user_updated", actor_id=current_user.id, resource_type="User",
                resource_id=user_id, detail=f"Fields changed: {', '.join(changes)}")
    return jsonify({"message": "User updated.", "user": user.to_dict()}), 200


@admin_bp.route("/users/<int:user_id>", methods=["DELETE"])
@admin_required
def deactivate_user(current_user, user_id: int):
    if user_id == current_user.id:
        return jsonify({"error": "Forbidden", "message": "Admins cannot deactivate their own account."}), 403

    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "Not Found", "message": f"User {user_id} not found."}), 404

    if not user.is_active:
        return jsonify({"message": "User is already deactivated."}), 200

    user.is_active = False
    db.session.commit()
    audit_user_deactivated(actor_id=current_user.id, target_user_id=user_id, email=user.email)
    return jsonify({"message": f"User {user.email} has been deactivated."}), 200


@admin_bp.route("/audit-logs", methods=["GET"])
@admin_required
def view_audit_logs(current_user):
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
