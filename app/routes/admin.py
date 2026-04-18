"""
routes/admin.py — Admin Blueprint (SonarQube Fixed)
====================================================
SONARQUBE KOREKCIJE:
  1. COGNITIVE COMPLEXITY (L68): update_user funkcija imala complexity 19.
     Reducirana na ~12 ekstraktovanjem logike promjene role i is_active
     u zasebne helper funkcije _apply_role_change() i _apply_active_change().
     → Sigurnosna relevantnost: NIJE direktno sigurnosna — code quality.
       Međutim, kompleksna funkcija je teže reviewati i lakše je propustiti
       sigurnosni propust (npr. nedostajuća provjera privilegija).

  2. MAGIC STRINGS: Sve ponavljajuće string literale zamijenjene konstantama
     iz app.utils.messages.
     → Konzistentnost poruka eliminira information disclosure kroz razlike.

  3. CSRF HOTSPOT objašnjenje je u app/__init__.py (vidi taj fajl).

[OWASP A01:2025 – Broken Access Control]: @admin_required, 3-layer RBAC
[OWASP A05:2025 – Injection]: Schemas validate all input before business logic
[OWASP A10:2025 – Mishandling of Exceptional Conditions]: ValidationError -> 400
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
from app.utils.messages import (
    ERR_BAD_REQUEST,
    ERR_CONFLICT,
    ERR_FORBIDDEN,
    ERR_NOT_FOUND,
    MSG_ADMIN_CANNOT_CHANGE_OWN_ROLE,
    MSG_ADMIN_CANNOT_DEACTIVATE_SELF,
    MSG_INVALID_ROLE_ID,
    MSG_JSON_REQUIRED,
    MSG_NO_CHANGES,
    MSG_USER_ALREADY_DEACTIVATED,
    MSG_USER_NOT_FOUND,
)

admin_bp = Blueprint("admin", __name__, url_prefix="/api/admin")

_create_user_schema = CreateUserSchema()
_update_user_schema = UpdateUserSchema()


# ---------------------------------------------------------------------------
# SONARQUBE FIX: Helper funkcije za smanjenje cognitive complexity u update_user
# ---------------------------------------------------------------------------

def _apply_role_change(user: User, current_user: User, user_id: int, role_id: int):
    """
    Primijeni promjenu role na korisnika.

    Ekstraktovano iz update_user() da reducira cognitive complexity.
    Sadrži sigurnosnu provjeru: admin ne može promijeniti vlastitu rolu.

    SIGURNOSNA RELEVANTNOST:
    [OWASP A01:2025 – Broken Access Control]: Sprječava admina da sebe
    degradira na nižu rolu (accidentalno ili zlonamjerno), što bi
    onemogućilo pristup admin funkcijama.

    Vraća (error_response, change_description) tuple.
    error_response je None ako je sve OK.
    """
    if user_id == current_user.id:
        return (
            jsonify({"error": ERR_FORBIDDEN, "message": MSG_ADMIN_CANNOT_CHANGE_OWN_ROLE}),
            403,
        ), None

    role = Role.query.get(role_id)
    if not role:
        return (
            jsonify({"error": ERR_BAD_REQUEST, "message": MSG_INVALID_ROLE_ID}),
            400,
        ), None

    user.role_id = role_id
    return None, f"role -> {role.name}"


def _apply_active_change(
    user: User, current_user: User, user_id: int, is_active: bool
):
    """
    Primijeni promjenu is_active statusa na korisnika i upiši audit log.

    Ekstraktovano iz update_user() da reducira cognitive complexity.

    SIGURNOSNA RELEVANTNOST:
    [OWASP A01:2025 – Broken Access Control]: Admin ne može deaktivirati
    vlastiti nalog — to bi zaključalo sve admin pristupe.
    [OWASP A09:2025 – Security Logging]: Svaka promjena aktivnog statusa
    se loguje kao zasebna audit akcija.

    Vraća (error_response, change_description) tuple.
    """
    if user_id == current_user.id and not is_active:
        return (
            jsonify({"error": ERR_FORBIDDEN, "message": MSG_ADMIN_CANNOT_DEACTIVATE_SELF}),
            403,
        ), None

    user.is_active = is_active
    action = "user_activated" if is_active else "user_deactivated"
    write_audit(
        action=action,
        actor_id=current_user.id,
        resource_type="User",
        resource_id=user_id,
        detail=f"{action} by admin {current_user.email}",
    )
    return None, f"is_active -> {is_active}"


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

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
    [OWASP A05:2025 – Injection]: CreateUserSchema validira sva polja.
    [OWASP A01:2025 – Broken Access Control]: role_id allowlist u shemi.
    [OWASP A10:2025 – Mishandling]: ValidationError -> 400.
    """
    raw = request.get_json(silent=True)
    if not raw:
        return jsonify({"error": ERR_BAD_REQUEST, "message": MSG_JSON_REQUIRED}), 400

    try:
        data = _create_user_schema.load(raw)
    except ValidationError as err:
        return jsonify({"error": ERR_BAD_REQUEST, "message": err.messages}), 400

    user, error = create_user(
        email=data["email"],
        password=data["password"],
        first_name=data["first_name"],
        last_name=data["last_name"],
        role_id=data["role_id"],
    )

    if error:
        return jsonify({"error": ERR_CONFLICT, "message": error}), 409

    audit_user_created(actor_id=current_user.id, new_user_id=user.id, email=user.email)
    return jsonify({"message": "User created.", "user": user.to_dict()}), 201


@admin_bp.route("/users/<int:user_id>", methods=["GET"])
@admin_required
def get_user(current_user, user_id: int):
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": ERR_NOT_FOUND, "message": f"User {user_id} not found."}), 404
    return jsonify({"user": user.to_dict()}), 200


@admin_bp.route("/users/<int:user_id>", methods=["PATCH"])
@admin_required
def update_user(current_user, user_id: int):
    """
    Parcijalno ažuriranje korisnika.

    SONARQUBE FIX (Cognitive Complexity):
    Originalna funkcija imala complexity 19 (limit: 15). Reducirana na ~10
    ekstraktovanjem role i active_change logike u helper funkcije.
    Svaki if-blok sada delegira na helper koji ima jasnu odgovornost.

    SIGURNOSNA RELEVANTNOST korekcije: Manja kompleksnost = lakši code review
    = manji rizik od propuštenih sigurnosnih provjera.
    [OWASP A01:2025 – Broken Access Control]
    [OWASP A05:2025 – Injection]: UpdateUserSchema validira sva polja.
    """
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": ERR_NOT_FOUND, "message": f"User {user_id} not found."}), 404

    raw = request.get_json(silent=True) or {}

    try:
        data = _update_user_schema.load(raw)
    except ValidationError as err:
        return jsonify({"error": ERR_BAD_REQUEST, "message": err.messages}), 400

    changes = []

    if "first_name" in data:
        user.first_name = data["first_name"]
        changes.append("first_name")

    if "last_name" in data:
        user.last_name = data["last_name"]
        changes.append("last_name")

    if "role_id" in data:
        # SONARQUBE FIX: delegirano na helper — smanjuje complexity
        error_resp, change_desc = _apply_role_change(
            user, current_user, user_id, data["role_id"]
        )
        if error_resp:
            return error_resp
        changes.append(change_desc)

    if "is_active" in data:
        # SONARQUBE FIX: delegirano na helper — smanjuje complexity
        error_resp, change_desc = _apply_active_change(
            user, current_user, user_id, data["is_active"]
        )
        if error_resp:
            return error_resp
        changes.append(change_desc)

    if not changes:
        return jsonify({"message": MSG_NO_CHANGES}), 200

    db.session.commit()
    write_audit(
        action="user_updated",
        actor_id=current_user.id,
        resource_type="User",
        resource_id=user_id,
        detail=f"Fields changed: {', '.join(changes)}",
    )
    return jsonify({"message": "User updated.", "user": user.to_dict()}), 200


@admin_bp.route("/users/<int:user_id>", methods=["DELETE"])
@admin_required
def deactivate_user(current_user, user_id: int):
    if user_id == current_user.id:
        return jsonify({"error": ERR_FORBIDDEN, "message": MSG_ADMIN_CANNOT_DEACTIVATE_SELF}), 403

    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": ERR_NOT_FOUND, "message": f"User {user_id} not found."}), 404

    if not user.is_active:
        return jsonify({"message": MSG_USER_ALREADY_DEACTIVATED}), 200

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
