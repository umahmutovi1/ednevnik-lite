"""
routes/student.py — Student (Učenik) Blueprint
================================================
Read-only endpoints for students viewing their own data.

RBAC & DATA ISOLATION:
  - @student_required: JWT + DB role check — admin and teacher tokens rejected
  - Every query scoped to student_id=current_user.id — students NEVER see peer data
  - No POST/PATCH/DELETE endpoints exist on this Blueprint — read-only by design

AVAILABLE ENDPOINTS:
  GET /api/student/grades        — My grades only
  GET /api/student/attendance    — My attendance only
  GET /api/student/profile       — My profile

TESTING SURFACE (Phase 2):
  - GET /api/student/grades: IDOR test — inject another student's ID in query params
  - Test with teacher/admin token (should return 403)
  - Test unauthenticated (should return 401)
"""

from flask import Blueprint, jsonify, request

from app.models import AttendanceRecord, Grade
from app.utils.decorators import student_required

student_bp = Blueprint("student", __name__, url_prefix="/api/student")


# ---------------------------------------------------------------------------
# GET /api/student/grades — My grades
# ---------------------------------------------------------------------------

@student_bp.route("/grades", methods=["GET"])
@student_required
def my_grades(current_user):
    """
    Return all grades for the authenticated student.

    ORM SCOPE: student_id=current_user.id — hard-coded from auth context.
    No query parameter can override this — a student cannot request another
    student's grades by passing a different student_id.

    Query params:
      - subject (str, optional filter)
      - page, per_page
    """
    page = request.args.get("page", 1, type=int)
    per_page = min(request.args.get("per_page", 50, type=int), 100)
    subject_filter = request.args.get("subject")

    # student_id from auth context only — query parameter student_id is intentionally ignored
    query = Grade.query.filter_by(student_id=current_user.id)

    if subject_filter:
        query = query.filter_by(subject=subject_filter)

    pagination = query.order_by(Grade.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )

    # Return grade data but omit teacher_id — students don't need to know which teacher
    # entered which grade at this level (may be surfaced with teacher name in Phase 2)
    grades = [
        {
            "id": g.id,
            "subject": g.subject,
            "value": g.value,
            "note": g.note,
            "created_at": g.created_at.isoformat(),
        }
        for g in pagination.items
    ]

    return jsonify({
        "grades": grades,
        "total": pagination.total,
        "page": pagination.page,
        "pages": pagination.pages,
    }), 200


# ---------------------------------------------------------------------------
# GET /api/student/attendance — My attendance
# ---------------------------------------------------------------------------

@student_bp.route("/attendance", methods=["GET"])
@student_required
def my_attendance(current_user):
    """
    Return attendance records for the authenticated student.
    Scoped to current_user.id — peer data is structurally inaccessible.
    """
    page = request.args.get("page", 1, type=int)
    per_page = min(request.args.get("per_page", 50, type=int), 100)
    subject_filter = request.args.get("subject")

    query = AttendanceRecord.query.filter_by(student_id=current_user.id)

    if subject_filter:
        query = query.filter_by(subject=subject_filter)

    pagination = query.order_by(AttendanceRecord.date.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )

    records = [
        {
            "id": r.id,
            "subject": r.subject,
            "date": r.date.isoformat(),
            "status": r.status,
            "note": r.note,
        }
        for r in pagination.items
    ]

    return jsonify({
        "attendance": records,
        "total": pagination.total,
        "page": pagination.page,
        "pages": pagination.pages,
    }), 200


# ---------------------------------------------------------------------------
# GET /api/student/profile — My profile
# ---------------------------------------------------------------------------

@student_bp.route("/profile", methods=["GET"])
@student_required
def my_profile(current_user):
    """
    Return the authenticated student's own profile.
    No sensitive fields (password_hash, role_id internals) are exposed.
    """
    return jsonify({
        "profile": {
            "id": current_user.id,
            "email": current_user.email,
            "first_name": current_user.first_name,
            "last_name": current_user.last_name,
            "role": current_user.role.name,
        }
    }), 200
