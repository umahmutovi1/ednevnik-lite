"""
routes/teacher.py — Teacher (Nastavnik) Blueprint
===================================================
Grade and attendance management for nastavnici (teachers).

RBAC & DATA SCOPING (Defense in Depth):
  - Layer 1: @teacher_required — JWT + DB role check
  - Layer 2: All queries filter by teacher_id=current_user.id (ORM-level scoping)
    → A teacher can NEVER see or modify another teacher's grades, even with a valid
      teacher token. The query itself excludes cross-teacher data.

AVAILABLE ENDPOINTS:
  GET    /api/teacher/grades                      — List grades entered by this teacher
  POST   /api/teacher/grades                      — Create a new grade
  GET    /api/teacher/grades/<id>                 — Get one grade (must belong to teacher)
  PATCH  /api/teacher/grades/<id>                 — Update a grade (must belong to teacher)
  DELETE /api/teacher/grades/<id>                 — Delete a grade (must belong to teacher)
  GET    /api/teacher/attendance                  — List attendance records by this teacher
  POST   /api/teacher/attendance                  — Create attendance record
  GET    /api/teacher/students                    — List students (visible to teachers)

TESTING SURFACE (Phase 2):
  - POST /api/teacher/grades: SQLMap injection test on subject/note fields
  - PATCH /api/teacher/grades/<id>: IDOR test — attempt to modify another teacher's grade
  - GET /api/teacher/grades: Test with admin token (should return 403)
"""

from datetime import datetime, timezone

from flask import Blueprint, jsonify, request

from app.models import AttendanceRecord, Grade, Role, User, db
from app.services.audit_service import (
    audit_grade_created,
    audit_grade_updated,
    write_audit,
)
from app.utils.decorators import teacher_required

teacher_bp = Blueprint("teacher", __name__, url_prefix="/api/teacher")


# ---------------------------------------------------------------------------
# Grades
# ---------------------------------------------------------------------------

@teacher_bp.route("/grades", methods=["GET"])
@teacher_required
def list_grades(current_user):
    """
    List all grades entered by the current teacher.

    ORM SCOPE: filter(teacher_id=current_user.id) — cross-teacher data is
    structurally excluded, not just filtered in application logic.

    Query params:
      - student_id (int, optional)
      - subject (str, optional)
      - page, per_page
    """
    page = request.args.get("page", 1, type=int)
    per_page = min(request.args.get("per_page", 50, type=int), 100)
    student_filter = request.args.get("student_id", type=int)
    subject_filter = request.args.get("subject")

    # ORM-level scope: teacher_id=current_user.id — mandatory, never removed
    query = Grade.query.filter_by(teacher_id=current_user.id)

    if student_filter:
        query = query.filter_by(student_id=student_filter)
    if subject_filter:
        query = query.filter_by(subject=subject_filter)

    pagination = query.order_by(Grade.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )

    return jsonify({
        "grades": [g.to_dict() for g in pagination.items],
        "total": pagination.total,
        "page": pagination.page,
    }), 200


@teacher_bp.route("/grades", methods=["POST"])
@teacher_required
def create_grade(current_user):
    """
    Create a new grade entry.

    SECURITY:
      - teacher_id is set to current_user.id — never taken from request body.
        This prevents a teacher from spoofing another teacher's ID in the payload.
      - student_id is validated to be a real student (role='ucenik').
      - Grade value validated by model's @validates decorator (1-5).
    """
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Bad Request", "message": "JSON body required."}), 400

    required = ["student_id", "subject", "value"]
    missing = [f for f in required if data.get(f) is None]
    if missing:
        return jsonify({"error": "Bad Request", "message": f"Missing: {', '.join(missing)}"}), 400

    # Validate student exists and has role 'ucenik'
    student = User.query.get(data["student_id"])
    if not student or not student.is_active:
        return jsonify({"error": "Not Found", "message": "Student not found."}), 404
    if student.role.name != "ucenik":
        return jsonify({"error": "Bad Request", "message": "Target user is not a student."}), 400

    try:
        grade = Grade(
            student_id=data["student_id"],
            teacher_id=current_user.id,  # Always from auth context — never from request body
            subject=data["subject"].strip(),
            value=int(data["value"]),
            note=data.get("note", "").strip() or None,
        )
        db.session.add(grade)
        db.session.commit()
    except ValueError as e:
        db.session.rollback()
        return jsonify({"error": "Bad Request", "message": str(e)}), 400

    audit_grade_created(
        actor_id=current_user.id,
        grade_id=grade.id,
        detail=f"Grade {grade.value} in {grade.subject} for student {student.email}",
    )

    return jsonify({"message": "Grade created.", "grade": grade.to_dict()}), 201


@teacher_bp.route("/grades/<int:grade_id>", methods=["GET"])
@teacher_required
def get_grade(current_user, grade_id: int):
    """
    Get a single grade.
    ORM scope ensures only the teacher who created it can retrieve it.
    """
    # Filter by both id AND teacher_id — prevents IDOR
    grade = Grade.query.filter_by(id=grade_id, teacher_id=current_user.id).first()
    if not grade:
        return jsonify({"error": "Not Found", "message": "Grade not found."}), 404

    return jsonify({"grade": grade.to_dict()}), 200


@teacher_bp.route("/grades/<int:grade_id>", methods=["PATCH"])
@teacher_required
def update_grade(current_user, grade_id: int):
    """
    Update a grade.

    SECURITY:
      - Filter by teacher_id prevents IDOR — a teacher cannot update grades
        entered by another teacher, even by guessing the grade ID.
      - Grade value validated by model @validates.
    """
    grade = Grade.query.filter_by(id=grade_id, teacher_id=current_user.id).first()
    if not grade:
        return jsonify({"error": "Not Found", "message": "Grade not found."}), 404

    data = request.get_json(silent=True) or {}
    old_value = grade.value
    changes = []

    try:
        if "value" in data:
            grade.value = int(data["value"])
            changes.append(f"value: {old_value} → {grade.value}")
        if "note" in data:
            grade.note = data["note"].strip() or None
            changes.append("note updated")
        if "subject" in data:
            grade.subject = data["subject"].strip()
            changes.append(f"subject → {grade.subject}")
    except ValueError as e:
        return jsonify({"error": "Bad Request", "message": str(e)}), 400

    if not changes:
        return jsonify({"message": "No changes."}), 200

    db.session.commit()

    audit_grade_updated(
        actor_id=current_user.id,
        grade_id=grade.id,
        detail=f"Changes: {', '.join(changes)}",
    )

    return jsonify({"message": "Grade updated.", "grade": grade.to_dict()}), 200


@teacher_bp.route("/grades/<int:grade_id>", methods=["DELETE"])
@teacher_required
def delete_grade(current_user, grade_id: int):
    """Delete a grade (teacher's own grades only)."""
    grade = Grade.query.filter_by(id=grade_id, teacher_id=current_user.id).first()
    if not grade:
        return jsonify({"error": "Not Found", "message": "Grade not found."}), 404

    write_audit(
        action="grade_deleted",
        actor_id=current_user.id,
        resource_type="Grade",
        resource_id=grade_id,
        detail=f"Deleted grade {grade.value} in {grade.subject}",
    )

    db.session.delete(grade)
    db.session.commit()

    return jsonify({"message": "Grade deleted."}), 200


# ---------------------------------------------------------------------------
# Attendance
# ---------------------------------------------------------------------------

@teacher_bp.route("/attendance", methods=["GET"])
@teacher_required
def list_attendance(current_user):
    """
    List attendance records entered by this teacher.
    ORM-scoped to current_user.id.
    """
    page = request.args.get("page", 1, type=int)
    per_page = min(request.args.get("per_page", 50, type=int), 100)

    pagination = (
        AttendanceRecord.query
        .filter_by(teacher_id=current_user.id)
        .order_by(AttendanceRecord.date.desc())
        .paginate(page=page, per_page=per_page, error_out=False)
    )

    return jsonify({
        "records": [r.to_dict() for r in pagination.items],
        "total": pagination.total,
        "page": pagination.page,
    }), 200


@teacher_bp.route("/attendance", methods=["POST"])
@teacher_required
def create_attendance(current_user):
    """
    Create an attendance record.
    teacher_id always set from auth context — never from request body.
    """
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Bad Request", "message": "JSON body required."}), 400

    required = ["student_id", "subject", "date", "status"]
    missing = [f for f in required if not data.get(f)]
    if missing:
        return jsonify({"error": "Bad Request", "message": f"Missing: {', '.join(missing)}"}), 400

    student = User.query.get(data["student_id"])
    if not student or student.role.name != "ucenik":
        return jsonify({"error": "Not Found", "message": "Student not found."}), 404

    valid_statuses = ("prisutan", "odsutan", "kasnjenje")
    if data["status"] not in valid_statuses:
        return jsonify({
            "error": "Bad Request",
            "message": f"Status must be one of: {', '.join(valid_statuses)}"
        }), 400

    try:
        date_obj = datetime.fromisoformat(data["date"]).replace(tzinfo=timezone.utc)
    except ValueError:
        return jsonify({"error": "Bad Request", "message": "Invalid date format. Use ISO 8601."}), 400

    record = AttendanceRecord(
        student_id=data["student_id"],
        teacher_id=current_user.id,
        subject=data["subject"].strip(),
        date=date_obj,
        status=data["status"],
        note=data.get("note", "").strip() or None,
    )

    try:
        db.session.add(record)
        db.session.commit()
    except Exception:
        db.session.rollback()
        return jsonify({
            "error": "Conflict",
            "message": "Attendance record already exists for this student/subject/date."
        }), 409

    write_audit(
        action="attendance_created",
        actor_id=current_user.id,
        resource_type="AttendanceRecord",
        resource_id=record.id,
        detail=f"{data['status']} — {student.email} in {data['subject']}",
    )

    return jsonify({"message": "Attendance recorded.", "record": record.to_dict()}), 201


# ---------------------------------------------------------------------------
# GET /api/teacher/students — Students visible to teacher
# ---------------------------------------------------------------------------

@teacher_bp.route("/students", methods=["GET"])
@teacher_required
def list_students(current_user):
    """
    List all active students. Teachers need to look up student IDs to enter grades.
    Returns minimal profile — no sensitive data exposed.
    """
    ucenik_role = Role.query.filter_by(name="ucenik").first()
    if not ucenik_role:
        return jsonify({"students": []}), 200

    students = (
        User.query
        .filter_by(role_id=ucenik_role.id, is_active=True)
        .order_by(User.last_name, User.first_name)
        .all()
    )

    return jsonify({
        "students": [
            {
                "id": s.id,
                "first_name": s.first_name,
                "last_name": s.last_name,
                "email": s.email,
            }
            for s in students
        ]
    }), 200
