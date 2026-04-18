"""
routes/teacher.py — Teacher Blueprint (SonarQube Fixed)
=========================================================
SONARQUBE KOREKCIJE:
  1. MAGIC STRINGS: "Bad Request", "Not Found", "Grade not found.",
     "JSON body required." zamijenjeni konstantama iz app.utils.messages.
     "Bad Request" se pojavljivao 7 puta — sada je jedna konstanta.

  2. COGNITIVE COMPLEXITY (L113): create_attendance imala complexity 17.
     Reducirana ekstraktovanjem student validacije u _get_valid_student() helper.

SIGURNOSNA RELEVANTNOST:
  Primarne code quality popravke. Konzistentnost poruka (magic strings fix)
  eliminira information disclosure kroz razlike u tekstu grešaka.
  [OWASP A05:2025 – Injection]: Schemas validiraju prije ORM interakcije.
  [OWASP A01:2025 – Broken Access Control]: teacher_id iz auth konteksta.
"""

from datetime import datetime, timezone

from flask import Blueprint, jsonify, request
from marshmallow import ValidationError

from app.models import AttendanceRecord, Grade, Role, User, db
from app.schemas.teacher_schemas import (
    CreateAttendanceSchema,
    CreateGradeSchema,
    UpdateGradeSchema,
)
from app.services.audit_service import (
    audit_grade_created,
    audit_grade_updated,
    write_audit,
)
from app.utils.decorators import teacher_required
from app.utils.messages import (
    ERR_BAD_REQUEST,
    ERR_CONFLICT,
    ERR_NOT_FOUND,
    MSG_ATTENDANCE_CONFLICT,
    MSG_GRADE_NOT_FOUND,
    MSG_GRADE_NO_CHANGES,
    MSG_JSON_REQUIRED,
    MSG_NOT_A_STUDENT,
    MSG_STUDENT_NOT_FOUND,
)

teacher_bp = Blueprint("teacher", __name__, url_prefix="/api/teacher")

_create_grade_schema = CreateGradeSchema()
_update_grade_schema = UpdateGradeSchema()
_create_attendance_schema = CreateAttendanceSchema()


# ---------------------------------------------------------------------------
# SONARQUBE FIX: Helper za smanjenje complexity u create_grade i create_attendance
# ---------------------------------------------------------------------------

def _get_valid_student(student_id: int):
    """
    Validira da student_id pripada aktivnom korisniku sa rolom 'ucenik'.

    SONARQUBE FIX (Cognitive Complexity):
    Ova provjera se ponavljala u create_grade i create_attendance,
    dodavajući complexity u obje funkcije. Ekstraktovana ovdje.

    SIGURNOSNA RELEVANTNOST:
    [OWASP A01:2025 – Broken Access Control]: Sprječava unos ocjena/prisustva
    za korisnike koji nisu učenici (npr. za admina ili nastavnika).
    Bez ove provjere, nastavnik bi mogao unijeti ocjenu za drugog nastavnika.

    Vraća (student, error_tuple) — error_tuple je None ako je OK.
    """
    student = User.query.get(student_id)
    if not student or not student.is_active:
        return None, (jsonify({"error": ERR_NOT_FOUND, "message": MSG_STUDENT_NOT_FOUND}), 404)
    if student.role.name != "ucenik":
        return None, (jsonify({"error": ERR_BAD_REQUEST, "message": MSG_NOT_A_STUDENT}), 400)
    return student, None


# ---------------------------------------------------------------------------
# Grades
# ---------------------------------------------------------------------------

@teacher_bp.route("/grades", methods=["GET"])
@teacher_required
def list_grades(current_user):
    page = request.args.get("page", 1, type=int)
    per_page = min(request.args.get("per_page", 50, type=int), 100)
    student_filter = request.args.get("student_id", type=int)
    subject_filter = request.args.get("subject")

    # [OWASP A01:2025 – Broken Access Control]: ORM-level scope, nikad se ne uklanja
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
    [OWASP A05:2025 – Injection]: CreateGradeSchema validira prije ORM.
    [OWASP A01:2025 – Broken Access Control]: teacher_id iz auth konteksta, nikad iz body.
    """
    raw = request.get_json(silent=True)
    if not raw:
        # SONARQUBE FIX: MSG_JSON_REQUIRED umjesto magic stringa "JSON body required."
        return jsonify({"error": ERR_BAD_REQUEST, "message": MSG_JSON_REQUIRED}), 400

    try:
        data = _create_grade_schema.load(raw)
    except ValidationError as err:
        return jsonify({"error": ERR_BAD_REQUEST, "message": err.messages}), 400

    # SONARQUBE FIX: delegirano na helper — smanjuje complexity create_grade
    student, err_response = _get_valid_student(data["student_id"])
    if err_response:
        return err_response

    try:
        grade = Grade(
            student_id=data["student_id"],
            teacher_id=current_user.id,  # Uvijek iz auth konteksta
            subject=data["subject"],
            value=data["value"],
            note=data.get("note"),
        )
        db.session.add(grade)
        db.session.commit()
    except ValueError as e:
        db.session.rollback()
        return jsonify({"error": ERR_BAD_REQUEST, "message": str(e)}), 400

    audit_grade_created(
        actor_id=current_user.id,
        grade_id=grade.id,
        detail=f"Grade {grade.value} in {grade.subject} for student {student.email}",
    )
    return jsonify({"message": "Grade created.", "grade": grade.to_dict()}), 201


@teacher_bp.route("/grades/<int:grade_id>", methods=["GET"])
@teacher_required
def get_grade(current_user, grade_id: int):
    # [OWASP A01:2025 – Broken Access Control]: filter po teacher_id sprječava IDOR
    grade = Grade.query.filter_by(id=grade_id, teacher_id=current_user.id).first()
    if not grade:
        # SONARQUBE FIX: MSG_GRADE_NOT_FOUND umjesto magic stringa
        return jsonify({"error": ERR_NOT_FOUND, "message": MSG_GRADE_NOT_FOUND}), 404
    return jsonify({"grade": grade.to_dict()}), 200


@teacher_bp.route("/grades/<int:grade_id>", methods=["PATCH"])
@teacher_required
def update_grade(current_user, grade_id: int):
    """[OWASP A05:2025 – Injection]: UpdateGradeSchema validira sva polja."""
    grade = Grade.query.filter_by(id=grade_id, teacher_id=current_user.id).first()
    if not grade:
        return jsonify({"error": ERR_NOT_FOUND, "message": MSG_GRADE_NOT_FOUND}), 404

    raw = request.get_json(silent=True) or {}
    try:
        data = _update_grade_schema.load(raw)
    except ValidationError as err:
        return jsonify({"error": ERR_BAD_REQUEST, "message": err.messages}), 400

    old_value = grade.value
    changes = []
    if "value" in data:
        grade.value = data["value"]
        changes.append(f"value: {old_value} -> {grade.value}")
    if "note" in data:
        grade.note = data["note"]
        changes.append("note updated")
    if "subject" in data:
        grade.subject = data["subject"]
        changes.append(f"subject -> {grade.subject}")

    if not changes:
        # SONARQUBE FIX: MSG_GRADE_NO_CHANGES umjesto magic stringa
        return jsonify({"message": MSG_GRADE_NO_CHANGES}), 200

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
    grade = Grade.query.filter_by(id=grade_id, teacher_id=current_user.id).first()
    if not grade:
        return jsonify({"error": ERR_NOT_FOUND, "message": MSG_GRADE_NOT_FOUND}), 404

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
    page = request.args.get("page", 1, type=int)
    per_page = min(request.args.get("per_page", 50, type=int), 100)
    pagination = (
        AttendanceRecord.query.filter_by(teacher_id=current_user.id)
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
    [OWASP A05:2025 – Injection]: CreateAttendanceSchema validira sva polja.

    SONARQUBE FIX (Cognitive Complexity):
    Originalna funkcija imala complexity 17. Reducirana delegiranjem
    student validacije na _get_valid_student() helper.
    """
    raw = request.get_json(silent=True)
    if not raw:
        return jsonify({"error": ERR_BAD_REQUEST, "message": MSG_JSON_REQUIRED}), 400

    try:
        data = _create_attendance_schema.load(raw)
    except ValidationError as err:
        return jsonify({"error": ERR_BAD_REQUEST, "message": err.messages}), 400

    # SONARQUBE FIX: helper umjesto inline provjere — smanjuje complexity
    student, err_response = _get_valid_student(data["student_id"])
    if err_response:
        return err_response

    date_obj = datetime.fromisoformat(data["date"]).replace(tzinfo=timezone.utc)

    record = AttendanceRecord(
        student_id=data["student_id"],
        teacher_id=current_user.id,
        subject=data["subject"],
        date=date_obj,
        status=data["status"],
        note=data.get("note"),
    )

    try:
        db.session.add(record)
        db.session.commit()
    except Exception:
        db.session.rollback()
        return jsonify({"error": ERR_CONFLICT, "message": MSG_ATTENDANCE_CONFLICT}), 409

    write_audit(
        action="attendance_created",
        actor_id=current_user.id,
        resource_type="AttendanceRecord",
        resource_id=record.id,
        detail=f"{data['status']} -- {student.email} in {data['subject']}",
    )
    return jsonify({"message": "Attendance recorded.", "record": record.to_dict()}), 201


@teacher_bp.route("/students", methods=["GET"])
@teacher_required
def list_students(current_user):
    ucenik_role = Role.query.filter_by(name="ucenik").first()
    if not ucenik_role:
        return jsonify({"students": []}), 200
    students = (
        User.query.filter_by(role_id=ucenik_role.id, is_active=True)
        .order_by(User.last_name, User.first_name)
        .all()
    )
    return jsonify({
        "students": [
            {"id": s.id, "first_name": s.first_name, "last_name": s.last_name, "email": s.email}
            for s in students
        ]
    }), 200
