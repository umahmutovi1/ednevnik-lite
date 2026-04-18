"""
app/schemas/teacher_schemas.py — Teacher Marshmallow Schemas (SonarQube Fixed)
===============================================================================
SONARQUBE KOREKCIJE:
  1. DUPLICATE CODE: validate_subject pojavljivao se identično u
     CreateGradeSchema, UpdateGradeSchema i CreateAttendanceSchema.
     Ekstraktovano u _validate_subject_field() helper.
     → Sigurnosna relevantnost: isto kao i za name validator — sprječava
       nekonzistentnu XSS zaštitu ako se jedan validator ispravi bez drugog.

  2. MAGIC STRINGS: "Invalid characters in subject." zamijenjeno
     referencom na messages.MSG_INVALID_SUBJECT_CHARS konstante.
"""

import re
from datetime import datetime, timezone

from marshmallow import Schema, ValidationError, fields, validate, validates, RAISE

from app.utils.messages import (
    MSG_INVALID_SUBJECT_CHARS,
    MSG_GRADE_NOT_FOUND,
)

# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------

# [OWASP A05:2025 – Injection]: Subject allowlist — slova (uključujući bosanski
# unicode), cifre, razmaci, crtice, tačke, dvotačke.
# Odbija HTML/JS specijalne karaktere.
_SUBJECT_PATTERN = re.compile(
    r"^[\w\s\-\.\:\u00C0-\u024F]+$",
    re.UNICODE
)

_VALID_STATUSES = {"prisutan", "odsutan", "kasnjenje"}


# ---------------------------------------------------------------------------
# SONARQUBE FIX: Deduplicirani subject validator
# ---------------------------------------------------------------------------

def _validate_subject_field(value: str) -> str:
    """
    Zajednički validator za subject polja u svim teacher schemama.

    MAINTAINABILITY FIX (SonarQube Duplicate Code):
    validate_subject se pojavljuje identično u CreateGradeSchema,
    UpdateGradeSchema i CreateAttendanceSchema. Ekstraktovano ovdje.

    SIGURNOSNA RELEVANTNOST:
    Subject polje se prikazuje u student view-u i admin dashboardu.
    Nedosljedna XSS validacija (npr. ispravi se u jednoj shemi, ne u drugoj)
    mogla bi dozvoliti stored XSS napad kroz subject polje.
    [OWASP A05:2025 – Injection]
    """
    stripped = value.strip()
    if not _SUBJECT_PATTERN.match(stripped):
        raise ValidationError(MSG_INVALID_SUBJECT_CHARS)  # SONARQUBE FIX: magic string
    return stripped


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class CreateGradeSchema(Schema):
    """
    Validira POST /api/teacher/grades request body.

    NAPOMENA: teacher_id NIJE u ovoj shemi — uvijek se uzima iz JWT auth
    konteksta u route handleru, nikad iz request body-ja.
    [OWASP A01:2025 – Broken Access Control]
    """

    class Meta:
        unknown = RAISE

    student_id = fields.Integer(
        required=True,
        load_only=True,
        strict=True,
        # [OWASP A01:2025 – Broken Access Control]: strict integer sprječava
        # IDOR putem non-integer student_id vrijednosti ("1 UNION SELECT...")
        error_messages={"required": "student_id is required.", "invalid": "Invalid student."},
    )

    subject = fields.Str(
        required=True,
        load_only=True,
        validate=validate.Length(min=2, max=100),
        error_messages={"required": "Subject is required."},
    )

    value = fields.Integer(
        required=True,
        load_only=True,
        strict=True,
        # [OWASP A06:2025 – Insecure Design]: Range enforcement na schema nivou
        # je defense-in-depth — ORM @validates to također provjerava.
        validate=validate.Range(min=1, max=5),
        error_messages={
            "required": "Grade value is required.",
            "invalid": "Invalid grade value.",
            "validator_failed": MSG_GRADE_NOT_FOUND,
        },
    )

    note = fields.Str(
        load_only=True,
        allow_none=True,
        # [OWASP A05:2025 – Injection]: 1000 char cap sprječava oversized payload DoS
        validate=validate.Length(max=1000),
        load_default=None,
    )

    @validates("subject")
    def validate_subject(self, value: str) -> str:
        """
        SONARQUBE FIX: Poziva _validate_subject_field() umjesto duplicirane logike.
        [OWASP A05:2025 – Injection]
        """
        return _validate_subject_field(value)

    @validates("note")
    def validate_note(self, value) -> str | None:
        if value is None:
            return None
        return value.strip() or None


class UpdateGradeSchema(Schema):
    """
    Validira PATCH /api/teacher/grades/<id> request body.
    Sva polja opcionalna — partial update.
    """

    class Meta:
        unknown = RAISE

    value = fields.Integer(
        load_only=True,
        strict=True,
        validate=validate.Range(min=1, max=5),
        error_messages={
            "invalid": "Invalid grade value.",
            "validator_failed": "Grade must be between 1 and 5.",
        },
    )

    subject = fields.Str(
        load_only=True,
        validate=validate.Length(min=2, max=100),
    )

    note = fields.Str(
        load_only=True,
        allow_none=True,
        validate=validate.Length(max=1000),
    )

    @validates("subject")
    def validate_subject(self, value: str) -> str:
        """SONARQUBE FIX: Dijeli logiku sa CreateGradeSchema."""
        return _validate_subject_field(value)

    @validates("note")
    def validate_note(self, value) -> str | None:
        if value is None:
            return None
        return value.strip() or None


class CreateAttendanceSchema(Schema):
    """
    Validira POST /api/teacher/attendance request body.
    [OWASP A10:2025 – Mishandling of Exceptional Conditions]: Strogi ISO 8601 parsing.
    """

    class Meta:
        unknown = RAISE

    student_id = fields.Integer(
        required=True,
        load_only=True,
        strict=True,
        error_messages={"required": "student_id is required.", "invalid": "Invalid student."},
    )

    subject = fields.Str(
        required=True,
        load_only=True,
        validate=validate.Length(min=2, max=100),
        error_messages={"required": "Subject is required."},
    )

    date = fields.Str(
        required=True,
        load_only=True,
        error_messages={"required": "Date is required."},
    )

    status = fields.Str(
        required=True,
        load_only=True,
        # [OWASP A05:2025 – Injection]: OneOf enum allowlist — samo tri validne
        # vrijednosti mogu doći do DB kolone. Free-text nikad ne dotiče Enum kolonu.
        validate=validate.OneOf(
            _VALID_STATUSES,
            error="Status must be one of: prisutan, odsutan, kasnjenje.",
        ),
        error_messages={"required": "Status is required."},
    )

    note = fields.Str(
        load_only=True,
        allow_none=True,
        validate=validate.Length(max=1000),
        load_default=None,
    )

    @validates("subject")
    def validate_subject(self, value: str) -> str:
        """SONARQUBE FIX: Dijeli logiku sa grade schemama."""
        return _validate_subject_field(value)

    @validates("date")
    def validate_date(self, value: str) -> str:
        """
        [OWASP A10:2025 – Mishandling of Exceptional Conditions]: Strogi ISO 8601 parsing.
        Validiramo string ovdje da route handler primi garantirano parsirabilni string.
        Nevalidiran datum bi uzrokovao nekontrolisani exception u route handleru —
        information disclosure rizik.
        """
        try:
            datetime.fromisoformat(value)
        except ValueError:
            raise ValidationError(
                "Invalid date format. Use ISO 8601 (e.g. 2024-09-01T08:00:00)."
            )
        return value

    @validates("note")
    def validate_note(self, value) -> str | None:
        if value is None:
            return None
        return value.strip() or None
