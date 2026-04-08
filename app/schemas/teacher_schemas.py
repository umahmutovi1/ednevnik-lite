"""
app/schemas/teacher_schemas.py — Teacher Marshmallow Schemas
=============================================================
Validates all input to /api/teacher/* endpoints.

OWASP 2025 MAPPINGS (summary):
  - student_id   : A01 (Broken Access Control) — integer type safety prevents IDOR via crafted ID
  - subject      : A05 (Injection) — length + regex prevents stored XSS and SQLi surface
  - value        : A05 (Injection), A06 (Insecure Design) — range enforcement at schema level
  - note         : A05 (Injection) — length cap prevents oversized payload DoS
  - date         : A10 (Mishandling Exceptional Conditions) — strict ISO 8601 parsing
  - status       : A05 (Injection) — enum allowlist, no free-text reaches DB
"""

import re
from datetime import datetime, timezone

from marshmallow import Schema, ValidationError, fields, validate, validates, RAISE


# ---------------------------------------------------------------------------
# Shared validators
# ---------------------------------------------------------------------------

# [OWASP A05:2025 – Injection]: Subject allowlist — letters (including Bosnian/Croatian
# unicode), digits, spaces, hyphens, dots, colons. Rejects HTML/JS special chars.
_SUBJECT_PATTERN = re.compile(
    r"^[\w\s\-\.\:\u00C0-\u024F]+$",
    re.UNICODE
)

# Valid attendance status values — same set as the DB Enum
# [OWASP A05:2025 – Injection]: Enum allowlist prevents free-text reaching the DB column
_VALID_STATUSES = {"prisutan", "odsutan", "kasnjenje"}


class CreateGradeSchema(Schema):
    """
    Validates POST /api/teacher/grades request body.

    Note: teacher_id is NOT in this schema — it is always taken from the JWT auth
    context in the route handler, never from the request body. Including it here
    would create a surface for teachers to spoof another teacher's ID.
    [OWASP A01:2025 – Broken Access Control]
    """

    class Meta:
        # [OWASP A05:2025 – Injection]: RAISE on unknown fields
        unknown = RAISE

    student_id = fields.Integer(
        required=True,
        load_only=True,
        strict=True,  # Rejects "1.0", "1abc", strings — must be a JSON integer
        # [OWASP A01:2025 – Broken Access Control]: strict integer type prevents
        # IDOR via non-integer student_id values ("1 UNION SELECT...", "1.0", etc.)
        error_messages={"required": "student_id is required.", "invalid": "Invalid student."},
    )

    subject = fields.Str(
        required=True,
        load_only=True,
        # [OWASP A05:2025 – Injection]: 2-100 chars; allowlist blocks XSS and SQLi surface
        # Max 100 matches the DB column length — prevents truncation surprises
        validate=validate.Length(min=2, max=100),
        error_messages={"required": "Subject is required."},
    )

    value = fields.Integer(
        required=True,
        load_only=True,
        strict=True,
        # [OWASP A06:2025 – Insecure Design]: Range enforcement at schema level is
        # defense-in-depth. The ORM @validates decorator also checks this, but we
        # catch invalid values here before they touch any business logic at all.
        validate=validate.Range(min=1, max=5),
        error_messages={
            "required": "Grade value is required.",
            "invalid": "Invalid grade value.",
            "validator_failed": "Grade must be between 1 and 5.",
        },
    )

    note = fields.Str(
        load_only=True,
        allow_none=True,
        # [OWASP A05:2025 – Injection]: 1000 char cap prevents oversized payload DoS
        # and limits the attack surface for stored XSS in note fields
        validate=validate.Length(max=1000),
        load_default=None,
    )

    @validates("subject")
    def validate_subject(self, value: str) -> str:
        """
        [OWASP A05:2025 – Injection]: Subject allowlist validation.
        Blocks HTML/JS injection payloads stored in subject fields that could be
        rendered in admin dashboards or student views without additional sanitization.
        """
        stripped = value.strip()
        if not _SUBJECT_PATTERN.match(stripped):
            raise ValidationError("Invalid characters in subject.")
        return stripped

    @validates("note")
    def validate_note(self, value) -> str | None:
        """[OWASP A05:2025 – Injection]: Strip whitespace from notes; allow None."""
        if value is None:
            return None
        return value.strip() or None


class UpdateGradeSchema(Schema):
    """
    Validates PATCH /api/teacher/grades/<id> request body.

    All fields optional — partial update. The same validation rules apply as
    CreateGradeSchema for any field that IS present.
    """

    class Meta:
        # [OWASP A05:2025 – Injection]: RAISE on unknown fields
        unknown = RAISE

    value = fields.Integer(
        load_only=True,
        strict=True,
        # [OWASP A06:2025 – Insecure Design]: same range enforcement on update
        validate=validate.Range(min=1, max=5),
        error_messages={"invalid": "Invalid grade value.", "validator_failed": "Grade must be between 1 and 5."},
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
        # [OWASP A05:2025 – Injection]: same allowlist as CreateGradeSchema
        stripped = value.strip()
        if not _SUBJECT_PATTERN.match(stripped):
            raise ValidationError("Invalid characters in subject.")
        return stripped

    @validates("note")
    def validate_note(self, value) -> str | None:
        if value is None:
            return None
        return value.strip() or None


class CreateAttendanceSchema(Schema):
    """
    Validates POST /api/teacher/attendance request body.

    Date handling is strict — we parse ISO 8601 here and reject anything that
    doesn't conform. This prevents the route handler from receiving a malformed
    date string and crashing in an unexpected way.
    [OWASP A10:2025 – Mishandling of Exceptional Conditions]
    """

    class Meta:
        # [OWASP A05:2025 – Injection]: RAISE on unknown fields
        unknown = RAISE

    student_id = fields.Integer(
        required=True,
        load_only=True,
        strict=True,
        # [OWASP A01:2025 – Broken Access Control]: integer type safety prevents IDOR
        error_messages={"required": "student_id is required.", "invalid": "Invalid student."},
    )

    subject = fields.Str(
        required=True,
        load_only=True,
        validate=validate.Length(min=2, max=100),
        # [OWASP A05:2025 – Injection]: length + allowlist (see @validates below)
        error_messages={"required": "Subject is required."},
    )

    date = fields.Str(
        required=True,
        load_only=True,
        # [OWASP A10:2025 – Mishandling of Exceptional Conditions]: string first,
        # then parsed in @validates to produce a clean datetime. Using fields.DateTime
        # directly would silently accept formats we don't want (e.g., "2024/01/01").
        error_messages={"required": "Date is required."},
    )

    status = fields.Str(
        required=True,
        load_only=True,
        # [OWASP A05:2025 – Injection]: OneOf enforces enum allowlist — only the three
        # valid status values can reach the DB. Free-text never reaches the Enum column.
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
        # [OWASP A05:2025 – Injection]: same allowlist as grade schemas
        stripped = value.strip()
        if not _SUBJECT_PATTERN.match(stripped):
            raise ValidationError("Invalid characters in subject.")
        return stripped

    @validates("date")
    def validate_date(self, value: str) -> str:
        """
        [OWASP A10:2025 – Mishandling of Exceptional Conditions]: Strict ISO 8601 parsing.
        We validate the date string here so the route handler receives a string that is
        guaranteed to be parseable. If parsing fails inside the route handler (outside a
        try/except), the app would return a raw 500 with a stack trace — information
        disclosure risk.
        """
        try:
            datetime.fromisoformat(value)
        except ValueError:
            raise ValidationError("Invalid date format. Use ISO 8601 (e.g. 2024-09-01T08:00:00).")
        return value

    @validates("note")
    def validate_note(self, value) -> str | None:
        if value is None:
            return None
        return value.strip() or None
