"""
app/schemas/admin_schemas.py — Admin Marshmallow Schemas
=========================================================
Validates all input to /api/admin/* endpoints.

OWASP 2025 MAPPINGS PER FIELD (summary — detailed inline below):
  - email          : A05 (Injection), A07 (Auth Failures)
  - password       : A04 (Cryptographic Failures), A07 (Auth Failures)
  - first/last_name: A05 (Injection) — prevents XSS payloads stored in name fields
  - role_id        : A01 (Broken Access Control) — allowlist prevents privilege escalation
"""

import re

from marshmallow import Schema, ValidationError, fields, post_load, validate, validates, RAISE


# ---------------------------------------------------------------------------
# Validators reused across schemas
# ---------------------------------------------------------------------------

# [OWASP A05:2025 – Injection]: Allowlist for name fields — permits letters (including
# unicode for Bosnian/Croatian characters: čćšžđ), hyphens, apostrophes, and spaces.
# Rejects '<', '>', '"', '&' which are the core XSS payload characters.
_NAME_PATTERN = re.compile(
    r"^[\w\s'\-\u00C0-\u024F]+$",  # \u00C0-\u024F covers Latin Extended-A/B (čćšžđ etc.)
    re.UNICODE
)

# [OWASP A07:2025 – Authentication Failures]: Minimum password complexity.
# Requires at least one uppercase, one lowercase, one digit, one special char.
# This is a *server-side* check — do not rely on frontend-only enforcement.
_PASSWORD_COMPLEXITY = re.compile(
    r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]).{8,}$"
)

# [OWASP A01:2025 – Broken Access Control]: Only these role IDs may be assigned via API.
# Role IDs are seeded at startup — this allowlist prevents assigning a non-existent or
# future privileged role by guessing its integer ID.
# NOTE: Update this set if roles are ever re-seeded with different IDs.
# A more robust approach (Phase 3) would query the Role table at validation time.
_ALLOWED_ROLE_IDS = frozenset({1, 2, 3})  # admin=1, nastavnik=2, ucenik=3


class CreateUserSchema(Schema):
    """
    Validates POST /api/admin/users request body.

    All fields required on creation. Password is validated for complexity here —
    the auth service hashes it immediately and never stores plaintext.
    """

    class Meta:
        # [OWASP A05:2025 – Injection]: RAISE on unknown fields — no parameter pollution
        unknown = RAISE

    email = fields.Email(
        required=True,
        load_only=True,
        # [OWASP A05:2025 – Injection]: max 255 matches DB column; min 3 rejects "@a.b"
        validate=validate.Length(min=5, max=255),
        error_messages={
            "required": "Email is required.",
            "invalid": "A valid email address is required.",
        },
    )

    password = fields.Str(
        required=True,
        load_only=True,
        # [OWASP A04:2025 – Cryptographic Failures]: 8 min enforces meaningful entropy;
        # 128 max prevents bcrypt DoS via silent truncation at 72 bytes.
        validate=validate.Length(min=8, max=128),
        error_messages={"required": "Password is required."},
    )

    first_name = fields.Str(
        required=True,
        load_only=True,
        # [OWASP A05:2025 – Injection]: 2-100 chars; name regex blocks XSS payloads
        validate=validate.Length(min=2, max=100),
        error_messages={"required": "First name is required."},
    )

    last_name = fields.Str(
        required=True,
        load_only=True,
        # [OWASP A05:2025 – Injection]: same as first_name
        validate=validate.Length(min=2, max=100),
        error_messages={"required": "Last name is required."},
    )

    role_id = fields.Integer(
        required=True,
        load_only=True,
        # [OWASP A01:2025 – Broken Access Control]: integer type enforcement prevents
        # string smuggling ("1 OR 1=1") even though the ORM parameterizes anyway
        strict=True,
        error_messages={"required": "Role is required.", "invalid": "Invalid role."},
    )

    @validates("password")
    def validate_password_complexity(self, value: str) -> str:
        """
        [OWASP A04:2025 – Cryptographic Failures]: Enforce password complexity server-side.
        A weak password undermines bcrypt's work factor — if the password is "password1!",
        no amount of hashing makes the account secure against dictionary attacks.
        """
        if not _PASSWORD_COMPLEXITY.match(value):
            # Generic message — do not reveal which rule failed (attacker could use that
            # to craft a barely-compliant password that is still weak).
            raise ValidationError(
                "Password does not meet complexity requirements."
            )
        return value

    @validates("first_name")
    def validate_first_name(self, value: str) -> str:
        # [OWASP A05:2025 – Injection]: block XSS payload characters in stored name fields
        if not _NAME_PATTERN.match(value.strip()):
            raise ValidationError("Invalid characters in name.")
        return value.strip()

    @validates("last_name")
    def validate_last_name(self, value: str) -> str:
        # [OWASP A05:2025 – Injection]: same as first_name
        if not _NAME_PATTERN.match(value.strip()):
            raise ValidationError("Invalid characters in name.")
        return value.strip()

    @validates("role_id")
    def validate_role_id(self, value: int) -> int:
        """
        [OWASP A01:2025 – Broken Access Control]: Allowlist validation on role_id.
        Without this, an attacker could POST role_id=99 or role_id=0 and either trigger
        a DB FK error (information disclosure) or, in a misconfigured system, assign an
        unintended role. We reject anything outside the known seed set immediately.
        """
        if value not in _ALLOWED_ROLE_IDS:
            raise ValidationError("Invalid role.")
        return value

    @post_load
    def normalize_email(self, data: dict, **kwargs) -> dict:
        """
        [OWASP A07:2025 – Authentication Failures]: Normalize email to lowercase after
        all field-level validation passes. Post-load ensures this runs once, consistently,
        regardless of which field validators ran — no double-normalization bugs.
        """
        if "email" in data:
            data["email"] = data["email"].strip().lower()
        return data


class UpdateUserSchema(Schema):
    """
    Validates PATCH /api/admin/users/<id> request body.

    All fields are optional (partial update). Fields that ARE present are subject to
    the same validation rules as CreateUserSchema. An empty payload is allowed by the
    schema — the route handler returns 200 "No changes" in that case.
    """

    class Meta:
        # [OWASP A05:2025 – Injection]: RAISE on unknown fields
        unknown = RAISE

    first_name = fields.Str(
        load_only=True,
        validate=validate.Length(min=2, max=100),
        # [OWASP A05:2025 – Injection]: same XSS protection as CreateUserSchema
    )

    last_name = fields.Str(
        load_only=True,
        validate=validate.Length(min=2, max=100),
    )

    role_id = fields.Integer(
        load_only=True,
        strict=True,
        # [OWASP A01:2025 – Broken Access Control]: same allowlist as CreateUserSchema
    )

    is_active = fields.Boolean(
        load_only=True,
        # [OWASP A01:2025 – Broken Access Control]: Boolean type-enforcement prevents
        # "is_active=1 AND 1=1" style smuggling — marshmallow rejects non-booleans strictly
    )

    @validates("first_name")
    def validate_first_name(self, value: str) -> str:
        if not _NAME_PATTERN.match(value.strip()):
            raise ValidationError("Invalid characters in name.")
        return value.strip()

    @validates("last_name")
    def validate_last_name(self, value: str) -> str:
        if not _NAME_PATTERN.match(value.strip()):
            raise ValidationError("Invalid characters in name.")
        return value.strip()

    @validates("role_id")
    def validate_role_id(self, value: int) -> int:
        # [OWASP A01:2025 – Broken Access Control]: allowlist check on partial update too
        if value not in _ALLOWED_ROLE_IDS:
            raise ValidationError("Invalid role.")
        return value
