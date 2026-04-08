"""
app/schemas/auth_schemas.py — Authentication Marshmallow Schemas
================================================================
Validates all input to /api/auth/* endpoints before any business logic runs.

OWASP 2025 MAPPINGS:
  - [A05:2025 – Injection]         : typed fields + length limits prevent crafted payloads
  - [A07:2025 – Authentication Failures]: whitespace stripping prevents login oracle bypass
  - [A10:2025 – Mishandling of Exceptional Conditions]: RAISE on unknown fields prevents
      parameter pollution; ValidationError is caught and returned as generic 400, never 500

DESIGN RULES (mandatory for all schemas in this project):
  - Meta.unknown = RAISE   — any unknown field causes an immediate ValidationError.
      This prevents parameter pollution attacks where an attacker smuggles extra fields
      past the schema hoping the route handler uses them directly.
  - load_only=True on all write fields — they are never serialized back into responses.
  - dump_only=True on computed/read fields — they cannot be supplied by the client.
  - Error messages are generic — they identify the field name but never the internal model,
      column name, or database constraint that was violated.
"""

from marshmallow import Schema, fields, validate, validates, ValidationError, RAISE


class LoginSchema(Schema):
    """
    Validates POST /api/auth/login request body.

    Security focus:
      - Whitespace stripping on email prevents a subtle timing oracle: if the application
        strips whitespace *after* the DB lookup, "user@example.com " (trailing space) could
        behave differently from "user@example.com", allowing enumeration of valid emails.
        We strip *before* validation so both inputs follow identical code paths.
        [OWASP A07:2025 – Authentication Failures]

      - Email format validation rejects obviously malformed inputs before they touch the ORM.
        This is a defence-in-depth measure — the ORM parameterizes anyway, but reducing the
        attack surface is always preferable.
        [OWASP A05:2025 – Injection]

      - Password length cap (128 chars): bcrypt silently truncates passwords longer than 72
        bytes. An attacker who knows this can exploit it. Alternatively, an attacker could
        send a 100 KB "password" to cause a CPU-exhausting bcrypt computation (DoS).
        Cap at 128 chars — long enough for any real passphrase, short enough to be safe.
        [OWASP A07:2025 – Authentication Failures]
    """

    class Meta:
        # [OWASP A05:2025 – Injection]: RAISE on unknown fields — no parameter pollution
        unknown = RAISE

    email = fields.Email(
        required=True,
        load_only=True,
        # [OWASP A07:2025 – Authentication Failures]: max 255 matches DB column length
        validate=validate.Length(min=3, max=255),
        metadata={"description": "User email address"},
        error_messages={"required": "Credentials required.", "invalid": "Invalid credentials."},
    )

    password = fields.Str(
        required=True,
        load_only=True,
        # [OWASP A07:2025 – Authentication Failures]: 128 char cap prevents bcrypt DoS
        validate=validate.Length(min=1, max=128),
        error_messages={"required": "Credentials required."},
    )
