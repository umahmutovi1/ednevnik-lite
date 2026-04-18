"""
app/schemas/admin_schemas.py — Admin Marshmallow Schemas (SonarQube Fixed)
===========================================================================
SONARQUBE KOREKCIJE:
  1. DUPLICATE CODE (L118, L192): validate_first_name i validate_last_name
     imali identičnu implementaciju. Ekstraktovana u zajednički helper
     _validate_name_field() koji obje metode pozivaju.
     → Sigurnosna relevantnost: NIJE direktno sigurnosna — code quality.
       Međutim, duplicirani validacijski kod nosi rizik da se u budućnosti
       jedna kopija ispravi a druga ne, što bi dovelo do nedosljedne validacije
       i potencijalnog XSS propusta u jednom od polja.

  2. MAGIC STRINGS: "Invalid role." i "Invalid characters in name." zamijenjeni
     referencama na app.utils.messages konstante.
     → Sigurnosna relevantnost: konzistentnost poruka eliminiše information
       disclosure kroz razlike u tekstu grešaka.

OWASP 2025 MAPPINGS (nepromijenjeno):
  - email     : A05 (Injection), A07 (Auth Failures)
  - password  : A04 (Cryptographic Failures), A07 (Auth Failures)
  - first/last: A05 (Injection) — sprječava XSS payloade u name poljima
  - role_id   : A01 (Broken Access Control) — allowlist sprječava eskalaciju privilegija
"""

import re

from marshmallow import Schema, ValidationError, fields, post_load, validate, validates, RAISE

from app.utils.messages import (
    MSG_INVALID_NAME_CHARS,
    MSG_INVALID_ROLE,
)

# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------

# [OWASP A05:2025 – Injection]: Allowlist za name polja — dozvoljava slova
# (uključujući Bosanski/Hrvatski: čćšžđ), crtice, apostrofe i razmake.
# Odbija '<', '>', '"', '&' koji su core XSS payload karakteri.
_NAME_PATTERN = re.compile(
    r"^[\w\s'\-\u00C0-\u024F]+$",
    re.UNICODE
)

# [OWASP A07:2025 – Authentication Failures]: Minimalna složenost lozinke.
# Server-side provjera — ne oslanjati se samo na frontend validaciju.
_PASSWORD_COMPLEXITY = re.compile(
    r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]).{8,}$"
)

# [OWASP A01:2025 – Broken Access Control]: Samo ovi role ID-ovi se mogu
# dodijeliti putem API-ja. Sprječava dodjeljivanje nepostojećih rola.
# NOTE: Ažurirati ako se rola re-seedaju sa drugačijim ID-ovima.
_ALLOWED_ROLE_IDS = frozenset({1, 2, 3})  # admin=1, nastavnik=2, ucenik=3


# ---------------------------------------------------------------------------
# SONARQUBE FIX #1: Deduplicirani name validator
# ---------------------------------------------------------------------------

def _validate_name_field(value: str) -> str:
    """
    Zajednički validator za first_name i last_name polja.

    MAINTAINABILITY FIX (SonarQube Duplicate Code):
    validate_first_name i validate_last_name su imali identičnu implementaciju
    na linijama L118 i L192 u admin_schemas.py. Ekstraktovano u ovaj helper
    da se izbjegne dupliciranje logike.

    SIGURNOSNA RELEVANTNOST:
    Nije direktno sigurnosna popravka, ali eliminira rizik da se u budućnosti
    jedna kopija validatora ispravi (npr. dodat novi zabranjen karakter) dok
    druga ostane nepromijenjena — što bi dovelo do nedosljedne XSS zaštite.
    [OWASP A05:2025 – Injection]
    """
    stripped = value.strip()
    if not _NAME_PATTERN.match(stripped):
        # Koristimo konstantu iz messages.py — SONARQUBE FIX #2 (Magic String)
        raise ValidationError(MSG_INVALID_NAME_CHARS)
    return stripped


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class CreateUserSchema(Schema):
    """Validira POST /api/admin/users request body."""

    class Meta:
        # [OWASP A05:2025 – Injection]: RAISE na nepoznatim poljima — nema parameter pollution
        unknown = RAISE

    email = fields.Email(
        required=True,
        load_only=True,
        validate=validate.Length(min=5, max=255),
        error_messages={
            "required": "Email is required.",
            "invalid": "A valid email address is required.",
        },
    )

    password = fields.Str(
        required=True,
        load_only=True,
        # [OWASP A04:2025 – Cryptographic Failures]: min 8 za entropiju;
        # max 128 sprječava bcrypt DoS (tiho truncation na 72 bajta)
        validate=validate.Length(min=8, max=128),
        error_messages={"required": "Password is required."},
    )

    first_name = fields.Str(
        required=True,
        load_only=True,
        validate=validate.Length(min=2, max=100),
        error_messages={"required": "First name is required."},
    )

    last_name = fields.Str(
        required=True,
        load_only=True,
        validate=validate.Length(min=2, max=100),
        error_messages={"required": "Last name is required."},
    )

    role_id = fields.Integer(
        required=True,
        load_only=True,
        strict=True,
        error_messages={"required": "Role is required.", "invalid": MSG_INVALID_ROLE},
    )

    @validates("password")
    def validate_password_complexity(self, value: str) -> str:
        """
        [OWASP A04:2025 – Cryptographic Failures]: Server-side provjera složenosti.
        Slaba lozinka poništava bcrypt work factor — "password1!" nije sigurno
        bez obzira koliko rundi hashiranja.
        Generička poruka — ne otkriva koje pravilo nije zadovoljeno.
        """
        if not _PASSWORD_COMPLEXITY.match(value):
            raise ValidationError("Password does not meet complexity requirements.")
        return value

    @validates("first_name")
    def validate_first_name(self, value: str) -> str:
        """
        SONARQUBE FIX: Poziva _validate_name_field() umjesto duplicirane logike.
        [OWASP A05:2025 – Injection]: Blokira XSS payload karaktere u name poljima.
        """
        return _validate_name_field(value)

    @validates("last_name")
    def validate_last_name(self, value: str) -> str:
        """
        SONARQUBE FIX: Poziva _validate_name_field() umjesto duplicirane logike.
        [OWASP A05:2025 – Injection]: Isti allowlist kao first_name.
        """
        return _validate_name_field(value)

    @validates("role_id")
    def validate_role_id(self, value: int) -> int:
        """
        [OWASP A01:2025 – Broken Access Control]: Allowlist validacija role_id.
        Bez ovoga, napadač može POST-ati role_id=99 i dobiti FK grešku
        (information disclosure) ili u pogrešno konfiguriranom sistemu
        dodijeliti nepostojuću rolu.
        """
        if value not in _ALLOWED_ROLE_IDS:
            raise ValidationError(MSG_INVALID_ROLE)  # SONARQUBE FIX #2
        return value

    @post_load
    def normalize_email(self, data: dict, **kwargs) -> dict:
        """
        [OWASP A07:2025 – Authentication Failures]: Normalizacija emaila na lowercase
        nakon svih field-level validacija. Post-load garantuje da se izvršava
        jedanput, konzistentno, bez dvostruke normalizacije.
        """
        if "email" in data:
            data["email"] = data["email"].strip().lower()
        return data


class UpdateUserSchema(Schema):
    """
    Validira PATCH /api/admin/users/<id> request body.
    Sva polja su opcionalna (partial update).
    """

    class Meta:
        unknown = RAISE

    first_name = fields.Str(
        load_only=True,
        validate=validate.Length(min=2, max=100),
    )

    last_name = fields.Str(
        load_only=True,
        validate=validate.Length(min=2, max=100),
    )

    role_id = fields.Integer(
        load_only=True,
        strict=True,
    )

    is_active = fields.Boolean(
        load_only=True,
        # [OWASP A01:2025 – Broken Access Control]: Boolean type-enforcement sprječava
        # "is_active=1 AND 1=1" style smuggling
    )

    @validates("first_name")
    def validate_first_name(self, value: str) -> str:
        """SONARQUBE FIX: Dijeli logiku sa CreateUserSchema kroz _validate_name_field()."""
        return _validate_name_field(value)

    @validates("last_name")
    def validate_last_name(self, value: str) -> str:
        """SONARQUBE FIX: Dijeli logiku sa CreateUserSchema kroz _validate_name_field()."""
        return _validate_name_field(value)

    @validates("role_id")
    def validate_role_id(self, value: int) -> int:
        # [OWASP A01:2025 – Broken Access Control]: allowlist provjera i na partial update
        if value not in _ALLOWED_ROLE_IDS:
            raise ValidationError(MSG_INVALID_ROLE)
        return value
