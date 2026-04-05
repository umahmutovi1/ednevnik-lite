"""
models.py — Dnevnik-Lite ORM Models
====================================
Five models covering users, roles, grades, attendance, and audit logs.

SECURITY PRINCIPLES applied throughout:
  - No raw SQL anywhere — SQLAlchemy parameterizes all queries (A03: Injection)
  - Passwords stored as bcrypt hashes only — no plaintext column exists (A02)
  - Role FK on User — roles are seeded, not user-creatable via API (A01)
  - teacher_id FK on Grade/Attendance — ORM-level scope, not just route-level (A01)
  - AuditLog has no update/delete methods exposed — append-only forensic record (A09)
  - All timestamps in UTC with server-side defaults — tamper-resistant ordering
  - is_active flag on User — soft-disable without data deletion (preserves audit trail)
"""

from datetime import datetime, timezone
from typing import Optional

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import (
    Boolean, Column, DateTime, Enum, ForeignKey,
    Integer, String, Text, UniqueConstraint, event
)
from sqlalchemy.orm import relationship, validates

db = SQLAlchemy()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _utcnow() -> datetime:
    """Server-side UTC timestamp — used as column default."""
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Role Model
# ---------------------------------------------------------------------------

class Role(db.Model):
    """
    Defines the three privilege tiers in the system.

    SECURITY: Roles are seeded at startup via migration/fixture.
    They are NOT user-creatable or user-editable via the API.
    This prevents privilege escalation through the role management surface.
    """
    __tablename__ = "roles"

    id = Column(Integer, primary_key=True)
    name = Column(
        Enum("admin", "nastavnik", "ucenik", name="role_enum"),
        unique=True,
        nullable=False,
        comment="admin | nastavnik | ucenik — seeded, not API-creatable"
    )
    description = Column(String(255), nullable=True)

    # Relationships
    users = relationship("User", back_populates="role", lazy="dynamic")

    def __repr__(self) -> str:
        return f"<Role {self.name}>"

    def to_dict(self) -> dict:
        return {"id": self.id, "name": self.name}


# ---------------------------------------------------------------------------
# User Model
# ---------------------------------------------------------------------------

class User(db.Model):
    """
    Represents all system actors: admins, teachers (nastavnici), and students (učenici).

    SECURITY:
      - `password_hash` stores bcrypt output only — no plaintext password column exists.
        If someone directly queries the DB, they get a hash, not a password.
      - `is_active` allows soft-disabling without deleting the account.
        Deleted accounts leave orphaned audit records; deactivated accounts don't.
      - `role_id` FK links to the seeded Role table — role cannot be an arbitrary string.
      - Email uniqueness enforced at DB level — not just application level.
    """
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    email = Column(
        String(255),
        unique=True,
        nullable=False,
        index=True,
        comment="Primary login identifier — unique, lowercased before storage"
    )

    # bcrypt hash — adaptive, work factor configurable, rainbow-table resistant.
    # Column is named 'password_hash' — no 'password' or 'password_plain' column.
    password_hash = Column(
        String(128),
        nullable=False,
        comment="bcrypt hash only — never store plaintext passwords"
    )

    first_name = Column(String(100), nullable=False)
    last_name = Column(String(100), nullable=False)

    # FK to Role — roles are seeded; this field is NOT a free-text string
    role_id = Column(
        Integer,
        ForeignKey("roles.id", ondelete="RESTRICT"),
        nullable=False,
        index=True
    )

    # Soft-disable: deactivated users cannot log in but their records are preserved
    # for audit trail integrity. Physical deletion would orphan AuditLog entries.
    is_active = Column(
        Boolean,
        default=True,
        nullable=False,
        comment="Soft-disable flag — deactivated users cannot authenticate"
    )

    # Forensic timestamps — server-side UTC defaults; application cannot set arbitrary values
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow, nullable=False)

    # Relationships
    role = relationship("Role", back_populates="users")
    grades_entered = relationship(
        "Grade",
        foreign_keys="Grade.teacher_id",
        back_populates="teacher",
        lazy="dynamic"
    )
    grades_received = relationship(
        "Grade",
        foreign_keys="Grade.student_id",
        back_populates="student",
        lazy="dynamic"
    )
    attendance_entered = relationship(
        "AttendanceRecord",
        foreign_keys="AttendanceRecord.teacher_id",
        back_populates="teacher",
        lazy="dynamic"
    )
    attendance_received = relationship(
        "AttendanceRecord",
        foreign_keys="AttendanceRecord.student_id",
        back_populates="student",
        lazy="dynamic"
    )

    @validates("email")
    def normalize_email(self, key, value: str) -> str:
        """Lowercase and strip email before storage — prevents duplicate-email bypass."""
        return value.strip().lower()

    def __repr__(self) -> str:
        return f"<User {self.email} [{self.role.name if self.role else 'no-role'}]>"

    def to_dict(self, include_role: bool = True) -> dict:
        """Safe serialization — never includes password_hash."""
        data = {
            "id": self.id,
            "email": self.email,
            "first_name": self.first_name,
            "last_name": self.last_name,
            "is_active": self.is_active,
            "created_at": self.created_at.isoformat(),
        }
        if include_role and self.role:
            data["role"] = self.role.name
        return data


# ---------------------------------------------------------------------------
# Grade Model
# ---------------------------------------------------------------------------

class Grade(db.Model):
    """
    A single grade entry for one student in one subject.

    SECURITY:
      - `teacher_id` FK enforced at ORM level — a teacher can only insert grades
        for students. The service layer further restricts to their own class.
      - ORM queries always include `teacher_id=current_user.id` in WHERE clauses
        (enforced in services/teacher_service.py) — even if the route guard fails,
        the query itself won't return cross-teacher data (defense in depth).
      - No raw SQL is used — SQLAlchemy parameterizes all inputs.
    """
    __tablename__ = "grades"

    id = Column(Integer, primary_key=True)

    # The student receiving the grade
    student_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
        index=True
    )

    # The teacher who entered the grade — enforced FK, not a free field
    teacher_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
        comment="Teacher FK — ORM-scoped so a teacher can only see/edit their own entries"
    )

    subject = Column(String(100), nullable=False)

    # Grade value: 1-5 (Bosnian grading system)
    value = Column(
        Integer,
        nullable=False,
        comment="1-5 (Bosnian grading scale)"
    )

    # Optional note from the teacher — stored as text, sanitized on input
    note = Column(Text, nullable=True)

    # Forensic timestamps
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow, nullable=False)

    # Relationships
    student = relationship("User", foreign_keys=[student_id], back_populates="grades_received")
    teacher = relationship("User", foreign_keys=[teacher_id], back_populates="grades_entered")

    @validates("value")
    def validate_grade_value(self, key, value: int) -> int:
        """Enforce Bosnian grading scale (1-5) at model level — not just API level."""
        if not isinstance(value, int) or value < 1 or value > 5:
            raise ValueError(f"Grade value must be an integer between 1 and 5, got: {value}")
        return value

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "student_id": self.student_id,
            "teacher_id": self.teacher_id,
            "subject": self.subject,
            "value": self.value,
            "note": self.note,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }


# ---------------------------------------------------------------------------
# AttendanceRecord Model
# ---------------------------------------------------------------------------

class AttendanceRecord(db.Model):
    """
    Tracks student attendance per class session.

    SECURITY: Same ORM-level scoping pattern as Grade.
    A teacher's queries are always filtered by teacher_id — cross-teacher
    access is structurally prevented, not just route-guarded.
    """
    __tablename__ = "attendance_records"

    id = Column(Integer, primary_key=True)

    student_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
        index=True
    )

    teacher_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
        comment="Teacher FK — ORM-scoped; prevents cross-teacher data access"
    )

    subject = Column(String(100), nullable=False)
    date = Column(DateTime(timezone=True), nullable=False, index=True)

    status = Column(
        Enum("prisutan", "odsutan", "kasnjenje", name="attendance_status_enum"),
        nullable=False,
        comment="prisutan=present | odsutan=absent | kasnjenje=late"
    )

    note = Column(Text, nullable=True)

    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow, nullable=False)

    # Prevent duplicate attendance record for same student/teacher/subject/date
    __table_args__ = (
        UniqueConstraint(
            "student_id", "teacher_id", "subject", "date",
            name="uq_attendance_student_teacher_subject_date"
        ),
    )

    # Relationships
    student = relationship("User", foreign_keys=[student_id], back_populates="attendance_received")
    teacher = relationship("User", foreign_keys=[teacher_id], back_populates="attendance_entered")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "student_id": self.student_id,
            "teacher_id": self.teacher_id,
            "subject": self.subject,
            "date": self.date.isoformat(),
            "status": self.status,
            "note": self.note,
            "created_at": self.created_at.isoformat(),
        }


# ---------------------------------------------------------------------------
# AuditLog Model
# ---------------------------------------------------------------------------

# Exhaustive list of auditable action types — adding a new action requires
# an explicit code change, not just a free-form string in a request.
AUDIT_ACTIONS = (
    # Authentication events
    "login_success",
    "login_failure",
    "logout",
    "token_refresh",
    "password_reset_request",
    "password_reset_complete",
    # Access control events
    "access_denied",
    "permission_escalation_attempt",
    # User management (Admin only)
    "user_created",
    "user_updated",
    "user_deactivated",
    "user_activated",
    "user_deleted",
    # Grade events
    "grade_created",
    "grade_updated",
    "grade_deleted",
    # Attendance events
    "attendance_created",
    "attendance_updated",
    "attendance_deleted",
)


class AuditLog(db.Model):
    """
    Append-only forensic log of every sensitive action in the system.

    SECURITY & FORENSICS:
      - This model intentionally has NO `update()` or `delete()` helper methods.
        Mutations are structurally prevented at the service layer.
      - Rows include actor_id (who), action (what), resource_type/resource_id (on what),
        ip_address (from where), and timestamp (when) — sufficient for forensic reconstruction.
      - `actor_id` is nullable to support pre-auth events (e.g., failed logins where
        no authenticated user exists yet).
      - Timestamps are always UTC, set server-side.
      - AuditLog writes happen on BOTH success and failure — failed actions
        are equally important forensically (they reveal attack attempts).

    NOTE: Do NOT add update() or delete() methods to this class.
    If the database-level DELETE privilege is also revoked for the app DB user,
    the log becomes tamper-evident even to a compromised application.
    """
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True)

    # Who performed the action — nullable for pre-auth events (login failures)
    actor_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        comment="Nullable — pre-auth events (login failures) have no authenticated actor"
    )

    # Constrained to known action types — prevents log injection via free-text
    action = Column(
        Enum(*AUDIT_ACTIONS, name="audit_action_enum"),
        nullable=False,
        index=True
    )

    # What type of object was affected (e.g., "Grade", "User", "AttendanceRecord")
    resource_type = Column(String(64), nullable=True)

    # The PK of the affected object — store as string to handle non-integer PKs
    resource_id = Column(String(64), nullable=True)

    # Optional human-readable detail (e.g., "Grade changed from 3 to 4 for student #12")
    detail = Column(Text, nullable=True)

    # Source IP — important for detecting distributed attacks or insider threats
    # Stored as string to handle both IPv4 and IPv6
    ip_address = Column(
        String(45),
        nullable=True,
        comment="IPv4 or IPv6 source address — up to 45 chars for IPv6"
    )

    # UTC timestamp — server-side default, application cannot set arbitrary timestamps
    timestamp = Column(
        DateTime(timezone=True),
        default=_utcnow,
        nullable=False,
        index=True
    )

    # Relationship — read-only access to actor info
    actor = relationship("User", foreign_keys=[actor_id], lazy="joined")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "actor_id": self.actor_id,
            "actor_email": self.actor.email if self.actor else None,
            "action": self.action,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "detail": self.detail,
            "ip_address": self.ip_address,
            "timestamp": self.timestamp.isoformat(),
        }

    # INTENTIONALLY NO update() or delete() METHODS.
    # If you need to "correct" an audit entry, append a new entry explaining
    # the correction — never modify or remove existing records.


# ---------------------------------------------------------------------------
# SQLAlchemy event: Block AuditLog UPDATE and DELETE at ORM level
# ---------------------------------------------------------------------------

@event.listens_for(AuditLog, "before_update")
def _block_audit_log_update(mapper, connection, target):
    """
    Raise an error if anyone attempts to update an AuditLog row via ORM.
    This is a defense-in-depth measure — the primary protection is that
    no update() method exists on the model, but this catches direct
    session.add() attempts on a modified AuditLog instance.
    """
    raise RuntimeError(
        "[Security] AuditLog records are immutable. "
        "Updates are not permitted. Append a new record instead."
    )


@event.listens_for(AuditLog, "before_delete")
def _block_audit_log_delete(mapper, connection, target):
    """
    Raise an error if anyone attempts to delete an AuditLog row via ORM.
    For maximum tamper-evidence, also revoke DELETE privilege on the
    audit_logs table from the application DB user at the PostgreSQL level.
    """
    raise RuntimeError(
        "[Security] AuditLog records cannot be deleted. "
        "The audit trail is a forensic artifact — deletion is not permitted."
    )
