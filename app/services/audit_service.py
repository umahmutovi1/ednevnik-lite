"""
services/audit_service.py — AuditLog Write Service
====================================================
Centralized service for writing to the AuditLog.

All sensitive actions in the system (login, grade changes, user management,
access denials) MUST call write_audit() from here — never write AuditLog
rows directly in route handlers.

FORENSIC PRINCIPLE:
  - Failures are as important as successes. A failed login attempt is not
    less interesting than a successful one — it may indicate an attack.
  - Every write includes: actor, action, affected resource, IP, and timestamp.
  - This module never raises — a failure to write an audit log is logged
    to stderr but does NOT propagate to the caller. The primary action
    (e.g., a login) should not fail because the audit log had an error.
    However, audit log failures are themselves logged as critical.
"""

import sys
import traceback
from typing import Optional

from flask import request

from app.models import AuditLog, db


def write_audit(
    action: str,
    actor_id: Optional[int] = None,
    resource_type: Optional[str] = None,
    resource_id: Optional[str | int] = None,
    detail: Optional[str] = None,
    ip_address: Optional[str] = None,
) -> Optional[AuditLog]:
    """
    Append a single audit record to the AuditLog table.

    Parameters
    ----------
    action       : One of the AUDIT_ACTIONS enum values from models.py.
    actor_id     : User.id of the authenticated actor. None for pre-auth events.
    resource_type: Class name of the affected object (e.g., "Grade", "User").
    resource_id  : PK of the affected object, coerced to string.
    detail       : Human-readable description of the change.
    ip_address   : Source IP. If None, extracted from Flask request context.

    Returns
    -------
    The created AuditLog instance, or None if the write failed.

    SECURITY NOTE: This function uses a nested transaction (savepoint) so that
    a failed audit log write does not roll back the parent transaction.
    In practice, audit log failures are extremely rare, but we must not let
    them silently swallow the primary action's DB commit.
    """
    # Auto-detect IP from Flask request context if not provided
    if ip_address is None:
        try:
            # X-Forwarded-For is set by reverse proxies (nginx, Cloudflare).
            # We take only the first IP to avoid spoofing via header injection.
            # Production deployments MUST configure trusted proxy IPs in nginx.
            forwarded_for = request.headers.get("X-Forwarded-For")
            if forwarded_for:
                ip_address = forwarded_for.split(",")[0].strip()
            else:
                ip_address = request.remote_addr
        except RuntimeError:
            # No active Flask request context (e.g., called from a CLI command)
            ip_address = None

    entry = AuditLog(
        actor_id=actor_id,
        action=action,
        resource_type=resource_type,
        resource_id=str(resource_id) if resource_id is not None else None,
        detail=detail,
        ip_address=ip_address,
    )

    try:
        db.session.add(entry)
        db.session.commit()
        return entry
    except Exception as exc:  # pylint: disable=broad-except
        # CRITICAL: Audit log write failed. Do not crash the app, but do log
        # loudly to stderr so ops teams see it in container/server logs.
        db.session.rollback()
        print(
            f"[CRITICAL] AuditLog write FAILED for action='{action}' actor={actor_id}: {exc}",
            file=sys.stderr,
        )
        traceback.print_exc(file=sys.stderr)
        return None


# ---------------------------------------------------------------------------
# Convenience wrappers — keeps route handlers readable
# ---------------------------------------------------------------------------

def audit_login_success(actor_id: int) -> None:
    write_audit(action="login_success", actor_id=actor_id, resource_type="User", resource_id=actor_id)


def audit_login_failure(attempted_email: str) -> None:
    write_audit(
        action="login_failure",
        actor_id=None,  # No authenticated actor — this is a pre-auth failure
        resource_type="User",
        detail=f"Failed login attempt for email: {attempted_email}",
    )


def audit_logout(actor_id: int) -> None:
    write_audit(action="logout", actor_id=actor_id)


def audit_access_denied(actor_id: Optional[int], attempted_resource: str) -> None:
    write_audit(
        action="access_denied",
        actor_id=actor_id,
        resource_type="Route",
        detail=f"Access denied to: {attempted_resource}",
    )


def audit_grade_created(actor_id: int, grade_id: int, detail: str) -> None:
    write_audit(
        action="grade_created",
        actor_id=actor_id,
        resource_type="Grade",
        resource_id=grade_id,
        detail=detail,
    )


def audit_grade_updated(actor_id: int, grade_id: int, detail: str) -> None:
    write_audit(
        action="grade_updated",
        actor_id=actor_id,
        resource_type="Grade",
        resource_id=grade_id,
        detail=detail,
    )


def audit_user_created(actor_id: int, new_user_id: int, email: str) -> None:
    write_audit(
        action="user_created",
        actor_id=actor_id,
        resource_type="User",
        resource_id=new_user_id,
        detail=f"Created user: {email}",
    )


def audit_user_deactivated(actor_id: int, target_user_id: int, email: str) -> None:
    write_audit(
        action="user_deactivated",
        actor_id=actor_id,
        resource_type="User",
        resource_id=target_user_id,
        detail=f"Deactivated user: {email}",
    )
