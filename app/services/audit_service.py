"""
services/audit_service.py — AuditLog Write Service (Audit-Fixed)
=================================================================
AUDIT FIX APPLIED:
  CF-05: audit_login_failure() now hashes the attempted email with HMAC-SHA256
         before writing to the detail field. Plaintext PII is no longer stored
         in the audit log.
"""

import hashlib
import sys
import traceback
from typing import Optional

from flask import current_app, request
from app.models import AuditLog, db


def write_audit(
    action: str,
    actor_id: Optional[int] = None,
    resource_type: Optional[str] = None,
    resource_id=None,
    detail: Optional[str] = None,
    ip_address: Optional[str] = None,
) -> Optional[AuditLog]:
    if ip_address is None:
        try:
            # [OWASP A09:2025]: Take only the first X-Forwarded-For value.
            # ProxyFix middleware (configured in __init__.py) should be used in
            # production to prevent spoofing — see W-02 in audit report.
            forwarded_for = request.headers.get("X-Forwarded-For")
            if forwarded_for:
                ip_address = forwarded_for.split(",")[0].strip()
            else:
                ip_address = request.remote_addr
        except RuntimeError:
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
    except Exception as exc:
        db.session.rollback()
        print(
            f"[CRITICAL] AuditLog write FAILED for action='{action}' actor={actor_id}: {exc}",
            file=sys.stderr,
        )
        traceback.print_exc(file=sys.stderr)
        return None


def audit_login_success(actor_id: int) -> None:
    write_audit(action="login_success", actor_id=actor_id, resource_type="User", resource_id=actor_id)


def audit_login_failure(attempted_email: str) -> None:
    """
    [OWASP A09:2025 – Security Logging and Alerting Failures]: CF-05 FIXED.
    The attempted email is hashed with HMAC-SHA256 (keyed by SECRET_KEY) before
    storage. This preserves forensic correlation ability (the same email produces
    the same fingerprint) without storing recoverable PII in the audit log.
    An attacker with only DB access cannot reconstruct the original email addresses.
    """
    secret = current_app.config.get("SECRET_KEY", "")
    email_fingerprint = hashlib.sha256(
        f"{secret}:{attempted_email.strip().lower()}".encode()
    ).hexdigest()[:16]

    write_audit(
        action="login_failure",
        actor_id=None,
        resource_type="User",
        detail=f"Failed login attempt. Email fingerprint: {email_fingerprint}",
    )


def audit_logout(actor_id: int) -> None:
    write_audit(action="logout", actor_id=actor_id)


def audit_access_denied(actor_id, attempted_resource: str) -> None:
    write_audit(
        action="access_denied",
        actor_id=actor_id,
        resource_type="Route",
        detail=f"Access denied to: {attempted_resource}",
    )


def audit_grade_created(actor_id: int, grade_id: int, detail: str) -> None:
    write_audit(action="grade_created", actor_id=actor_id, resource_type="Grade",
                resource_id=grade_id, detail=detail)


def audit_grade_updated(actor_id: int, grade_id: int, detail: str) -> None:
    write_audit(action="grade_updated", actor_id=actor_id, resource_type="Grade",
                resource_id=grade_id, detail=detail)


def audit_user_created(actor_id: int, new_user_id: int, email: str) -> None:
    write_audit(action="user_created", actor_id=actor_id, resource_type="User",
                resource_id=new_user_id, detail=f"Created user: {email}")


def audit_user_deactivated(actor_id: int, target_user_id: int, email: str) -> None:
    write_audit(action="user_deactivated", actor_id=actor_id, resource_type="User",
                resource_id=target_user_id, detail=f"Deactivated user: {email}")
