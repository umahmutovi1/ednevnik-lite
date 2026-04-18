"""
app/utils/messages.py — Centralizovane poruke grešaka
======================================================
MAINTAINABILITY FIX (SonarQube: Magic Strings)
-----------------------------------------------
Sve poruke grešaka koje se ponavljaju u više fajlova su premještene ovdje.

ZAŠTO JE OVO VAŽNO:
  - Maintainability: promjena poruke na jednom mjestu mijenja je svuda
  - Security: konzistentne poruke sprječavaju information disclosure
    (različite verzije iste poruke mogu otkriti internu logiku)
  - [OWASP A10:2025 – Mishandling of Exceptional Conditions]: 
    konzistentne, generičke poruke ne otkrivaju internu strukturu

SIGURNOSNA RELEVANTNOST:
  Ovo je primarno code quality popravka, ali ima i sigurnosnu dimenziju:
  ako se "Not Found" negdje napiše kao "Resource not found" a drugdje kao
  "Not Found", napadač može koristiti razlike u porukama za fingerprinting
  interne logike (information disclosure). Centralizacija eliminiše ovaj rizik.
"""

# ---------------------------------------------------------------------------
# HTTP Error Labels — koriste se kao "error" ključ u JSON odgovorima
# ---------------------------------------------------------------------------
ERR_NOT_FOUND = "Not Found"
ERR_BAD_REQUEST = "Bad Request"
ERR_FORBIDDEN = "Forbidden"
ERR_UNAUTHORIZED = "Unauthorized"
ERR_CONFLICT = "Conflict"
ERR_SERVICE_UNAVAILABLE = "ServiceUnavailable"

# ---------------------------------------------------------------------------
# Validation Messages — koriste se u marshmallow schemama i route handlerima
# ---------------------------------------------------------------------------

# Generičke
MSG_JSON_REQUIRED = "JSON body required."
MSG_NO_CHANGES = "No changes provided."

# Korisnici
MSG_USER_NOT_FOUND = "User not found."
MSG_INVALID_ROLE = "Invalid role."
MSG_INVALID_ROLE_ID = "Invalid role_id."
MSG_ADMIN_CANNOT_CHANGE_OWN_ROLE = "Admins cannot change their own role."
MSG_ADMIN_CANNOT_DEACTIVATE_SELF = "Admins cannot deactivate their own account."
MSG_USER_ALREADY_DEACTIVATED = "User is already deactivated."

# Autentikacija
MSG_INVALID_CREDENTIALS = "Invalid email or password."
MSG_ACCOUNT_DEACTIVATED = "Account not found or deactivated."
MSG_TOKEN_REQUIRED = "A Bearer token is required. Include it in the Authorization header."
MSG_TOKEN_REVOKED = "Token has been revoked."

# Validacija — nazivi
MSG_INVALID_NAME_CHARS = "Invalid characters in name."

# Validacija — predmet (subject)
MSG_INVALID_SUBJECT_CHARS = "Invalid characters in subject."

# Ocjene
MSG_GRADE_NOT_FOUND = "Grade not found."
MSG_GRADE_NO_CHANGES = "No changes."
MSG_INVALID_GRADE_VALUE = "Grade must be between 1 and 5."
MSG_NOT_A_STUDENT = "Target user is not a student."
MSG_STUDENT_NOT_FOUND = "Student not found."

# Evidencija prisustva
MSG_ATTENDANCE_CONFLICT = "Attendance record already exists for this student/subject/date."

# Logout
MSG_LOGOUT_SUCCESS = "Logged out successfully. Both tokens have been revoked."
MSG_LOGOUT_FAILED = "Logout could not be completed. Please try again."
