# schemas package — marshmallow validation layer
# All POST/PATCH endpoints must run input through a schema before any business logic.
# [OWASP A05:2025 – Injection]: schemas are the first gate; untrusted input never
# reaches the ORM without type enforcement and length limits.
