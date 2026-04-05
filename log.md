## Sesija 1 — Datum: 5. april 2026.

### Prompt #1: Inicijalna arhitektura

**Šta sam tražila:** Početna struktura projekta sa sigurnosnim kontrolama

**Šta je Claude generisao:**
- app/__init__.py (Application Factory sa svim ekstenzijama, napomena: content_type_option uzrokovalo bug, ručno prepravila u x_content_type_options zbog verzije Talisman) 
- app/models.py (User, Role, Grade, AttendanceRecord, AuditLog)
- app/config.py (Development/Testing/Production konfiguracija)
- app/routes/auth.py (login, logout, refresh, /me)
- app/routes/admin.py (user management, audit log viewer)
- app/routes/teacher.py (grade i attendance CRUD)
- app/routes/student.py (read-only vlastiti podaci)
- app/services/auth_service.py
- app/services/audit_service.py
- app/utils/decorators.py (RBAC dekoratori)
- requirements.txt, .env.example, README.md

**Šta je ispravno implementirano:**
- bcrypt hashing sa konfigurabilnim work factorom
- JWT access (15min) i refresh (7 dana) tokeni
- SQLAlchemy ORM isključivo — SQL Injection strukturalno nemoguć
- AuditLog append-only (ORM eventi blokiraju UPDATE/DELETE)
- IDOR prevencija: teacher_id scoping na svim upitima
- Timing-safe login (dummy bcrypt kad email ne postoji)
- Security headeri via Flask-Talisman
- Rate limiting via Flask-Limiter
- Soft-delete korisnika (čuva audit trail)
- 3-slojna RBAC: JWT → JWT claim → DB provjera

**Šta sam morala ručno ispraviti:**
- Ništa u ovoj fazi

**Identificirane slabosti:**
- Rate limiting na /login koristi nekonvencionalan "workaround"
- CSP headeri su permisivni (AI navodi da je to Phase 2 task)
- Refresh token rotacija nije implementirana (replay attack moguć)
- Bug u ProductionConfig: mrtav kod (if False grana)

**OWASP pokrivenost:**
- A01 Broken Access Control: ✅ RBAC + ORM scoping
- A02 Cryptographic Failures: ✅ bcrypt + JWT + HTTPS
- A03 Injection: ✅ SQLAlchemy ORM
- A07 Auth Failures: ⚠️ Djelimično (nedostaje refresh rotacija)
- A09 Logging: ✅ AuditLog
