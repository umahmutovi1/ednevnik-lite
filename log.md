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
- CSP headeri su permisivni (AI navodi da je to task za Fazu 2)
- Refresh token rotacija nije implementirana (replay attack moguć)
- Bug u ProductionConfig: mrtav kod (if False grana)

***Napomene:***
- Claude ja automatski koristio OWASP Top 10 listu iz 2021, te je tek nakon eksplicitnog promptovanja da se koristi lista iz 2025. moguće pokriće najnovijih stavki. U sljedećim tabelama referencirana je OWASP Top 10 2025 lista.
- Neke sigurnosne stavke su pokrivene kroz requirements.txt i README.md fajlove, što je ostavljeno na developeru da ispoštuje.
- ***requirements.txt: Ovdje se pokrivaju tehničke kontrole (libraries / dependencies):***

| Sigurnosna oblast | Dependency | Opis implementacije | OWASP kategorije | Status |
|------------------|-----------|---------------------|------------------|--------|
| Autentikacija i sesije | Flask-JWT-Extended | JWT access + refresh tokeni | A07: Authentication Failures | ✅ |
| Hashiranje lozinki | flask-bcrypt | bcrypt (work factor 12) | A04: Cryptographic Failures | ✅ |
| Token sigurnost | itsdangerous | HMAC signed tokeni | A07: Authentication Failures | ✅ |
| Brute-force zaštita | Flask-Limiter | Rate limiting po IP | A07: Authentication Failures | ✅ |
| Distribuirani rate limit | redis | Persistent counters | A07: Authentication Failures | ✅ |
| HTTPS + sigurnosni headeri | Flask-Talisman | HSTS, CSP, X-Frame-Options | A04: Cryptographic Failures, A02: Security Misconfiguration | ✅ |
| ORM zaštita | Flask-SQLAlchemy | Bez raw SQL (nema injectiona) | A05: Injection | ✅ |
| Migracije | Flask-Migrate | Kontrolisane DB promjene | A08: Software or Data Integrity Failures | ✅ |
| Validacija inputa | marshmallow | Schema validation (Faza 2) | A05: Injection, A06: Insecure Design | ⚠️ |
| Tajne i konfiguracija | python-dotenv | Secrets u .env | A04: Cryptographic Failures, A02: Security Misconfiguration | ✅ |
| CORS kontrola | Flask-Cors | Ograničen pristup API-ju | A02: Security Misconfiguration | ✅ |
| Testing alati | pytest, factory-boy | Testiranje sigurnosti (Faza 2) | A09: Security Logging and Alerting Failures | ⚠️ |
| Supply chain sigurnost | pinned verzije | Fiksne verzije paketa | A03: Software Supply Chain Failures | ⚠️ |

- ***Pokrivenost kroz README.md:***

| Sigurnosna oblast | Implementacija | Opis | OWASP kategorije | Status |
|------------------|---------------|------|------------------|--------|
| RBAC autorizacija | 4-layer security | JWT + role + DB + ORM scoping | A01: Broken Access Control | ✅ |
| Horizontalna izolacija | ORM scoping | teacher_id / student_id filtering | A01: Broken Access Control | ✅ |
| Audit logging | AuditLog model | Logovanje svih akcija (success + fail) | A09: Security Logging and Alerting Failures | ✅ |
| Immutable logovi | ORM events | Nema UPDATE/DELETE nad logovima | A08: Software or Data Integrity Failures | ✅ |
| Sigurnosni dizajn | Application Factory | Separation of concerns | A06: Insecure Design | ✅ |
| Token lifecycle | JWT config | Kratki access + refresh tokeni | A07: Authentication Failures | ✅ |
| HTTPS enforcement | Talisman + nginx | SSL + HSTS | A04: Cryptographic Failures | ✅ |
| Brute-force zaštita | Rate limiting | Login endpoint zaštita | A07: Authentication Failures | ✅ |
| Error handling | No stack trace | Sigurne greške u productionu | A02: Security Misconfiguration | ✅ |
| CSP konfiguracija | Security headers | Osnovni CSP (može jači) | A02: Security Misconfiguration | ⚠️ |
| Token revocation | Redis blocklist | Planirano u Fazi 2 | A07: Authentication Failures | ⚠️ |
| Input validacija | Marshmallow | Planirano u Fazi 2 | A05: Injection | ⚠️ |
| Security testing | SQLMap, Burp, ZAP | Planirano testiranje | A05: Injection, A01: Broken Access Control | ⚠️ |

- **OWASP Top 10 (2025): Ukupna pokrivenost**

| OWASP 2025 kategorija | Status | Implementacija u projektu | Napomena |
|-----------------------|--------|----------------------------|----------|
| A01:2025 - Broken Access Control | ✅ | RBAC (JWT + role + DB provjera) + ORM scoping (teacher_id / student_id) | Nema IDOR ni horizontalne eskalacije |
| A02:2025 - Security Misconfiguration | ⚠️ | Flask-Talisman (CSP, HSTS, headers), produkcijski config, DEBUG=False | CSP se mora dodatno pooštriti |
| A03:2025 - Software Supply Chain Failures | ⚠️ | Pinned dependencies u requirements.txt | Nedostaje automated scanning (pip-audit / Dependabot) |
| A04:2025 - Cryptographic Failures | ✅ | bcrypt hashing, JWT signing, HTTPS enforcement, secrets u .env | Sigurna obrada lozinki i tokena |
| A05:2025 - Injection | ✅ | SQLAlchemy ORM (bez raw SQL), validacije modela | Potpuna schema validacija (marshmallow) u Fazi 2 |
| A06:2025 - Insecure Design | ✅ | Application Factory, separation of concerns, least privilege | Planirana sigurnost prije implementacije |
| A07:2025 - Authentication Failures | ✅ | JWT auth, refresh tokeni, rate limiting (Flask-Limiter), bcrypt | Brute-force zaštita implementirana |
| A08:2025 - Software or Data Integrity Failures | ✅ | Flask-Migrate, nema unsafe funkcija, immutable AuditLog | Kontrolisane promjene i zaštita podataka |
| A09:2025 - Security Logging and Alerting Failures | ✅ | AuditLog (success + failure eventi), admin viewer | Nema alertinga (može se dodati u Fazi 2) |
| A10:2025 - Mishandling of Exceptional Conditions | ⚠️ | Siguran error handling (bez stack trace), rate limiting | Može se poboljšati centralizovanim monitoring-om |

## Sesija 1 — Datum: 7. april 2026.

### Prompt #1: Poboljšanje aplikacije sa sigurnosnim kontrolama (Faza 2)

**Šta sam tražila:** Input Validation via marshmallow (Schema), Security Headers & Configuration Hardening, Dependency Audit & Supply Chain Security, Refresh Token Rotation + Redis Blocklist

**Šta je Claude generisao:**

**Šta je ispravno implementirano:**

**Šta sam morala ručno ispraviti:**

**Identificirane slabosti:**

***Napomene:***
