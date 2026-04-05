# Dnevnik-Lite — Secure School Web Application

A production-aware Flask REST API for managing student grades and attendance, built with defense-in-depth security from day one.

---

## Project Structure

```
ednevnik-lite/
├── app/
│   ├── __init__.py          # Application Factory (create_app) — all extensions & blueprints
│   ├── models.py            # SQLAlchemy ORM: User, Role, Grade, AttendanceRecord, AuditLog
│   ├── config.py            # DevelopmentConfig, TestingConfig, ProductionConfig
│   ├── routes/
│   │   ├── auth.py          # POST /api/auth/login|logout|refresh, GET /api/auth/me
│   │   ├── admin.py         # Full user management + audit log viewer (admin only)
│   │   ├── teacher.py       # Grade & attendance CRUD (nastavnik only, ORM-scoped)
│   │   └── student.py       # Read-only grades & attendance (ucenik only, own data)
│   ├── services/
│   │   ├── auth_service.py  # authenticate_user, hash_password, create_tokens
│   │   └── audit_service.py # write_audit + convenience wrappers
│   └── utils/
│       └── decorators.py    # @admin_required, @teacher_required, @student_required
├── migrations/              # Flask-Migrate / Alembic (run `flask db init` to populate)
├── tests/                   # Phase 2 security test suite (placeholder + test plan)
├── .env.example             # All required env vars documented
├── .env                     # Never committed — listed in .gitignore
├── .gitignore
├── requirements.txt         # Pinned versions with security comments
├── run.py                   # Dev entry point (use gunicorn in production)
└── README.md
```

---

## Quick Start

### 1. Clone & set up environment

```bash
git clone <repo>
cd ednevnik-lite

python -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Configure secrets

```bash
cp .env.example .env
# Edit .env — fill in SECRET_KEY, JWT_SECRET_KEY, DATABASE_URL
# Generate keys: python -c "import secrets; print(secrets.token_hex(32))"
```

### 3. Initialize database

```bash
flask db init        # Creates migrations/ structure
flask db migrate -m "Initial schema"
flask db upgrade     # Applies migration to PostgreSQL
```

### 4. Seed roles and admin user

```bash
flask seed-roles     # Creates: admin, nastavnik, ucenik roles
flask seed-admin     # Creates first admin from .env credentials
# Remove ADMIN_BOOTSTRAP_EMAIL and ADMIN_BOOTSTRAP_PASSWORD from .env after this step
```

### 5. Run

```bash
python run.py        # Development server on http://127.0.0.1:5000

# Production (behind nginx):
gunicorn -w 4 -b 127.0.0.1:8000 "run:app"
```

---

## API Endpoints

### Authentication (`/api/auth`)

| Method | Path | Description | Auth |
|--------|------|-------------|------|
| POST | `/api/auth/login` | Login — returns JWT access + refresh tokens | Public |
| POST | `/api/auth/refresh` | Renew access token using refresh token | Refresh token |
| POST | `/api/auth/logout` | Logout (client discards tokens; Phase 2: blocklist) | Any JWT |
| GET | `/api/auth/me` | Current user profile | Any JWT |
| GET | `/api/health` | Health check for load balancers | Public |

### Admin (`/api/admin`) — Role: `admin`

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/admin/users` | List all users (paginated, filterable) |
| POST | `/api/admin/users` | Create a new user |
| GET | `/api/admin/users/<id>` | Get one user |
| PATCH | `/api/admin/users/<id>` | Update user (name, role, active status) |
| DELETE | `/api/admin/users/<id>` | Soft-deactivate user |
| GET | `/api/admin/audit-logs` | Paginated audit log viewer |

### Teacher (`/api/teacher`) — Role: `nastavnik`

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/teacher/grades` | My grade entries (ORM-scoped to teacher) |
| POST | `/api/teacher/grades` | Create a grade |
| GET | `/api/teacher/grades/<id>` | Get one grade (must be mine) |
| PATCH | `/api/teacher/grades/<id>` | Update a grade (must be mine) |
| DELETE | `/api/teacher/grades/<id>` | Delete a grade (must be mine) |
| GET | `/api/teacher/attendance` | My attendance records |
| POST | `/api/teacher/attendance` | Record attendance |
| GET | `/api/teacher/students` | List active students |

### Student (`/api/student`) — Role: `ucenik`

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/student/grades` | My grades (read-only, own data only) |
| GET | `/api/student/attendance` | My attendance (read-only, own data only) |
| GET | `/api/student/profile` | My profile |

---

## Security Architecture

### RBAC — Three-Layer Defense

```
Request
  │
  ▼
Layer 1: JWT signature & expiry (Flask-JWT-Extended)
  │         → 401 if missing/expired/tampered
  ▼
Layer 2: Role claim in JWT (fast, no DB hit)
  │         → 403 if wrong role
  ▼
Layer 3: Role verified in DB (authoritative — catches post-issuance changes)
  │         → 403 if DB role doesn't match
  ▼
Layer 4: ORM-scoped queries (teacher_id=current_user.id in all teacher queries)
  │         → Data access structurally restricted, not just filtered
  ▼
Route Handler
```

### AuditLog — Forensic Events Captured

| Event | Logged |
|-------|--------|
| Login success | ✅ |
| Login failure | ✅ |
| Logout | ✅ |
| Token refresh | ✅ |
| Access denied | ✅ |
| User created | ✅ |
| User deactivated | ✅ |
| User updated | ✅ |
| Grade created | ✅ |
| Grade updated | ✅ |
| Grade deleted | ✅ |
| Attendance created | ✅ |

AuditLog rows are **immutable** — ORM events raise `RuntimeError` on any UPDATE or DELETE attempt.

---

## OWASP Top 10 (2021) Coverage

| # | Category | Status | Implementation |
|---|----------|--------|----------------|
| A01 | Broken Access Control | ✅ | 3-layer RBAC decorators; ORM-level `teacher_id` / `student_id` scoping; Admin cannot self-demote; No horizontal privilege escalation possible |
| A02 | Cryptographic Failures | ✅ | bcrypt (work factor 12) for all passwords; no plaintext column exists; HTTPS enforced via Flask-Talisman + HSTS; secrets in `.env` only; JWT signed with HS256 |
| A03 | Injection | ✅ | SQLAlchemy ORM exclusively — zero raw SQL in codebase; all inputs parameterized; `@validates` on Grade.value and User.email; marshmallow included for Phase 2 full schema validation |
| A04 | Insecure Design | ✅ | Application Factory pattern; separation of concerns (services / routes / models); principle of least privilege throughout; security requirements modeled before code |
| A05 | Security Misconfiguration | ⚠️ | Security headers via Talisman (CSP, HSTS, X-Frame-Options, X-Content-Type); `DEBUG=False` hardcoded in production; no stack traces in error responses; full CSP tightening deferred to Phase 2 |
| A06 | Vulnerable & Outdated Components | ⚠️ | All dependencies pinned to specific versions; security role of each dependency documented in `requirements.txt`; automated dependency scanning (Dependabot / pip-audit) recommended as Phase 2 CI step |
| A07 | Auth & Session Mgmt Failures | ✅ | JWT access tokens (15 min expiry); refresh tokens (7 days); Flask-Limiter brute-force defense on `/login`; bcrypt timing-safe comparison; username enumeration prevented (constant-time dummy hash); `is_active` soft-disable; token blocklist deferred to Phase 2 (Redis) |
| A08 | Software & Data Integrity Failures | ✅ | No `eval()`, `pickle`, or `yaml.load()` unsafe patterns; pinned dependency versions; Flask-Migrate for controlled schema changes; AuditLog ORM events prevent tampering |
| A09 | Security Logging & Monitoring | ✅ | AuditLog on every sensitive action (success AND failure); fields: actor_id, action, resource_type, resource_id, ip_address, timestamp (UTC); append-only enforced at ORM event level; admin audit log viewer endpoint |
| A10 | Server-Side Request Forgery (SSRF) | 🔲 | Not applicable in Phase 1 (no user-supplied URLs fetched by the server); flag for review if Phase 2 introduces webhook or external API features |

**Legend:** ✅ Addressed | ⚠️ Partial — Phase 2 task | 🔲 Out of scope / N/A

---

## Phase 2 Proposed Tasks

### Task 1 — Full marshmallow Schema Validation
Implement request body validation using marshmallow schemas on every POST/PATCH endpoint. Replace the current manual field extraction with typed, validated, and sanitized schema deserialization. Include: field length limits, allowed character sets, custom validators for email format, and meaningful validation error responses.

### Task 2 — Refresh Token Rotation + Redis Blocklist
Implement server-side refresh token revocation using Redis. On each `/api/auth/refresh` call, issue a new refresh token and blocklist the old one's JTI. On `/api/auth/logout`, blocklist both tokens. This converts stateless JWTs into revocable tokens without sacrificing horizontal scalability.

### Task 3 — Security Test Suite (pytest + SQLMap + Burp Suite)
Set up a pytest suite with factory-boy fixtures seeding both hardened and deliberately-vulnerable app states. Run SQLMap against `/api/auth/login`, `/api/teacher/grades`, and `/api/admin/audit-logs`. Run Burp Suite auth flow tests (IDOR, role bypass, token manipulation). Configure OWASP ZAP for full crawl in CI pipeline. Document findings and verify all OWASP controls block their respective attacks.

---

## Production Deployment Checklist

- [ ] Generate cryptographically random `SECRET_KEY` and `JWT_SECRET_KEY`
- [ ] Set `FLASK_ENV=production` in environment
- [ ] Set `DATABASE_URL` with `?sslmode=require`
- [ ] Set `REDIS_URL` for Flask-Limiter distributed counters
- [ ] Set `FORCE_HTTPS=1`
- [ ] Set `CORS_ORIGINS` to specific frontend URLs (not `*`)
- [ ] Run `flask seed-roles` and `flask seed-admin`, then remove bootstrap credentials from `.env`
- [ ] Configure nginx with SSL termination, `X-Forwarded-For` passthrough, and upstream connection limits
- [ ] Run with gunicorn (4+ workers): `gunicorn -w 4 -b 127.0.0.1:8000 "run:app"`
- [ ] Revoke `DELETE` and `UPDATE` privileges on `audit_logs` table from the app DB user
- [ ] Set up log aggregation (stdout → syslog / ELK / Datadog)
- [ ] Schedule regular `pip-audit` / Dependabot scans for dependency CVEs
