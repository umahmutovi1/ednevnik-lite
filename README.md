# Dnevnik-Lite — Secure School Web Application (Phase 1 + 2)

A production-hardened Flask REST API for managing student grades and attendance,
built with defense-in-depth security and verified against OWASP Top 10 (2025).

---

## Project Structure

```
ednevnik-lite/
├── app/
│   ├── __init__.py               # Application Factory — extensions, blueprints, hardened CSP
│   ├── models.py                 # SQLAlchemy ORM: User, Role, Grade, AttendanceRecord, AuditLog
│   ├── config.py                 # DevelopmentConfig, TestingConfig, ProductionConfig
│   ├── schemas/                  # Phase 2: marshmallow validation layer
│   │   ├── auth_schemas.py       # LoginSchema
│   │   ├── admin_schemas.py      # CreateUserSchema, UpdateUserSchema
│   │   └── teacher_schemas.py   # CreateGradeSchema, UpdateGradeSchema, CreateAttendanceSchema
│   ├── routes/
│   │   ├── auth.py               # Login, logout (dual-JTI revocation), refresh (rotation)
│   │   ├── admin.py              # User management + audit log viewer
│   │   ├── teacher.py            # Grade & attendance CRUD (ORM-scoped)
│   │   └── student.py            # Read-only (own data only)
│   ├── services/
│   │   ├── auth_service.py       # authenticate_user, create_tokens, decode_token_claims
│   │   └── audit_service.py      # write_audit + convenience wrappers
│   └── utils/
│       ├── decorators.py         # @admin_required, @teacher_required, @student_required
│       └── token_blocklist.py    # Phase 2: Redis JTI blocklist, fail-closed
├── tests/
│   ├── conftest.py               # App factory, DB fixtures, role-seeded users, token factories
│   ├── test_auth.py              # Login, logout, schema validation, deactivation
│   ├── test_rbac.py              # Role enforcement + deactivated user rejection
│   ├── test_schemas.py           # All 6 schemas: valid + invalid + attack inputs
│   ├── test_grades.py            # Grade CRUD + IDOR prevention
│   ├── test_audit.py             # AuditLog immutability + event completeness
│   └── security/
│       ├── test_sql_injection.py     # SQLi payloads across all user-controlled inputs
│       ├── test_jwt_manipulation.py  # alg:none, claim forgery, malformed tokens
│       ├── test_token_revocation.py  # Blocklist, rotation, fail-closed Redis behavior
│       └── test_rate_limiting.py     # Brute-force simulation
├── .github/workflows/ci.yml     # Phase 2: pip-audit + pytest + OWASP ZAP
├── .env.example
├── .gitignore
├── requirements.txt              # Pinned + supply chain risk annotations
└── run.py
```

---

## Quick Start

```bash
# 1. Clone and install
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# 2. Configure
cp .env.example .env
# Fill in: SECRET_KEY, JWT_SECRET_KEY, DATABASE_URL, REDIS_URL

# 3. Initialize DB
flask db init && flask db migrate -m "Initial schema" && flask db upgrade

# 4. Seed
flask seed-roles && flask seed-admin

# 5. Start Redis (required for token blocklist)
docker run -d -p 6379:6379 redis:7-alpine

# 6. Run
python run.py

# 7. Run tests
pytest tests/ -v --cov=app
```

---

## API Endpoints

### Auth (`/api/auth`)
| Method | Path | Auth |
|--------|------|------|
| POST | `/api/auth/login` | Public |
| POST | `/api/auth/refresh` | Refresh token — issues NEW pair, blocklists old |
| POST | `/api/auth/logout` | Any JWT — blocklists access + refresh JTIs |
| GET | `/api/auth/me` | Any JWT |

### Admin (`/api/admin`) — role: `admin`
| Method | Path |
|--------|------|
| GET/POST | `/api/admin/users` |
| GET/PATCH/DELETE | `/api/admin/users/<id>` |
| GET | `/api/admin/audit-logs` |

### Teacher (`/api/teacher`) — role: `nastavnik`
| Method | Path |
|--------|------|
| GET/POST | `/api/teacher/grades` |
| GET/PATCH/DELETE | `/api/teacher/grades/<id>` |
| GET/POST | `/api/teacher/attendance` |
| GET | `/api/teacher/students` |

### Student (`/api/student`) — role: `ucenik`
| Method | Path |
|--------|------|
| GET | `/api/student/grades` |
| GET | `/api/student/attendance` |
| GET | `/api/student/profile` |

---

## Security Architecture

### RBAC — Four-Layer Defense
```
Request
  │
  ▼ Layer 1: JWT signature & expiry + Redis blocklist check
  │           → 401 if missing/expired/tampered/blocklisted
  ▼ Layer 2: marshmallow schema validation
  │           → 400 if any field fails type/length/allowlist check
  ▼ Layer 3: Role claim (JWT) + DB re-verification
  │           → 403 if role mismatch; catches post-issuance role changes
  ▼ Layer 4: ORM-scoped queries (teacher_id / student_id = current_user.id)
  │           → Data access structurally restricted
  ▼
Route Handler
```

### Token Lifecycle (Phase 2)
```
Login  → access_token (15 min) + refresh_token (7 days)
         Both carry a unique JTI claim

/refresh → NEW access_token + NEW refresh_token issued
           OLD refresh JTI written to Redis blocklist (TTL = remaining lifetime)
           → Old refresh token is now dead

/logout  → access JTI + refresh JTI both written to Redis blocklist
           → Both tokens dead immediately, before natural expiry

Every @jwt_required route → token_in_blocklist_loader checks Redis
  Redis unreachable → FAIL CLOSED (token rejected, not accepted)
```

---

## OWASP Top 10 (2025) Coverage

| # | Category | Status | Implementation |
|---|----------|--------|----------------|
| A01:2025 | Broken Access Control | ✅ | 3-layer RBAC; ORM `teacher_id`/`student_id` scoping; role allowlist in schema; admin self-demotion blocked; IDOR prevented via filter-by-owner |
| A02:2025 | Security Misconfiguration | ✅ | Hardened Talisman CSP (`default-src 'none'`); HSTS preload; Permissions-Policy; `DEBUG=False` hardcoded; no stack traces in responses |
| A03:2025 | Software Supply Chain Failures | ✅ | All deps pinned; `# [SUPPLY CHAIN RISK]` annotations; `pip-audit` in CI failing on HIGH/CRITICAL CVEs; Dependabot config recommended |
| A04:2025 | Cryptographic Failures | ✅ | bcrypt (work factor 12); JWT HS256; HTTPS/HSTS; Redis blocklist with TTL = remaining token lifetime; no plaintext secrets |
| A05:2025 | Injection | ✅ | SQLAlchemy ORM exclusively (zero raw SQL); marshmallow schemas with `unknown=RAISE`, type enforcement, length limits, regex allowlists on all POST/PATCH |
| A06:2025 | Insecure Design | ✅ | Application Factory; separation of concerns; schema-first validation; grade range enforced at schema AND model level; principle of least privilege |
| A07:2025 | Authentication Failures | ✅ | JWT 15 min expiry; refresh token rotation; Redis blocklist (fail-closed); rate limiting (10/min on login); constant-time dummy bcrypt for enumeration prevention; `is_active` checked on every DB-re-query route |
| A08:2025 | Software or Data Integrity Failures | ✅ | No `eval()`/`pickle`/unsafe YAML; pinned deps; Flask-Migrate for schema integrity; AuditLog ORM events block UPDATE/DELETE; `unknown=RAISE` prevents parameter pollution |
| A09:2025 | Security Logging and Alerting Failures | ✅ | AuditLog on every sensitive action (success AND failure); append-only ORM events; fields: actor_id, action, resource_type, resource_id, ip_address, timestamp (UTC); admin viewer endpoint; CI test verifies log completeness |
| A10:2025 | Mishandling of Exceptional Conditions | ✅ | ValidationError → 400 with generic message (no ORM internals exposed); Redis failure → fail-closed (True); no unhandled 500s for input errors; strict date parsing in schema |

**Legend:** ✅ Fully addressed with tests

---

## Supply Chain Audit

Run locally:
```bash
pip install pip-audit
pip-audit --requirement requirements.txt --severity-threshold high
```

CI integration: `.github/workflows/ci.yml` — fails build on HIGH/CRITICAL CVEs.

**pip-audit vs Dependabot:**
- `pip-audit` — knows about **CVEs in your current pinned versions** (PyPI Advisory DB)
- Dependabot — alerts when **newer versions exist** (doesn't require a CVE)
- You need both: a pinned version can have a fresh CVE (pip-audit catches it); an unpinned version
  can be months behind security patches (Dependabot catches it).

---

## Security Testing (Phase 2)

### pytest
```bash
pytest tests/ -v
pytest tests/security/ -v          # Security-specific tests only
pytest tests/ --cov=app --cov-fail-under=70
```

### SQLMap (against live dev server)
```bash
# Login endpoint
sqlmap -u "http://localhost:5000/api/auth/login" \
  --data='{"email":"*","password":"test"}' \
  --content-type="application/json" \
  --level=5 --risk=3 --batch --dbms=postgresql

# Teacher grades — authenticated, query param
sqlmap -u "http://localhost:5000/api/teacher/grades?subject=*" \
  -H "Authorization: Bearer <teacher_token>" \
  --level=5 --risk=3 --batch --dbms=postgresql

# Admin audit-logs — authenticated, query params
sqlmap -u "http://localhost:5000/api/admin/audit-logs?action=*&actor_id=*" \
  -H "Authorization: Bearer <admin_token>" \
  --level=5 --risk=3 --batch --dbms=postgresql
```

### Burp Suite Test Cases
| Test | Endpoint | Expected |
|------|----------|----------|
| IDOR: Student A reads Student B's grades | `GET /api/student/grades?student_id=<B_id>` | 200 — but returns only Student A's grades (param ignored) |
| Role bypass: Teacher → admin endpoint | `POST /api/admin/users` with teacher token | 403 |
| JWT `alg:none` | `GET /api/auth/me` with unsigned token | 401 |
| JWT claim forgery (role: admin) | Any admin endpoint with forged student token | 401 (signature invalid) |
| Blocklisted token reuse | `/api/auth/refresh` with rotated token | 401 |

### OWASP ZAP
```bash
# Docker-based ZAP scan (CI)
docker run --rm ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py \
  -t http://localhost:5000 \
  -J zap-report.json \
  -r zap-report.html \
  -l WARN
```

---

## Production Checklist

- [ ] `SECRET_KEY` and `JWT_SECRET_KEY` — cryptographically random, minimum 32 bytes
- [ ] `FLASK_ENV=production`
- [ ] `DATABASE_URL` with `?sslmode=require`
- [ ] `REDIS_URL` — with `requirepass` set in Redis config
- [ ] `FORCE_HTTPS=1`
- [ ] `CORS_ORIGINS` — specific frontend URLs only (no `*`)
- [ ] Run `flask seed-roles` + `flask seed-admin`, then remove bootstrap vars from `.env`
- [ ] nginx with SSL termination + `X-Forwarded-For` passthrough
- [ ] gunicorn: `gunicorn -w 4 -b 127.0.0.1:8000 "run:app"`
- [ ] Revoke `DELETE` + `UPDATE` on `audit_logs` table from app DB user
- [ ] `pip-audit` + Dependabot enabled
- [ ] OWASP ZAP scan on staging before each release
