## Sesija 1 — Datum: 5. april 2026.

### Prompt #1: Inicijalna arhitektura

**Šta sam tražila:** Početna struktura projekta sa sigurnosnim kontrolama

**Šta je Claude generisao:**
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

**Šta je ispravno implementirano:**

**Šta sam morala ručno ispraviti:**


**Sigurnosne napomene:**
- [tvoja zapažanja]
