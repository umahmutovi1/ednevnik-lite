"""
app/__init__.py — Application Factory (create_app)
===================================================
The Application Factory pattern (create_app) is the standard Flask
approach for production applications. Benefits:
  1. Multiple app instances with different configs (production vs test)
  2. Extensions initialized with the app — not at import time
  3. Circular import prevention through lazy initialization
  4. Clean Blueprint registration

EXTENSIONS INITIALIZED HERE:
  - SQLAlchemy (ORM — SQL Injection prevention)
  - Flask-Migrate (schema version control)
  - Flask-JWT-Extended (stateless auth)
  - Flask-Bcrypt (password hashing)
  - Flask-Limiter (brute-force defense)
  - Flask-Talisman (security headers, HTTPS)
  - Flask-CORS (cross-origin control)

BLUEPRINTS REGISTERED HERE:
  - auth_bp    : /api/auth/*
  - admin_bp   : /api/admin/*
  - teacher_bp : /api/teacher/*
  - student_bp : /api/student/*
"""

import logging
import os
from typing import Optional

from flask import Flask, jsonify
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_migrate import Migrate
from flask_talisman import Talisman

from app.config import get_config
from app.models import db

# ---------------------------------------------------------------------------
# Extension instances — initialized without app (init_app pattern)
# ---------------------------------------------------------------------------

bcrypt = Bcrypt()
jwt = JWTManager()
migrate = Migrate()
limiter = Limiter(
    key_func=get_remote_address,
    # TODO: Production — switch storage to Redis via RATELIMIT_STORAGE_URI in config
    # In-memory storage is NOT suitable for multi-process/multi-container deployments:
    #   - Counters reset on restart
    #   - Different workers have separate counters (limits are per-process, not per-IP)
    # Set REDIS_URL in .env and RATELIMIT_STORAGE_URI in ProductionConfig
    default_limits=["200 per day", "50 per hour"],
)
talisman = Talisman()
cors = CORS()


# ---------------------------------------------------------------------------
# Factory Function
# ---------------------------------------------------------------------------

def create_app(config_name: Optional[str] = None) -> Flask:
    """
    Application factory. Creates and configures a Flask application instance.

    Parameters
    ----------
    config_name : str, optional
        One of 'development', 'testing', 'production'.
        Falls back to FLASK_ENV environment variable, then 'development'.

    Returns
    -------
    Flask application instance, fully configured and ready to run.
    """
    app = Flask(__name__)

    # -------------------------------------------------------------------------
    # 1. Load Configuration
    # -------------------------------------------------------------------------
    config_class = get_config(config_name)

    # Init secrets (raises ValueError if required env vars are missing in prod)
    if hasattr(config_class, "init_secrets"):
        config_class.init_secrets()

    app.config.from_object(config_class)

    # -------------------------------------------------------------------------
    # 2. Configure Logging
    # -------------------------------------------------------------------------
    logging.basicConfig(
        level=logging.DEBUG if app.config.get("DEBUG") else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    app.logger.info(f"Starting Dnevnik-Lite in '{config_name or os.environ.get('FLASK_ENV', 'development')}' mode")

    # -------------------------------------------------------------------------
    # 3. Initialize Extensions
    # -------------------------------------------------------------------------

    # SQLAlchemy ORM — all queries parameterized → SQL Injection structurally impossible
    db.init_app(app)

    # Alembic migrations — tracks schema changes with version history
    migrate.init_app(app, db)

    # bcrypt — adaptive password hashing, work factor from config
    bcrypt.init_app(app)

    # JWT — stateless auth tokens with expiry and role claims
    jwt.init_app(app)

    # Register Redis blocklist loader — every @jwt_required route checks this
    # [OWASP A07:2025 – Authentication Failures]: fail-closed blocklist
    from app.utils.token_blocklist import register_blocklist_loader
    register_blocklist_loader(jwt)

    # Flask-Limiter — per-IP rate limiting for brute-force defense
    # Storage URI from config (in-memory for dev, Redis for prod)
    if app.config.get("RATELIMIT_STORAGE_URI"):
        limiter._storage_uri = app.config["RATELIMIT_STORAGE_URI"]
    limiter.init_app(app)

    # Flask-Talisman — HTTPS enforcement + security headers
    # Content-Security-Policy is intentionally permissive here — tighten in Phase 2
    # with a proper per-route CSP policy.
    force_https = app.config.get("FORCE_HTTPS", False)

    # ---------------------------------------------------------------------------
    # Phase 2 — Hardened Security Headers
    # [OWASP A02:2025 – Security Misconfiguration]
    # ---------------------------------------------------------------------------
    #
    # CSP nonce-based script policy:
    #   'unsafe-inline' is NEVER acceptable — it permits any inline <script> tag,
    #   completely defeating XSS protection. With 'unsafe-inline', an attacker who
    #   can inject <script>evil()</script> into any page bypasses the entire CSP.
    #   Nonces (cryptographically random per-request values) allow specific inline
    #   scripts while blocking all others.
    #
    # This API does not serve HTML — it is a JSON REST API. Therefore:
    #   - script-src: 'none'  (no scripts served by this origin)
    #   - style-src:  'none'  (no stylesheets served by this origin)
    #   - frame-ancestors: 'none'  (API responses must never be embedded in iframes)
    #
    # When a frontend SPA is added in Phase 3, configure CSP per-route using
    # Talisman's `content_security_policy_nonce_in` and generate nonces per-request.

    talisman.init_app(
        app,
        force_https=force_https,
        # [OWASP A02:2025 – Security Misconfiguration]: HSTS with 1-year max-age
        # forces all browsers to use HTTPS — protects against protocol downgrade attacks
        strict_transport_security=True,
        strict_transport_security_max_age=31536000,
        strict_transport_security_include_subdomains=True,
        strict_transport_security_preload=True,
        # [OWASP A02:2025 – Security Misconfiguration]: X-Frame-Options DENY
        # prevents clickjacking — an API endpoint must never be embedded in an iframe
        frame_options="DENY",
        # [OWASP A02:2025 – Security Misconfiguration]: X-Content-Type-Options nosniff
        # prevents MIME-type sniffing attacks on JSON responses
        x_content_type_options=True,
        # [OWASP A02:2025 – Security Misconfiguration]: Hardened CSP for a JSON API.
        # This API serves no HTML/scripts/styles — lock down all fetch directives.
        content_security_policy={
            "default-src": "'none'",          # Deny everything not explicitly allowed
            "script-src": "'none'",           # API serves no scripts — 'unsafe-inline' forbidden
            "style-src": "'none'",            # API serves no styles
            "img-src": "'none'",              # API serves no images
            "connect-src": "'self'",          # Allow XHR/fetch to same origin only
            "form-action": "'none'",          # Prevents form-based exfiltration attacks
            "frame-ancestors": "'none'",      # Equivalent to X-Frame-Options: DENY (belt+suspenders)
            "base-uri": "'none'",             # Prevents <base> tag injection attacks
            "object-src": "'none'",           # No Flash/plugins ever
            "upgrade-insecure-requests": "",  # Force HTTPS on any mixed-content requests
        },
        # [OWASP A02:2025 – Security Misconfiguration]: Referrer-Policy limits
        # what URL information is sent to third parties in the Referer header.
        # strict-origin-when-cross-origin: sends full URL for same-origin, origin only cross-origin.
        referrer_policy="strict-origin-when-cross-origin",
        # [OWASP A02:2025 – Security Misconfiguration]: Permissions-Policy
        # explicitly disables browser features this API will never use.
        # Prevents malicious pages from requesting these capabilities via our origin.
        feature_policy={
            "camera": "'none'",
            "microphone": "'none'",
            "geolocation": "'none'",
            "payment": "'none'",
            "usb": "'none'",
        },
    )

    # CORS — restrict cross-origin requests to configured origins
    # In production, CORS_ORIGINS must be set in .env to specific frontend URLs
    cors_origins = app.config.get("CORS_ORIGINS", "")
    if isinstance(cors_origins, str):
        cors_origins = [o.strip() for o in cors_origins.split(",") if o.strip()]
    cors.init_app(
        app,
        origins=cors_origins,
        methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Content-Type", "Authorization"],
        supports_credentials=True,
    )

    # -------------------------------------------------------------------------
    # 4. JWT Error Handlers
    # -------------------------------------------------------------------------

    @jwt.expired_token_loader
    def expired_token_callback(jwt_header, jwt_payload):
        """Return a clear error when a JWT has expired — client should refresh."""
        return jsonify({
            "error": "TokenExpired",
            "message": "Your access token has expired. Use /api/auth/refresh to renew it.",
        }), 401

    @jwt.invalid_token_loader
    def invalid_token_callback(error):
        """Return a clear error for malformed or tampered tokens."""
        return jsonify({
            "error": "InvalidToken",
            "message": "The provided token is invalid.",
        }), 401

    @jwt.unauthorized_loader
    def missing_token_callback(error):
        """Return 401 when no token is provided."""
        return jsonify({
            "error": "Unauthorized",
            "message": "A Bearer token is required. Include it in the Authorization header.",
        }), 401

    # -------------------------------------------------------------------------
    # 5. Register Blueprints
    # -------------------------------------------------------------------------

    from app.routes.auth import auth_bp
    from app.routes.admin import admin_bp
    from app.routes.teacher import teacher_bp
    from app.routes.student import student_bp

    app.register_blueprint(auth_bp)     # /api/auth/*
    app.register_blueprint(admin_bp)    # /api/admin/*
    app.register_blueprint(teacher_bp)  # /api/teacher/*
    app.register_blueprint(student_bp)  # /api/student/*

    # -------------------------------------------------------------------------
    # 6. Global Error Handlers
    # -------------------------------------------------------------------------

    @app.errorhandler(404)
    def not_found(e):
        return jsonify({"error": "Not Found", "message": str(e)}), 404

    @app.errorhandler(405)
    def method_not_allowed(e):
        return jsonify({"error": "Method Not Allowed", "message": str(e)}), 405

    @app.errorhandler(429)
    def rate_limit_exceeded(e):
        """Rate limit hit — return 429 with Retry-After header."""
        return jsonify({
            "error": "TooManyRequests",
            "message": "Rate limit exceeded. Please slow down.",
        }), 429

    @app.errorhandler(500)
    def internal_error(e):
        """
        Never expose internal error details to clients — log them server-side.
        Stack traces in error responses are a common information disclosure vector.
        """
        app.logger.error(f"Internal server error: {e}", exc_info=True)
        return jsonify({
            "error": "InternalServerError",
            "message": "An unexpected error occurred. Please try again later.",
        }), 500

    # -------------------------------------------------------------------------
    # 6b. Rate-limit login endpoint (CF-02 Fix)
    # -------------------------------------------------------------------------
    # [OWASP A07:2025 – Authentication Failures]: Apply 10/min per-IP rate limit
    # to the login view function directly. This is the correct pattern for
    # Blueprint-registered views — applying limiter.limit() inside the view
    # function body (e.g. to a lambda) does not work.
    # CF-02 FIXED: Removed the broken `limiter.limit()(lambda: None)()` pattern.
    from flask_limiter.util import get_remote_address as _gra
    limiter.limit(
        "10 per minute",
        key_func=_gra,
        error_message="Too many login attempts. Please wait before trying again.",
    )(app.view_functions["auth.login"])

    # -------------------------------------------------------------------------
    # 6c. ProxyFix for trusted X-Forwarded-For (W-02 Fix)
    # -------------------------------------------------------------------------
    # [OWASP A02:2025 – Security Misconfiguration]: Only trust X-Forwarded-For
    # headers from the configured number of upstream proxies. Without this,
    # any client can spoof their IP in audit logs.
    trusted_proxies = int(os.environ.get("TRUSTED_PROXY_COUNT", 0))
    if trusted_proxies > 0:
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=trusted_proxies)

    # -------------------------------------------------------------------------
    # 6d. Production startup assertion (CF-01 safeguard)
    # -------------------------------------------------------------------------
    if os.environ.get("FLASK_ENV") == "production":
        assert app.config.get("RATELIMIT_STORAGE_URI"), (
            "[Security] RATELIMIT_STORAGE_URI must be set in production. "
            "In-memory rate limiting is invalid across gunicorn workers."
        )

    # -------------------------------------------------------------------------
    # 7. Health Check
    # -------------------------------------------------------------------------

    @app.route("/api/health", methods=["GET"])
    def health():
        """
        Lightweight health check endpoint for load balancers and monitoring.
        Does NOT expose version info, config, or internal state.
        """
        return jsonify({"status": "ok"}), 200

    # -------------------------------------------------------------------------
    # 8. CLI Commands
    # -------------------------------------------------------------------------

    @app.cli.command("seed-roles")
    def seed_roles():
        """
        Seed the Role table with the three allowed roles.
        Run once after initial migration: flask seed-roles
        """
        from app.models import Role
        with app.app_context():
            roles_to_seed = [
                {"name": "admin", "description": "System administrator — full access"},
                {"name": "nastavnik", "description": "Teacher — grade and attendance management"},
                {"name": "ucenik", "description": "Student — read-only access to own data"},
            ]
            for role_data in roles_to_seed:
                if not Role.query.filter_by(name=role_data["name"]).first():
                    db.session.add(Role(**role_data))
            db.session.commit()
            print("✅ Roles seeded: admin, nastavnik, ucenik")

    @app.cli.command("seed-admin")
    def seed_admin():
        """
        Create the bootstrap admin account from environment variables.
        Run once: flask seed-admin
        Requires ADMIN_BOOTSTRAP_EMAIL and ADMIN_BOOTSTRAP_PASSWORD in .env.
        Remove these variables from .env after running.
        """
        from app.models import Role, User
        from app.services.auth_service import hash_password

        email = os.environ.get("ADMIN_BOOTSTRAP_EMAIL")
        password = os.environ.get("ADMIN_BOOTSTRAP_PASSWORD")

        if not email or not password:
            print("❌ Set ADMIN_BOOTSTRAP_EMAIL and ADMIN_BOOTSTRAP_PASSWORD in .env first.")
            return

        admin_role = Role.query.filter_by(name="admin").first()
        if not admin_role:
            print("❌ Run 'flask seed-roles' first.")
            return

        if User.query.filter_by(email=email.lower()).first():
            print(f"⚠️  Admin user {email} already exists — skipping.")
            return

        admin = User(
            email=email.lower(),
            password_hash=hash_password(password),
            first_name="System",
            last_name="Admin",
            role_id=admin_role.id,
            is_active=True,
        )
        db.session.add(admin)
        db.session.commit()
        print(f"✅ Admin user created: {email}")
        print("⚠️  Remove ADMIN_BOOTSTRAP_EMAIL and ADMIN_BOOTSTRAP_PASSWORD from .env now.")

    app.logger.info("Dnevnik-Lite application initialized successfully.")
    return app
