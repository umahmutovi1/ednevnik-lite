"""
run.py — Application Entry Point
==================================
Development server entry point.

PRODUCTION NOTE:
  Never use 'flask run' or this script in production.
  Use a production WSGI server instead:
    gunicorn -w 4 -b 0.0.0.0:8000 "run:app"
    uwsgi --http 0.0.0.0:8000 --module run:app

  Behind an nginx reverse proxy configured with:
    - SSL termination (certificates via Let's Encrypt)
    - X-Forwarded-For / X-Real-IP passthrough for Flask-Limiter IP detection
    - Connection limits and upstream timeouts
"""

import os

from dotenv import load_dotenv

# Load .env before importing the app — secrets must be available at import time
load_dotenv()

from app import create_app

app = create_app(os.environ.get("FLASK_ENV", "development"))

if __name__ == "__main__":
    # Debug mode off by default even here — config controls it
    # Host 127.0.0.1 (not 0.0.0.0) in dev — don't expose to LAN by default
    app.run(
        host="127.0.0.1",
        port=int(os.environ.get("PORT", 5000)),
        debug=app.config.get("DEBUG", False),
    )
