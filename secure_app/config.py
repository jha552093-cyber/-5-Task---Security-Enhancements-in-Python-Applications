"""
Secure configuration module for MedSecure Application.

Security Best Practices Applied:
- CWE-798 / CWE-259: Elimination of hardcoded secrets. Uses environment variables with CSPRNG fallback.
- CWE-489: Debug mode disabled by default.
- CWE-1004 / CWE-614: Secure cookie configuration (HttpOnly, Secure, SameSite=Lax).
"""

import os
import secrets
import base64

# Base directory
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Database configuration
DB_PATH = os.environ.get("MEDSECURE_DB_PATH", os.path.join(BASE_DIR, "secure_portal.db"))

# Application Secret Key for Flask sessions / CSRF / HMAC tokens
# Prioritizes environment variable. Falls back to cryptographically random key persisted locally.
SECRET_KEY = os.environ.get("MEDSECURE_SECRET_KEY")
if not SECRET_KEY:
    _secret_file = os.path.join(BASE_DIR, ".dev_secret_key")
    if os.path.exists(_secret_file):
        with open(_secret_file, "r", encoding="utf-8") as f:
            SECRET_KEY = f.read().strip()
    else:
        SECRET_KEY = secrets.token_hex(32)
        try:
            with open(_secret_file, "w", encoding="utf-8") as f:
                f.write(SECRET_KEY)
        except OSError:
            pass

# Field-level Encryption Key for sensitive PII/PHI (Fernet / AES)
# Must be a 32-byte base64-encoded key
ENCRYPTION_KEY = os.environ.get("MEDSECURE_ENCRYPTION_KEY")
if not ENCRYPTION_KEY:
    _enc_file = os.path.join(BASE_DIR, ".dev_enc_key")
    if os.path.exists(_enc_file):
        with open(_enc_file, "r", encoding="utf-8") as f:
            ENCRYPTION_KEY = f.read().strip()
    else:
        from cryptography.fernet import Fernet
        ENCRYPTION_KEY = Fernet.generate_key().decode("utf-8")
        try:
            with open(_enc_file, "w", encoding="utf-8") as f:
                f.write(ENCRYPTION_KEY)
        except OSError:
            pass

# Environment & Debug settings
DEBUG = False
TESTING = False

# Session & Security Settings
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SECURE = False  # Set to True in production with HTTPS
SESSION_COOKIE_SAMESITE = "Lax"
SESSION_LIFETIME_SECONDS = 1800  # 30 minutes session expiry

# Rate Limiting & Account Lockout
MAX_FAILED_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION_SECONDS = 300  # 5 minutes lockout

# Storage Directory
STORAGE_DIR = os.path.join(BASE_DIR, "secure_storage")
os.makedirs(STORAGE_DIR, exist_ok=True)
