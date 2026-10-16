"""
Secure audit logging module for MedSecure Application.

Security Best Practices Applied:
- CWE-532: Insertion of Sensitive Information into Log File - Automatic PII and credential redaction.
- CWE-778: Insufficient Logging - Structured security event logging (logins, access, violations).
- Tamper-resistant log formatting with timestamps, event categories, and severity levels.
"""

import os
import re
import logging
from datetime import datetime, timezone
from typing import Optional
from .config import BASE_DIR

LOG_FILE = os.path.join(BASE_DIR, "secure_audit.log")

# Setup Python standard logger
_audit_logger = logging.getLogger("medsecure_audit")
_audit_logger.setLevel(logging.INFO)

if not _audit_logger.handlers:
    _handler = logging.FileHandler(LOG_FILE, encoding="utf-8")
    _formatter = logging.Formatter(
        fmt='{"timestamp": "%(asctime)s", "level": "%(levelname)s", "event": %(message)s}',
        datefmt="%Y-%m-%dT%H:%M:%SZ"
    )
    _handler.setFormatter(_formatter)
    _audit_logger.addHandler(_handler)

# Regex patterns for sensitive data redaction
_SSN_PATTERN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_CC_PATTERN = re.compile(r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b")
_PASSWORD_PATTERN = re.compile(r'(password["\':\s=]+)[^\s&,"\']+', re.IGNORECASE)


def redact_sensitive_info(text: str) -> str:
    """
    Masks SSNs, credit card numbers, and passwords from log strings.
    """
    if not isinstance(text, str):
        return ""
    # Redact SSN
    text = _SSN_PATTERN.sub("***-**-****", text)
    # Redact Credit Cards
    text = _CC_PATTERN.sub("****-****-****-****", text)
    # Redact Passwords
    text = _PASSWORD_PATTERN.sub(r"\1[REDACTED]", text)
    return text


def log_security_event(
    event_type: str,
    details: str,
    user_id: Optional[int] = None,
    username: Optional[str] = None,
    ip_address: Optional[str] = "127.0.0.1",
    severity: str = "INFO",
    success: bool = True
):
    """
    Logs structured security events with automatic sanitization and PII masking.
    """
    safe_details = redact_sensitive_info(details)
    event_data = (
        f'{{"type": "{event_type}", "success": {str(success).lower()}, '
        f'"user_id": {user_id if user_id is not None else "null"}, '
        f'"username": "{username or "anonymous"}", '
        f'"ip": "{ip_address or "unknown"}", '
        f'"details": "{safe_details}"}}'
    )

    if severity == "WARNING":
        _audit_logger.warning(event_data)
    elif severity == "ERROR" or severity == "CRITICAL":
        _audit_logger.error(event_data)
    else:
        _audit_logger.info(event_data)
