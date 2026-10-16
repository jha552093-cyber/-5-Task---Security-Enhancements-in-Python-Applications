"""
Input validation and sanitization module for MedSecure Application.

Security Best Practices Applied:
- CWE-20: Improper Input Validation - All inputs strictly validated against whitelist schemas.
- CWE-79: Cross-Site Scripting (XSS) - Context-aware HTML escaping and text sanitization.
- CWE-78: Command Injection - Hostnames/IP addresses validated via ipaddress/strict regex.
- CWE-22: Path Traversal - Filenames restricted to safe alphanumeric characters and extension whitelist.
"""

import re
import ipaddress
from typing import Tuple, Optional
from markupsafe import escape

# Allowed filename extensions
ALLOWED_EXTENSIONS = {".txt", ".pdf", ".csv", ".json"}

# Regex definitions
USERNAME_REGEX = re.compile(r"^[a-zA-Z0-9_-]{3,30}$")
EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")
SSN_REGEX = re.compile(r"^\d{3}-\d{2}-\d{4}$")
DATE_REGEX = re.compile(r"^\d{4}-\d{2}-\d{2}$")
HOSTNAME_REGEX = re.compile(r"^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}$")


def validate_username(username: str) -> bool:
    """Validates alphanumeric username of 3-30 characters."""
    if not isinstance(username, str):
        return False
    return bool(USERNAME_REGEX.match(username))


def validate_email(email: str) -> bool:
    """Validates email format."""
    if not isinstance(email, str) or len(email) > 254:
        return False
    return bool(EMAIL_REGEX.match(email))


def validate_password_strength(password: str) -> Tuple[bool, str]:
    """
    Enforces strong password policy:
    - Minimum 8 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one digit
    - At least one special character
    """
    if not isinstance(password, str):
        return False, "Password must be a valid string."
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if len(password) > 128:
        return False, "Password cannot exceed 128 characters."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r"\d", password):
        return False, "Password must contain at least one numerical digit."
    if not re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>/?]", password):
        return False, "Password must contain at least one special character."
    return True, "Password meets complexity requirements."


def validate_ssn(ssn: str) -> bool:
    """Validates SSN format: XXX-XX-XXXX."""
    if not isinstance(ssn, str):
        return False
    return bool(SSN_REGEX.match(ssn.strip()))


def validate_date(date_str: str) -> bool:
    """Validates ISO date format YYYY-MM-DD."""
    if not isinstance(date_str, str):
        return False
    return bool(DATE_REGEX.match(date_str.strip()))


def validate_credit_card(cc: str) -> bool:
    """
    Validates credit card format and verifies Luhn checksum.
    """
    if not isinstance(cc, str):
        return False
    digits = re.sub(r"[\s-]", "", cc)
    if not digits.isdigit() or not (13 <= len(digits) <= 19):
        return False

    # Luhn checksum algorithm
    total = 0
    reverse_digits = digits[::-1]
    for i, char in enumerate(reverse_digits):
        n = int(char)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return (total % 10 == 0)


def sanitize_html_text(text: str) -> str:
    """
    Neutralizes XSS by escaping HTML entities (&, <, >, ", ').
    Uses Markupsafe which is battle-tested in Jinja2.
    """
    if not isinstance(text, str):
        return ""
    return str(escape(text))


def sanitize_search_query(query: str, max_length: int = 100) -> str:
    """
    Sanitizes search query: removes control characters and limits length.
    """
    if not isinstance(query, str):
        return ""
    # Strip non-printable ASCII / control characters
    cleaned = "".join(ch for ch in query if ch.isprintable())
    return cleaned.strip()[:max_length]


def validate_safe_filename(filename: str) -> Tuple[bool, str]:
    """
    Validates and cleans filename to protect against path traversal (CWE-22).
    Disallows directory separators, relative traversals (..), and null bytes.
    Enforces extension whitelist.
    """
    if not isinstance(filename, str) or not filename.strip():
        return False, "Filename cannot be empty."

    # Reject path traversal attempts explicitly
    if "/" in filename or "\\" in filename or ".." in filename or "\x00" in filename:
        return False, "Path traversal sequence or forbidden characters detected."

    # Match safe characters: alphanumeric, dots, underscores, dashes
    if not re.match(r"^[a-zA-Z0-9_\-\.]+$", filename):
        return False, "Filename contains forbidden characters."

    # Check extension
    dot_index = filename.rfind(".")
    if dot_index == -1:
        return False, "Filename must include a valid file extension."

    ext = filename[dot_index:].lower()
    if ext not in ALLOWED_EXTENSIONS:
        return False, f"File extension '{ext}' is not permitted."

    return True, filename


def validate_host_for_diagnostics(host: str) -> Tuple[bool, str]:
    """
    Validates host for network ping diagnostics.
    Permits strictly valid IPv4, IPv6, or localhost.
    Rejects all shell metacharacters (;, &, |, `, $, etc.) to prevent Command Injection (CWE-78).
    """
    if not isinstance(host, str) or not host.strip():
        return False, "Host cannot be empty."

    cleaned_host = host.strip()

    # Reject known shell metacharacters immediately
    dangerous_chars = [";", "&", "|", "`", "$", "(", ")", "{", "}", "<", ">", "\n", "\r", " "]
    if any(char in cleaned_host for char in dangerous_chars):
        return False, "Host contains forbidden command injection characters."

    if cleaned_host.lower() == "localhost":
        return True, cleaned_host

    # Check if valid IP address
    try:
        ipaddress.ip_address(cleaned_host)
        return True, cleaned_host
    except ValueError:
        pass

    # Check if valid domain name
    if HOSTNAME_REGEX.match(cleaned_host):
        return True, cleaned_host

    return False, "Host must be a valid IP address or domain name."
