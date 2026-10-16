"""
Authentication, Authorization, and Rate Limiting for MedSecure Application.

Security Best Practices Applied:
- CWE-307: Protection against Brute Force Attacks - Account lockout policy.
- CWE-384 / CWE-287: Cryptographically signed tamper-evident session tokens.
- CWE-284 / CWE-639: Role-Based Access Control (RBAC) and object ownership validation (prevents IDOR).
- Constant-time password validation.
"""

import time
from typing import Optional, Tuple, Dict, Any
from .config import MAX_FAILED_LOGIN_ATTEMPTS, LOCKOUT_DURATION_SECONDS
from .crypto import verify_password, create_signed_token, verify_signed_token
from .database import (
    get_user_by_username,
    get_user_by_id,
    update_user_failed_attempts,
    reset_user_failed_attempts
)
from .logger import log_security_event


def authenticate_user(username: str, password_raw: str, ip_address: str = "127.0.0.1") -> Tuple[bool, Optional[str], Optional[dict]]:
    """
    Authenticates a user with brute-force defense, lockout enforcement, and PBKDF2 hashing.
    Returns: (success: bool, message: Optional[str], user_dict: Optional[dict])
    """
    if not username or not password_raw:
        return False, "Username and password are required.", None

    user = get_user_by_username(username)
    if not user:
        # Avoid user enumeration by returning generic failure message
        log_security_event("LOGIN_FAILURE", f"Non-existent username: {username}", ip_address=ip_address, success=False, severity="WARNING")
        return False, "Invalid username or password.", None

    user_id = user["id"]
    current_time = time.time()

    # Check account lockout
    if user["locked_until"] and user["locked_until"] > current_time:
        remaining = int(user["locked_until"] - current_time)
        log_security_event("LOGIN_LOCKED", f"Account locked: {username}", user_id=user_id, username=username, ip_address=ip_address, success=False, severity="WARNING")
        return False, f"Account is temporarily locked due to multiple failed attempts. Try again in {remaining} seconds.", None

    # Verify password with constant-time comparison
    is_valid = verify_password(password_raw, user["password_hash"])
    if is_valid:
        # Reset failed attempts
        reset_user_failed_attempts(user_id)
        token = create_signed_token({
            "user_id": user_id,
            "username": user["username"],
            "role": user["role"],
            "email": user["email"]
        })
        log_security_event("LOGIN_SUCCESS", f"User {username} authenticated successfully", user_id=user_id, username=username, ip_address=ip_address, success=True)
        return True, "Login successful.", {
            "id": user["id"],
            "username": user["username"],
            "role": user["role"],
            "email": user["email"],
            "token": token
        }
    else:
        # Increment failed attempts
        new_attempts = user["failed_attempts"] + 1
        locked_until = 0.0
        if new_attempts >= MAX_FAILED_LOGIN_ATTEMPTS:
            locked_until = current_time + LOCKOUT_DURATION_SECONDS
            update_user_failed_attempts(user_id, new_attempts, locked_until)
            log_security_event("ACCOUNT_LOCKED", f"Account {username} locked after {new_attempts} failed attempts", user_id=user_id, username=username, ip_address=ip_address, success=False, severity="CRITICAL")
            return False, f"Account locked for {LOCKOUT_DURATION_SECONDS // 60} minutes due to excessive failed attempts.", None
        else:
            update_user_failed_attempts(user_id, new_attempts, 0.0)
            log_security_event("LOGIN_FAILURE", f"Invalid password for {username} (Attempt {new_attempts})", user_id=user_id, username=username, ip_address=ip_address, success=False, severity="WARNING")
            return False, "Invalid username or password.", None


def get_authenticated_session(token: Optional[str]) -> Optional[dict]:
    """
    Validates token signature and expiration.
    """
    if not token:
        return None
    return verify_signed_token(token)


def check_record_authorization(current_user: dict, record_created_by: int) -> bool:
    """
    Prevents IDOR (CWE-639 / CWE-284).
    Doctors, Nurses, and Admins can view records.
    Patients can ONLY view records created for/by them.
    """
    role = current_user.get("role", "")
    user_id = current_user.get("user_id")

    if role in ["admin", "doctor", "nurse"]:
        return True

    # Patient ownership check
    if role == "patient" and user_id == record_created_by:
        return True

    return False
