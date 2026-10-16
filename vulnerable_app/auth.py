"""
Authentication and session management module for Baseline Vulnerable Application.

VULNERABILITIES DEMONSTRATED:
- CWE-384 / CWE-287: Predictable, forgeable session tokens (base64 encoded JSON without HMAC signature).
- CWE-307: Absence of brute-force mitigation or account lockout mechanism.
- CWE-284 / CWE-639: Broken Access Control (Insecure Direct Object Reference - IDOR).
"""

import base64
import json
from typing import Optional, Dict

# In-memory session table mapping token -> session dict
SESSIONS: Dict[str, dict] = {}


def generate_vulnerable_session_token(user_id: int, username: str, role: str) -> str:
    """
    VULNERABLE: Session token is merely a base64 encoded JSON string.
    An attacker can forge any user token (e.g., admin) simply by crafting a base64 string.
    """
    payload = {
        "user_id": user_id,
        "username": username,
        "role": role
    }
    raw = json.dumps(payload)
    token = base64.b64encode(raw.encode("utf-8")).decode("utf-8")
    SESSIONS[token] = payload
    return token


def parse_vulnerable_session_token(token: str) -> Optional[dict]:
    """
    VULNERABLE: Directly decodes user-supplied token without cryptographic signature verification.
    """
    if not token:
        return None
    try:
        raw = base64.b64decode(token.encode("utf-8")).decode("utf-8")
        session_data = json.loads(raw)
        return session_data
    except Exception:
        return None


def check_access_vulnerable(session: Optional[dict], required_role: Optional[str] = None) -> bool:
    """
    VULNERABLE: Incomplete access control checks; allows missing or forged sessions.
    """
    if not session:
        return False
    if required_role and session.get("role") != required_role:
        return False
    return True
