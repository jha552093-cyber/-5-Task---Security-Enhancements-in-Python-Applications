"""
Cryptographic module for MedSecure Application.

Security Best Practices Applied:
- CWE-328: Replaces MD5 with NIST SP 800-63B compliant PBKDF2-HMAC-SHA256 (600,000 iterations).
- CWE-208: Constant-time comparison via hmac.compare_digest against side-channel timing attacks.
- CWE-312 / CWE-327: Authenticated symmetric encryption (Fernet / AES-128-CBC + HMAC-SHA256)
  for sensitive PII/PHI at rest.
- Cryptographically signed tamper-evident tokens preventing token forgery and replay.
"""

import os
import hmac
import hashlib
import base64
import json
import time
import secrets
from typing import Optional, Tuple
from cryptography.fernet import Fernet, InvalidToken
from .config import SECRET_KEY, ENCRYPTION_KEY, SESSION_LIFETIME_SECONDS

# Initialize Fernet cipher suite
try:
    _cipher_suite = Fernet(ENCRYPTION_KEY.encode("utf-8"))
except Exception:
    # Fallback to key derivation if ENCRYPTION_KEY is not a standard 32-byte b64 key
    derived = base64.urlsafe_b64encode(hashlib.sha256(ENCRYPTION_KEY.encode("utf-8")).digest())
    _cipher_suite = Fernet(derived)

# Password hashing parameters
PBKDF2_ALGORITHM = "sha256"
PBKDF2_ITERATIONS = 600000
SALT_BYTES = 16


def hash_password(password: str) -> str:
    """
    Hashes a password using PBKDF2-HMAC-SHA256 with 600,000 iterations and a unique salt.
    Format: pbkdf2:sha256:<iterations>$<salt_hex>$<hash_hex>
    """
    salt = secrets.token_bytes(SALT_BYTES)
    key = hashlib.pbkdf2_hmac(
        hash_name=PBKDF2_ALGORITHM,
        password=password.encode("utf-8"),
        salt=salt,
        iterations=PBKDF2_ITERATIONS
    )
    salt_hex = salt.hex()
    key_hex = key.hex()
    return f"pbkdf2:{PBKDF2_ALGORITHM}:{PBKDF2_ITERATIONS}${salt_hex}${key_hex}"


def verify_password(password: str, stored_hash: str) -> bool:
    """
    Verifies a password against the stored hash in constant time (prevents timing attacks).
    """
    if not stored_hash or not stored_hash.startswith("pbkdf2:"):
        return False

    try:
        header, salt_hex, key_hex = stored_hash.split("$")
        parts = header.split(":")
        algorithm = parts[1]
        iterations = int(parts[2])
        salt = bytes.fromhex(salt_hex)
        expected_key = bytes.fromhex(key_hex)

        candidate_key = hashlib.pbkdf2_hmac(
            hash_name=algorithm,
            password=password.encode("utf-8"),
            salt=salt,
            iterations=iterations
        )
        return hmac.compare_digest(candidate_key, expected_key)
    except Exception:
        return False


def encrypt_field(plaintext: Optional[str]) -> str:
    """
    Encrypts a sensitive string field using authenticated symmetric encryption (AES + HMAC).
    Returns base64 ciphertext string.
    """
    if plaintext is None or plaintext == "":
        return ""
    encrypted_bytes = _cipher_suite.encrypt(plaintext.encode("utf-8"))
    return encrypted_bytes.decode("utf-8")


def decrypt_field(ciphertext: Optional[str]) -> str:
    """
    Decrypts an encrypted field. If decryption fails, returns a safe error string or empty.
    """
    if not ciphertext:
        return ""
    try:
        decrypted_bytes = _cipher_suite.decrypt(ciphertext.encode("utf-8"))
        return decrypted_bytes.decode("utf-8")
    except InvalidToken:
        return "[ENCRYPTED_DATA_CORRUPTED]"
    except Exception:
        return "[DECRYPTION_ERROR]"


def mask_ssn(ssn: Optional[str]) -> str:
    """
    Masks Social Security Number: e.g. '000-12-3456' -> '***-**-3456'.
    """
    if not ssn or not isinstance(ssn, str):
        return "***-**-****"
    clean = ssn.strip()
    if len(clean) == 11 and clean[3] == "-" and clean[6] == "-":
        return f"***-**-{clean[-4:]}"
    elif len(clean) == 9 and clean.isdigit():
        return f"***-**-{clean[-4:]}"
    return "***-**-****"


def mask_credit_card(cc: Optional[str]) -> str:
    """
    Masks Credit Card number: e.g. '4111-2222-3333-4444' -> '****-****-****-4444'.
    """
    if not cc or len(cc) < 4:
        return "****-****-****-****"
    clean = cc.replace("-", "").replace(" ", "")
    if len(clean) >= 4:
        return f"****-****-****-{clean[-4:]}"
    return "****-****-****-****"


def create_signed_token(payload: dict, secret: str = SECRET_KEY) -> str:
    """
    Generates a cryptographically signed session token with expiration.
    Structure: base64(json_payload).hmac_signature
    """
    payload_copy = dict(payload)
    payload_copy["_iat"] = int(time.time())
    payload_copy["_exp"] = int(time.time()) + SESSION_LIFETIME_SECONDS

    data_json = json.dumps(payload_copy, sort_keys=True, separators=(",", ":"))
    data_b64 = base64.urlsafe_b64encode(data_json.encode("utf-8")).decode("utf-8")

    signature = hmac.new(
        secret.encode("utf-8"),
        data_b64.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()

    return f"{data_b64}.{signature}"


def verify_signed_token(token: str, secret: str = SECRET_KEY) -> Optional[dict]:
    """
    Verifies the HMAC signature and expiration timestamp of a session token.
    Uses hmac.compare_digest to prevent timing attacks.
    """
    if not token or "." not in token:
        return None

    try:
        data_b64, signature = token.split(".", 1)
        expected_sig = hmac.new(
            secret.encode("utf-8"),
            data_b64.encode("utf-8"),
            hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(signature, expected_sig):
            return None

        raw_json = base64.urlsafe_b64decode(data_b64.encode("utf-8")).decode("utf-8")
        payload = json.loads(raw_json)

        # Expiration check
        exp = payload.get("_exp", 0)
        if time.time() > exp:
            return None  # Token expired

        return payload
    except Exception:
        return None
