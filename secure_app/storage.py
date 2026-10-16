"""
Secure Storage & Safe Export/Import module for MedSecure Application.

Security Best Practices Applied:
- CWE-22: Path Traversal defense using strict character whitelisting, basename validation,
  and canonical path boundary verification (commonpath check).
- CWE-502: Complete elimination of Python pickle. Uses safe JSON serialization with HMAC signature verification.
"""

import os
import json
import base64
import hmac
import hashlib
from typing import Tuple, Dict, Any, Optional
from .config import STORAGE_DIR, SECRET_KEY
from .validator import validate_safe_filename

# Ensure storage directory exists with safe sample file
os.makedirs(STORAGE_DIR, exist_ok=True)
_sample_file = os.path.join(STORAGE_DIR, "annual_report_2026.txt")
if not os.path.exists(_sample_file):
    with open(_sample_file, "w", encoding="utf-8") as f:
        f.write("MedSecure Hospital Annual Performance Report 2026.\nAll metrics within secure thresholds.")


def safe_read_report_file(filename: str) -> Tuple[bool, str]:
    """
    Safely reads a report file preventing Path Traversal (CWE-22).
    1. Validates filename against regex whitelist and allowed extensions.
    2. Resolves canonical real path.
    3. Asserts the canonical target path resides strictly inside STORAGE_DIR.
    """
    is_valid, err_or_name = validate_safe_filename(filename)
    if not is_valid:
        return False, f"Invalid filename: {err_or_name}"

    # Normalize storage directory base path
    base_dir_real = os.path.realpath(STORAGE_DIR)

    # Secure path combination
    target_path = os.path.join(base_dir_real, err_or_name)
    target_real = os.path.realpath(target_path)

    # Strict containment check
    try:
        common = os.path.commonpath([base_dir_real, target_real])
        if common != base_dir_real:
            return False, "Access denied: Path traversal outside designated storage directory."
    except ValueError:
        return False, "Access denied: Invalid path."

    if not os.path.isfile(target_real):
        return False, "Requested file does not exist."

    try:
        with open(target_real, "r", encoding="utf-8", errors="replace") as f:
            return True, f.read()
    except Exception as e:
        return False, "An error occurred while reading the requested file."


def export_backup_secure(data: Dict[str, Any]) -> str:
    """
    Safely serializes application state into JSON with HMAC-SHA256 integrity signature.
    Completely eliminates CWE-502 (Insecure Deserialization).
    Structure: base64(json_payload).hmac_signature
    """
    serialized_json = json.dumps(data, sort_keys=True, separators=(",", ":"))
    payload_b64 = base64.urlsafe_b64encode(serialized_json.encode("utf-8")).decode("utf-8")

    signature = hmac.new(
        SECRET_KEY.encode("utf-8"),
        payload_b64.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()

    return f"{payload_b64}.{signature}"


def import_backup_secure(signed_payload: str) -> Tuple[bool, Any]:
    """
    Safely imports and verifies backup data:
    1. Validates signature format.
    2. Verifies HMAC-SHA256 signature in constant time.
    3. Deserializes only using standard json.loads with schema validation.
    """
    if not signed_payload or "." not in signed_payload:
        return False, "Invalid backup format: Missing cryptographic signature."

    try:
        payload_b64, signature = signed_payload.split(".", 1)
        expected_sig = hmac.new(
            SECRET_KEY.encode("utf-8"),
            payload_b64.encode("utf-8"),
            hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(signature, expected_sig):
            return False, "Integrity check failed: Backup has been tampered with or signature is invalid."

        raw_json = base64.urlsafe_b64decode(payload_b64.encode("utf-8")).decode("utf-8")
        data = json.loads(raw_json)

        # Basic schema verification
        if not isinstance(data, dict):
            return False, "Invalid payload: Root must be a JSON object."

        return True, data
    except Exception as e:
        return False, "Failed to decode backup package."
