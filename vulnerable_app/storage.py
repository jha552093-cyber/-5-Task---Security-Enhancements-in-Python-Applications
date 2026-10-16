"""
File storage and export/import module for the Baseline Vulnerable Application.

VULNERABILITIES DEMONSTRATED:
- CWE-22: Path Traversal in report downloads and file retrieval.
- CWE-502: Insecure Deserialization via Python's pickle module.
"""

import os
import pickle
import base64

STORAGE_DIR = os.path.join(os.path.dirname(__file__), "reports_storage")
os.makedirs(STORAGE_DIR, exist_ok=True)

# Create a sample benign file in storage
with open(os.path.join(STORAGE_DIR, "annual_report_2026.txt"), "w") as f:
    f.write("MedSecure Hospital Annual Performance Report 2026.\nAll metrics normal.")


def read_report_file_vulnerable(filename: str) -> str:
    """
    VULNERABLE: Direct concatenation of user-supplied filename without path canonicalization.
    Vulnerable to Directory Traversal (CWE-22).
    Payload: "../../vulnerable_portal.db" or "../../../Windows/win.ini"
    """
    # Flawed: os.path.join accepts absolute paths or relative traversals
    target_path = os.path.join(STORAGE_DIR, filename)
    with open(target_path, "r", errors="ignore") as f:
        return f.read()


def export_backup_vulnerable(data: dict) -> str:
    """
    VULNERABLE: Serializes application state using pickle.
    """
    pickled = pickle.dumps(data)
    return base64.b64encode(pickled).decode("utf-8")


def import_backup_vulnerable(serialized_data_b64: str) -> dict:
    """
    VULNERABLE: Insecure deserialization using pickle.loads (CWE-502).
    Any payload with __reduce__() will execute arbitrary operating system commands.
    """
    raw_bytes = base64.b64decode(serialized_data_b64.encode("utf-8"))
    # Highly dangerous: executes arbitrary Python bytecode/functions
    return pickle.loads(raw_bytes)
