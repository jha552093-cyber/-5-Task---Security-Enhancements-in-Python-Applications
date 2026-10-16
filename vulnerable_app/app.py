"""
Flask Web Application & REST API - Baseline Vulnerable Application.

VULNERABILITIES DEMONSTRATED:
- CWE-89: SQL Injection in authentication and patient search
- CWE-79: Cross-Site Scripting (XSS) in HTML rendering
- CWE-78: OS Command Injection in network diagnostics
- CWE-22: Path Traversal in document retrieval
- CWE-502: Insecure Deserialization via pickle in backup restore
- CWE-639: Insecure Direct Object Reference (IDOR) in patient records
- CWE-209: Detailed error messages disclosing internal stack traces
- CWE-259 / CWE-798: Hardcoded secret keys
- CWE-1004 / CWE-693: Missing HTTP security headers and unhardened cookies
"""

import os
import subprocess
from flask import Flask, request, jsonify, make_response
from .database import (
    init_db,
    query_user_vulnerable,
    search_patients_vulnerable,
    get_patient_by_id_vulnerable,
    add_patient_vulnerable
)
from .storage import (
    read_report_file_vulnerable,
    export_backup_vulnerable,
    import_backup_vulnerable
)
from .auth import (
    generate_vulnerable_session_token,
    parse_vulnerable_session_token
)

app = Flask(__name__)
# VULNERABLE: Hardcoded weak secret key (CWE-798)
app.secret_key = "super_insecure_hardcoded_key_12345"
# VULNERABLE: Debug mode explicitly enabled (CWE-489)
app.config["DEBUG"] = True


@app.before_request
def initialize_app_database():
    """Ensure DB exists."""
    init_db()


@app.route("/api/login", methods=["POST"])
def login_endpoint():
    """
    VULNERABLE: Susceptible to SQL injection authentication bypass.
    """
    data = request.get_json(force=True, silent=True) or request.form
    username = data.get("username", "")
    password = data.get("password", "")

    # Executes raw SQL concatenation query
    user = query_user_vulnerable(username, password)
    if user:
        token = generate_vulnerable_session_token(user["id"], user["username"], user["role"])
        resp = make_response(jsonify({
            "status": "success",
            "message": f"Welcome back, {user['username']}!",
            "token": token,
            "user": {
                "id": user["id"],
                "username": user["username"],
                "role": user["role"],
                "email": user["email"]
            }
        }))
        # Insecure cookie: Missing HttpOnly, Secure, and SameSite flags
        resp.set_cookie("session_token", token)
        return resp
    else:
        return jsonify({"status": "error", "message": "Invalid username or password"}), 401


@app.route("/api/search", methods=["GET"])
def search_endpoint():
    """
    VULNERABLE: Susceptible to SQL injection in patient search.
    """
    query = request.args.get("q", "")
    records = search_patients_vulnerable(query)
    results = []
    for r in records:
        # Sensitive data leaked in cleartext without masking
        results.append({
            "id": r["id"],
            "patient_name": r["patient_name"],
            "ssn": r["ssn"],
            "date_of_birth": r["date_of_birth"],
            "diagnosis": r["diagnosis"],
            "credit_card": r["credit_card"],
            "doctor_notes": r["doctor_notes"]
        })
    return jsonify({"status": "success", "count": len(results), "data": results})


@app.route("/api/records/<record_id>", methods=["GET"])
def get_record_endpoint(record_id):
    """
    VULNERABLE: IDOR (CWE-639) - no check to see if current user owns or is authorized to view this record.
    Also vulnerable to SQL injection through record_id string parameter.
    """
    record = get_patient_by_id_vulnerable(record_id)
    if not record:
        return jsonify({"status": "error", "message": "Record not found"}), 404

    return jsonify({
        "status": "success",
        "record": {
            "id": record["id"],
            "patient_name": record["patient_name"],
            "ssn": record["ssn"],
            "date_of_birth": record["date_of_birth"],
            "diagnosis": record["diagnosis"],
            "credit_card": record["credit_card"],
            "doctor_notes": record["doctor_notes"]
        }
    })


@app.route("/api/notes/render", methods=["POST"])
def render_note_endpoint():
    """
    VULNERABLE: Cross-Site Scripting (XSS) (CWE-79).
    Directly concatenates unescaped user HTML input.
    """
    data = request.get_json(force=True, silent=True) or request.form
    note = data.get("note", "")
    patient_name = data.get("patient_name", "Anonymous")

    # Raw HTML injection vulnerability
    html_response = f"""
    <div class="patient-note-card">
        <h3>Clinical Note for: {patient_name}</h3>
        <div class="content">{note}</div>
    </div>
    """
    return html_response, 200, {"Content-Type": "text/html"}


@app.route("/api/diagnostics/ping", methods=["POST"])
def ping_diagnostic_endpoint():
    """
    VULNERABLE: OS Command Injection (CWE-78).
    Passes user input directly into shell execution.
    """
    data = request.get_json(force=True, silent=True) or request.form
    target_host = data.get("host", "127.0.0.1")

    # Command Injection: e.g., "127.0.0.1 && whoami"
    command = f"ping -n 1 {target_host}"
    try:
        output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, text=True)
        return jsonify({"status": "success", "output": output})
    except subprocess.CalledProcessError as e:
        return jsonify({"status": "error", "output": e.output}), 500


@app.route("/api/reports/download", methods=["GET"])
def download_report_endpoint():
    """
    VULNERABLE: Path Traversal (CWE-22).
    Permits reading arbitrary system files outside storage folder.
    """
    filename = request.args.get("filename", "")
    try:
        content = read_report_file_vulnerable(filename)
        return jsonify({"status": "success", "filename": filename, "content": content})
    except Exception as e:
        # Information disclosure via raw exception message
        return jsonify({"status": "error", "exception": str(e)}), 500


@app.route("/api/backup/export", methods=["GET"])
def export_backup_endpoint():
    """
    Exports state via insecure pickle serialization.
    """
    sample_backup = {
        "version": "1.0",
        "metadata": "MedSecure Backup",
        "exported_records": 3
    }
    encoded = export_backup_vulnerable(sample_backup)
    return jsonify({"status": "success", "payload": encoded})


@app.route("/api/backup/import", methods=["POST"])
def import_backup_endpoint():
    """
    VULNERABLE: Insecure Deserialization (CWE-502).
    Unpickles untrusted payload leading to Remote Code Execution (RCE).
    """
    data = request.get_json(force=True, silent=True) or request.form
    payload_b64 = data.get("payload", "")
    try:
        result = import_backup_vulnerable(payload_b64)
        return jsonify({"status": "success", "restored": str(result)})
    except Exception as e:
        return jsonify({"status": "error", "exception": str(e)}), 500


if __name__ == "__main__":
    init_db()
    # Runs in debug mode with all interfaces exposed
    app.run(host="0.0.0.0", port=5000, debug=True)
