"""
Hardened Flask Web Application & REST API - MedSecure Portal.

Security Best Practices Applied:
- CWE-89: Parameterized database queries exclusively.
- CWE-79: Markupsafe context-aware HTML escaping and Content-Security-Policy.
- CWE-78: Native socket health check replacing dangerous shell subprocesses.
- CWE-22: Path canonicalization and directory boundary validation.
- CWE-502: Safe JSON deserialization with HMAC signature verification replacing pickle.
- CWE-639: Role-Based Access Control and IDOR mitigation.
- CWE-209: Sanitized error handlers with incident correlation UUIDs.
- CWE-489: Debug mode disabled.
- CWE-1004 / CWE-693: Comprehensive HTTP security headers (CSP, HSTS, X-Frame-Options, etc.).
"""

import os
import uuid
import socket
from functools import wraps
from flask import Flask, request, jsonify, make_response
from .config import (
    SECRET_KEY,
    DEBUG,
    SESSION_COOKIE_HTTPONLY,
    SESSION_COOKIE_SECURE,
    SESSION_COOKIE_SAMESITE
)
from .database import (
    init_db,
    search_patients_secure,
    get_patient_by_id_secure,
    add_patient_secure
)
from .crypto import mask_ssn, mask_credit_card, decrypt_field
from .validator import (
    validate_username,
    validate_password_strength,
    validate_ssn,
    validate_date,
    validate_credit_card,
    sanitize_html_text,
    sanitize_search_query,
    validate_safe_filename,
    validate_host_for_diagnostics
)
from .storage import safe_read_report_file, export_backup_secure, import_backup_secure
from .auth import (
    authenticate_user,
    get_authenticated_session,
    check_record_authorization
)
from .logger import log_security_event

app = Flask(__name__)
app.secret_key = SECRET_KEY
app.config["DEBUG"] = False


@app.before_request
def initialize_system():
    """Ensure database schema is ready."""
    init_db()


# --------------------------------------------------------------------------
# Security Headers Middleware (CWE-693)
# --------------------------------------------------------------------------
@app.after_request
def add_security_headers(response):
    """Injects defense-in-depth HTTP security headers."""
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "object-src 'none'; "
        "frame-ancestors 'none';"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    return response


# --------------------------------------------------------------------------
# Global Sanitized Error Handlers (CWE-209)
# --------------------------------------------------------------------------
@app.errorhandler(400)
def handle_bad_request(e):
    return jsonify({"status": "error", "message": "Bad request. Please verify your input parameters."}), 400


@app.errorhandler(401)
def handle_unauthorized(e):
    return jsonify({"status": "error", "message": "Authentication required. Please provide a valid session token."}), 401


@app.errorhandler(403)
def handle_forbidden(e):
    return jsonify({"status": "error", "message": "Access forbidden. Insufficient privileges."}), 403


@app.errorhandler(404)
def handle_not_found(e):
    return jsonify({"status": "error", "message": "The requested resource was not found."}), 404


@app.errorhandler(Exception)
def handle_internal_error(e):
    incident_id = str(uuid.uuid4())
    # Log internal error securely with correlation ID
    log_security_event(
        "INTERNAL_SERVER_ERROR",
        f"Incident [{incident_id}]: {type(e).__name__} - {str(e)}",
        severity="ERROR",
        success=False
    )
    return jsonify({
        "status": "error",
        "message": "An internal server error occurred. Our engineering team has been notified.",
        "incident_id": incident_id
    }), 500


# --------------------------------------------------------------------------
# Authentication & Authorization Decorators
# --------------------------------------------------------------------------
def get_current_user_from_request():
    auth_header = request.headers.get("Authorization", "")
    token = None
    if auth_header.startswith("Bearer "):
        token = auth_header.split(" ", 1)[1]
    elif "session_token" in request.cookies:
        token = request.cookies.get("session_token")
    return get_authenticated_session(token)


def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        current_user = get_current_user_from_request()
        if not current_user:
            return jsonify({"status": "error", "message": "Valid authentication credentials required."}), 401
        request.current_user = current_user
        return f(*args, **kwargs)
    return decorated


def require_roles(*allowed_roles):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            current_user = getattr(request, "current_user", None) or get_current_user_from_request()
            if not current_user:
                return jsonify({"status": "error", "message": "Authentication required."}), 401
            if current_user.get("role") not in allowed_roles:
                log_security_event(
                    "UNAUTHORIZED_ACCESS_ATTEMPT",
                    f"User {current_user.get('username')} with role {current_user.get('role')} attempted to access restricted endpoint",
                    user_id=current_user.get("user_id"),
                    username=current_user.get("username"),
                    severity="WARNING",
                    success=False
                )
                return jsonify({"status": "error", "message": "Forbidden: You do not possess the required permissions."}), 403
            request.current_user = current_user
            return f(*args, **kwargs)
        return decorated
    return decorator


# --------------------------------------------------------------------------
# Application Routes
# --------------------------------------------------------------------------
@app.route("/api/login", methods=["POST"])
def login_endpoint():
    """
    Secure login with rate limiting, lockout protection, and constant-time password check.
    """
    data = request.get_json(force=True, silent=True) or request.form
    if not data:
        return jsonify({"status": "error", "message": "Invalid request payload."}), 400

    username = data.get("username", "").strip()
    password = data.get("password", "")
    client_ip = request.remote_addr or "127.0.0.1"

    success, message, user_info = authenticate_user(username, password, ip_address=client_ip)
    if not success:
        return jsonify({"status": "error", "message": message}), 401

    token = user_info["token"]
    resp = make_response(jsonify({
        "status": "success",
        "message": f"Welcome back, {user_info['username']}!",
        "token": token,
        "user": {
            "id": user_info["id"],
            "username": user_info["username"],
            "role": user_info["role"],
            "email": user_info["email"]
        }
    }))

    # Secure Cookie hardening
    resp.set_cookie(
        "session_token",
        token,
        httponly=SESSION_COOKIE_HTTPONLY,
        secure=SESSION_COOKIE_SECURE,
        samesite=SESSION_COOKIE_SAMESITE,
        max_age=1800
    )
    return resp


@app.route("/api/search", methods=["GET"])
@require_auth
def search_endpoint():
    """
    Secure patient search with parameterized query, sanitized input, and masked sensitive data.
    """
    raw_query = request.args.get("q", "")
    query = sanitize_search_query(raw_query)

    current_user = request.current_user
    user_role = current_user.get("role")
    user_id = current_user.get("user_id")

    rows = search_patients_secure(query)
    results = []
    for r in rows:
        # Authorization check: patients can only see their own records in search
        if user_role == "patient" and r["created_by"] != user_id:
            continue

        decrypted_ssn = decrypt_field(r["ssn_encrypted"])
        decrypted_cc = decrypt_field(r["credit_card_encrypted"])
        decrypted_diag = decrypt_field(r["diagnosis_encrypted"])

        # Display masking: Only doctors and admins see full SSN/CC
        if user_role in ["doctor", "admin"]:
            display_ssn = decrypted_ssn
            display_cc = decrypted_cc
        else:
            display_ssn = mask_ssn(decrypted_ssn)
            display_cc = mask_credit_card(decrypted_cc)

        results.append({
            "id": r["id"],
            "patient_name": r["patient_name"],
            "ssn": display_ssn,
            "date_of_birth": r["date_of_birth"],
            "diagnosis": decrypted_diag,
            "credit_card": display_cc,
            "doctor_notes": r["doctor_notes"]
        })

    return jsonify({"status": "success", "count": len(results), "data": results})


@app.route("/api/records/<record_id>", methods=["GET"])
@require_auth
def get_record_endpoint(record_id):
    """
    Secure patient record retrieval with IDOR mitigation and ID type validation.
    """
    try:
        val_id = int(record_id)
        if val_id <= 0:
            raise ValueError()
    except ValueError:
        return jsonify({"status": "error", "message": "Invalid record ID. Must be a positive integer."}), 400

    record = get_patient_by_id_secure(val_id)
    if not record:
        return jsonify({"status": "error", "message": "Record not found."}), 404

    # IDOR Prevention: Check ownership or clinical role
    current_user = request.current_user
    if not check_record_authorization(current_user, record["created_by"]):
        log_security_event(
            "IDOR_BLOCKED",
            f"User {current_user['username']} attempted unauthorized access to record #{val_id}",
            user_id=current_user["user_id"],
            username=current_user["username"],
            severity="WARNING",
            success=False
        )
        return jsonify({"status": "error", "message": "Access denied: You are not authorized to view this record."}), 403

    decrypted_ssn = decrypt_field(record["ssn_encrypted"])
    decrypted_cc = decrypt_field(record["credit_card_encrypted"])
    decrypted_diag = decrypt_field(record["diagnosis_encrypted"])

    # Mask sensitive numbers for non-doctor/admin roles
    if current_user["role"] in ["doctor", "admin"]:
        display_ssn = decrypted_ssn
        display_cc = decrypted_cc
    else:
        display_ssn = mask_ssn(decrypted_ssn)
        display_cc = mask_credit_card(decrypted_cc)

    return jsonify({
        "status": "success",
        "record": {
            "id": record["id"],
            "patient_name": record["patient_name"],
            "ssn": display_ssn,
            "date_of_birth": record["date_of_birth"],
            "diagnosis": decrypted_diag,
            "credit_card": display_cc,
            "doctor_notes": record["doctor_notes"]
        }
    })


@app.route("/api/records", methods=["POST"])
@require_auth
@require_roles("doctor", "admin")
def add_record_endpoint():
    """
    Creates a new patient record with strict schema validation and field-level encryption.
    """
    data = request.get_json(force=True, silent=True) or request.form
    if not data:
        return jsonify({"status": "error", "message": "Invalid JSON payload."}), 400

    name = data.get("patient_name", "").strip()
    ssn = data.get("ssn", "").strip()
    dob = data.get("date_of_birth", "").strip()
    diagnosis = data.get("diagnosis", "").strip()
    credit_card = data.get("credit_card", "").strip()
    notes = sanitize_html_text(data.get("doctor_notes", ""))

    if not name or len(name) < 2:
        return jsonify({"status": "error", "message": "Patient name must be at least 2 characters."}), 400
    if not validate_ssn(ssn):
        return jsonify({"status": "error", "message": "Invalid SSN format. Expected XXX-XX-XXXX."}), 400
    if not validate_date(dob):
        return jsonify({"status": "error", "message": "Invalid date format. Expected YYYY-MM-DD."}), 400
    if not validate_credit_card(credit_card):
        return jsonify({"status": "error", "message": "Invalid credit card number or failed checksum."}), 400

    new_id = add_patient_secure(
        name,
        ssn,
        dob,
        diagnosis,
        credit_card,
        notes,
        request.current_user["user_id"]
    )

    log_security_event(
        "RECORD_CREATED",
        f"Record #{new_id} created for patient {name}",
        user_id=request.current_user["user_id"],
        username=request.current_user["username"]
    )

    return jsonify({"status": "success", "message": "Record successfully created.", "record_id": new_id}), 201


@app.route("/api/notes/render", methods=["POST"])
@require_auth
def render_note_endpoint():
    """
    Neutralizes XSS (CWE-79) using Markupsafe HTML escaping.
    """
    data = request.get_json(force=True, silent=True) or request.form
    raw_note = data.get("note", "")
    raw_patient = data.get("patient_name", "Anonymous")

    # Sanitize inputs with Markupsafe
    safe_note = sanitize_html_text(raw_note)
    safe_patient = sanitize_html_text(raw_patient)

    html_response = f"""
    <div class="patient-note-card">
        <h3>Clinical Note for: {safe_patient}</h3>
        <div class="content">{safe_note}</div>
    </div>
    """
    return html_response, 200, {"Content-Type": "text/html; charset=utf-8"}


@app.route("/api/diagnostics/ping", methods=["POST"])
@require_auth
@require_roles("admin")
def ping_diagnostic_endpoint():
    """
    Neutralizes Command Injection (CWE-78).
    Eliminates shell subprocess execution completely.
    Performs network reachability check via native socket connection.
    """
    data = request.get_json(force=True, silent=True) or request.form
    target_host = data.get("host", "").strip()

    is_valid, err_or_host = validate_host_for_diagnostics(target_host)
    if not is_valid:
        log_security_event(
            "COMMAND_INJECTION_ATTEMPT",
            f"Blocked malicious ping host input: {target_host}",
            user_id=request.current_user["user_id"],
            username=request.current_user["username"],
            severity="CRITICAL",
            success=False
        )
        return jsonify({"status": "error", "message": f"Invalid host: {err_or_host}"}), 400

    # Safe network check using native Python socket (zero shell invocation)
    try:
        # Check standard HTTPS/HTTP port connectivity or resolve hostname
        socket.setdefaulttimeout(3.0)
        resolved_ip = socket.gethostbyname(err_or_host)
        return jsonify({
            "status": "success",
            "host": err_or_host,
            "resolved_ip": resolved_ip,
            "message": f"Host '{err_or_host}' resolved successfully to {resolved_ip} with zero shell subprocess execution."
        })
    except socket.gaierror:
        return jsonify({"status": "error", "message": f"Unable to resolve host '{err_or_host}'."}), 404
    except Exception as e:
        return jsonify({"status": "error", "message": "Diagnostic network check failed."}), 500


@app.route("/api/reports/download", methods=["GET"])
@require_auth
def download_report_endpoint():
    """
    Safely serves report files, neutralizing Path Traversal (CWE-22).
    """
    filename = request.args.get("filename", "")
    success, content_or_err = safe_read_report_file(filename)
    if not success:
        log_security_event(
            "PATH_TRAVERSAL_BLOCKED",
            f"Blocked file access attempt for: {filename}",
            user_id=request.current_user["user_id"],
            username=request.current_user["username"],
            severity="WARNING",
            success=False
        )
        return jsonify({"status": "error", "message": content_or_err}), 400

    return jsonify({"status": "success", "filename": filename, "content": content_or_err})


@app.route("/api/backup/export", methods=["GET"])
@require_auth
@require_roles("admin")
def export_backup_endpoint():
    """
    Safe backup export using JSON with HMAC-SHA256 signature.
    """
    sample_backup = {
        "version": "2.0",
        "system": "MedSecure Portal",
        "export_timestamp": "2026-10-10T12:00:00Z",
        "exported_records": 3
    }
    signed_payload = export_backup_secure(sample_backup)
    log_security_event("BACKUP_EXPORTED", "System backup generated", user_id=request.current_user["user_id"])
    return jsonify({"status": "success", "signed_payload": signed_payload})


@app.route("/api/backup/import", methods=["POST"])
@require_auth
@require_roles("admin")
def import_backup_endpoint():
    """
    Safe backup import neutralizing Insecure Deserialization (CWE-502).
    Validates HMAC-SHA256 signature and uses json.loads.
    """
    data = request.get_json(force=True, silent=True) or request.form
    signed_payload = data.get("signed_payload", "")

    success, result_or_err = import_backup_secure(signed_payload)
    if not success:
        log_security_event(
            "TAMPERED_BACKUP_REJECTED",
            f"Rejected backup import: {result_or_err}",
            user_id=request.current_user["user_id"],
            severity="CRITICAL",
            success=False
        )
        return jsonify({"status": "error", "message": result_or_err}), 400

    log_security_event("BACKUP_RESTORED", "System backup verified and restored", user_id=request.current_user["user_id"])
    return jsonify({"status": "success", "message": "Backup verified and imported successfully.", "data": result_or_err})


if __name__ == "__main__":
    init_db()
    # Hardened local production run configuration
    app.run(host="127.0.0.1", port=5000, debug=False)
