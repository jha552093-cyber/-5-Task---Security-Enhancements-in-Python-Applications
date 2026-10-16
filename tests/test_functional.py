"""
Functional Verification Test Suite for MedSecure Application.
Verifies that all core business capabilities operate seamlessly in the hardened application.
"""

import pytest
import os
import tempfile
from secure_app.database import init_db
from secure_app.app import app
from secure_app.crypto import create_signed_token, encrypt_field


@pytest.fixture(autouse=True)
def setup_test_environment():
    """Initializes a fresh test database for each run."""
    with app.app_context():
        init_db()
    yield


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


@pytest.fixture
def doctor_token():
    return create_signed_token({
        "user_id": 2,
        "username": "dr_smith",
        "role": "doctor",
        "email": "drsmith@medsecure.local"
    })


@pytest.fixture
def admin_token():
    return create_signed_token({
        "user_id": 1,
        "username": "admin",
        "role": "admin",
        "email": "admin@medsecure.local"
    })


@pytest.fixture
def patient_token():
    return create_signed_token({
        "user_id": 4,
        "username": "john_doe",
        "role": "patient",
        "email": "john.doe@email.com"
    })


def test_login_success(client):
    """Verifies that legitimate user can authenticate successfully."""
    response = client.post("/api/login", json={
        "username": "dr_smith",
        "password": "DoctorSecret!"
    })
    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "success"
    assert "token" in data
    assert data["user"]["role"] == "doctor"
    # Verify cookie flags
    cookie = response.headers.get("Set-Cookie", "")
    assert "HttpOnly" in cookie


def test_login_invalid_credentials(client):
    """Verifies that invalid credentials fail gracefully."""
    response = client.post("/api/login", json={
        "username": "dr_smith",
        "password": "WrongPassword!"
    })
    assert response.status_code == 401
    data = response.get_json()
    assert data["status"] == "error"


def test_search_patients(client, doctor_token):
    """Verifies patient search functionality for authenticated doctor."""
    response = client.get("/api/search?q=John", headers={
        "Authorization": f"Bearer {doctor_token}"
    })
    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "success"
    assert len(data["data"]) >= 1
    patient = data["data"][0]
    assert "John Doe" in patient["patient_name"]


def test_get_patient_record_as_doctor(client, doctor_token):
    """Doctor retrieves patient record and can view full clinical details."""
    response = client.get("/api/records/1", headers={
        "Authorization": f"Bearer {doctor_token}"
    })
    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "success"
    rec = data["record"]
    assert rec["patient_name"] == "John Doe"
    assert rec["ssn"] == "000-12-3456"  # Doctor sees unmasked


def test_create_patient_record_success(client, doctor_token):
    """Verifies doctor can add a new patient record with encrypted storage."""
    new_patient = {
        "patient_name": "Eleanor Vance",
        "ssn": "987-65-4321",
        "date_of_birth": "1995-07-19",
        "diagnosis": "Generalized Anxiety Disorder",
        "credit_card": "4111-1111-1111-1111",
        "doctor_notes": "Prescribed cognitive behavioral therapy."
    }
    response = client.post("/api/records", json=new_patient, headers={
        "Authorization": f"Bearer {doctor_token}"
    })
    assert response.status_code == 201
    data = response.get_json()
    assert data["status"] == "success"
    assert "record_id" in data


def test_render_clinical_notes_neutralized(client, doctor_token):
    """Verifies clinical notes are rendered safely."""
    response = client.post("/api/notes/render", json={
        "patient_name": "Eleanor Vance",
        "note": "Routine wellness checkup completed. Vital signs stable."
    }, headers={
        "Authorization": f"Bearer {doctor_token}"
    })
    assert response.status_code == 200
    assert "Routine wellness checkup completed" in response.get_data(as_text=True)


def test_download_legitimate_report(client, doctor_token):
    """Verifies safe file download within designated storage folder."""
    response = client.get("/api/reports/download?filename=annual_report_2026.txt", headers={
        "Authorization": f"Bearer {doctor_token}"
    })
    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "success"
    assert "MedSecure Hospital Annual Performance Report" in data["content"]


def test_backup_export_and_import(client, admin_token):
    """Verifies HMAC-signed JSON backup export and import cycle."""
    # 1. Export
    export_resp = client.get("/api/backup/export", headers={
        "Authorization": f"Bearer {admin_token}"
    })
    assert export_resp.status_code == 200
    signed_payload = export_resp.get_json()["signed_payload"]
    assert "." in signed_payload

    # 2. Import
    import_resp = client.post("/api/backup/import", json={
        "signed_payload": signed_payload
    }, headers={
        "Authorization": f"Bearer {admin_token}"
    })
    assert import_resp.status_code == 200
    assert import_resp.get_json()["status"] == "success"


def test_network_diagnostic_localhost(client, admin_token):
    """Verifies network diagnostic reachability for valid localhost IP."""
    response = client.post("/api/diagnostics/ping", json={
        "host": "127.0.0.1"
    }, headers={
        "Authorization": f"Bearer {admin_token}"
    })
    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "success"
    assert data["resolved_ip"] == "127.0.0.1"
