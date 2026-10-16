"""
Database module for the Baseline Vulnerable Application.

VULNERABILITIES DEMONSTRATED:
- CWE-89: SQL Injection via direct f-string string concatenation in queries.
- CWE-328: Use of weak cryptographic hash (MD5 without salt) for passwords.
- CWE-312: Cleartext storage of sensitive PII (SSN, credit cards, medical records).
- CWE-209: Raw database exception propagation disclosing database schema.
"""

import sqlite3
import hashlib
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "vulnerable_portal.db")


def get_db_connection():
    """Establishes an unhardened SQLite connection."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def hash_password(password: str) -> str:
    """
    VULNERABLE: Uses obsolete, unsalted MD5 hashing.
    Vulnerable to precomputed rainbow tables and rapid dictionary attacks.
    """
    return hashlib.md5(password.encode("utf-8")).hexdigest()


def init_db():
    """Initializes the database schema with sample seed data."""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL,
            email TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS patient_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_name TEXT NOT NULL,
            ssn TEXT NOT NULL,
            date_of_birth TEXT NOT NULL,
            diagnosis TEXT NOT NULL,
            credit_card TEXT NOT NULL,
            doctor_notes TEXT,
            created_by INTEGER,
            FOREIGN KEY (created_by) REFERENCES users (id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            action TEXT NOT NULL,
            details TEXT
        )
    """)

    # Seed users if empty
    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        # Passwords hashed with weak unsalted MD5
        users = [
            ("admin", hash_password("AdminPass123!"), "admin", "admin@medsecure.local"),
            ("dr_smith", hash_password("DoctorSecret!"), "doctor", "drsmith@medsecure.local"),
            ("nurse_jane", hash_password("NursePass2026"), "nurse", "jane@medsecure.local"),
            ("john_doe", hash_password("Password123"), "patient", "john.doe@email.com"),
            ("alice_wonder", hash_password("AlicePass99"), "patient", "alice@email.com")
        ]
        for u in users:
            # Notice the raw SQL insertion
            cursor.execute(f"INSERT INTO users (username, password, role, email) VALUES ('{u[0]}', '{u[1]}', '{u[2]}', '{u[3]}')")

        # Seed records with cleartext sensitive data
        records = [
            ("John Doe", "000-12-3456", "1985-04-12", "Hypertension Stage 2", "4111-2222-3333-4444", "Patient reports mild chest tightness.", 2),
            ("Alice Wonder", "111-23-4567", "1992-09-24", "Type 1 Diabetes Mellitus", "5500-0000-1111-2222", "Insulin pump calibrated.", 2),
            ("Robert Brown", "222-34-5678", "1978-11-03", "Chronic Lumbar Radiculopathy", "3782-8224-6310-0051", "Physiotherapy recommended twice weekly.", 2)
        ]
        for r in records:
            cursor.execute(f"""
                INSERT INTO patient_records 
                (patient_name, ssn, date_of_birth, diagnosis, credit_card, doctor_notes, created_by)
                VALUES ('{r[0]}', '{r[1]}', '{r[2]}', '{r[3]}', '{r[4]}', '{r[5]}', {r[6]})
            """)

    conn.commit()
    conn.close()


def query_user_vulnerable(username: str, password_raw: str):
    """
    VULNERABLE: Direct SQL string concatenation allows authentication bypass.
    Payload: username = "admin' --" or password = "' OR '1'='1"
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    pwd_hash = hash_password(password_raw)
    # Direct string formatting - CRITICAL SQL INJECTION VULNERABILITY (CWE-89)
    sql = f"SELECT * FROM users WHERE username = '{username}' AND password = '{pwd_hash}'"
    cursor.execute(sql)
    user = cursor.fetchone()
    conn.close()
    return user


def search_patients_vulnerable(search_term: str):
    """
    VULNERABLE: Raw SQL formatting allows SQL injection in patient search.
    Payload: "' UNION SELECT id, username, password, email, 'leaked', 'leaked', 'leaked', 1 FROM users --"
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    # SQL Injection via string interpolation
    sql = f"SELECT * FROM patient_records WHERE patient_name LIKE '%{search_term}%' OR diagnosis LIKE '%{search_term}%'"
    cursor.execute(sql)
    records = cursor.fetchall()
    conn.close()
    return records


def get_patient_by_id_vulnerable(record_id: str):
    """
    VULNERABLE: SQL injection via record_id parameter string concatenation.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    sql = f"SELECT * FROM patient_records WHERE id = {record_id}"
    cursor.execute(sql)
    record = cursor.fetchone()
    conn.close()
    return record


def add_patient_vulnerable(name: str, ssn: str, dob: str, diagnosis: str, credit_card: str, notes: str, created_by: int):
    """
    VULNERABLE: Inserts unencrypted PII/PHI directly into the database.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    sql = f"""
        INSERT INTO patient_records (patient_name, ssn, date_of_birth, diagnosis, credit_card, doctor_notes, created_by)
        VALUES ('{name}', '{ssn}', '{dob}', '{diagnosis}', '{credit_card}', '{notes}', {created_by})
    """
    cursor.execute(sql)
    conn.commit()
    new_id = cursor.lastrowid
    conn.close()
    return new_id
