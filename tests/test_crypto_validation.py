"""
Cryptographic and Input Validation Test Suite.
Validates the mathematical, cryptographic, and algorithmic correctness of security controls.
"""

import pytest
import time
from secure_app.crypto import (
    hash_password,
    verify_password,
    encrypt_field,
    decrypt_field,
    mask_ssn,
    mask_credit_card,
    create_signed_token,
    verify_signed_token
)
from secure_app.validator import (
    validate_username,
    validate_email,
    validate_password_strength,
    validate_ssn,
    validate_date,
    validate_credit_card,
    sanitize_html_text,
    sanitize_search_query,
    validate_safe_filename,
    validate_host_for_diagnostics
)


# --------------------------------------------------------------------------
# Cryptographic Password Hashing Tests
# --------------------------------------------------------------------------
def test_password_hashing_format_and_rounds():
    pwd = "CorrectHorseBatteryStaple123!"
    hashed = hash_password(pwd)
    assert hashed.startswith("pbkdf2:sha256:600000$")
    assert verify_password(pwd, hashed) is True
    assert verify_password("WrongPassword!", hashed) is False


def test_password_hashing_unique_salts():
    pwd = "UniversalPassword123!"
    hash1 = hash_password(pwd)
    hash2 = hash_password(pwd)
    # Different salts ensure different hashes for identical passwords
    assert hash1 != hash2
    assert verify_password(pwd, hash1) is True
    assert verify_password(pwd, hash2) is True


# --------------------------------------------------------------------------
# Field-Level Encryption & Decryption Tests
# --------------------------------------------------------------------------
def test_authenticated_field_encryption():
    sensitive_data = "123-45-6789"
    cipher_text = encrypt_field(sensitive_data)
    assert cipher_text != sensitive_data
    assert len(cipher_text) > 40
    # Decrypt returns exact original
    recovered = decrypt_field(cipher_text)
    assert recovered == sensitive_data


def test_tampered_ciphertext_rejection():
    sensitive_data = "4111-2222-3333-4444"
    cipher_text = encrypt_field(sensitive_data)
    # Flip bytes to tamper
    tampered = cipher_text[:-5] + "AAAAA"
    result = decrypt_field(tampered)
    assert result == "[ENCRYPTED_DATA_CORRUPTED]"


# --------------------------------------------------------------------------
# Display Masking Tests
# --------------------------------------------------------------------------
def test_mask_ssn():
    assert mask_ssn("000-12-3456") == "***-**-3456"
    assert mask_ssn("invalid") == "***-**-****"
    assert mask_ssn("") == "***-**-****"


def test_mask_credit_card():
    assert mask_credit_card("4111-2222-3333-4444") == "****-****-****-4444"
    assert mask_credit_card("4111222233334444") == "****-****-****-4444"
    assert mask_credit_card("") == "****-****-****-****"


# --------------------------------------------------------------------------
# Signed Session Token Tests
# --------------------------------------------------------------------------
def test_signed_token_lifecycle():
    payload = {"user_id": 42, "role": "doctor"}
    token = create_signed_token(payload)
    parsed = verify_signed_token(token)
    assert parsed is not None
    assert parsed["user_id"] == 42
    assert parsed["role"] == "doctor"


def test_forged_token_rejection():
    payload = {"user_id": 42, "role": "patient"}
    token = create_signed_token(payload)
    # Attacker tries to elevate privilege to admin
    data_b64, sig = token.split(".", 1)
    forged_token = data_b64 + ".forgedsignature1234567890abcdef"
    assert verify_signed_token(forged_token) is None


# --------------------------------------------------------------------------
# Input Validation & Sanitization Tests
# --------------------------------------------------------------------------
def test_validate_username():
    assert validate_username("dr_smith") is True
    assert validate_username("alice123") is True
    # Injections / invalid usernames
    assert validate_username("admin' --") is False
    assert validate_username("<script>") is False
    assert validate_username("ab") is False  # Too short


def test_validate_email():
    assert validate_email("doctor@medsecure.local") is True
    assert validate_email("not-an-email") is False
    assert validate_email("<script>@domain.com") is False


def test_password_complexity():
    valid, _ = validate_password_strength("StrongPass2026!")
    assert valid is True
    # Missing digit
    invalid1, msg1 = validate_password_strength("NoDigitsHere!")
    assert invalid1 is False
    # Missing uppercase
    invalid2, msg2 = validate_password_strength("lowercase123!")
    assert invalid2 is False
    # Too short
    invalid3, msg3 = validate_password_strength("Short1!")
    assert invalid3 is False


def test_validate_ssn():
    assert validate_ssn("000-12-3456") is True
    assert validate_ssn("123456789") is False
    assert validate_ssn("000-12-3456; DROP TABLE") is False


def test_validate_date():
    assert validate_date("1990-12-31") is True
    assert validate_date("31-12-1990") is False
    assert validate_date("invalid-date") is False


def test_credit_card_luhn():
    # Valid Visa card passing Luhn
    assert validate_credit_card("4111-1111-1111-1111") is True
    # Invalid card failing Luhn
    assert validate_credit_card("4111-1111-1111-1112") is False
    assert validate_credit_card("1234") is False


def test_sanitize_html_xss():
    raw_payload = "<script>alert('XSS')</script><img src=x onerror=steal()>"
    safe = sanitize_html_text(raw_payload)
    assert "<script>" not in safe
    assert "&lt;script&gt;" in safe
    assert "&lt;img" in safe


def test_validate_safe_filename():
    ok, name = validate_safe_filename("lab_results_2026.pdf")
    assert ok is True

    # Path traversal payloads
    bad1, _ = validate_safe_filename("../../etc/passwd")
    assert bad1 is False
    bad2, _ = validate_safe_filename("..\\..\\windows\\win.ini")
    assert bad2 is False
    bad3, _ = validate_safe_filename("report.exe")  # Disallowed extension
    assert bad3 is False


def test_validate_host_for_diagnostics():
    ok1, h1 = validate_host_for_diagnostics("127.0.0.1")
    assert ok1 is True
    ok2, h2 = validate_host_for_diagnostics("medsecure.local")
    assert ok2 is True

    # Command injection payloads
    bad1, _ = validate_host_for_diagnostics("127.0.0.1 && whoami")
    assert bad1 is False
    bad2, _ = validate_host_for_diagnostics("127.0.0.1; cat /etc/passwd")
    assert bad2 is False
    bad3, _ = validate_host_for_diagnostics("`id`")
    assert bad3 is False
