"""
Command-Line Interface (CLI) for Hardened Secure Application.
"""

import sys
import argparse
from secure_app.database import (
    init_db,
    search_patients_secure,
    get_patient_by_id_secure,
    add_patient_secure
)
from secure_app.crypto import decrypt_field, mask_ssn, mask_credit_card
from secure_app.validator import (
    validate_ssn,
    validate_date,
    validate_credit_card,
    sanitize_search_query
)
from secure_app.storage import safe_read_report_file
from secure_app.auth import (
    authenticate_user,
    get_authenticated_session,
    check_record_authorization
)


def run_cli():
    init_db()
    parser = argparse.ArgumentParser(description="MedSecure CLI (Hardened Secure)")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Login
    login_parser = subparsers.add_parser("login", help="Authenticate user securely")
    login_parser.add_argument("--username", required=True)
    login_parser.add_argument("--password", required=True)

    # Search
    search_parser = subparsers.add_parser("search", help="Search patient records")
    search_parser.add_argument("--query", required=True)
    search_parser.add_argument("--token", required=True, help="HMAC-signed session token")

    # View record
    view_parser = subparsers.add_parser("view", help="View patient record by ID")
    view_parser.add_argument("--id", required=True, type=int)
    view_parser.add_argument("--token", required=True, help="HMAC-signed session token")

    # Read file
    read_parser = subparsers.add_parser("read-file", help="Safely read report file")
    read_parser.add_argument("--file", required=True)
    read_parser.add_argument("--token", required=True, help="HMAC-signed session token")

    # Add patient
    add_parser = subparsers.add_parser("add-patient", help="Add patient record")
    add_parser.add_argument("--name", required=True)
    add_parser.add_argument("--ssn", required=True)
    add_parser.add_argument("--dob", required=True)
    add_parser.add_argument("--diagnosis", required=True)
    add_parser.add_argument("--cc", required=True)
    add_parser.add_argument("--notes", default="")
    add_parser.add_argument("--token", required=True)

    args = parser.parse_args()

    if args.command == "login":
        success, msg, user_info = authenticate_user(args.username, args.password)
        if success:
            print(f"[+] Login SUCCESS! Welcome {user_info['username']} (Role: {user_info['role']})")
            print(f"[+] Signed Token: {user_info['token']}")
        else:
            print(f"[-] Login FAILED: {msg}")

    elif args.command == "search":
        session = get_authenticated_session(args.token)
        if not session:
            print("[-] Access DENIED: Invalid or expired session token.")
            return

        cleaned_query = sanitize_search_query(args.query)
        rows = search_patients_secure(cleaned_query)
        user_role = session.get("role")
        user_id = session.get("user_id")

        print(f"[+] Found {len(rows)} matching records:")
        for r in rows:
            if user_role == "patient" and r["created_by"] != user_id:
                continue

            ssn_dec = decrypt_field(r["ssn_encrypted"])
            cc_dec = decrypt_field(r["credit_card_encrypted"])
            diag_dec = decrypt_field(r["diagnosis_encrypted"])

            ssn_disp = ssn_dec if user_role in ["doctor", "admin"] else mask_ssn(ssn_dec)
            cc_disp = cc_dec if user_role in ["doctor", "admin"] else mask_credit_card(cc_dec)

            print(f"  - [{r['id']}] {r['patient_name']} | SSN: {ssn_disp} | Diag: {diag_dec} | CC: {cc_disp}")

    elif args.command == "view":
        session = get_authenticated_session(args.token)
        if not session:
            print("[-] Access DENIED: Invalid or expired session token.")
            return

        record = get_patient_by_id_secure(args.id)
        if not record:
            print("[-] Record not found.")
            return

        if not check_record_authorization(session, record["created_by"]):
            print("[-] Access FORBIDDEN: You are not authorized to view this record (IDOR Protection).")
            return

        user_role = session.get("role")
        ssn_dec = decrypt_field(record["ssn_encrypted"])
        cc_dec = decrypt_field(record["credit_card_encrypted"])
        diag_dec = decrypt_field(record["diagnosis_encrypted"])

        ssn_disp = ssn_dec if user_role in ["doctor", "admin"] else mask_ssn(ssn_dec)
        cc_disp = cc_dec if user_role in ["doctor", "admin"] else mask_credit_card(cc_dec)

        print(f"[+] Patient #{record['id']}: {record['patient_name']}")
        print(f"    SSN: {ssn_disp}")
        print(f"    DOB: {record['date_of_birth']}")
        print(f"    Diagnosis: {diag_dec}")
        print(f"    Credit Card: {cc_disp}")
        print(f"    Notes: {record['doctor_notes']}")

    elif args.command == "read-file":
        session = get_authenticated_session(args.token)
        if not session:
            print("[-] Access DENIED: Invalid or expired session token.")
            return

        ok, content = safe_read_report_file(args.file)
        if ok:
            print(f"[+] File Content ({args.file}):\n{content}")
        else:
            print(f"[-] Error: {content}")

    elif args.command == "add-patient":
        session = get_authenticated_session(args.token)
        if not session or session.get("role") not in ["doctor", "admin"]:
            print("[-] Access FORBIDDEN: Only doctors or admins can create patient records.")
            return

        if not validate_ssn(args.ssn):
            print("[-] Invalid SSN format (XXX-XX-XXXX required).")
            return
        if not validate_date(args.dob):
            print("[-] Invalid Date of Birth format (YYYY-MM-DD required).")
            return
        if not validate_credit_card(args.cc):
            print("[-] Invalid Credit Card number or checksum.")
            return

        new_id = add_patient_secure(
            args.name,
            args.ssn,
            args.dob,
            args.diagnosis,
            args.cc,
            args.notes,
            session["user_id"]
        )
        print(f"[+] Successfully encrypted and stored patient record #{new_id}!")

    else:
        parser.print_help()


if __name__ == "__main__":
    run_cli()
