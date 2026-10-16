"""
Command-Line Interface (CLI) for Baseline Vulnerable Application.
"""

import sys
import argparse
from vulnerable_app.database import (
    init_db,
    query_user_vulnerable,
    search_patients_vulnerable,
    get_patient_by_id_vulnerable,
    add_patient_vulnerable
)
from vulnerable_app.storage import read_report_file_vulnerable
from vulnerable_app.auth import generate_vulnerable_session_token


def run_cli():
    init_db()
    parser = argparse.ArgumentParser(description="MedSecure CLI (Vulnerable)")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Login command
    login_parser = subparsers.add_parser("login", help="Authenticate user")
    login_parser.add_argument("--username", required=True)
    login_parser.add_argument("--password", required=True)

    # Search command
    search_parser = subparsers.add_parser("search", help="Search patient records")
    search_parser.add_argument("--query", required=True)

    # View record
    view_parser = subparsers.add_parser("view", help="View patient record by ID")
    view_parser.add_argument("--id", required=True)

    # Read file
    read_parser = subparsers.add_parser("read-file", help="Read report file")
    read_parser.add_argument("--file", required=True)

    args = parser.parse_args()

    if args.command == "login":
        user = query_user_vulnerable(args.username, args.password)
        if user:
            token = generate_vulnerable_session_token(user["id"], user["username"], user["role"])
            print(f"[+] Login SUCCESS! Welcome {user['username']} ({user['role']})")
            print(f"[+] Session Token: {token}")
        else:
            print("[-] Login FAILED: Invalid credentials")

    elif args.command == "search":
        records = search_patients_vulnerable(args.query)
        print(f"[+] Found {len(records)} matching records:")
        for r in records:
            print(f"  - [{r['id']}] {r['patient_name']} | SSN: {r['ssn']} | Diag: {r['diagnosis']} | CC: {r['credit_card']}")

    elif args.command == "view":
        record = get_patient_by_id_vulnerable(args.id)
        if record:
            print(f"[+] Patient #{record['id']}: {record['patient_name']}")
            print(f"    SSN: {record['ssn']}")
            print(f"    DOB: {record['date_of_birth']}")
            print(f"    Diagnosis: {record['diagnosis']}")
            print(f"    Credit Card: {record['credit_card']}")
            print(f"    Notes: {record['doctor_notes']}")
        else:
            print("[-] Record not found")

    elif args.command == "read-file":
        try:
            content = read_report_file_vulnerable(args.file)
            print(f"[+] File Content ({args.file}):\n{content}")
        except Exception as e:
            print(f"[-] Error: {e}")

    else:
        parser.print_help()


if __name__ == "__main__":
    run_cli()
