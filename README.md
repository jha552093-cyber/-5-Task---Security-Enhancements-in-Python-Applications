# Week 5 Task: Security Enhancements in Python Applications
## MedSecure Healthcare Patient & Clinical Portal (Security Audit & Hardening)

[![Python Version](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-blue.svg)](https://www.python.org/)
[![Security Audit](https://img.shields.io/badge/bandit-0%20vulnerabilities-brightgreen.svg)](https://bandit.readthedocs.io/)
[![Tests Passing](https://img.shields.io/badge/pytest-36%2F36%20passed%20(100%25)-success.svg)](https://pytest.org/)
[![Compliance](https://img.shields.io/badge/compliance-HIPAA%20%7C%20NIST%20SP%20800--63B%20%7C%20OWASP%20ASVS-purple.svg)](https://owasp.org/)

---

## 1. Project Overview

This repository contains the complete deliverables for **Week 5 Task: Security Enhancements in Python Applications**. The project centers on a realistic, high-stakes healthcare application: **MedSecure Healthcare Portal**, an enterprise clinical data management system handling sensitive user credentials, Protected Health Information (PHI), Social Security Numbers (SSN), payment card details, and diagnostic reports.

The repository includes:
1. **`vulnerable_app/`**: The baseline vulnerable application illustrating critical security pitfalls (SQL injection, weak MD5 hashing, cleartext PHI at rest, XSS, OS command injection, path traversal, pickle deserialization, IDOR, brute-force vulnerability).
2. **`secure_app/`**: The fully remediated, hardened production-grade application implementing modern defense-in-depth principles (parameterized queries, PBKDF2-HMAC-SHA256, Fernet AES authenticated encryption, context-aware HTML escaping, path canonicalization, RBAC, account lockout).
3. **`static_analysis/`**: Automated Bandit security scan configurations and reports showing a reduction from **14 detected vulnerabilities down to 0**.
4. **`tests/`**: Comprehensive 36-test suite verifying functional behavior, cryptographic correctness, and direct real-world exploit simulations.
5. **`reports/`**: In-depth Markdown and PDF Security Audit Reports (`SECURITY_AUDIT_REPORT.md`, `Security_Audit_Report.pdf`, `APPLIED_SECURITY_MEASURES.md`, `THREAT_MODEL_MATRIX.md`).
6. **`scripts/`**: Automation pipelines for running audit comparisons, executing live side-by-side attack simulations, and generating the deliverable ZIP archive.

---

## 2. Directory Structure

```
Task 5/
│
├── vulnerable_app/                  # Baseline vulnerable application (educational baseline)
│   ├── __init__.py
│   ├── app.py                       # Vulnerable Flask Web App (SQLi, XSS, Command Injection, Debug=True)
│   ├── cli.py                       # Vulnerable CLI tool
│   ├── database.py                  # Vulnerable SQLite layer (raw string concatenation, unsalted MD5)
│   ├── storage.py                   # Vulnerable storage (Path traversal, unsafe pickle unmarshaling)
│   ├── auth.py                      # Weak session handling (unauthenticated base64 tokens)
│   └── models.py                    # Vulnerable data models
│
├── secure_app/                      # Hardened, production-grade secure application
│   ├── __init__.py
│   ├── app.py                       # Hardened Flask Web App (Security headers, RBAC, CSRF, sanitized errors)
│   ├── cli.py                       # Hardened CLI management tool
│   ├── config.py                    # Secure secret management & CSPRNG fallback
│   ├── crypto.py                    # PBKDF2 hashing, Fernet AES encryption, signed HMAC tokens
│   ├── validator.py                 # Strict regex whitelisting, Luhn check, HTML escaping
│   ├── database.py                  # 100% Parameterized queries ('?'), encrypted columns
│   ├── storage.py                   # Path canonicalization & safe HMAC-signed JSON backup parser
│   ├── auth.py                      # Role-Based Access Control (RBAC), lockout policy, IDOR defense
│   ├── logger.py                    # Structured JSON audit logging with automatic PII redaction
│   └── models.py                    # Secure data models with display masking
│
├── static_analysis/                 # Automated Bandit static analysis outputs
│   ├── vulnerable_scan_report.json  # 14 issues detected in baseline
│   ├── vulnerable_scan_report.txt
│   ├── secure_scan_report.json      # 0 issues detected in hardened app (Clean bill of health)
│   └── secure_scan_report.txt
│
├── tests/                           # Pytest automated test suites (36 tests)
│   ├── __init__.py
│   ├── test_crypto_validation.py    # Validates PBKDF2 rounds, Fernet cipher, Luhn, regex schemas
│   ├── test_functional.py           # Verifies all application business features operate cleanly
│   └── test_security_attacks.py     # Side-by-side exploit simulations (SQLi, XSS, RCE, IDOR, etc.)
│
├── reports/                         # Executive & developer-grade audit reports
│   ├── SECURITY_AUDIT_REPORT.md     # In-depth 30-page equivalent markdown security report
│   ├── generate_pdf_report.py       # ReportLab PDF report generation script
│   ├── Security_Audit_Report.pdf    # Professional multi-page PDF audit report
│   ├── APPLIED_SECURITY_MEASURES.md # Technical reference guide of all applied security measures
│   └── THREAT_MODEL_MATRIX.md       # STRIDE threat model & CVSS v3.1 scoring breakdown
│
├── scripts/                         # Automation & demonstration scripts
│   ├── run_audit.py                 # Master audit orchestrator (Bandit + Pytest + Summary Table)
│   ├── simulate_attacks.py          # Interactive side-by-side exploit demonstration harness
│   └── package_deliverables.py      # Automates packaging of deliverable ZIP archive
│
├── README.md                        # Master project guide (this document)
├── requirements.txt                 # Python project dependencies
└── Secure_Python_Application_Week5.zip # Self-contained final submission archive
```

---

## 3. Vulnerabilities Identified & Fixed

| ID | Vulnerability Title | CWE | OWASP (2021) | Baseline CVSS | Hardened CVSS | Remediated Countermeasure |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **VULN-01** | SQL Injection (Auth & Search) | CWE-89 | A03: Injection | **9.8** (Critical) | **0.0** (None) | 100% Parameterized queries using `?` placeholders |
| **VULN-02** | Weak MD5 Password Hashing | CWE-328 | A07: Auth Failures | **8.1** (High) | **0.0** (None) | PBKDF2-HMAC-SHA256 (600,000 rounds) + unique 16B salt |
| **VULN-03** | Plaintext PHI/PII Storage at Rest | CWE-312 | A02: Cryptographic | **7.5** (High) | **0.0** (None) | Field-level authenticated AES-128-CBC + HMAC (Fernet) |
| **VULN-04** | Stored/Reflected XSS | CWE-79 | A03: Injection | **7.3** (High) | **0.0** (None) | Markupsafe contextual HTML escaping + CSP headers |
| **VULN-05** | OS Command Injection | CWE-78 | A03: Injection | **9.8** (Critical) | **0.0** (None) | Native Python socket reachability (zero shell invocation) |
| **VULN-06** | Directory Path Traversal | CWE-22 | A01: Broken Access | **7.5** (High) | **0.0** (None) | Character whitelist + `realpath` + `commonpath` boundary check |
| **VULN-07** | Insecure Pickle Deserialization | CWE-502 | A08: Data Integrity| **9.8** (Critical) | **0.0** (None) | Migrated to JSON + HMAC-SHA256 signature verification |
| **VULN-08** | Insecure Direct Object Reference | CWE-639 | A01: Broken Access | **6.5** (Medium) | **0.0** (None) | Role-Based Access Control (RBAC) + ownership validation |
| **VULN-09** | Missing Brute-Force Rate Limiting | CWE-307 | A07: Auth Failures | **7.5** (High) | **0.0** (None) | 5-attempt threshold with automated 5-minute account lockout |
| **VULN-10** | Security Misconfiguration & Cookies | CWE-693 | A05: Misconfig | **7.5** (High) | **0.0** (None) | `debug=False`, CSP, HSTS, `HttpOnly`/`SameSite=Lax` cookies |

---

## 4. Installation & Quickstart

### Prerequisites
* Python 3.10+ (tested on Python 3.14.6)
* Git

### Step 1: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 2: Run the Automated Security Audit Pipeline
To execute Bandit static analysis, run the unit/functional test suite, and print a consolidated comparison scorecard:
```bash
python scripts/run_audit.py
```

### Step 3: Run the Attack Simulation Harness
To watch an automated side-by-side demonstration of all 10 exploits succeeding on the vulnerable app and failing on the hardened app:
```bash
python scripts/simulate_attacks.py
```

### Step 4: Run the Complete Pytest Suite
```bash
python -m pytest tests -v
```
To run with test coverage reporting:
```bash
python -m pytest tests --cov=secure_app --cov-report=term-missing
```

---

## 5. Running the Applications

### 5.1 Hardened Secure Application
#### Running the Web Application & REST API
```bash
python -m secure_app.app
```
* Server binds to `http://127.0.0.1:5000` with `debug=False`.
* Standard accounts seeded in the database:
  * **Administrator:** `admin` / `AdminPass123!`
  * **Doctor:** `dr_smith` / `DoctorSecret!`
  * **Nurse:** `nurse_jane` / `NursePass2026!`
  * **Patient:** `john_doe` / `Password123!`

#### Using the Secure CLI Interface
Authenticate and obtain a signed session token:
```bash
python -m secure_app.cli login --username dr_smith --password DoctorSecret!
```
Search patient records safely:
```bash
python -m secure_app.cli search --query "John" --token <SIGNED_TOKEN>
```
Safely retrieve patient details:
```bash
python -m secure_app.cli view --id 1 --token <SIGNED_TOKEN>
```
Safely read report documents:
```bash
python -m secure_app.cli read-file --file "annual_report_2026.txt" --token <SIGNED_TOKEN>
```

---

## 6. Deliverable Artifacts

1. **`reports/Security_Audit_Report.pdf`**: Multi-page PDF report generated with ReportLab.
2. **`reports/SECURITY_AUDIT_REPORT.md`**: In-depth Markdown report documenting each vulnerability, exploit scenario, and code fix.
3. **`reports/APPLIED_SECURITY_MEASURES.md`**: Architectural breakdown of encryption, password derivation, RBAC, and input sanitization.
4. **`reports/THREAT_MODEL_MATRIX.md`**: STRIDE threat model, DREAD scoring, and CVSS v3.1 vector breakdown.
5. **`Secure_Python_Application_Week5.zip`**: Self-contained archive containing all code, tests, reports, and scripts.

To re-package the final ZIP archive at any time:
```bash
python scripts/package_deliverables.py
```
