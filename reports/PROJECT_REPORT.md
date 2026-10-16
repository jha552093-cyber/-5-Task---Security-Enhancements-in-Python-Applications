# PROJECT REPORT: SECURITY ENHANCEMENTS IN PYTHON APPLICATIONS
## MedSecure Healthcare Patient & Clinical Portal
**Course/Task:** Week 5 Task — Security Enhancements in Python Applications  
**Target Application:** MedSecure Clinical & Patient Portal  
**Document Type:** Final Comprehensive Project & Security Audit Report  
**GitHub Repository:** https://github.com/jha552093-cyber/-5-Task---Security-Enhancements-in-Python-Applications.git  

---

## 1. Executive Summary

Healthcare web applications manage sensitive personal information, including medical histories, doctor notes, Social Security Numbers (SSN), and credit card payments. If these applications are poorly coded, cybercriminals can steal patient identities, modify medical data, or take full control of the hospital server.

This project evaluated an application called the **MedSecure Healthcare Portal**. 
- In the initial assessment (the **vulnerable baseline**), the application suffered from **10 major security flaws**, including SQL injection, weak passwords, unencrypted patient data, cross-site scripting (XSS), and arbitrary command execution. Static security scanning with **Bandit detected 14 vulnerabilities**.
- We completely redesigned and re-engineered the software into a **hardened production-grade system (`secure_app`)**.
- After implementing modern defenses (parameterized queries, AES-128 encryption at rest, PBKDF2 password hashing, input sanitization, and role-based access control), a re-scan with Bandit showed **0 vulnerabilities (100% clean)**.
- All **36 automated test cases passed**, verifying that every single attack attempt is actively detected and blocked.

---

## 2. Project Architecture & Components

The project repository is structured with a clear separation between the vulnerable baseline and the secure version:

1. **`vulnerable_app/` (The Insecure Baseline):**
   A working Flask web application intentionally containing common security mistakes to demonstrate how hackers exploit real-world applications.

2. **`secure_app/` (The Hardened Application):**
   The production-ready, remediated application implementing defense-in-depth principles:
   - `crypto.py`: Cryptographic engine using PBKDF2-HMAC-SHA256 for passwords and Fernet AES for patient data.
   - `database.py`: Secure SQLite database using strictly parameterized queries.
   - `validator.py`: Input validation, HTML escaping, and path sanitization.
   - `auth.py`: Cryptographic HMAC session tokens and account lockout logic.
   - `storage.py`: Safe JSON-based storage and canonical path checking.
   - `logger.py`: Structured security event logging with automatic PII masking.
   - `config.py`: Hardened settings (debug mode disabled, secure cookie flags).

3. **`tests/` (Automated Security & Functional Testing):**
   A comprehensive test suite of 36 unit tests, cryptographic checks, and real-world exploit simulations.

4. **`static_analysis/` (Code Scanners):**
   Bandit configuration files and comparative scan reports proving the reduction of security issues from 14 down to 0.

5. **`reports/` (Audit Deliverables):**
   Full documentation in Markdown, PDF, and Microsoft Word format.

6. **`scripts/` (Automation):**
   Command-line tools to run audit comparisons, execute attack simulations, and build the deliverable package.

---

## 3. The 10 Vulnerabilities: What Was Wrong & How It Was Fixed

### Vulnerability 1: SQL Injection (SQLi)
* **The Problem:** The app combined user input directly into SQL commands using Python f-strings. An attacker could enter `admin' --` as a username to bypass password verification and log in as the administrator.
* **The Fix:** Replaced all string formatting with **parameterized queries** using SQLite `?` placeholders. The database now treats user input purely as plain text data, never as executable code.

### Vulnerability 2: Weak Password Storage (MD5)
* **The Problem:** Passwords were saved using unsalted MD5 hashes. Modern computers can reverse unsalted MD5 hashes in seconds using pre-calculated rainbow tables.
* **The Fix:** Upgraded password hashing to **PBKDF2-HMAC-SHA256 with 600,000 iterations** and a unique 256-bit random salt for every user. We also used `hmac.compare_digest` to prevent timing attacks.

### Vulnerability 3: Plaintext Sensitive Patient Data at Rest
* **The Problem:** Social Security Numbers (SSN), medical diagnoses, and credit card numbers were saved in clear text in the database. Anyone accessing the database file could read all patient records.
* **The Fix:** Applied **Fernet AES-128-CBC authenticated encryption** to all sensitive fields before writing them to the database. The data is encrypted at rest and can only be decrypted in memory with the secure master key.

### Vulnerability 4: Cross-Site Scripting (XSS)
* **The Problem:** User search input was reflected directly into the HTML response without sanitization. An attacker could inject malicious JavaScript (`<script>...</script>`) to steal cookies.
* **The Fix:** Implemented **context-aware HTML entity escaping** (`html.escape`) and configured Content-Security-Policy (CSP) headers to block unauthorized inline script execution.

### Vulnerability 5: Operating System Command Injection
* **The Problem:** The network diagnostic feature ran system commands via `subprocess.check_output(cmd, shell=True)`. An attacker could append `; whoami` or `&& cat /etc/passwd` to execute arbitrary server commands.
* **The Fix:** Completely removed the shell subprocess. Replaced it with **native Python socket connections** (`socket.create_connection`) to test host connectivity without spawning any OS commands.

### Vulnerability 6: Path Traversal (Arbitrary File Download)
* **The Problem:** The document download feature joined file paths naively. Attackers could supply `../../database.db` to download files outside the designated storage folder.
* **The Fix:** Implemented **canonical path boundary checking** using `os.path.realpath`. The system verifies that the resolved target path strictly resides inside the allowed directory.

### Vulnerability 7: Insecure Deserialization (Python Pickle)
* **The Problem:** Data backups were loaded using Python's `pickle.loads()`. Pickle can execute arbitrary code during unmarshaling, giving attackers instant Remote Code Execution.
* **The Fix:** Replaced pickle with **standard JSON serialization** combined with an **HMAC-SHA256 cryptographic signature** to ensure data integrity and prevent tampering.

### Vulnerability 8: Insecure Direct Object References (IDOR)
* **The Problem:** Patient records could be viewed by anyone who changed the record ID in the URL (`/api/records/2`), even without being logged in or without having permission.
* **The Fix:** Enforced **Role-Based Access Control (RBAC)** decorators (`@login_required`, `@role_required`). Doctors and admins can review records, while patients can only view their own records.

### Vulnerability 9: Missing Brute-Force & Rate Limiting Protection
* **The Problem:** Attackers could run automated scripts to try millions of passwords against user accounts without being stopped or slowed down.
* **The Fix:** Added an **automated account lockout system**. If an account fails authentication 5 consecutive times, it is locked for 5 minutes, and exponential delays are added to repeated requests.

### Vulnerability 10: Security Misconfigurations & Missing Security Headers
* **The Problem:** Flask debug mode was left enabled (`debug=True`), exposing an interactive web debugger on errors. Session cookies also lacked protection flags.
* **The Fix:** Disabled debug mode (`debug=False`), enabled secure cookie attributes (`HttpOnly=True`, `SameSite='Lax'`), and injected modern security headers (`X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Strict-Transport-Security`).

---

## 4. Verification & Testing Results

To verify that the fixes work under realistic conditions, the project underwent two independent evaluations:

### A. Static Code Analysis (Bandit Scanner)
* **Baseline Scan:** **14 vulnerabilities detected** (3 High severity, 8 Medium severity, 3 Low severity).
* **Hardened App Scan:** **0 vulnerabilities detected (100% clean)**.

### B. Automated Testing Suite (Pytest)
A comprehensive test suite of 36 automated tests was executed:
- `tests/test_crypto_validation.py`: 17 tests passed (verifying PBKDF2 salts, Fernet AES encryption, tamper resistance).
- `tests/test_functional.py`: 9 tests passed (verifying login workflows, RBAC permissions, audit logging).
- `tests/test_security_attacks.py`: 10 tests passed (simulating live SQLi, XSS, Command Injection, Path Traversal, and IDOR attacks).
- **Result:** **36 out of 36 tests passed (100% pass rate)**.

---

## 5. Industry Compliance Alignment

The security controls implemented in this project directly satisfy key regulatory mandates:
* **HIPAA Security Rule (45 CFR § 164.312):** Satisfies technical safeguards for data encryption at rest and in transit, access control, and audit trails.
* **NIST SP 800-63B:** Adheres to digital identity guidelines for secure password storage and brute-force mitigation.
* **OWASP Top 10 (2021):** Completely mitigates vulnerabilities in categories A01 (Broken Access Control), A02 (Cryptographic Failures), A03 (Injection), A05 (Security Misconfiguration), A07 (Authentication Failures), and A08 (Integrity Failures).
* **PCI-DSS v4.0:** Protects cardholder data through authenticated encryption and account lockout controls.

---

## 6. How to Run & Verify

All source code and test tools are ready to run in Python:

```bash
# 1. Run all 36 automated tests
py -m pytest

# 2. Run the live exploit simulation (side-by-side attack test)
py scripts/simulate_attacks.py

# 3. Run Bandit static analysis comparison
py scripts/run_audit.py

# 4. Generate the Word (.docx) report
py reports/generate_docx_report.py
```

---

## 7. Conclusion

This project successfully demonstrates the identification, exploitation analysis, and comprehensive defense-in-depth remediation of critical vulnerabilities in a Python web application. By replacing unsafe anti-patterns with parameterized database queries, authenticated field-level encryption, safe serialization, and granular access control, the MedSecure portal achieves an enterprise-grade security posture with zero static analysis flaws and 100% exploit prevention.
