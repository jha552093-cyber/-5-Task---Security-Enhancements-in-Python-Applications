# Technical Guide: Applied Security Measures & Architecture

**Document Version:** 2.0.0  
**Application:** MedSecure Healthcare Portal (Hardened Architecture)  
**Standard References:** NIST SP 800-63B, OWASP ASVS v4.0, HIPAA Security Rule (45 CFR § 164.312), CIS Benchmarks  

---

## 1. Architectural Security Blueprint

The hardened MedSecure application architecture employs a **Defense-in-Depth** multi-layered security strategy. Security is enforced at every boundary: HTTP transport, request middleware, authentication decorators, domain validators, database queries, and data storage.

```
                      +---------------------------------------+
                      |         HTTP Client / Browser         |
                      +---------------------------------------+
                                          |
                                          | [HTTPS / TLS]
                                          v
                      +---------------------------------------+
                      |       Security Headers Middleware     |
                      |  - Content-Security-Policy            |
                      |  - X-Frame-Options: DENY              |
                      |  - X-Content-Type-Options: nosniff    |
                      |  - Strict-Transport-Security          |
                      +---------------------------------------+
                                          |
                                          v
                      +---------------------------------------+
                      |      Input Validation & Sanitization  |
                      |  - Regex Schema Whitelisting          |
                      |  - Markupsafe Context HTML Escaping   |
                      |  - Path Canonicalization (Realpath)   |
                      |  - Shell Subprocess Elimination       |
                      +---------------------------------------+
                                          |
                                          v
                      +---------------------------------------+
                      |     Authentication & Authorization    |
                      |  - PBKDF2-HMAC-SHA256 (600,000 rds)   |
                      |  - Account Lockout (5 failed attempts)|
                      |  - Signed HMAC-SHA256 Session Tokens  |
                      |  - Role-Based Access Control (RBAC)   |
                      |  - Object Ownership Verification(IDOR)|
                      +---------------------------------------+
                                          |
                                          v
                      +---------------------------------------+
                      |      Field-Level Cryptography (AEAD)  |
                      |  - AES-128-CBC + HMAC-SHA256 (Fernet) |
                      |  - Display Masking (SSN, Credit Card) |
                      |  - Dynamic CSPRNG Key Derivation      |
                      +---------------------------------------+
                                          |
                                          v
                      +---------------------------------------+
                      |       Secure Database & Storage       |
                      |  - 100% Parameterized SQL ('?')       |
                      |  - Encrypted PII/PHI Columns          |
                      |  - Safe JSON Serialization + HMAC     |
                      |  - Zero Pickle Deserialization        |
                      +---------------------------------------+
```

---

## 2. Cryptographic Security Measures

### 2.1 Password Storage & Derivation (NIST SP 800-63B Compliant)
* **Vulnerability Addressed:** CWE-328 (Weak Cryptographic Hash), CWE-259 (Hardcoded Passwords).
* **Implementation Module:** `secure_app/crypto.py`
* **Algorithm:** PBKDF2 (Password-Based Key Derivation Function 2) using HMAC-SHA256.
* **Work Factor (Iterations):** 600,000 iterations (meeting current OWASP and NIST recommendations for high-security environments).
* **Salt Management:** Unique 16-byte cryptographically secure random salt generated per-user using `secrets.token_bytes(16)`.
* **Storage Format:** `pbkdf2:sha256:600000$<salt_hex>$<hash_hex>`
* **Verification:** Constant-time comparison via `hmac.compare_digest` to neutralize side-channel timing attacks (CWE-208).

### 2.2 Field-Level Authenticated Encryption at Rest (AEAD)
* **Vulnerability Addressed:** CWE-312 (Cleartext Storage of Sensitive Information), HIPAA 45 CFR § 164.312(a)(2)(iv).
* **Implementation Module:** `secure_app/crypto.py`
* **Algorithm:** Fernet (AES in CBC mode with 128-bit key, PKCS7 padding, authenticated via HMAC-SHA256).
* **Encrypted Attributes:** Social Security Number (`ssn_encrypted`), Medical Diagnosis (`diagnosis_encrypted`), Payment Card (`credit_card_encrypted`).
* **Integrity Guarantee:** Any ciphertext tampering or byte manipulation causes HMAC validation failure and raises `InvalidToken`, preventing chosen-ciphertext and bit-flipping attacks.

### 2.3 Display Masking
* **Functions:** `mask_ssn()`, `mask_credit_card()`
* **Mechanism:** Sensitive identifiers are dynamically masked on retrieval based on role authorization:
  * SSN: Masked to `***-**-3456` for non-physicians.
  * Credit Card: Masked to `****-****-****-4444` for general viewing.

### 2.4 Cryptographically Signed Session Tokens
* **Vulnerability Addressed:** CWE-384 (Session Fixation), CWE-287 (Improper Authentication).
* **Token Structure:** `base64_url(payload).hmac_sha256_signature`
* **Security Controls:**
  * Contains issue timestamp (`_iat`) and expiration timestamp (`_exp`).
  * Default lifetime of 1,800 seconds (30 minutes).
  * Validated using `hmac.compare_digest` with application master key.
  * Forged or tampered tokens are rejected instantly.

---

## 3. Input Validation, Sanitization & Defense-in-Depth

### 3.1 Strict Input Whitelisting Schemas
* **Implementation Module:** `secure_app/validator.py`
* **Principles Applied:** Reject by default; accept only known-good patterns.
* **Validation Rules:**
  * **Usernames:** `^[a-zA-Z0-9_-]{3,30}$` (Disallows SQL/shell/HTML metacharacters).
  * **Emails:** RFC 5322 compliant regex, max length 254 bytes.
  * **Social Security Numbers:** Strict format `^\d{3}-\d{2}-\d{4}$`.
  * **Dates:** ISO 8601 `YYYY-MM-DD` strictly enforced.
  * **Credit Cards:** Luhn Modulo-10 checksum validation combined with length verification (13-19 digits).
  * **Password Complexity:** Enforces minimum 8 characters, at least 1 uppercase, 1 lowercase, 1 digit, and 1 special symbol.

### 3.2 Context-Aware Output Encoding (XSS Mitigation)
* **Vulnerability Addressed:** CWE-79 (Cross-Site Scripting).
* **Library:** `markupsafe.escape`
* **Mechanism:** Converts HTML control characters into HTML character entities:
  * `&` -> `&amp;`
  * `<` -> `&lt;`
  * `>` -> `&gt;`
  * `"` -> `&quot;`
  * `'` -> `&#39;`
* This neutralizes `<script>`, `<img>`, `<iframe>`, and event handler injections.

### 3.3 Directory Path Traversal Prevention
* **Vulnerability Addressed:** CWE-22 (Path Traversal).
* **Implementation Module:** `secure_app/storage.py`
* **Multi-Step Defense Pipeline:**
  1. **Character Filtering:** Rejects any filename containing `/`, `\`, `..`, or `\x00`.
  2. **Extension Whitelisting:** Permits only `.txt`, `.pdf`, `.csv`, `.json`.
  3. **Path Canonicalization:** Resolves symlinks and relative elements via `os.path.realpath`.
  4. **Boundary Containment Check:** Asserts that `os.path.commonpath([base_dir, target_real]) == base_dir`.

### 3.4 Command Injection Mitigation via Subprocess Elimination
* **Vulnerability Addressed:** CWE-78 (OS Command Injection).
* **Implementation Module:** `secure_app/app.py`
* **Remediation:** Removed `subprocess.Popen` and `shell=True` entirely. Network reachability checks use Python's native `socket.gethostbyname` with strict timeout controls. User input is validated against `ipaddress.ip_address` or strict FQDN regexes.

---

## 4. Authentication, Authorization & Access Control

### 4.1 Role-Based Access Control (RBAC)
* **Vulnerability Addressed:** CWE-284 (Improper Access Control).
* **Roles Defined:**
  * `admin`: System configuration, audit logs, system backups, network diagnostics.
  * `doctor`: Create/view all patient clinical records, full unmasked medical notes.
  * `nurse`: View patient records with masked SSN/CC.
  * `patient`: View strictly own records.
* **Enforcement:** `@require_auth` and `@require_roles(*roles)` Flask route decorators.

### 4.2 Insecure Direct Object Reference (IDOR) Protection
* **Vulnerability Addressed:** CWE-639 (Authorization Bypass Through User-Controlled Key).
* **Mechanism:** When accessing `/api/records/<record_id>`, the application verifies whether the requesting user is a clinical professional (`doctor`/`admin`/`nurse`) or the specific patient that owns the record (`record.created_by == current_user.user_id`). Unauthorized queries return HTTP 403 Forbidden.

### 4.3 Brute-Force Rate Limiting & Account Lockout
* **Vulnerability Addressed:** CWE-307 (Improper Restriction of Excessive Authentication Attempts).
* **Thresholds:**
  * Maximum 5 failed attempts per user account.
  * Upon 5th consecutive failure, account is locked for 300 seconds (5 minutes).
  * Successful authentication resets failed counter to 0.

---

## 5. Secure Data Storage & Safe Serialization

### 5.1 Parameterized SQL Queries (SQL Injection Defense)
* **Vulnerability Addressed:** CWE-89 (SQL Injection).
* **Implementation Module:** `secure_app/database.py`
* **Rule:** Zero string concatenation (`f"..."`, `+`, `%`, `.format()`) permitted in query construction. All queries use SQLite `?` placeholder parameter bindings.

### 5.2 Safe Serialization (Pickle Replacement)
* **Vulnerability Addressed:** CWE-502 (Insecure Deserialization).
* **Implementation Module:** `secure_app/storage.py`
* **Remediation:** `pickle` was completely removed from the project. Backup export/import uses standard JSON parsing (`json.loads`) combined with an HMAC-SHA256 digital signature. Unsigned or modified backup files are rejected prior to processing.

---

## 6. Security Misconfigurations & Auditing

### 6.1 Elimination of Hardcoded Secrets
* **Vulnerability Addressed:** CWE-798, CWE-259.
* **Mechanism:** Secret keys and encryption keys are loaded from environment variables (`MEDSECURE_SECRET_KEY`, `MEDSECURE_ENCRYPTION_KEY`). In development environments without configured environment variables, keys are generated via `secrets.token_hex(32)` / `Fernet.generate_key()` and cached in local files with restricted permissions.

### 6.2 HTTP Security Headers Suite
* **Vulnerability Addressed:** CWE-693, CWE-1004.
* **Headers Injected on Every Response:**
  * `Content-Security-Policy`: Disallows untrusted scripts, restricts object embeds.
  * `X-Content-Type-Options: nosniff`: Prevents MIME-confusion attacks.
  * `X-Frame-Options: DENY`: Prevents clickjacking in iframes.
  * `X-XSS-Protection: 1; mode=block`: Activates browser XSS filters.
  * `Strict-Transport-Security: max-age=31536000; includeSubDomains`: Enforces HTTPS.
  * `Referrer-Policy: strict-origin-when-cross-origin`: Restricts referrer data leakage.
  * `Cache-Control: no-store, no-cache, must-revalidate`: Prevents sensitive medical data caching on shared workstations.

### 6.3 Secure Audit Logging with PII Redaction
* **Vulnerability Addressed:** CWE-778 (Insufficient Logging), CWE-532 (Sensitive Information in Log File).
* **Implementation Module:** `secure_app/logger.py`
* **Mechanism:** Structured JSON log events record authentication attempts, authorization failures, and administrative actions. Automated regex redaction replaces SSNs (`***-**-****`), credit cards (`****-****-****-****`), and passwords (`[REDACTED]`) before logs are written to disk.

### 6.4 Sanitized Error Handlers
* **Vulnerability Addressed:** CWE-209 (Generation of Error Message Containing Sensitive Information).
* **Mechanism:** Flask `debug=False` is enforced. Uncaught exceptions return a generic message and a unique incident correlation UUID (`incident_id`), shielding internal file paths, module names, and SQL schema details from end users.
