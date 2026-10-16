# MedSecure Portal: Threat Modeling Matrix & Risk Assessment

**Methodologies:** STRIDE Threat Modeling, CVSS v3.1, DREAD Risk Scoring  
**Target Architecture:** MedSecure Healthcare Patient & Clinical Portal  

---

## 1. Threat Actor Profiling

| Threat Actor Persona | Capabilities & Access Level | Primary Motivation | Likely Attack Vectors |
| :--- | :--- | :--- | :--- |
| **External Cybercriminal** | No prior system access, internet-facing network vantage | Financial extortion, medical identity theft, ransomware | SQL injection, OS command injection, pickle deserialization, brute-force |
| **Malicious Insider / Nurse** | Low-privilege authenticated user credentials | Unauthorized snooping into celebrity/family medical files | IDOR privilege escalation, cleartext database inspection |
| **Rogue Patient** | Patient-role credentials | Accessing clinical doctor notes, altering billing records | Parameter tampering, session token forgery, stored XSS |
| **Network Eavesdropper** | Man-in-the-Middle (MitM) position on hospital Wi-Fi | Intercepting credentials, medical telemetry | Session cookie hijacking, packet sniffing, unencrypted traffic |

---

## 2. Asset Classification Matrix

| Asset Description | Classification | Confidentiality Impact | Integrity Impact | Availability Impact |
| :--- | :--- | :--- | :--- | :--- |
| **Patient Protected Health Info (PHI)** | Critical (Tier 1) | **High** (HIPAA breach) | **High** (Falsified diagnosis) | Medium |
| **Social Security & Billing Numbers** | Critical (Tier 1) | **High** (Identity theft) | Medium | Low |
| **Physician & Admin Credentials** | High (Tier 2) | **High** (System takeover) | **High** (Data corruption) | **High** (Account lockout) |
| **Application Secret & Encryption Keys**| Critical (Tier 1) | **High** (Decryption of all PHI) | **High** (Signature forgery) | Medium |
| **System Audit Logs** | Medium (Tier 3) | Low | **High** (Evidence tampering)| Medium |

---

## 3. STRIDE Threat Assessment & Mitigation Matrix

### Comprehensive Threat Mapping

| Threat ID | STRIDE Category | Component / Endpoint | Threat Scenario | Pre-Mitigation Risk | Implemented Countermeasure | Post-Mitigation Risk |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **TH-01** | **Spoofing** | `/api/login` | Attacker bypasses authentication using `' OR 1=1 --` | **Critical** (DREAD: 9.6) | Strictly parameterized SQLite queries | **Low** (DREAD: 1.2) |
| **TH-02** | **Spoofing** | Session Tokens | Attacker alters base64 JSON payload to forge `admin` role | **High** (DREAD: 8.8) | Cryptographically signed HMAC-SHA256 tokens | **Low** (DREAD: 1.0) |
| **TH-03** | **Tampering** | `/api/backup/import` | Attacker injects malicious Pickle RCE gadget into backups | **Critical** (DREAD: 9.8) | Migrated to JSON + HMAC-SHA256 signature verification | **Low** (DREAD: 0.8) |
| **TH-04** | **Tampering** | `/api/notes/render` | Attacker injects persistent JavaScript into patient note | **High** (DREAD: 8.4) | Context-aware HTML entity escaping + CSP headers | **Low** (DREAD: 1.1) |
| **TH-05** | **Repudiation** | Audit Subsystem | Rogue doctor deletes records without audit trail | **Medium** (DREAD: 6.2) | Structured JSON logging with automated PII masking | **Low** (DREAD: 1.4) |
| **TH-06** | **Info Disclosure**| Database at Rest | Adversary steals SQLite file and reads SSN / CC / PHI | **High** (DREAD: 8.9) | Field-level Fernet AEAD encryption (AES-128 + HMAC) | **Low** (DREAD: 1.2) |
| **TH-07** | **Info Disclosure**| `/api/reports/download` | Directory traversal (`../../`) leaks system files | **High** (DREAD: 8.5) | Realpath canonicalization & commonpath containment | **Low** (DREAD: 0.9) |
| **TH-08** | **Info Disclosure**| Global Error Handler | Uncaught exception returns database schema & stack trace | **Medium** (DREAD: 6.5) | Sanitized JSON error handlers with incident UUIDs | **Low** (DREAD: 0.8) |
| **TH-09** | **Denial of Service**| `/api/login` | Automated botnet locks users out via brute-force | **High** (DREAD: 7.8) | IP/Account lockout (5 attempts / 5 mins) | **Low** (DREAD: 1.8) |
| **TH-10** | **Privilege Elevation**| `/api/records/<id>` | Patient modifies ID to view arbitrary medical records (IDOR) | **High** (DREAD: 8.7) | Role-Based Access Control (RBAC) + ownership check | **Low** (DREAD: 1.0) |

---

## 4. CVSS v3.1 Vector Breakdown Table

| Vuln ID | Vulnerability Name | CVSS v3.1 Vector String | Base Score | Severity |
| :--- | :--- | :--- | :--- | :--- |
| **VULN-01** | SQL Injection (Auth & Search) | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | **9.8** | Critical |
| **VULN-02** | Weak MD5 Password Hashing | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` | **8.1** | High |
| **VULN-03** | Plaintext PHI/PII Storage | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` | **7.5** | High |
| **VULN-04** | Stored/Reflected XSS | `CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:N` | **7.3** | High |
| **VULN-05** | OS Command Injection | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | **9.8** | Critical |
| **VULN-06** | Directory Path Traversal | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` | **7.5** | High |
| **VULN-07** | Insecure Deserialization (Pickle) | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | **9.8** | Critical |
| **VULN-08** | Insecure Direct Object Reference | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` | **6.5** | Medium |
| **VULN-09** | Missing Brute-Force Rate Limiting | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` | **7.5** | High |
| **VULN-10** | Security Misconfigurations (Debug/CSP)| `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` | **7.5** | High |
