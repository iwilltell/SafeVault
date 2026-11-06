# SafeVault — Secure File Management System

**Course:** CSE316 — Operating Systems  
**Implementation:** Python 3.13, Flask, SQLite  
**Project mode:** Solo, PC-only local web application

## Project purpose
SafeVault is an educational secure file-management application. The intended features are:
- Password-based registration and login
- Optional two-factor authentication (TOTP)
- Encrypted file storage
- User/owner-based access control and controlled sharing
- File operations: upload, download, read, write and metadata viewing
- Basic educational threat checks and security-event logging

> This repository is a learning scaffold, not a finished security product. Implement and understand each feature yourself. The CSE316 assignment brief says students must code the project themselves and warns that submitting copied or AI-generated code can result in zero marks. Use this scaffold to organize your work, then write, test, explain and document your own implementation.

## Three project modules
1. **Authentication and User Security** — registration, password hashing, 2FA and session handling.
2. **Secure File Management** — file operations, encryption, metadata, permissions and sharing.
3. **Threat Detection and Monitoring** — input/file validation, educational threat checks and audit events.

## Suggested development sequence
1. Environment and project structure
2. SQLite schema and database access
3. Password hashing and registration
4. Login, sessions and logout
5. TOTP two-factor authentication
6. File upload/download and safe storage paths
7. Encryption/decryption
8. Ownership, permissions and sharing
9. Metadata and audit logging
10. Educational threat checks
11. Glassmorphism PC dashboard
12. Tests, integration, report and presentation

## Setup (Windows PowerShell)
```powershell
py -3.13 -m venv venv
.env\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
Copy-Item .env.example .env
python run.py
```

If PowerShell blocks activation, use:
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.env\Scripts\Activate.ps1
```

Open the local address printed by Flask in your PC browser.

## Git workflow required by the assignment
Maintain **at least 7 meaningful revisions**, use clear commit messages, develop features on branches, test them, and merge into `main`.

Example:
```bash
git init
git add .
git commit -m "chore: create SafeVault project scaffold"
git branch -M main

git switch -c feature/database
# implement and test your database work
git add .
git commit -m "feat: add initial SQLite schema"
git switch main
git merge --no-ff feature/database
```

Repeat with separate branches such as `feature/auth`, `feature/two-factor`, `feature/file-encryption`, `feature/access-control`, `feature/threat-checks`, and `feature/dashboard`. Do not create empty commits just to reach seven revisions; each revision should represent real, tested progress.

## Security boundaries
- This is a local educational prototype, not production-ready cloud storage.
- Never store plaintext passwords. Use a vetted password-hashing library.
- Do not invent your own cryptographic algorithm.
- Keep secrets out of Git; `.env` is ignored.
- Treat uploaded files as untrusted. Validate names, sizes and paths; never execute uploaded files.
- The threat-check module is a demonstration, not a substitute for antivirus/EDR.
- Python input validation can demonstrate safe bounds checks, but it cannot claim to detect every native memory buffer overflow.
- Use synthetic test files and harmless test signatures only.

## LPU report checklist
The uploaded CSE316 brief specifies these report sections:
1. Project Overview
2. Module-Wise Breakdown
3. Functionalities
4. Technology Used (programming languages, libraries/tools, other tools)
5. Flow Diagram
6. Revision Tracking on GitHub (repository name and link)
7. Conclusion and Future Scope
8. References

Appendix:
- A. AI-generated project elaboration/breakdown report
- B. Problem statement
- C. Complete project code

The brief also requires a group project of at most 3 students, one integrated project, individual UMS submission, a presentation, documentation, and GitHub revision tracking. Follow your faculty's latest instructions and deadline.

## Current status
This is the initial scaffold. Features are intentionally marked TODO and will be implemented incrementally with tests and commits.
