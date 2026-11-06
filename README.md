# SafeVault --- Secure File Management System

**Live application:** https://safevault-efou.onrender.com\
**GitHub repository:** https://github.com/iwilltell/SafeVault

SafeVault is an educational secure file management system built with
Python and Flask. It demonstrates user authentication, two-factor
authentication, encrypted file storage, file sharing, access
permissions, basic threat detection, and security activity logging.

> **Important:** SafeVault is an academic prototype, not a
> production-grade security or antivirus product. The free Render
> deployment uses temporary local storage. Accounts, database records,
> and uploaded files may be lost when the service restarts or redeploys.
> Use dummy accounts and non-sensitive test files only.

## Features

-   **Authentication:** Registration, login, Argon2 password hashing,
    sessions, and logout.
-   **Two-factor authentication:** QR-code setup, TOTP verification, and
    enable/disable controls.
-   **File management:** Upload, download, Fernet encryption, SHA-256
    integrity verification, and metadata.
-   **File sharing:** Read/write permissions, permission updates, and
    access revocation.
-   **Threat detection:** Filename and extension validation,
    suspicious-input checks, basic path-traversal/injection pattern
    detection, EICAR test-signature detection, and basic executable
    identification.
-   **Audit logging:** Records important account, file, and security
    events.

Threat detection is heuristic and educational. It is not a replacement
for professional antivirus software and does not guarantee that files
are safe.

## Technology stack

  Area                        Technology
  --------------------------- -------------------------
  Backend                     Python, Flask
  Database                    SQLite
  Frontend                    HTML, CSS, JavaScript
  Password hashing            Argon2
  File encryption             Fernet (`cryptography`)
  Integrity checking          SHA-256
  Two-factor authentication   PyOTP
  QR-code generation          qrcode, Pillow
  Testing                     Pytest
  Production server           Gunicorn
  Hosting                     Render

## Project structure

``` text
SafeVault/
├── app/
│   ├── auth/
│   ├── audit/
│   ├── database/
│   ├── files/
│   ├── security/
│   ├── services/
│   ├── static/
│   │   ├── css/
│   │   └── js/
│   ├── templates/
│   ├── config.py
│   └── __init__.py
├── tests/
├── instance/
├── requirements.txt
└── run.py
```

## Run locally

### Prerequisites

-   Python 3.13 or a compatible Python version
-   Git

### 1. Clone the repository

``` bash
git clone https://github.com/iwilltell/SafeVault.git
cd SafeVault
```

### 2. Create and activate a virtual environment

Windows PowerShell:

``` powershell
python -m venv venv
venv\Scripts\activate
```

### 3. Install dependencies

``` powershell
pip install -r requirements.txt
```

### 4. Configure environment variables

Create a `.env` file in the project root. Generate a Fernet key:

``` powershell
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Generate a Flask secret:

``` powershell
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Example `.env`:

``` env
FLASK_SECRET_KEY=replace_with_a_generated_secret
SAFEVAULT_ENCRYPTION_KEY=replace_with_your_generated_fernet_key
DATABASE_PATH=instance/safevault.sqlite3
STORAGE_PATH=instance/uploads
MAX_CONTENT_LENGTH_MB=10
SESSION_COOKIE_SECURE=false
```

Keep `.env` private. Never commit it or publish the secret values. Back
up the encryption key securely: files encrypted with a key cannot be
decrypted if that key is lost.

### 5. Start the application

``` powershell
python run.py
```

Open http://127.0.0.1:5000 in your browser.

## Run tests

``` powershell
python -m pytest
```

The project reached **99 passing tests** in the development environment.
Run the command against the current checkout to verify its present
state.

## Render deployment

**Live application:** https://safevault-efou.onrender.com

Render service configuration:

  Setting         Value
  --------------- -----------------------------------
  Runtime         Python
  Branch          `main`
  Build command   `pip install -r requirements.txt`
  Start command   `gunicorn run:app`

Configure these environment variables in the Render dashboard. Do not
put secret values in this README or in Git:

``` text
FLASK_SECRET_KEY=<your generated Flask secret>
SAFEVAULT_ENCRYPTION_KEY=<your generated Fernet key>
DATABASE_PATH=/tmp/safevault.sqlite3
STORAGE_PATH=/tmp/safevault_uploads
SESSION_COOKIE_SECURE=true
```

### Free-tier storage limitation

The free Render web service has an ephemeral filesystem. SQLite data and
locally stored encrypted uploads can disappear after restarts,
redeployments, or instance replacement. This deployment is intended for
demonstration. Do not use it for confidential or important files.

For durable use, migrate to a persistent database and external object
storage, and configure backups and access controls.

## Demo account

There is no guaranteed pre-created demo account. To try the application,
open the live URL and register an account using an email address you
control.

If a dedicated shared demo account is created later, its credentials can
be added here. Do not publish credentials for a personal account. A
public shared account should contain only disposable test data.

## Development workflow

The project uses Git and GitHub for version control. Feature branches
are used for development, and tested changes are merged into `main`.

``` bash
git switch -c feature/your-feature
# Make and test your changes
git add .
git commit -m "feat: describe your change"
git push origin feature/your-feature
```

## Future improvements

-   Persistent database and cloud file storage
-   File version history
-   More comprehensive security scanning
-   Improved activity analytics
-   Further UI and accessibility improvements

## Academic project

**Project:** SafeVault --- Secure File Management System\
**Course:** CSE316 --- Operating Systems\
**Purpose:** Educational demonstration of file management,
authentication, access control, encryption, integrity checking, and
security monitoring.

## Disclaimer

SafeVault is an educational prototype. It has not been independently
security-audited and should not be used to store confidential,
regulated, or irreplaceable information. 

I hope you like our project.

