# Security notes

Use this file to record design decisions and limitations as you learn.

- Passwords: store password hashes, never plaintext passwords.
- Authentication: protect sessions and verify authorization server-side.
- File storage: use generated storage names and prevent path traversal.
- Encryption: use established cryptographic libraries and document key handling.
- Upload scanning: never execute uploaded files; scanning is educational only.
- Logging: never log passwords, OTPs, session secrets or encryption keys.
- Buffer overflow: explain the limits of Python-level validation accurately.
