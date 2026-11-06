from cryptography.fernet import Fernet, InvalidToken
from flask import current_app


class EncryptionError(Exception):
    """Raised when encryption or decryption fails."""


def get_cipher():
    key = current_app.config.get("ENCRYPTION_KEY")

    if not key:
        raise EncryptionError("Encryption key is not configured.")

    try:
        return Fernet(key.encode("utf-8"))
    except (ValueError, TypeError):
        raise EncryptionError("Encryption key is invalid.")


def encrypt_file(file_content: bytes) -> bytes:
    if not isinstance(file_content, bytes):
        raise TypeError("File content must be bytes.")

    try:
        return get_cipher().encrypt(file_content)
    except Exception as exc:
        raise EncryptionError("File encryption failed.") from exc


def decrypt_file(encrypted_content: bytes) -> bytes:
    if not isinstance(encrypted_content, bytes):
        raise TypeError("Encrypted content must be bytes.")

    try:
        return get_cipher().decrypt(encrypted_content)
    except InvalidToken as exc:
        raise EncryptionError(
            "Decryption failed: invalid key or corrupted file."
        ) from exc
    except EncryptionError:
        raise
    except Exception as exc:
        raise EncryptionError("File decryption failed.") from exc