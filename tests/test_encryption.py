import pytest

from cryptography.fernet import Fernet

from app import create_app
from app.config import Config
from app.files.encryption import (
    encrypt_file,
    decrypt_file,
    EncryptionError,
)


@pytest.fixture
def app_context(tmp_path, monkeypatch):
    database_path = tmp_path / "test_safevault.db"

    monkeypatch.setattr(
        Config,
        "DATABASE_PATH",
        str(database_path),
    )

    monkeypatch.setattr(
        Config,
        "STORAGE_PATH",
        str(tmp_path / "uploads"),
    )

    monkeypatch.setattr(
        Config,
        "ENCRYPTION_KEY",
        Fernet.generate_key().decode("utf-8"),
    )

    app = create_app()
    app.config["TESTING"] = True

    with app.app_context():
        yield app


def test_encrypt_and_decrypt_file(app_context):
    original_content = b"SafeVault confidential document"

    encrypted_content = encrypt_file(original_content)
    decrypted_content = decrypt_file(encrypted_content)

    assert encrypted_content != original_content
    assert decrypted_content == original_content


def test_encryption_uses_different_ciphertext_each_time(app_context):
    original_content = b"SafeVault test document"

    first_encryption = encrypt_file(original_content)
    second_encryption = encrypt_file(original_content)

    assert first_encryption != second_encryption


def test_decryption_rejects_invalid_ciphertext(app_context):
    with pytest.raises(EncryptionError):
        decrypt_file(b"this is not valid encrypted content")


def test_encryption_rejects_non_bytes(app_context):
    with pytest.raises(TypeError):
        encrypt_file("plain text")


def test_decryption_rejects_non_bytes(app_context):
    with pytest.raises(TypeError):
        decrypt_file("encrypted text")


def test_encryption_requires_configured_key(app_context):
    app_context.config["ENCRYPTION_KEY"] = None

    with pytest.raises(EncryptionError):
        encrypt_file(b"secret")