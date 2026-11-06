
import hashlib
import io
import sqlite3

import pytest

from cryptography.fernet import Fernet

from app import create_app
from app.config import Config
from app.files.encryption import decrypt_file
from app.security.threat_detector import EICAR_TEST_SIGNATURE


@pytest.fixture
def client(tmp_path, monkeypatch):
    database_path = tmp_path / "test_safevault.db"
    storage_path = tmp_path / "uploads"

    encryption_key = Fernet.generate_key().decode("utf-8")

    monkeypatch.setattr(
        Config,
        "DATABASE_PATH",
        str(database_path),
    )

    monkeypatch.setattr(
        Config,
        "STORAGE_PATH",
        str(storage_path),
    )

    monkeypatch.setattr(
        Config,
        "ENCRYPTION_KEY",
        encryption_key,
    )

    app = create_app()
    app.config["TESTING"] = True
    app.config["SECRET_KEY"] = "test-secret-key"

    return app.test_client(), database_path, storage_path, app


def register_and_login(client):
    client.post(
        "/auth/register",
        json={
            "username": "master",
            "email": "master@example.com",
            "password": "SafeVaultPassword123!",
        },
    )

    return client.post(
        "/auth/login",
        json={
            "username": "master",
            "password": "SafeVaultPassword123!",
        },
    )


# ============================================================
# BASIC FILE UPLOAD TESTS
# ============================================================

def test_upload_requires_login(client):
    test_client, _, _, _ = client

    response = test_client.post(
        "/files/upload",
        data={
            "file": (io.BytesIO(b"hello"), "notes.txt")
        },
        content_type="multipart/form-data",
    )

    assert response.status_code == 401


def test_upload_requires_file(client):
    test_client, _, _, _ = client
    register_and_login(test_client)

    response = test_client.post(
        "/files/upload",
        data={},
        content_type="multipart/form-data",
    )

    assert response.status_code == 400


def test_upload_rejects_unsupported_extension(client):
    test_client, _, _, _ = client
    register_and_login(test_client)

    response = test_client.post(
        "/files/upload",
        data={
            "file": (io.BytesIO(b"test"), "script.exe")
        },
        content_type="multipart/form-data",
    )

    assert response.status_code == 400


def test_successful_upload_stores_encrypted_file_and_metadata(client):
    test_client, database_path, storage_path, app = client
    register_and_login(test_client)

    file_content = b"SafeVault confidential test document"
    expected_hash = hashlib.sha256(file_content).hexdigest()

    response = test_client.post(
        "/files/upload",
        data={
            "file": (io.BytesIO(file_content), "notes.txt")
        },
        content_type="multipart/form-data",
    )

    assert response.status_code == 201

    response_data = response.get_json()

    assert response_data["original_name"] == "notes.txt"
    assert response_data["file_size"] == len(file_content)
    assert response_data["sha256_hash"] == expected_hash
    assert response_data["is_encrypted"] is True

    stored_files = list(storage_path.iterdir())

    assert len(stored_files) == 1

    encrypted_content = stored_files[0].read_bytes()

    assert encrypted_content != file_content

    with app.app_context():
        decrypted_content = decrypt_file(encrypted_content)

    assert decrypted_content == file_content

    connection = sqlite3.connect(database_path)
    connection.row_factory = sqlite3.Row

    row = connection.execute(
        """
        SELECT *
        FROM files
        WHERE original_name = ?
        """,
        ("notes.txt",),
    ).fetchone()

    connection.close()

    assert row is not None
    assert row["file_size"] == len(file_content)
    assert row["sha256_hash"] == expected_hash
    assert row["is_encrypted"] == 1


def test_uploads_with_same_name_do_not_overwrite(client):
    test_client, _, storage_path, _ = client
    register_and_login(test_client)

    first_response = test_client.post(
        "/files/upload",
        data={
            "file": (io.BytesIO(b"first"), "notes.txt")
        },
        content_type="multipart/form-data",
    )

    second_response = test_client.post(
        "/files/upload",
        data={
            "file": (io.BytesIO(b"second"), "notes.txt")
        },
        content_type="multipart/form-data",
    )

    assert first_response.status_code == 201
    assert second_response.status_code == 201

    first_name = first_response.get_json()["stored_name"]
    second_name = second_response.get_json()["stored_name"]

    assert first_name != second_name
    assert len(list(storage_path.iterdir())) == 2


# ============================================================
# THREAT DETECTION INTEGRATION TESTS
# ============================================================

def test_upload_rejects_windows_executable_disguised_as_txt(client):
    test_client, _, _, _ = client
    register_and_login(test_client)

    suspicious_content = b"MZ" + b"Suspicious executable content"

    response = test_client.post(
        "/files/upload",
        data={
            "file": (
                io.BytesIO(suspicious_content),
                "notes.txt",
            )
        },
        content_type="multipart/form-data",
    )

    assert response.status_code == 400
    assert b"windows_executable" in response.data


def test_rejected_threat_is_not_stored_or_registered(client):
    test_client, database_path, storage_path, _ = client
    register_and_login(test_client)

    suspicious_content = b"MZ" + b"Suspicious executable content"

    response = test_client.post(
        "/files/upload",
        data={
            "file": (
                io.BytesIO(suspicious_content),
                "suspicious.txt",
            )
        },
        content_type="multipart/form-data",
    )

    assert response.status_code == 400

    # A rejected upload must not create or store a file.
    assert (
        not storage_path.exists()
        or len(list(storage_path.iterdir())) == 0
    )

    connection = sqlite3.connect(database_path)

    file_count = connection.execute(
        """
        SELECT COUNT(*)
        FROM files
        WHERE original_name = ?
        """,
        ("suspicious.txt",),
    ).fetchone()[0]

    threat_count = connection.execute(
        """
        SELECT COUNT(*)
        FROM audit_events
        WHERE event_type = ?
        """,
        ("THREAT_DETECTED",),
    ).fetchone()[0]

    connection.close()

    assert file_count == 0
    assert threat_count >= 1


def test_upload_rejects_eicar_test_signature(client):
    test_client, _, storage_path, _ = client
    register_and_login(test_client)

    response = test_client.post(
        "/files/upload",
        data={
            "file": (
                io.BytesIO(EICAR_TEST_SIGNATURE),
                "test.txt",
            )
        },
        content_type="multipart/form-data",
    )

    assert response.status_code == 400
    assert b"eicar_test_signature" in response.data

    # A rejected EICAR test file must not be stored.
    assert (
        not storage_path.exists()
        or len(list(storage_path.iterdir())) == 0
    )
