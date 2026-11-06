import io

import pytest
from cryptography.fernet import Fernet

from app import create_app
from app.config import Config
from app.database.db import execute_query, fetch_one


@pytest.fixture
def client(tmp_path, monkeypatch):

    database_path = tmp_path / "test_safevault.db"
    storage_path = tmp_path / "uploads"

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
        Fernet.generate_key().decode("utf-8"),
    )

    app = create_app()
    app.config["TESTING"] = True
    app.config["SECRET_KEY"] = "test-secret-key"

    return app.test_client(), storage_path


def register_and_login(client, username="master", email="master@example.com"):

    registration = client.post(
        "/auth/register",
        json={
            "username": username,
            "email": email,
            "password": "SafeVaultPassword123!",
        },
    )

    assert registration.status_code == 201

    login = client.post(
        "/auth/login",
        json={
            "username": username,
            "password": "SafeVaultPassword123!",
        },
    )

    assert login.status_code == 200


def upload_test_file(client, content=b"Confidential SafeVault document"):

    response = client.post(
        "/files/upload",
        data={
            "file": (
                io.BytesIO(content),
                "confidential.txt",
            )
        },
        content_type="multipart/form-data",
    )

    assert response.status_code == 201

    return response.get_json()["file_id"]


def test_file_listing_requires_login(client):

    test_client, _ = client

    response = test_client.get("/files")

    assert response.status_code == 401


def test_user_can_list_own_files(client):

    test_client, _ = client

    register_and_login(test_client)

    upload_test_file(test_client)

    response = test_client.get("/files")

    assert response.status_code == 200

    data = response.get_json()

    assert data["count"] == 1
    assert data["files"][0]["original_name"] == "confidential.txt"
    assert data["files"][0]["access_type"] == "owner"


def test_download_requires_login(client):

    test_client, _ = client

    response = test_client.get("/files/1/download")

    assert response.status_code == 401


def test_owner_can_download_and_decrypt_file(client):

    test_client, _ = client

    register_and_login(test_client)

    original_content = b"Confidential SafeVault document"

    file_id = upload_test_file(
        test_client,
        original_content,
    )

    response = test_client.get(
        f"/files/{file_id}/download"
    )

    assert response.status_code == 200
    assert response.data == original_content
    assert "attachment" in response.headers["Content-Disposition"]
    assert "confidential.txt" in response.headers["Content-Disposition"]


def test_other_user_cannot_download_private_file(client):

    test_client, _ = client

    register_and_login(test_client)

    file_id = upload_test_file(test_client)

    test_client.post("/auth/logout")

    register_and_login(
        test_client,
        username="reader",
        email="reader@example.com",
    )

    response = test_client.get(
        f"/files/{file_id}/download"
    )

    assert response.status_code == 404


def test_shared_user_with_read_permission_can_download(client):

    test_client, _ = client

    register_and_login(test_client)

    file_id = upload_test_file(test_client)

    owner = fetch_one(
        "SELECT id FROM users WHERE username = ?",
        ("master",),
    )

    test_client.post("/auth/logout")

    register_and_login(
        test_client,
        username="reader",
        email="reader@example.com",
    )

    reader = fetch_one(
        "SELECT id FROM users WHERE username = ?",
        ("reader",),
    )

    execute_query(
        """
        INSERT INTO shares (
            file_id,
            user_id,
            shared_by_id,
            permission
        )
        VALUES (?, ?, ?, ?)
        """,
        (
            file_id,
            reader["id"],
            owner["id"],
            "read",
        ),
    )

    response = test_client.get(
        f"/files/{file_id}/download"
    )

    assert response.status_code == 200
    assert response.data == b"Confidential SafeVault document"


def test_download_rejects_modified_file_integrity(client):

    test_client, storage_path = client

    register_and_login(test_client)

    file_id = upload_test_file(test_client)

    file_record = fetch_one(
        "SELECT stored_name FROM files WHERE id = ?",
        (file_id,),
    )

    stored_path = storage_path / file_record["stored_name"]

    # Replace the stored content with valid encryption of altered data.
    tampered_content = Fernet(
        Config.ENCRYPTION_KEY.encode("utf-8")
    ).encrypt(b"tampered plaintext")

    stored_path.write_bytes(tampered_content)

    response = test_client.get(
        f"/files/{file_id}/download"
    )

    assert response.status_code == 409
    assert response.get_json()["error"] == (
        "File integrity verification failed"
    )

    # Modify the encrypted file to simulate disk corruption.
    stored_path.write_bytes(b"tampered file content")

    response = test_client.get(
        f"/files/{file_id}/download"
    )

    assert response.status_code == 500
    assert response.get_json()["error"] == "Unable to decrypt file"


def test_download_returns_not_found_for_missing_file(client):

    test_client, _ = client

    register_and_login(test_client)

    response = test_client.get("/files/99999/download")

    assert response.status_code == 404