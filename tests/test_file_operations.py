import hashlib
import io
import sqlite3

import pytest

from app import create_app
from app.config import Config


@pytest.fixture
def client(tmp_path, monkeypatch):

    database_path = tmp_path / "test_safevault.db"
    storage_path = tmp_path / "uploads"

    monkeypatch.setattr(
        Config,
        "DATABASE_PATH",
        str(database_path)
    )

    monkeypatch.setattr(
        Config,
        "STORAGE_PATH",
        str(storage_path)
    )

    app = create_app()

    app.config["TESTING"] = True
    app.config["SECRET_KEY"] = "test-secret-key"

    return (
        app.test_client(),
        database_path,
        storage_path
    )


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


def test_upload_requires_login(client):

    test_client, _, _ = client

    response = test_client.post(
        "/files/upload",
        data={
            "file": (
                io.BytesIO(b"hello"),
                "notes.txt"
            )
        },
        content_type="multipart/form-data",
    )

    assert response.status_code == 401


def test_upload_requires_file(client):

    test_client, _, _ = client

    register_and_login(test_client)

    response = test_client.post(
        "/files/upload",
        data={},
        content_type="multipart/form-data",
    )

    assert response.status_code == 400


def test_upload_rejects_unsupported_extension(client):

    test_client, _, _ = client

    register_and_login(test_client)

    response = test_client.post(
        "/files/upload",
        data={
            "file": (
                io.BytesIO(b"print('hello')"),
                "script.exe"
            )
        },
        content_type="multipart/form-data",
    )

    assert response.status_code == 400


def test_successful_upload_saves_file_and_metadata(client):

    test_client, database_path, storage_path = client

    register_and_login(test_client)

    file_content = b"SafeVault test document"

    response = test_client.post(
        "/files/upload",
        data={
            "file": (
                io.BytesIO(file_content),
                "notes.txt"
            )
        },
        content_type="multipart/form-data",
    )

    assert response.status_code == 201

    response_data = response.get_json()

    expected_hash = hashlib.sha256(
        file_content
    ).hexdigest()

    assert response_data["original_name"] == "notes.txt"
    assert response_data["file_size"] == len(file_content)
    assert response_data["sha256_hash"] == expected_hash

    stored_files = list(storage_path.iterdir())

    assert len(stored_files) == 1
    assert stored_files[0].read_bytes() == file_content

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
    assert row["is_encrypted"] == 0


def test_uploads_with_same_name_do_not_overwrite(client):

    test_client, _, storage_path = client

    register_and_login(test_client)

    first_response = test_client.post(
        "/files/upload",
        data={
            "file": (
                io.BytesIO(b"first"),
                "notes.txt"
            )
        },
        content_type="multipart/form-data",
    )

    second_response = test_client.post(
        "/files/upload",
        data={
            "file": (
                io.BytesIO(b"second"),
                "notes.txt"
            )
        },
        content_type="multipart/form-data",
    )

    assert first_response.status_code == 201
    assert second_response.status_code == 201

    first_name = first_response.get_json()["stored_name"]
    second_name = second_response.get_json()["stored_name"]

    assert first_name != second_name
    assert len(list(storage_path.iterdir())) == 2