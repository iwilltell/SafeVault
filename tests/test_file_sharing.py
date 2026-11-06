import io

import pytest
from cryptography.fernet import Fernet

from app import create_app
from app.config import Config
from app.database.db import fetch_one


@pytest.fixture
def sharing_setup(tmp_path, monkeypatch):

    monkeypatch.setattr(
        Config,
        "DATABASE_PATH",
        str(tmp_path / "test_safevault.db"),
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
    app.config["SECRET_KEY"] = "test-secret-key"

    client = app.test_client()

    def register(username):
        response = client.post(
            "/auth/register",
            json={
                "username": username,
                "email": f"{username}@example.com",
                "password": "SafeVaultPassword123!",
            },
        )
        assert response.status_code == 201

    def login(username):
        response = client.post(
            "/auth/login",
            json={
                "username": username,
                "password": "SafeVaultPassword123!",
            },
        )
        assert response.status_code == 200

    register("owner")
    register("reader")
    register("writer")
    register("stranger")

    login("owner")

    upload_response = client.post(
        "/files/upload",
        data={
            "file": (
                io.BytesIO(b"Original SafeVault document"),
                "document.txt",
            )
        },
        content_type="multipart/form-data",
    )

    assert upload_response.status_code == 201

    file_id = upload_response.get_json()["file_id"]

    users = {
        username: fetch_one(
            "SELECT id FROM users WHERE username = ?",
            (username,),
        )["id"]
        for username in ("owner", "reader", "writer", "stranger")
    }

    return {
        "client": client,
        "file_id": file_id,
        "users": users,
    }


def login_as(setup, username):
    client = setup["client"]

    client.post("/auth/logout")

    response = client.post(
        "/auth/login",
        json={
            "username": username,
            "password": "SafeVaultPassword123!",
        },
    )

    assert response.status_code == 200

    return client


def share_with(setup, username, permission):
    client = setup["client"]

    return client.post(
        f"/files/{setup['file_id']}/share",
        json={
            "username": username,
            "permission": permission,
        },
    )


def test_share_requires_login(sharing_setup):

    setup = sharing_setup
    client = setup["client"]

    client.post("/auth/logout")

    response = client.post(
        f"/files/{setup['file_id']}/share",
        json={
            "username": "reader",
            "permission": "read",
        },
    )

    assert response.status_code == 401


def test_owner_can_share_file_with_read_permission(sharing_setup):

    setup = sharing_setup

    response = share_with(
        setup,
        "reader",
        "read",
    )

    assert response.status_code == 200
    assert response.get_json()["permission"] == "read"


def test_owner_can_share_file_with_write_permission(sharing_setup):

    setup = sharing_setup

    response = share_with(
        setup,
        "writer",
        "write",
    )

    assert response.status_code == 200
    assert response.get_json()["permission"] == "write"


def test_cannot_share_with_unknown_user(sharing_setup):

    setup = sharing_setup

    response = share_with(
        setup,
        "unknown_user",
        "read",
    )

    assert response.status_code == 404


def test_invalid_permission_is_rejected(sharing_setup):

    setup = sharing_setup

    response = share_with(
        setup,
        "reader",
        "admin",
    )

    assert response.status_code == 400


def test_non_owner_cannot_share_file(sharing_setup):

    setup = sharing_setup
    client = login_as(setup, "reader")

    response = client.post(
        f"/files/{setup['file_id']}/share",
        json={
            "username": "stranger",
            "permission": "read",
        },
    )

    assert response.status_code == 403


def test_owner_can_view_shares(sharing_setup):

    setup = sharing_setup

    share_with(setup, "reader", "read")

    response = setup["client"].get(
        f"/files/{setup['file_id']}/shares"
    )

    assert response.status_code == 200

    data = response.get_json()

    assert data["count"] == 1
    assert data["shares"][0]["username"] == "reader"
    assert data["shares"][0]["permission"] == "read"


def test_owner_can_change_share_permission(sharing_setup):

    setup = sharing_setup

    share_with(setup, "reader", "read")

    response = setup["client"].put(
        f"/files/{setup['file_id']}/share/{setup['users']['reader']}",
        json={"permission": "write"},
    )

    assert response.status_code == 200
    assert response.get_json()["permission"] == "write"


def test_owner_can_revoke_file_access(sharing_setup):

    setup = sharing_setup

    share_with(setup, "reader", "read")

    response = setup["client"].delete(
        f"/files/{setup['file_id']}/share/{setup['users']['reader']}"
    )

    assert response.status_code == 200

    reader_client = login_as(setup, "reader")

    download_response = reader_client.get(
        f"/files/{setup['file_id']}/download"
    )

    assert download_response.status_code == 404


def test_reader_cannot_edit_file(sharing_setup):

    setup = sharing_setup

    share_with(setup, "reader", "read")

    reader_client = login_as(setup, "reader")

    response = reader_client.put(
        f"/files/{setup['file_id']}/edit",
        data={
            "file": (
                io.BytesIO(b"Modified content"),
                "document.txt",
            )
        },
        content_type="multipart/form-data",
    )

    assert response.status_code == 403


def test_writer_can_edit_file(sharing_setup):

    setup = sharing_setup

    share_with(setup, "writer", "write")

    writer_client = login_as(setup, "writer")

    new_content = b"Updated SafeVault document"

    response = writer_client.put(
        f"/files/{setup['file_id']}/edit",
        data={
            "file": (
                io.BytesIO(new_content),
                "document.txt",
            )
        },
        content_type="multipart/form-data",
    )

    assert response.status_code == 200

    download_response = writer_client.get(
        f"/files/{setup['file_id']}/download"
    )

    assert download_response.status_code == 200
    assert download_response.data == new_content


def test_non_owner_cannot_revoke_share(sharing_setup):

    setup = sharing_setup

    share_with(setup, "reader", "read")

    reader_client = login_as(setup, "reader")

    response = reader_client.delete(
        f"/files/{setup['file_id']}/share/{setup['users']['reader']}"
    )

    assert response.status_code == 403

def test_metadata_requires_login(sharing_setup):
    setup = sharing_setup

    setup["client"].post("/auth/logout")

    response = setup["client"].get(
        f"/files/{setup['file_id']}/metadata"
    )

    assert response.status_code == 401


def test_owner_can_view_file_metadata(sharing_setup):
    setup = sharing_setup

    response = setup["client"].get(
        f"/files/{setup['file_id']}/metadata"
    )

    assert response.status_code == 200

    data = response.get_json()

    assert data["file_id"] == setup["file_id"]
    assert data["original_name"] == "document.txt"
    assert data["access_type"] == "owner"
    assert data["is_encrypted"] is True
    assert data["file_size"] > 0
    assert data["sha256_hash"]


def test_reader_can_view_file_metadata(sharing_setup):
    setup = sharing_setup

    share_with(setup, "reader", "read")
    login_as(setup, "reader")

    response = setup["client"].get(
        f"/files/{setup['file_id']}/metadata"
    )

    assert response.status_code == 200
    assert response.get_json()["access_type"] == "read"


def test_writer_can_view_file_metadata(sharing_setup):
    setup = sharing_setup

    share_with(setup, "writer", "write")
    login_as(setup, "writer")

    response = setup["client"].get(
        f"/files/{setup['file_id']}/metadata"
    )

    assert response.status_code == 200
    assert response.get_json()["access_type"] == "write"


def test_stranger_cannot_view_file_metadata(sharing_setup):
    setup = sharing_setup

    login_as(setup, "stranger")

    response = setup["client"].get(
        f"/files/{setup['file_id']}/metadata"
    )

    assert response.status_code == 404


def test_nonexistent_file_metadata_returns_404(sharing_setup):
    setup = sharing_setup

    response = setup["client"].get(
        "/files/999999/metadata"
    )

    assert response.status_code == 404