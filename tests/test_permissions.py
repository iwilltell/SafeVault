import pytest
from cryptography.fernet import Fernet

from app import create_app
from app.config import Config
from app.database.db import execute_query, fetch_one
from app.files.permissions import (
    get_file_permission,
    can_read_file,
    can_write_file,
    is_file_owner,
)


@pytest.fixture
def setup_users(tmp_path, monkeypatch):

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

    with app.app_context():

        execute_query(
            """
            INSERT INTO users (username, email, password_hash)
            VALUES (?, ?, ?)
            """,
            ("owner", "owner@example.com", "test-hash"),
        )

        execute_query(
            """
            INSERT INTO users (username, email, password_hash)
            VALUES (?, ?, ?)
            """,
            ("reader", "reader@example.com", "test-hash"),
        )

        execute_query(
            """
            INSERT INTO users (username, email, password_hash)
            VALUES (?, ?, ?)
            """,
            ("writer", "writer@example.com", "test-hash"),
        )

        execute_query(
            """
            INSERT INTO users (username, email, password_hash)
            VALUES (?, ?, ?)
            """,
            ("stranger", "stranger@example.com", "test-hash"),
        )

        owner = fetch_one(
            "SELECT id FROM users WHERE username = ?",
            ("owner",),
        )

        reader = fetch_one(
            "SELECT id FROM users WHERE username = ?",
            ("reader",),
        )

        writer = fetch_one(
            "SELECT id FROM users WHERE username = ?",
            ("writer",),
        )

        stranger = fetch_one(
            "SELECT id FROM users WHERE username = ?",
            ("stranger",),
        )

        execute_query(
            """
            INSERT INTO files (
                owner_id,
                original_name,
                stored_name,
                file_size,
                mime_type,
                sha256_hash,
                is_encrypted
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                owner["id"],
                "document.txt",
                "test-document.enc",
                20,
                "text/plain",
                "test-hash",
                1,
            ),
        )

        file_record = fetch_one(
            "SELECT id FROM files WHERE stored_name = ?",
            ("test-document.enc",),
        )

        file_id = file_record["id"]

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
                writer["id"],
                owner["id"],
                "write",
            ),
        )

        yield {
            "file_id": file_id,
            "owner_id": owner["id"],
            "reader_id": reader["id"],
            "writer_id": writer["id"],
            "stranger_id": stranger["id"],
        }


def test_owner_has_owner_permission(setup_users):

    data = setup_users

    permission = get_file_permission(
        data["file_id"],
        data["owner_id"],
    )

    assert permission == "owner"


def test_reader_has_read_permission(setup_users):

    data = setup_users

    permission = get_file_permission(
        data["file_id"],
        data["reader_id"],
    )

    assert permission == "read"


def test_writer_has_write_permission(setup_users):

    data = setup_users

    permission = get_file_permission(
        data["file_id"],
        data["writer_id"],
    )

    assert permission == "write"


def test_stranger_has_no_permission(setup_users):

    data = setup_users

    permission = get_file_permission(
        data["file_id"],
        data["stranger_id"],
    )

    assert permission is None


def test_read_permission_allows_download_but_not_edit(setup_users):

    data = setup_users

    assert can_read_file(
        data["file_id"],
        data["reader_id"],
    ) is True

    assert can_write_file(
        data["file_id"],
        data["reader_id"],
    ) is False


def test_write_permission_allows_download_and_edit(setup_users):

    data = setup_users

    assert can_read_file(
        data["file_id"],
        data["writer_id"],
    ) is True

    assert can_write_file(
        data["file_id"],
        data["writer_id"],
    ) is True


def test_owner_has_full_access(setup_users):

    data = setup_users

    assert is_file_owner(
        data["file_id"],
        data["owner_id"],
    ) is True

    assert can_read_file(
        data["file_id"],
        data["owner_id"],
    ) is True

    assert can_write_file(
        data["file_id"],
        data["owner_id"],
    ) is True