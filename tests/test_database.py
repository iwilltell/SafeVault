
import sqlite3

import pytest

from app.config import Config
from app.database.db import (
    get_connection,
    initialize_database,
    execute_query,
    fetch_one,
    fetch_all,
)


@pytest.fixture
def test_database(tmp_path, monkeypatch):
    """
    Give every test its own temporary database.
    """

    database_path = tmp_path / "test_safevault.sqlite3"

    monkeypatch.setattr(
        Config,
        "DATABASE_PATH",
        str(database_path)
    )

    initialize_database()

    return database_path


def test_database_initialization(test_database):
    connection = get_connection()

    try:
        cursor = connection.execute(
            """
            SELECT name
            FROM sqlite_master
            WHERE type = 'table'
            """
        )

        tables = {row["name"] for row in cursor.fetchall()}

        assert "users" in tables
        assert "files" in tables
        assert "shares" in tables
        assert "audit_events" in tables

    finally:
        connection.close()


def test_user_insertion(test_database):
    user_id = execute_query(
        """
        INSERT INTO users (username, email, password_hash)
        VALUES (?, ?, ?)
        """,
        ("master", "master@example.com", "test_hash")
    )

    assert user_id is not None

    user = fetch_one(
        "SELECT * FROM users WHERE id = ?",
        (user_id,)
    )

    assert user["username"] == "master"
    assert user["email"] == "master@example.com"


def test_duplicate_username_is_rejected(test_database):
    execute_query(
        """
        INSERT INTO users (username, email, password_hash)
        VALUES (?, ?, ?)
        """,
        ("master", "one@example.com", "hash_one")
    )

    with pytest.raises(sqlite3.IntegrityError):
        execute_query(
            """
            INSERT INTO users (username, email, password_hash)
            VALUES (?, ?, ?)
            """,
            ("master", "two@example.com", "hash_two")
        )


def test_file_requires_valid_owner(test_database):
    with pytest.raises(sqlite3.IntegrityError):
        execute_query(
            """
            INSERT INTO files (
                owner_id,
                original_name,
                stored_name,
                file_size
            )
            VALUES (?, ?, ?, ?)
            """,
            (999, "document.pdf", "random123.enc", 100)
        )


def test_file_insertion(test_database):
    user_id = execute_query(
        """
        INSERT INTO users (username, email, password_hash)
        VALUES (?, ?, ?)
        """,
        ("owner", "owner@example.com", "test_hash")
    )

    file_id = execute_query(
        """
        INSERT INTO files (
            owner_id,
            original_name,
            stored_name,
            file_size,
            is_encrypted
        )
        VALUES (?, ?, ?, ?, ?)
        """,
        (user_id, "document.pdf", "random123.enc", 1024, 1)
    )

    file_record = fetch_one(
        "SELECT * FROM files WHERE id = ?",
        (file_id,)
    )

    assert file_record["original_name"] == "document.pdf"
    assert file_record["file_size"] == 1024
    assert file_record["is_encrypted"] == 1


def test_share_permissions(test_database):
    owner_id = execute_query(
        """
        INSERT INTO users (username, email, password_hash)
        VALUES (?, ?, ?)
        """,
        ("owner", "owner@example.com", "hash1")
    )

    recipient_id = execute_query(
        """
        INSERT INTO users (username, email, password_hash)
        VALUES (?, ?, ?)
        """,
        ("recipient", "recipient@example.com", "hash2")
    )

    file_id = execute_query(
        """
        INSERT INTO files (
            owner_id,
            original_name,
            stored_name,
            file_size
        )
        VALUES (?, ?, ?, ?)
        """,
        (owner_id, "notes.txt", "stored_notes.enc", 500)
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
        (file_id, recipient_id, owner_id, "read")
    )

    share = fetch_one(
        "SELECT * FROM shares WHERE file_id = ?",
        (file_id,)
    )

    assert share["user_id"] == recipient_id
    assert share["permission"] == "read"


def test_invalid_share_permission_is_rejected(test_database):
    owner_id = execute_query(
        """
        INSERT INTO users (username, email, password_hash)
        VALUES (?, ?, ?)
        """,
        ("owner", "owner@example.com", "hash1")
    )

    recipient_id = execute_query(
        """
        INSERT INTO users (username, email, password_hash)
        VALUES (?, ?, ?)
        """,
        ("recipient", "recipient@example.com", "hash2")
    )

    file_id = execute_query(
        """
        INSERT INTO files (
            owner_id,
            original_name,
            stored_name,
            file_size
        )
        VALUES (?, ?, ?, ?)
        """,
        (owner_id, "notes.txt", "notes.enc", 500)
    )

    with pytest.raises(sqlite3.IntegrityError):
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
            (file_id, recipient_id, owner_id, "admin")
        )


def test_audit_event_insertion(test_database):
    user_id = execute_query(
        """
        INSERT INTO users (username, email, password_hash)
        VALUES (?, ?, ?)
        """,
        ("master", "master@example.com", "test_hash")
    )

    event_id = execute_query(
        """
        INSERT INTO audit_events (
            user_id,
            event_type,
            details
        )
        VALUES (?, ?, ?)
        """,
        (user_id, "LOGIN_SUCCESS", "User logged in")
    )

    event = fetch_one(
        "SELECT * FROM audit_events WHERE id = ?",
        (event_id,)
    )

    assert event["event_type"] == "LOGIN_SUCCESS"
    assert event["user_id"] == user_id


def test_fetch_all_users(test_database):
    execute_query(
        """
        INSERT INTO users (username, email, password_hash)
        VALUES (?, ?, ?)
        """,
        ("user1", "user1@example.com", "hash1")
    )

    execute_query(
        """
        INSERT INTO users (username, email, password_hash)
        VALUES (?, ?, ?)
        """,
        ("user2", "user2@example.com", "hash2")
    )

    users = fetch_all(
        "SELECT * FROM users ORDER BY id"
    )

    assert len(users) == 2
    assert users[0]["username"] == "user1"
    assert users[1]["username"] == "user2"
