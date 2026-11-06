
import sqlite3
from pathlib import Path

from app.config import Config


def get_connection():
    """
    Create and return a connection to the SafeVault SQLite database.
    """

    database_path = Path(Config.DATABASE_PATH)

    # Create the database directory if it does not exist.
    database_path.parent.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(
        database_path,
        timeout=10
    )

    # Allow accessing database columns using their names.
    connection.row_factory = sqlite3.Row

    # Enforce foreign key relationships.
    connection.execute("PRAGMA foreign_keys = ON")

    # Wait for database locks instead of failing immediately.
    connection.execute("PRAGMA busy_timeout = 10000")

    return connection


def initialize_database():
    """
    Create all required SafeVault database tables.
    """

    connection = get_connection()

    try:
        connection.executescript("""

            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,

                username TEXT NOT NULL UNIQUE,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,

                totp_secret TEXT,
                two_factor_enabled INTEGER NOT NULL DEFAULT 0
                    CHECK (two_factor_enabled IN (0, 1)),

                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );


            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,

                owner_id INTEGER NOT NULL,

                original_name TEXT NOT NULL,
                stored_name TEXT NOT NULL UNIQUE,

                file_size INTEGER NOT NULL CHECK (file_size >= 0),
                mime_type TEXT,

                sha256_hash TEXT,

                is_encrypted INTEGER NOT NULL DEFAULT 0
                    CHECK (is_encrypted IN (0, 1)),

                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

                FOREIGN KEY (owner_id)
                    REFERENCES users(id)
                    ON DELETE CASCADE
            );


            CREATE TABLE IF NOT EXISTS shares (
                id INTEGER PRIMARY KEY AUTOINCREMENT,

                file_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                shared_by_id INTEGER NOT NULL,

                permission TEXT NOT NULL
                    CHECK (permission IN ('read', 'write')),

                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

                UNIQUE(file_id, user_id),

                FOREIGN KEY (file_id)
                    REFERENCES files(id)
                    ON DELETE CASCADE,

                FOREIGN KEY (user_id)
                    REFERENCES users(id)
                    ON DELETE CASCADE,

                FOREIGN KEY (shared_by_id)
                    REFERENCES users(id)
                    ON DELETE CASCADE
            );


            CREATE TABLE IF NOT EXISTS audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,

                user_id INTEGER,

                event_type TEXT NOT NULL,
                details TEXT,

                ip_address TEXT,

                timestamp TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

                FOREIGN KEY (user_id)
                    REFERENCES users(id)
                    ON DELETE SET NULL
            );


            CREATE INDEX IF NOT EXISTS idx_files_owner
            ON files(owner_id);


            CREATE INDEX IF NOT EXISTS idx_shares_user
            ON shares(user_id);


            CREATE INDEX IF NOT EXISTS idx_shares_file
            ON shares(file_id);


            CREATE INDEX IF NOT EXISTS idx_audit_user
            ON audit_events(user_id);


            CREATE INDEX IF NOT EXISTS idx_audit_timestamp
            ON audit_events(timestamp);

        """)

        connection.commit()

    except sqlite3.Error:
        connection.rollback()
        raise

    finally:
        connection.close()


def execute_query(query, parameters=()):
    """
    Execute an INSERT, UPDATE or DELETE query.

    Returns the ID of the affected row where available.
    """

    connection = get_connection()

    try:
        cursor = connection.execute(query, parameters)
        connection.commit()

        return cursor.lastrowid

    except sqlite3.Error:
        connection.rollback()
        raise

    finally:
        connection.close()


def fetch_one(query, parameters=()):
    """
    Fetch a single database record.
    """

    connection = get_connection()

    try:
        cursor = connection.execute(query, parameters)
        result = cursor.fetchone()

        return result

    finally:
        connection.close()


def fetch_all(query, parameters=()):
    """
    Fetch multiple database records.
    """

    connection = get_connection()

    try:
        cursor = connection.execute(query, parameters)
        results = cursor.fetchall()

        return results

    finally:
        connection.close()
