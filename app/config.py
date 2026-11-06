import os
from pathlib import Path


class Config:
    SECRET_KEY = os.getenv(
        "FLASK_SECRET_KEY",
        "development-only-change-me"
    )

    DATABASE_PATH = os.getenv(
        "DATABASE_PATH",
        str(Path("instance") / "safevault.sqlite3")
    )

    STORAGE_PATH = os.getenv(
        "STORAGE_PATH",
        str(Path("instance") / "uploads")
    )

    ENCRYPTION_KEY = os.getenv("SAFEVAULT_ENCRYPTION_KEY")

    MAX_CONTENT_LENGTH = (
        int(os.getenv("MAX_CONTENT_LENGTH_MB", "10"))
        * 1024 * 1024
    )

    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"

    SESSION_COOKIE_SECURE = (
        os.getenv("SESSION_COOKIE_SECURE", "false").lower() == "true"
    )

    PERMANENT_SESSION_LIFETIME = 1800