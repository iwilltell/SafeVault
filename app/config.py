import os
from pathlib import Path


class Config:
    # Load secrets from the environment; never commit .env.
    SECRET_KEY = os.getenv("FLASK_SECRET_KEY", "development-only-change-me")
    DATABASE_PATH = os.getenv(
        "DATABASE_PATH",
        str(Path("instance") / "safevault.sqlite3"),
    )
    MAX_CONTENT_LENGTH = int(os.getenv("MAX_CONTENT_LENGTH_MB", "10")) * 1024 * 1024
