
from flask import Flask

from app.config import Config
from app.database.db import initialize_database


def create_app():
    app = Flask(__name__)

    app.config.from_object(Config)

    # Initialize the database when the application starts.
    initialize_database()

    @app.get("/")
    def index():
        return {
            "application": "SafeVault",
            "status": "running",
            "database": "initialized"
        }

    return app
