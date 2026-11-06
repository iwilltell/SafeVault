
from flask import Flask

from app.config import Config
from app.database.db import initialize_database


def create_app():
    app = Flask(__name__)

    app.config.from_object(Config)

    initialize_database()

    from app.auth.authentication import auth_bp

    app.register_blueprint(auth_bp)

    @app.get("/")
    def index():
        return {
            "application": "SafeVault",
            "status": "running",
            "database": "initialized"
        }

    return app
