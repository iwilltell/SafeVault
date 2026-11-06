from flask import Flask

from app.config import Config


def create_app() -> Flask:
    app = Flask(__name__)
    app.config.from_object(Config)

    @app.get("/")
    def index():
        return {
            "application": "SafeVault",
            "status": "starter scaffold",
            "next_step": "Implement the database module with tests.",
        }

    return app
