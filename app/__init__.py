from flask import Flask

from app.config import Config
from app.database.db import initialize_database


def create_app():

    app = Flask(__name__)

    app.config.from_object(Config)

    # Initialize SQLite database.
    initialize_database()

    # Import application blueprints.
    from app.auth.authentication import auth_bp
    from app.auth.two_factor import two_factor_bp
    from app.files.file_operations import files_bp

    # Register application routes.
    app.register_blueprint(auth_bp)
    app.register_blueprint(two_factor_bp)
    app.register_blueprint(files_bp)

    @app.get("/")
    def index():
        return {
            "application": "SafeVault",
            "status": "running",
            "database": "initialized"
        }

    return app