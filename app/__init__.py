
from flask import Flask, render_template, session, redirect, url_for

from app.config import Config
from app.database.db import initialize_database


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    initialize_database()

    from app.auth.authentication import auth_bp
    from app.auth.two_factor import two_factor_bp
    from app.files.file_operations import files_bp
    from app.audit.audit_routes import audit_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(two_factor_bp)
    app.register_blueprint(files_bp)
    app.register_blueprint(audit_bp)

    @app.get("/")
    def index():
        if session.get("user_id"):
            return redirect(url_for("dashboard"))
        return render_template("login.html")

    @app.get("/dashboard")
    def dashboard():
        if not session.get("user_id"):
            return redirect(url_for("index"))
        return render_template("dashboard.html")

    return app
