
from flask import Flask, render_template, session, redirect, url_for

from app.config import Config
from app.database.db import initialize_database


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # Initialize database
    initialize_database()

    # Import application blueprints
    from app.auth.authentication import auth_bp
    from app.auth.two_factor import two_factor_bp
    from app.files.file_operations import files_bp
    from app.audit.audit_routes import audit_bp

    # Register blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(two_factor_bp)
    app.register_blueprint(files_bp)
    app.register_blueprint(audit_bp)

    # Login page
    @app.get("/")
    def index():
        if session.get("user_id"):
            return redirect(url_for("dashboard"))

        return render_template("login.html")

    # Registration page
    @app.get("/register")
    def register():
        if session.get("user_id"):
            return redirect(url_for("dashboard"))

        return render_template("register.html")

    # Dashboard page
    @app.get("/dashboard")
    def dashboard():
        if not session.get("user_id"):
            return redirect(url_for("index"))

        return render_template("dashboard.html")

    # File manager page
    @app.get("/file-manager")
    def file_manager():
        if not session.get("user_id"):
            return redirect(url_for("index"))

        return render_template("file_manager.html")

    # Activity logs page
    @app.get("/activity")
    def activity():
        if not session.get("user_id"):
            return redirect(url_for("index"))

        return render_template("activity.html")

    # Two-factor authentication settings page
    @app.get("/two-factor")
    def two_factor_settings():
        if not session.get("user_id"):
            return redirect(url_for("index"))

        return render_template("two_factor.html")

    # Two-factor login verification page
    @app.get("/verify-2fa")
    def verify_2fa_page():
        if not session.get("pending_2fa_user"):
            return redirect(url_for("index"))

        return render_template("two_factor_verify.html")

    return app
