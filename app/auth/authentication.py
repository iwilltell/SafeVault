
import re

from flask import Blueprint, request, jsonify, session

from app.database.db import (
    execute_query,
    fetch_one,
)

from app.auth.password import (
    hash_password,
    verify_password,
    needs_rehash,
)

from app.services.audit_logger import record_event


auth_bp = Blueprint("auth", __name__, url_prefix="/auth")

MAX_LOGIN_ATTEMPTS = 5


def validate_registration(username, email, password):
    """Validate registration details."""

    if not isinstance(username, str):
        return "Username must be text."

    if not isinstance(email, str):
        return "Email must be text."

    if not isinstance(password, str):
        return "Password must be text."

    username = username.strip()
    email = email.strip()

    if not 3 <= len(username) <= 30:
        return "Username must contain 3-30 characters."

    if not re.fullmatch(r"[A-Za-z0-9_]+", username):
        return "Username can only contain letters, numbers and underscores."

    if len(email) > 254:
        return "Email is too long."

    if not re.fullmatch(
        r"[^@\s]+@[^@\s]+\.[^@\s]+",
        email
    ):
        return "Enter a valid email address."

    if not 12 <= len(password) <= 128:
        return "Password must contain 12-128 characters."

    return None


@auth_bp.post("/register")
def register():
    """Register a new SafeVault user."""

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "Invalid JSON request."}), 400

    username = data.get("username")
    email = data.get("email")
    password = data.get("password")

    error = validate_registration(username, email, password)

    if error:
        return jsonify({"error": error}), 400

    username = username.strip()
    email = email.strip().lower()

    existing_user = fetch_one(
        """
        SELECT id
        FROM users
        WHERE username = ? OR email = ?
        """,
        (username, email)
    )

    if existing_user:
        return jsonify({
            "error": "Username or email already exists."
        }), 409

    password_hash = hash_password(password)

    try:
        user_id = execute_query(
            """
            INSERT INTO users (
                username,
                email,
                password_hash
            )
            VALUES (?, ?, ?)
            """,
            (username, email, password_hash)
        )

    except Exception:
        return jsonify({
            "error": "Unable to create account."
        }), 500

    record_event(
        user_id,
        "USER_REGISTERED",
        "New account created."
    )

    return jsonify({
        "message": "Registration successful.",
        "user_id": user_id
    }), 201


@auth_bp.post("/login")
def login():
    """Authenticate a user and create a session."""

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "Invalid JSON request."}), 400

    username = data.get("username")
    password = data.get("password")

    if not isinstance(username, str) or not isinstance(password, str):
        return jsonify({"error": "Invalid credentials."}), 400

    username = username.strip()

    if not username or len(username) > 30 or len(password) > 128:
        return jsonify({"error": "Invalid credentials."}), 401

    user = fetch_one(
        """
        SELECT *
        FROM users
        WHERE username = ?
        """,
        (username,)
    )

    if not user:
        return jsonify({"error": "Invalid credentials."}), 401

    attempts = fetch_one(
        """
        SELECT COUNT(*) AS total
        FROM audit_events
        WHERE user_id = ?
        AND event_type = 'LOGIN_FAILED'
        AND timestamp >= datetime('now', '-15 minutes')
        """,
        (user["id"],)
    )

    if attempts["total"] >= MAX_LOGIN_ATTEMPTS:
        return jsonify({
            "error": "Too many failed attempts. Try again later."
        }), 429

    if not verify_password(user["password_hash"], password):
        record_event(
            user["id"],
            "LOGIN_FAILED",
            "Incorrect password."
        )

        return jsonify({"error": "Invalid credentials."}), 401

    if needs_rehash(user["password_hash"]):
        execute_query(
            """
            UPDATE users
            SET password_hash = ?
            WHERE id = ?
            """,
            (hash_password(password), user["id"])
        )

    session.clear()

    if user["two_factor_enabled"]:
        session["pending_2fa_user"] = user["id"]

        return jsonify({
            "message": "Two-factor authentication required.",
            "requires_2fa": True
        }), 200

    session["user_id"] = user["id"]

    record_event(
        user["id"],
        "LOGIN_SUCCESS",
        "User logged in."
    )

    return jsonify({
        "message": "Login successful.",
        "requires_2fa": False
    }), 200


@auth_bp.post("/logout")
def logout():
    """Destroy the current user session."""

    user_id = session.get("user_id")

    if user_id is None:
        return jsonify({"error": "Not authenticated."}), 401

    record_event(
        user_id,
        "LOGOUT",
        "User logged out."
    )

    session.clear()

    return jsonify({
        "message": "Logout successful."
    }), 200


@auth_bp.get("/me")
def current_user():
    """Return information about the logged-in user."""

    user_id = session.get("user_id")

    if user_id is None:
        return jsonify({"error": "Not authenticated."}), 401

    user = fetch_one(
        """
        SELECT id, username, email, two_factor_enabled, created_at
        FROM users
        WHERE id = ?
        """,
        (user_id,)
    )

    if not user:
        session.clear()
        return jsonify({"error": "User not found."}), 401

    return jsonify({
        "id": user["id"],
        "username": user["username"],
        "email": user["email"],
        "two_factor_enabled": bool(user["two_factor_enabled"])
    }), 200
