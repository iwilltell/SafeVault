
import base64
from io import BytesIO

import pyotp
import qrcode

from flask import Blueprint, request, jsonify, session

from app.database.db import execute_query, fetch_one


two_factor_bp = Blueprint(
    "two_factor",
    __name__,
    url_prefix="/auth/2fa"
)


def get_authenticated_user():
    """Return the currently authenticated user."""

    user_id = session.get("user_id")

    if user_id is None:
        return None

    return fetch_one(
        "SELECT * FROM users WHERE id = ?",
        (user_id,)
    )


def generate_qr_code(provisioning_uri):
    """Generate a Base64 encoded QR code image."""

    qr = qrcode.make(provisioning_uri)

    image_buffer = BytesIO()
    qr.save(image_buffer, format="PNG")

    encoded_image = base64.b64encode(
        image_buffer.getvalue()
    ).decode("utf-8")

    return encoded_image


@two_factor_bp.post("/setup")
def setup_two_factor():
    """
    Generate a new TOTP secret for the authenticated user.

    The user must verify an OTP before 2FA becomes enabled.
    """

    user = get_authenticated_user()

    if user is None:
        return jsonify({"error": "Authentication required."}), 401

    if user["two_factor_enabled"]:
        return jsonify({
            "error": "Two-factor authentication is already enabled."
        }), 409

    secret = pyotp.random_base32()

    totp = pyotp.TOTP(secret)

    provisioning_uri = totp.provisioning_uri(
        name=user["email"],
        issuer_name="SafeVault"
    )

    qr_image = generate_qr_code(provisioning_uri)

    execute_query(
        """
        UPDATE users
        SET totp_secret = ?
        WHERE id = ?
        """,
        (secret, user["id"])
    )

    session["pending_2fa_setup"] = True

    return jsonify({
        "message": "Scan the QR code using an authenticator app.",
        "qr_code": qr_image,
        "manual_secret": secret,
        "instructions": "Verify an OTP to enable 2FA."
    }), 200


@two_factor_bp.post("/enable")
def enable_two_factor():
    """Enable 2FA after validating the initial OTP."""

    user = get_authenticated_user()

    if user is None:
        return jsonify({"error": "Authentication required."}), 401

    if not session.get("pending_2fa_setup"):
        return jsonify({"error": "Start 2FA setup first."}), 400

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "Invalid request."}), 400

    otp = data.get("otp")

    if not isinstance(otp, str) or not otp.isdigit() or len(otp) != 6:
        return jsonify({"error": "Enter a valid six-digit OTP."}), 400

    if not user["totp_secret"]:
        return jsonify({"error": "No 2FA secret found."}), 400

    totp = pyotp.TOTP(user["totp_secret"])

    if not totp.verify(otp, valid_window=0):
        return jsonify({"error": "Invalid OTP."}), 401

    execute_query(
        """
        UPDATE users
        SET two_factor_enabled = 1
        WHERE id = ?
        """,
        (user["id"],)
    )

    session.pop("pending_2fa_setup", None)

    execute_query(
        """
        INSERT INTO audit_events (user_id, event_type, details)
        VALUES (?, ?, ?)
        """,
        (
            user["id"],
            "TWO_FACTOR_ENABLED",
            "Two-factor authentication enabled."
        )
    )

    return jsonify({
        "message": "Two-factor authentication enabled successfully."
    }), 200


@two_factor_bp.post("/verify")
def verify_two_factor():
    """Complete login after successful OTP verification."""

    pending_user_id = session.get("pending_2fa_user")

    if pending_user_id is None:
        return jsonify({
            "error": "No pending two-factor login."
        }), 401

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "Invalid request."}), 400

    otp = data.get("otp")

    if not isinstance(otp, str) or not otp.isdigit() or len(otp) != 6:
        return jsonify({"error": "Enter a valid six-digit OTP."}), 400

    user = fetch_one(
        """
        SELECT id, totp_secret, two_factor_enabled
        FROM users
        WHERE id = ?
        """,
        (pending_user_id,)
    )

    if user is None or not user["two_factor_enabled"] or not user["totp_secret"]:
        session.pop("pending_2fa_user", None)

        return jsonify({
            "error": "Two-factor authentication is unavailable."
        }), 401

    totp = pyotp.TOTP(user["totp_secret"])

    if not totp.verify(otp, valid_window=0):
        execute_query(
            """
            INSERT INTO audit_events (user_id, event_type, details)
            VALUES (?, ?, ?)
            """,
            (
                user["id"],
                "TWO_FACTOR_FAILED",
                "Invalid OTP entered."
            )
        )

        return jsonify({"error": "Invalid OTP."}), 401

    session.clear()
    session["user_id"] = user["id"]

    execute_query(
        """
        INSERT INTO audit_events (user_id, event_type, details)
        VALUES (?, ?, ?)
        """,
        (
            user["id"],
            "TWO_FACTOR_SUCCESS",
            "Two-factor login completed."
        )
    )

    return jsonify({
        "message": "Two-factor authentication successful."
    }), 200


@two_factor_bp.post("/disable")
def disable_two_factor():
    """Disable 2FA after password and OTP verification."""

    user = get_authenticated_user()

    if user is None:
        return jsonify({"error": "Authentication required."}), 401

    if not user["two_factor_enabled"]:
        return jsonify({
            "error": "Two-factor authentication is not enabled."
        }), 400

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "Invalid request."}), 400

    password = data.get("password")
    otp = data.get("otp")

    if not isinstance(password, str) or not isinstance(otp, str):
        return jsonify({"error": "Password and OTP are required."}), 400

    if len(password) > 128 or not otp.isdigit() or len(otp) != 6:
        return jsonify({"error": "Invalid credentials."}), 400

    from app.auth.password import verify_password

    if not verify_password(user["password_hash"], password):
        return jsonify({"error": "Invalid credentials."}), 401

    if not pyotp.TOTP(user["totp_secret"]).verify(otp, valid_window=0):
        return jsonify({"error": "Invalid credentials."}), 401

    execute_query(
        """
        UPDATE users
        SET totp_secret = NULL,
            two_factor_enabled = 0
        WHERE id = ?
        """,
        (user["id"],)
    )

    execute_query(
        """
        INSERT INTO audit_events (user_id, event_type, details)
        VALUES (?, ?, ?)
        """,
        (
            user["id"],
            "TWO_FACTOR_DISABLED",
            "Two-factor authentication disabled."
        )
    )

    session.clear()

    return jsonify({
        "message": "Two-factor authentication disabled. Please log in again."
    }), 200
