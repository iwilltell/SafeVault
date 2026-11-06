
import pytest
import pyotp

from app import create_app
from app.config import Config
from app.database.db import fetch_one


@pytest.fixture
def client(tmp_path, monkeypatch):

    database_path = tmp_path / "two_factor_test.sqlite3"

    monkeypatch.setattr(
        Config,
        "DATABASE_PATH",
        str(database_path)
    )

    app = create_app()

    app.config.update({
        "TESTING": True,
        "SECRET_KEY": "test-secret-key"
    })

    with app.test_client() as client:
        yield client


def register_and_login(client):

    client.post(
        "/auth/register",
        json={
            "username": "master",
            "email": "master@example.com",
            "password": "SafeVaultPassword123!"
        }
    )

    return client.post(
        "/auth/login",
        json={
            "username": "master",
            "password": "SafeVaultPassword123!"
        }
    )


def test_2fa_setup_requires_login(client):

    response = client.post("/auth/2fa/setup")

    assert response.status_code == 401


def test_2fa_setup(client):

    register_and_login(client)

    response = client.post("/auth/2fa/setup")

    assert response.status_code == 200
    assert "qr_code" in response.json
    assert "manual_secret" in response.json

    assert response.json["manual_secret"]


def test_2fa_enable_with_valid_otp(client):

    register_and_login(client)

    client.post("/auth/2fa/setup")

    user = fetch_one(
        "SELECT * FROM users WHERE username = ?",
        ("master",)
    )

    otp = pyotp.TOTP(user["totp_secret"]).now()

    response = client.post(
        "/auth/2fa/enable",
        json={"otp": otp}
    )

    assert response.status_code == 200

    updated_user = fetch_one(
        "SELECT * FROM users WHERE username = ?",
        ("master",)
    )

    assert updated_user["two_factor_enabled"] == 1


def test_2fa_enable_with_invalid_otp(client):

    register_and_login(client)

    client.post("/auth/2fa/setup")

    response = client.post(
        "/auth/2fa/enable",
        json={"otp": "000000"}
    )

    assert response.status_code == 401


def test_2fa_login_requires_otp(client):

    register_and_login(client)

    client.post("/auth/2fa/setup")

    user = fetch_one(
        "SELECT * FROM users WHERE username = ?",
        ("master",)
    )

    otp = pyotp.TOTP(user["totp_secret"]).now()

    client.post(
        "/auth/2fa/enable",
        json={"otp": otp}
    )

    client.post("/auth/logout")

    response = client.post(
        "/auth/login",
        json={
            "username": "master",
            "password": "SafeVaultPassword123!"
        }
    )

    assert response.status_code == 200
    assert response.json["requires_2fa"] is True

    current_user = client.get("/auth/me")

    assert current_user.status_code == 401


def test_2fa_login_verification(client):

    register_and_login(client)

    client.post("/auth/2fa/setup")

    user = fetch_one(
        "SELECT * FROM users WHERE username = ?",
        ("master",)
    )

    otp = pyotp.TOTP(user["totp_secret"]).now()

    client.post(
        "/auth/2fa/enable",
        json={"otp": otp}
    )

    client.post("/auth/logout")

    client.post(
        "/auth/login",
        json={
            "username": "master",
            "password": "SafeVaultPassword123!"
        }
    )

    otp = pyotp.TOTP(user["totp_secret"]).now()

    response = client.post(
        "/auth/2fa/verify",
        json={"otp": otp}
    )

    assert response.status_code == 200

    current_user = client.get("/auth/me")

    assert current_user.status_code == 200


def test_2fa_login_rejects_invalid_otp(client):

    register_and_login(client)

    client.post("/auth/2fa/setup")

    user = fetch_one(
        "SELECT * FROM users WHERE username = ?",
        ("master",)
    )

    otp = pyotp.TOTP(user["totp_secret"]).now()

    client.post(
        "/auth/2fa/enable",
        json={"otp": otp}
    )

    client.post("/auth/logout")

    client.post(
        "/auth/login",
        json={
            "username": "master",
            "password": "SafeVaultPassword123!"
        }
    )

    response = client.post(
        "/auth/2fa/verify",
        json={"otp": "000000"}
    )

    assert response.status_code == 401

    current_user = client.get("/auth/me")

    assert current_user.status_code == 401


def test_2fa_disable(client):

    register_and_login(client)

    client.post("/auth/2fa/setup")

    user = fetch_one(
        "SELECT * FROM users WHERE username = ?",
        ("master",)
    )

    otp = pyotp.TOTP(user["totp_secret"]).now()

    client.post(
        "/auth/2fa/enable",
        json={"otp": otp}
    )

    response = client.post(
        "/auth/2fa/disable",
        json={
            "password": "SafeVaultPassword123!",
            "otp": pyotp.TOTP(user["totp_secret"]).now()
        }
    )

    assert response.status_code == 200

    updated_user = fetch_one(
        "SELECT * FROM users WHERE username = ?",
        ("master",)
    )

    assert updated_user["two_factor_enabled"] == 0
    assert updated_user["totp_secret"] is None
