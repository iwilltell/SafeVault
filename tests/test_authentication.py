
import pytest

from app import create_app
from app.config import Config


@pytest.fixture
def client(tmp_path, monkeypatch):

    database_path = tmp_path / "auth_test.sqlite3"

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


def register_user(client):

    return client.post(
        "/auth/register",
        json={
            "username": "master",
            "email": "master@example.com",
            "password": "SafeVaultPassword123!"
        }
    )


def test_user_registration(client):

    response = register_user(client)

    assert response.status_code == 201
    assert response.json["message"] == "Registration successful."


def test_duplicate_registration(client):

    register_user(client)

    response = register_user(client)

    assert response.status_code == 409


def test_invalid_password_registration(client):

    response = client.post(
        "/auth/register",
        json={
            "username": "master",
            "email": "master@example.com",
            "password": "weak"
        }
    )

    assert response.status_code == 400


def test_successful_login(client):

    register_user(client)

    response = client.post(
        "/auth/login",
        json={
            "username": "master",
            "password": "SafeVaultPassword123!"
        }
    )

    assert response.status_code == 200
    assert response.json["requires_2fa"] is False


def test_wrong_password(client):

    register_user(client)

    response = client.post(
        "/auth/login",
        json={
            "username": "master",
            "password": "WrongPassword123!"
        }
    )

    assert response.status_code == 401


def test_current_user(client):

    register_user(client)

    client.post(
        "/auth/login",
        json={
            "username": "master",
            "password": "SafeVaultPassword123!"
        }
    )

    response = client.get("/auth/me")

    assert response.status_code == 200
    assert response.json["username"] == "master"


def test_logout(client):

    register_user(client)

    client.post(
        "/auth/login",
        json={
            "username": "master",
            "password": "SafeVaultPassword123!"
        }
    )

    response = client.post("/auth/logout")

    assert response.status_code == 200

    response = client.get("/auth/me")

    assert response.status_code == 401


def test_unauthenticated_user(client):

    response = client.get("/auth/me")

    assert response.status_code == 401
