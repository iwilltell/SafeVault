
from app import create_app


def test_home_route_returns_login_page():
    app = create_app()
    app.config["TESTING"] = True

    client = app.test_client()

    response = client.get("/")

    assert response.status_code == 200
    assert b"SafeVault" in response.data
    assert b"loginForm" in response.data


def test_home_route_redirects_authenticated_user():
    app = create_app()
    app.config["TESTING"] = True

    client = app.test_client()

    with client.session_transaction() as session:
        session["user_id"] = 1

    response = client.get("/")

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/dashboard")
