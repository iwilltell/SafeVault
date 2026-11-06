from app import create_app


def test_home_route_returns_safevault_status():
    app = create_app()
    app.config["TESTING"] = True
    client = app.test_client()

    response = client.get("/")

    assert response.status_code == 200
    assert response.json["application"] == "SafeVault"
