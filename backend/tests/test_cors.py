"""CORS wiring tests (Phase 10): the SOC dashboard (`frontend/`) calls this
API from its own origin, so the browser's preflight/actual-request CORS
headers have to be real, not just a middleware line nobody exercised.
"""

from fastapi.testclient import TestClient

from app.core.app_factory import create_app
from app.core.config import Settings

app = create_app(Settings(cors_allowed_origins=["http://localhost:5173"]))
client = TestClient(app)


def test_allowed_origin_gets_cors_headers_on_a_real_request():
    response = client.get("/health", headers={"Origin": "http://localhost:5173"})
    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "http://localhost:5173"


def test_disallowed_origin_gets_no_cors_header():
    response = client.get("/health", headers={"Origin": "http://evil.example"})
    assert response.status_code == 200
    assert "access-control-allow-origin" not in response.headers


def test_preflight_request_for_allowed_origin_is_approved():
    response = client.options(
        "/incidents",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type",
        },
    )
    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "http://localhost:5173"


def test_settings_parses_comma_separated_origins_from_a_plain_string():
    settings = Settings(cors_allowed_origins="http://a.example, http://b.example")
    assert settings.cors_allowed_origins == ["http://a.example", "http://b.example"]


def test_settings_parses_a_json_array_string_of_origins():
    settings = Settings(cors_allowed_origins='["http://a.example", "http://b.example"]')
    assert settings.cors_allowed_origins == ["http://a.example", "http://b.example"]


def test_settings_default_origins_are_the_vite_dev_server():
    settings = Settings()
    assert "http://localhost:5173" in settings.cors_allowed_origins
