"""
Phase 1 smoke tests: verifies the FastAPI app builds successfully and the
/health endpoint responds. Domain-specific unit tests (feature_builder,
predictor, etc.) are added alongside their modules in Phase 2.

Run with (from inside the `asde/` directory):
    pytest tests/unit/test_main.py -v

Requires a .env file (copied from .env.example) in the working directory
so Settings() can resolve DATABASE_URL and SECRET_KEY. A live PostgreSQL
instance is NOT required for this test -- check_database_connection()
fails gracefully and /health simply reports database_connected: false.
"""

from fastapi.testclient import TestClient

from main import app

client = TestClient(app)


def test_health_check_returns_200():
    response = client.get("/health")
    assert response.status_code == 200


def test_health_check_payload_shape():
    response = client.get("/health")
    body = response.json()
    assert body["status"] == "ok"
    assert "app_name" in body
    assert "version" in body
    assert "environment" in body
    assert "database_connected" in body


def test_unknown_route_returns_consistent_error_envelope():
    response = client.get("/this-route-does-not-exist")
    assert response.status_code == 404
    body = response.json()
    assert "error" in body
    assert "code" in body["error"]
    assert "message" in body["error"]
