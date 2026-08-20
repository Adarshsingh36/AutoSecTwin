from fastapi.testclient import TestClient

from main import app


def test_health_endpoint_works_without_database():
    client = TestClient(app)

    response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_openapi_includes_required_routes():
    client = TestClient(app)

    schema = client.get("/openapi.json").json()
    paths = schema["paths"]

    for path in [
        "/vulnerabilities/",
        "/exploits/",
        "/validations/",
        "/confidence/",
        "/confidence/calculate",
        "/approvals/",
        "/approval/legacy",
        "/approval/hallucinations",
        "/trust/compare",
        "/trust/statistics",
        "/trust/drift",
        "/legacy/profile",
        "/recommendation/generate",
        "/remediations/",
        "/reports/",
        "/twins/",
    ]:
        assert path in paths
