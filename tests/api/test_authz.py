import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from api.dependencies import get_db
from core.config import settings
from database.base import Base
from database.models.asset import Asset
from database.models.vulnerability import Vulnerability


@pytest.fixture()
def auth_client(monkeypatch):
    from main import app

    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

    monkeypatch.setattr(settings, "AUTH_ENABLED", True)
    monkeypatch.setattr(settings, "AUTH_DEV_ADMIN_TOKEN", "admin-token")
    monkeypatch.setattr(settings, "AUTH_STATIC_TOKEN_HASHES_JSON", "{}")
    monkeypatch.setattr(settings, "MOCK_MODE", True)

    def override_get_db():
        session = SessionLocal()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_db] = override_get_db
    try:
        with TestClient(app) as client:
            yield client, SessionLocal
    finally:
        app.dependency_overrides.pop(get_db, None)
        engine.dispose()


def test_sensitive_route_rejects_unauthenticated(auth_client):
    client, _ = auth_client

    response = client.get("/vulnerabilities/")

    assert response.status_code == 401


def test_viewer_cannot_create_exploit(auth_client, monkeypatch):
    client, SessionLocal = auth_client
    import hashlib
    import json

    viewer_token = "viewer-token"
    monkeypatch.setattr(
        settings,
        "AUTH_STATIC_TOKEN_HASHES_JSON",
        json.dumps({hashlib.sha256(viewer_token.encode("utf-8")).hexdigest(): ["viewer"]}),
    )

    with SessionLocal() as db:
        asset = Asset(name="a", asset_type="server")
        db.add(asset)
        db.commit()
        db.refresh(asset)
        vuln = Vulnerability(asset_id=asset.id, cve_id="CVE-2099-0001", title="x")
        db.add(vuln)
        db.commit()
        db.refresh(vuln)
        vuln_id = vuln.id

    response = client.post(
        "/exploits/",
        headers={"Authorization": f"Bearer {viewer_token}"},
        json={
            "vulnerability_id": vuln_id,
            "source": "metasploit",
            "module_name": "multi/test/module",
            "title": "test",
        },
    )

    assert response.status_code == 403


def test_admin_token_can_read_protected_route(auth_client):
    client, _ = auth_client

    response = client.get("/vulnerabilities/", headers={"Authorization": "Bearer admin-token"})

    assert response.status_code == 200
