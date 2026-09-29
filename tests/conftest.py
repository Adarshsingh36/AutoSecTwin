import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from api.dependencies import get_db
from core.config import settings
from database.base import Base


@pytest.fixture()
def test_db_engine():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    yield engine
    engine.dispose()


@pytest.fixture()
def TestSessionLocal(test_db_engine):
    return sessionmaker(bind=test_db_engine, autoflush=False, autocommit=False)


@pytest.fixture()
def db(TestSessionLocal):
    """A raw SQLAlchemy session for seeding data directly."""

    session = TestSessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture()
def client(TestSessionLocal, monkeypatch):
    """A FastAPI TestClient wired to the in-memory test database instead
    of the real (Postgres) one, and with MOCK_MODE forced on so nothing
    tries to reach real external infrastructure."""

    from main import app

    monkeypatch.setattr(settings, "MOCK_MODE", True)

    def override_get_db():
        session = TestSessionLocal()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_db] = override_get_db
    try:
        yield TestClient(app)
    finally:
        app.dependency_overrides.pop(get_db, None)
