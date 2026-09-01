"""
Shared pytest fixtures for twin_generator tests.
"""

from __future__ import annotations

from typing import Generator
from unittest.mock import MagicMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

import database.models
from twin_generator.api.deps import get_session
from twin_generator.api.legacy import router as legacy_router
from twin_generator.api.registry import router as registry_router
from twin_generator.api.twins import router as twins_router
from twin_generator.models.base import Base


@pytest.fixture
def db_session() -> Generator[Session, None, None]:
    """
    Synchronous in-memory database used by the generator test suite.

    StaticPool ensures the same SQLite connection is reused by the
    application and FastAPI TestClient.
    """
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    Base.metadata.create_all(engine)

    SessionLocal = sessionmaker(
        bind=engine,
        autocommit=False,
        autoflush=False,
        expire_on_commit=False,
    )

    db = SessionLocal()

    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(engine)
        engine.dispose()


@pytest.fixture
def session(db_session: Session) -> Session:
    """
    Backwards-compatible alias used by cleanup/legacy tests.
    """
    return db_session


@pytest.fixture
def orchestrator() -> MagicMock:
    return MagicMock()


@pytest.fixture
def docker_client() -> MagicMock:
    client = MagicMock()
    client.containers.list.return_value = []
    client.networks.prune.return_value = {}
    client.volumes.prune.return_value = {}
    return client


@pytest.fixture
def app(db_session: Session) -> FastAPI:
    application = FastAPI()

    application.include_router(registry_router)
    application.include_router(legacy_router)
    application.include_router(twins_router)

    def _override_get_session() -> Generator[Session, None, None]:
        yield db_session

    application.dependency_overrides[get_session] = _override_get_session

    return application


@pytest.fixture
def client(app: FastAPI) -> Generator[TestClient, None, None]:
    with TestClient(app) as test_client:
        yield test_client