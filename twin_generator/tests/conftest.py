"""
Shared pytest fixtures for twin_generator tests.

Uses an in-memory SQLite database purely for test isolation and speed.
Production runs against the project's existing PostgreSQL instance via
core.database -- this fixture never touches that.
"""

from __future__ import annotations

from typing import Iterator

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from twin_generator.api.deps import get_session
from twin_generator.api.legacy import router as legacy_router
from twin_generator.api.registry import router as registry_router
from twin_generator.api.twins import router as twins_router
from twin_generator.models.base import Base


@pytest.fixture
def session() -> Iterator[Session]:
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
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
        engine.dispose()


@pytest.fixture
def app(session: Session) -> FastAPI:
    application = FastAPI()
    application.include_router(registry_router)
    application.include_router(legacy_router)
    application.include_router(twins_router)

    def _override_get_session() -> Iterator[Session]:
        yield session

    application.dependency_overrides[get_session] = _override_get_session
    return application


@pytest.fixture
def client(app: FastAPI) -> Iterator[TestClient]:
    with TestClient(app) as client:
        yield client