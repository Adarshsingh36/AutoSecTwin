from database.base import Base
from database.session import engine

import database.models


def create_tables():
    """Create all SQLAlchemy tables for local development."""

    Base.metadata.create_all(bind=engine)
