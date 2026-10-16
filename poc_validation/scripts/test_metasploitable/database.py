from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

# Connecting to the local Docker Postgres database
SQLALCHEMY_DATABASE_URL = "postgresql://admin:password@localhost:5432/autosectwin"

engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()