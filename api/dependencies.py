from database.session import SessionLocal


def pagination(limit: int = 50, offset: int = 0) -> tuple[int, int]:
    if limit < 1:
        limit = 1
    if limit > 500:
        limit = 500
    if offset < 0:
        offset = 0
    return limit, offset


def get_db():

    db = SessionLocal()

    try:
        yield db

    finally:
        db.close()
