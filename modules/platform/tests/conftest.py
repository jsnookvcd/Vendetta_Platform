"""Platform control-plane tests run against a real Postgres. Point
PLATFORM_TEST_DATABASE_URL at a disposable database."""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
TEST_DB = os.environ.get("PLATFORM_TEST_DATABASE_URL", "postgresql+psycopg://platform:platform@localhost:5432/platform_test")
os.environ["DATABASE_URL"] = TEST_DB
os.environ.setdefault("SECRET_KEY", "test-secret")

import bcrypt  # noqa: E402

os.environ["ADMIN_PASSWORD_HASH"] = bcrypt.hashpw(b"pw", bcrypt.gensalt(4)).decode()


def _db_up() -> bool:
    try:
        from sqlalchemy import create_engine, text

        with create_engine(TEST_DB).connect() as c:
            c.execute(text("select 1"))
        return True
    except Exception:  # noqa: BLE001
        return False


def _release(engine):
    from sqlalchemy.orm import close_all_sessions

    close_all_sessions()
    engine.dispose()


@pytest.fixture()
def fresh_db():
    if not _db_up():
        pytest.skip("test database not reachable")
    from app import aggregate, client360
    from app.db import Base, engine, init_db

    aggregate.clear_cache()
    client360.use_transport(None)
    _release(engine)
    Base.metadata.drop_all(engine)
    init_db()
    yield
    _release(engine)


@pytest.fixture()
def client(fresh_db):
    from fastapi.testclient import TestClient

    from app.main import app

    with TestClient(app) as tc:
        yield tc


@pytest.fixture()
def admin(client):
    client.post("/login", data={"username": "admin", "password": "pw", "next": "/"})
    return client
