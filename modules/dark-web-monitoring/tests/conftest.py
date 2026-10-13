"""Shared test setup. Most dark web tests are pure unit tests; the provisioning
test needs a real Postgres. Point DARKWEB_TEST_DATABASE_URL at a disposable
database; it is dropped and recreated. The DB-backed test skips if unreachable."""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
TEST_DB = os.environ.get("DARKWEB_TEST_DATABASE_URL", "postgresql+psycopg://darkweb:darkweb@localhost:5432/darkweb_test")
os.environ["DATABASE_URL"] = TEST_DB
os.environ.setdefault("SECRET_KEY", "test-secret")


def _db_up() -> bool:
    try:
        from sqlalchemy import create_engine, text

        with create_engine(TEST_DB).connect() as c:
            c.execute(text("select 1"))
        return True
    except Exception:  # noqa: BLE001
        return False


@pytest.fixture()
def fresh_db():
    if not _db_up():
        pytest.skip("test database not reachable")
    from sqlalchemy.orm import close_all_sessions

    from app.db import Base, engine, init_db

    close_all_sessions()
    engine.dispose()
    Base.metadata.drop_all(engine)
    init_db()
    yield
    close_all_sessions()
    engine.dispose()
