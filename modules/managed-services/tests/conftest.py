"""Integration tests run against a real Postgres. Point MSP_TEST_DATABASE_URL at a
disposable database; the tests drop and recreate its tables. Skipped if the
database is unreachable. Tool credentials are set to dummies so every connector
reports configured; tests swap in connectors built on httpx.MockTransport."""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
TEST_DB = os.environ.get("MSP_TEST_DATABASE_URL", "postgresql+psycopg://msp:msp@localhost:5432/msp_test")
os.environ["DATABASE_URL"] = TEST_DB
os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.update(
    SUPEROPS_API_TOKEN="t", SUPEROPS_SUBDOMAIN="vendetta", SUPEROPS_BASE_URL="https://vendetta.superops.ai",
    SENTINELONE_URL="https://vendetta.sentinelone.net", SENTINELONE_API_TOKEN="t",
    CROWDSTRIKE_CLIENT_ID="cid", CROWDSTRIKE_CLIENT_SECRET="sec",
    HUNTRESS_API_KEY="k", HUNTRESS_API_SECRET="s", HUNTRESS_BASE_URL="https://vendetta.huntress.io",
    ACRONIS_DC_URL="https://us5-cloud.acronis.com", ACRONIS_CLIENT_ID="ac", ACRONIS_CLIENT_SECRET="as",
)

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
    from app import connectors
    from app.db import Base, engine, init_db
    from app.sync import LAST_SYNC

    connectors.reset()
    LAST_SYNC.clear()
    _release(engine)
    Base.metadata.drop_all(engine)
    init_db()
    yield
    connectors.reset()
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
