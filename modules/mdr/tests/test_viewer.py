"""The viewer level: a read-only internal grant from the platform roster. A viewer
opens every staff page and reads every API; every state-changing request is
refused with 403 and a plain message, enforced once in auth.current_user."""
import datetime as dt

from app.db import Client, Investigation, SessionLocal, Suppression, User
from helpers import as_user, finding, ingest, make_client


def test_viewer_reads_pages_and_api(client, now):
    make_client()
    ingest([finding(fid="a1", at=now)], now=now)
    inv = SessionLocal().query(Investigation).one()
    as_user(client, "board@vendettacd.io", "viewer")
    for path in ("/", "/investigations", f"/investigations/{inv.id}", "/rules", "/rules/ransomware-behavior",
                 "/suppressions", "/coverage", "/clients", "/settings"):
        assert client.get(path).status_code == 200, path
    for path in ("/api/findings", "/api/metrics", "/api/coverage", "/api/suppressions", "/api/module"):
        assert client.get(path).status_code == 200, path
    page = client.get(f"/investigations/{inv.id}").text
    assert "Read-only access" in page and "Acknowledge</button>" not in page


def test_viewer_cannot_change_anything(client, now):
    c = make_client()
    ingest([finding(fid="a1", at=now)], now=now)
    inv = SessionLocal().query(Investigation).one()
    as_user(client, "board@vendettacd.io", "viewer")
    posts = [
        (f"/investigations/{inv.id}/ack", {}),
        (f"/investigations/{inv.id}/verdict", {"verdict": "benign"}),
        (f"/investigations/{inv.id}/note", {"text": "x"}),
        (f"/investigations/{inv.id}/noise", {"reason": "x", "days": 30}),
        (f"/investigations/{inv.id}/close", {}),
        (f"/investigations/{inv.id}/escalate", {}),
        (f"/investigations/{inv.id}/prepare-containment", {"action": "isolate_host"}),
        ("/suppressions", {"client_id": c.id, "tool": "aws", "reason": "x", "days": 5}),
        ("/clients", {"name": "Viewer Co"}),
        ("/detect/run", {}),
        ("/rules/ransomware-behavior/overrides", {"client_id": c.id, "disabled": "true"}),
    ]
    for path, data in posts:
        r = client.post(path, data=data, follow_redirects=False)
        assert r.status_code == 403, path
        assert "read-only" in r.json()["detail"]
    r = client.post("/api/suppressions", json={"platform_client_id": "plat-acme", "tool": "aws",
                                               "reason": "x", "days": 5})
    assert r.status_code == 403
    db = SessionLocal()
    i = db.get(Investigation, inv.id)
    assert i.acknowledged_at is None and i.status == "new"
    assert db.query(Suppression).count() == 0 and db.query(Client).filter_by(name="Viewer Co").count() == 0


def test_viewer_is_admitted_by_the_roster(client):
    from app import provision
    body = {"governs": True, "staff": [{"email": "board@vendettacd.io", "name": "Board", "role": "viewer", "config": {}}]}
    db = SessionLocal()
    try:
        provision._apply_staff(db, body)
        u = db.query(User).filter_by(email="board@vendettacd.io").one()
        assert u.role == "viewer" and u.active and u.source == "platform"
    finally:
        db.close()


def test_deactivated_user_loses_session(client, now):
    as_user(client, "gone@vendettacd.io", "analyst")
    assert client.get("/").status_code == 200
    db = SessionLocal()
    db.query(User).filter_by(email="gone@vendettacd.io").one().active = False
    db.commit()
    r = client.get("/", follow_redirects=False)
    assert r.status_code == 302 and r.headers["location"].startswith("/login")
    _ = dt
