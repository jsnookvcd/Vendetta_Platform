"""The viewer level: a read-only internal grant from the platform roster. A viewer
opens every staff page and reads every API; every state-changing request is
refused with 403 and a plain message, enforced once in auth.current_user."""
from app import auth
from app.db import SessionLocal, User


def _as_viewer(client, email="board@vendettacd.io"):
    db = SessionLocal()
    try:
        if not db.query(User).filter_by(email=email).count():
            db.add(User(email=email, role="viewer", source="platform"))
            db.commit()
    finally:
        db.close()
    client.cookies.set(auth.COOKIE, auth.make_session(email))


def test_viewer_reads_pages_and_api(client):
    _as_viewer(client)
    assert client.get("/").status_code == 200
    assert client.get("/api/queue").status_code == 200


def test_viewer_cannot_change_anything(client):
    _as_viewer(client)
    r = client.post("/run", data={}, follow_redirects=False)
    assert r.status_code == 403
    assert "read-only" in r.json()["detail"]
    


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
