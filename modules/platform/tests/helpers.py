"""Shared helpers for the control-plane tests."""
from app import auth
from app.db import Client, SessionLocal, User


def bearer(actor: str = "") -> dict:
    h = {"Authorization": f"Bearer {auth.api_token()}"}
    if actor:
        h["X-Vendetta-Actor"] = actor
    return h


def make_client(admin, name="Riverbend Credit Union", **edit) -> Client:
    admin.post("/clients", data={"name": name})
    c = SessionLocal().query(Client).filter_by(name=name).one()
    if edit:
        data = {"active": "true", **edit}
        r = admin.post(f"/clients/{c.id}/edit", data=data, follow_redirects=False)
        assert "msg=" in r.headers["location"], r.headers["location"]
    return SessionLocal().get(Client, c.id)


def sign_in_as(client, email, role, client_id=None):
    db = SessionLocal()
    try:
        u = db.query(User).filter_by(email=email).one_or_none()
        if u is None:
            db.add(User(email=email, role=role, client_id=client_id, source="entra"))
        else:
            u.role, u.client_id, u.active = role, client_id, True
        db.commit()
    finally:
        db.close()
    client.cookies.set(auth.COOKIE, auth.make_session(email))
