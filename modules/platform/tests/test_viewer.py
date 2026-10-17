"""The viewer level on the control plane: a platform role that reads every page and
API and changes nothing, and a module grant the Staff page hands out. The
Leadership profile is viewer everywhere except SABINE."""
from app import auth, staff
from app.db import SessionLocal, User


def _as_viewer(client, email="board@vendettacd.io"):
    db = SessionLocal()
    try:
        if not db.query(User).filter_by(email=email).count():
            db.add(User(email=email, role="viewer", source="entra"))
            db.commit()
    finally:
        db.close()
    client.cookies.set(auth.COOKIE, auth.make_session(email))


def test_viewer_reads_pages_and_api(client):
    _as_viewer(client)
    assert client.get("/").status_code == 200
    assert client.get("/staff").status_code == 200
    assert client.get("/api/module").status_code == 200


def test_viewer_cannot_change_anything(client):
    _as_viewer(client)
    r = client.post("/clients", data={"name": "Viewer Co"}, follow_redirects=False)
    assert r.status_code == 403 and "read-only" in r.json()["detail"]
    r = client.post("/staff", data={"email": "x@vendettacd.io", "profile": "soc-analyst"}, follow_redirects=False)
    assert r.status_code == 403


def test_viewer_grant_is_offered_and_pushed_to_modules(admin):
    r = admin.post("/staff", data={"email": "board@vendettacd.io", "name": "Board", "profile": "leadership"},
                   follow_redirects=False)
    sid = r.headers["location"].split("/staff/")[1].split("?")[0]
    # the roster a module pulls carries the viewer level
    out = admin.get("/api/platform/staff", params={"module": "incident-response"},
                    headers={"Authorization": f"Bearer {auth.api_token()}"}).json()
    assert out["staff"][0]["role"] == "viewer"
    out = admin.get("/api/platform/staff", params={"module": "sabine"},
                    headers={"Authorization": f"Bearer {auth.api_token()}"}).json()
    assert out["staff"][0]["role"] == "analyst"
    out = admin.get("/api/platform/staff", params={"module": "managed-services"},
                    headers={"Authorization": f"Bearer {auth.api_token()}"}).json()
    assert out["staff"][0]["config"] == {"can_act": False, "can_approve": False}
    # a single grant can be set to viewer, and ticking act/approve on it is ignored
    admin.post(f"/staff/{sid}/grant/managed-services", data={"role": "viewer", "can_act": "true", "can_approve": "true"})
    out = admin.get("/api/platform/staff", params={"module": "managed-services"},
                    headers={"Authorization": f"Bearer {auth.api_token()}"}).json()
    assert out["staff"][0]["role"] == "viewer" and out["staff"][0]["config"] == {"can_act": False, "can_approve": False}
    assert "viewer" in staff.MODULE_ROLES and "viewer" in staff.PLATFORM_ROLES
    assert staff.PROFILES["leadership"][2] == "viewer"
