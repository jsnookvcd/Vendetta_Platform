"""The one-click defensible evidence export: the route returns a sealed package whose
bundled standalone verifier confirms it offline."""
import io
import zipfile

from app import auth
from app.db import Client, Deliverable, SessionLocal, User
from app.evidence_export import verify_package


def _client(name="Acme Corp"):
    db = SessionLocal()
    c = Client(name=name, portal_enabled=True, portal_domains="acme.example")
    db.add(c); db.commit()
    return c


def _engagement(admin, cid, name="vCISO Retainer"):
    r = admin.post(f"/clients/{cid}/engagements",
                   data={"name": name, "kind": "vciso", "cadence": "monthly"}, follow_redirects=False)
    return r.headers["location"].split("/engagements/")[1]


def _delivered(admin, eid, title="ISP v1"):
    admin.post(f"/engagements/{eid}/deliverables", data={"title": title, "kind": "policy"})
    did = SessionLocal().query(Deliverable).filter_by(engagement_id=eid, title=title).one().id
    admin.post(f"/deliverables/{did}/edit", data={"status": "delivered", "kind": "policy", "title": title})
    return did


def _verify_bytes(zip_bytes, tmp_path, name="export.zip"):
    p = tmp_path / name
    p.write_bytes(zip_bytes)
    return verify_package(str(p))


def test_staff_export_verifies(admin, tmp_path):
    c = _client()
    eid = _engagement(admin, c.id)
    _delivered(admin, eid)
    r = admin.get(f"/clients/{c.id}/evidence/export.zip")
    assert r.status_code == 200 and r.headers["content-type"] == "application/zip"
    report = _verify_bytes(r.content, tmp_path)
    assert report["ok"] is True
    assert report["checks"]["chain_of_custody"]["ok"]
    assert report["subject"]["name"] == "Acme Corp"


def test_export_is_self_contained(admin):
    c = _client()
    _engagement(admin, c.id)
    r = admin.get(f"/clients/{c.id}/evidence/export.zip")
    with zipfile.ZipFile(io.BytesIO(r.content)) as z:
        names = [n.split("/", 1)[1] for n in z.namelist()]
    for want in ("MANIFEST.json", "MANIFEST.sig", "proof.json", "verify_evidence.py", "README.txt"):
        assert want in names


def test_portal_export_scoped_to_tenant(admin, client, tmp_path):
    c = _client()
    eid = _engagement(admin, c.id)
    _delivered(admin, eid)
    db = SessionLocal()
    db.add(User(email="it@acme.example", role="client", client_id=c.id)); db.commit()
    client.cookies.set(auth.COOKIE, auth.make_session("it@acme.example"))
    r = client.get("/portal/evidence/export.zip")
    assert r.status_code == 200
    report = _verify_bytes(r.content, tmp_path, "portal.zip")
    assert report["ok"] is True and report["subject"]["id"] == c.id
