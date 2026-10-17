"""The one-click sealed evidence export per client: the route returns a package whose
bundled standalone verifier confirms it offline, tampering fails, and a portal user
gets only their own tenant's package."""
import io
import json
import zipfile

from app import auth
from app.db import ActionLog, Client, SessionLocal, User
from app.evidence_export import verify_package


def _client(name="Acme Corp"):
    db = SessionLocal()
    c = Client(name=name, portal_enabled=True, portal_domains="acme.example")
    db.add(c); db.commit()
    return c


def _action(client_id, action, actor="tech@vendettacd.io"):
    db = SessionLocal()
    db.add(ActionLog(client_id=client_id, tool="sentinelone", action=action, actor=actor, client_visible=True))
    db.commit()


def _verify_bytes(zip_bytes, tmp_path, name="export.zip"):
    p = tmp_path / name
    p.write_bytes(zip_bytes)
    return verify_package(str(p))


def test_staff_export_verifies(admin, tmp_path):
    c = _client()
    for a in ("isolate", "contain", "resolve"):
        _action(c.id, a)
    r = admin.get(f"/clients/{c.id}/evidence/export.zip")
    assert r.status_code == 200 and r.headers["content-type"] == "application/zip"
    report = _verify_bytes(r.content, tmp_path)
    assert report["ok"] is True
    assert report["checks"]["chain_of_custody"]["ok"]
    assert report["subject"]["name"] == "Acme Corp"


def test_export_is_self_contained(admin):
    c = _client()
    _action(c.id, "isolate")
    r = admin.get(f"/clients/{c.id}/evidence/export.zip")
    with zipfile.ZipFile(io.BytesIO(r.content)) as z:
        names = [n.split("/", 1)[1] for n in z.namelist()]
    for want in ("MANIFEST.json", "MANIFEST.sig", "proof.json", "verify_evidence.py", "README.txt"):
        assert want in names


def test_tampered_package_fails(admin, tmp_path):
    c = _client()
    _action(c.id, "isolate")
    r = admin.get(f"/clients/{c.id}/evidence/export.zip")
    with zipfile.ZipFile(io.BytesIO(r.content)) as z:
        root = z.namelist()[0].split("/", 1)[0]
        files = {n: z.read(n) for n in z.namelist()}
    proof = json.loads(files[f"{root}/proof.json"])
    proof["records"][0]["fields"]["actor"] = "someone-else@evil.example"
    files[f"{root}/proof.json"] = json.dumps(proof, indent=2).encode()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for n, b in files.items():
            z.writestr(n, b)
    assert _verify_bytes(buf.getvalue(), tmp_path, "tampered.zip")["ok"] is False


def test_portal_export_scoped_to_tenant(client, tmp_path):
    c = _client()
    other = _client("Other Co")
    _action(c.id, "isolate")
    _action(other.id, "contain", actor="other-tech@vendettacd.io")
    db = SessionLocal()
    db.add(User(email="it@acme.example", role="client", client_id=c.id)); db.commit()
    client.cookies.set(auth.COOKIE, auth.make_session("it@acme.example"))
    r = client.get("/portal/evidence/export.zip")
    assert r.status_code == 200
    report = _verify_bytes(r.content, tmp_path, "portal.zip")
    assert report["ok"] is True and report["subject"]["id"] == c.id
    with zipfile.ZipFile(io.BytesIO(r.content)) as z:
        proof = z.read(next(n for n in z.namelist() if n.endswith("proof.json"))).decode()
    assert "other-tech@vendettacd.io" not in proof
