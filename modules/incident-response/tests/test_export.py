"""The one-click sealed evidence export per case: the route returns a package whose
bundled standalone verifier confirms it offline, tampering fails, and the client's
copy seals internal entries while still verifying."""
import io
import json
import zipfile

from app import auth
from app.db import Case, CaseUpdate, Client, SessionLocal, User, open_case
from app.evidence_export import verify_package


def _case(title="Ransomware on file server"):
    db = SessionLocal()
    c = Client(name="Acme Corp", portal_enabled=True, portal_domains="acme.example")
    db.add(c); db.commit()
    case = open_case(db, c, title, actor="dan@vendettacd.io")
    db = SessionLocal()
    cs = db.get(Case, case.id)
    cs.updates.append(CaseUpdate(actor="analyst", kind="note", note="Isolated FS01", internal_only=False))
    cs.updates.append(CaseUpdate(actor="analyst", kind="note", note="Suspect insider", internal_only=True))
    db.commit()
    return case


def _verify_bytes(zip_bytes, tmp_path, name="export.zip"):
    p = tmp_path / name
    p.write_bytes(zip_bytes)
    return verify_package(str(p))


def test_staff_export_verifies(admin, tmp_path):
    case = _case()
    r = admin.get(f"/cases/{case.id}/evidence/export.zip")
    assert r.status_code == 200 and r.headers["content-type"] == "application/zip"
    assert case.number in r.headers["content-disposition"]
    report = _verify_bytes(r.content, tmp_path)
    assert report["ok"] is True
    assert report["checks"]["chain_of_custody"]["ok"]
    assert report["subject"]["number"] == case.number and report["subject"]["client"] == "Acme Corp"


def test_export_is_self_contained(admin):
    case = _case()
    r = admin.get(f"/cases/{case.id}/evidence/export.zip")
    with zipfile.ZipFile(io.BytesIO(r.content)) as z:
        names = [n.split("/", 1)[1] for n in z.namelist()]
    for want in ("MANIFEST.json", "MANIFEST.sig", "proof.json", "verify_evidence.py", "README.txt"):
        assert want in names


def test_tampered_package_fails(admin, tmp_path):
    case = _case()
    r = admin.get(f"/cases/{case.id}/evidence/export.zip")
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
    report = _verify_bytes(buf.getvalue(), tmp_path, "tampered.zip")
    assert report["ok"] is False


def test_portal_export_seals_internal_entries_and_is_tenant_scoped(client, tmp_path):
    case = _case()
    db = SessionLocal()
    other = Client(name="Other Co")
    db.add(other); db.commit()
    other_case = open_case(db, other, "not mine")
    db.add(User(email="it@acme.example", role="client", client_id=case.client_id)); db.commit()
    client.cookies.set(auth.COOKIE, auth.make_session("it@acme.example"))
    r = client.get(f"/portal/cases/{case.id}/evidence/export.zip")
    assert r.status_code == 200
    report = _verify_bytes(r.content, tmp_path, "portal.zip")
    assert report["ok"] is True and report["subject"]["id"] == case.id
    with zipfile.ZipFile(io.BytesIO(r.content)) as z:
        proof = json.loads(z.read(next(n for n in z.namelist() if n.endswith("proof.json"))))
    sealed = [rec for rec in proof["records"] if rec["fields"] is None]
    assert sealed and all(rec["sealed"] for rec in sealed)
    assert "Suspect insider" not in json.dumps(proof)
    assert client.get(f"/portal/cases/{other_case.id}/evidence/export.zip").status_code == 404
