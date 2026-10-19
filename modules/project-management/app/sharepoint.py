"""SharePoint mirror for meeting notes (Microsoft Graph, app-only).

A note is always saved in this module first; the mirror is a copy written as a Word
document into the engagement's SharePoint folder. When the engagement carries its
own site (an IR case site provisioned in Microsoft 365) the note goes there;
otherwise it goes to the module default site under <folder>/<engagement code>.

The upload is a path-based PUT, which creates any missing folders. A changed note
overwrites the same document by item id. A failure leaves the note saved with
sp_status "failed" and the reason, and a background loop retries failed notes.
"""
from __future__ import annotations

import datetime as dt
import io
import logging
import re
import time
from urllib.parse import quote, urlparse

import httpx

from . import integrations
from .db import Engagement, MeetingNote, utcnow

log = logging.getLogger(__name__)
GRAPH = "https://graph.microsoft.com/v1.0"
TRANSPORT: httpx.BaseTransport | None = None
_TOKEN: dict = {"value": "", "exp": 0.0, "key": ""}
_SITES: dict[str, str] = {}


class SharePointError(Exception):
    pass


def configured_for(eng: Engagement) -> bool:
    cfg = integrations.resolve()
    has_creds = bool(cfg["graph_tenant_id"] and cfg["graph_client_id"] and cfg["graph_client_secret"])
    return has_creds and bool(eng.sharepoint_site_url or cfg["sharepoint_site_url"])


def _token(http: httpx.Client) -> str:
    cfg = integrations.resolve()
    key = f"{cfg['graph_tenant_id']}|{cfg['graph_client_id']}"
    if _TOKEN["value"] and _TOKEN["key"] == key and time.time() < _TOKEN["exp"] - 120:
        return _TOKEN["value"]
    r = http.post(f"https://login.microsoftonline.com/{cfg['graph_tenant_id']}/oauth2/v2.0/token",
                  data={"client_id": cfg["graph_client_id"], "client_secret": cfg["graph_client_secret"],
                        "grant_type": "client_credentials", "scope": "https://graph.microsoft.com/.default"})
    if r.status_code != 200:
        raise SharePointError(f"Graph token request failed (HTTP {r.status_code}); check the app credentials")
    body = r.json()
    _TOKEN.update(value=body["access_token"], exp=time.time() + int(body.get("expires_in", 3600)), key=key)
    return _TOKEN["value"]


def _site_id(http: httpx.Client, site_url: str) -> str:
    if site_url in _SITES:
        return _SITES[site_url]
    u = urlparse(site_url)
    if not u.hostname:
        raise SharePointError(f"'{site_url}' is not a SharePoint site URL")
    path = u.path.rstrip("/")
    ref = f"{u.hostname}:{path}" if path else u.hostname
    r = http.get(f"{GRAPH}/sites/{ref}")
    if r.status_code == 404:
        raise SharePointError(f"SharePoint site not found: {site_url}")
    if r.status_code in (401, 403):
        raise SharePointError("The app has no access to that site. Grant it Sites.Selected on the site, "
                              "or Sites.ReadWrite.All.")
    if r.status_code != 200:
        raise SharePointError(f"Graph HTTP {r.status_code} resolving the site")
    _SITES[site_url] = r.json()["id"]
    return _SITES[site_url]


def _safe(name: str) -> str:
    name = re.sub(r'[\\/:*?"<>|#%]+', " ", name or "").strip()
    return re.sub(r"\s+", " ", name)[:120] or "Meeting"


def target(eng: Engagement) -> tuple[str, str]:
    """(site URL, folder path) a note for this engagement is written to."""
    cfg = integrations.resolve()
    if eng.sharepoint_site_url:
        return eng.sharepoint_site_url, (eng.sharepoint_folder or "Meeting Notes").strip("/")
    folder = eng.sharepoint_folder or f"{cfg['sharepoint_folder'].strip('/')}/{_safe(eng.code)}/Meeting Notes"
    return cfg["sharepoint_site_url"], folder.strip("/")


def filename(note: MeetingNote) -> str:
    return f"{note.held_at:%Y-%m-%d} {_safe(note.title)}.docx"


# ---------------------------------------------------------------- the document
def _add_markdown(doc, text: str) -> None:
    for raw in (text or "").splitlines():
        line = raw.rstrip()
        if not line.strip():
            continue
        m = re.match(r"^(#{1,3})\s+(.*)$", line)
        if m:
            doc.add_heading(m.group(2), level=min(len(m.group(1)) + 1, 4))
        elif re.match(r"^\s*[-*]\s+", line):
            doc.add_paragraph(re.sub(r"^\s*[-*]\s+", "", line), style="List Bullet")
        elif re.match(r"^\s*\d+[.)]\s+", line):
            doc.add_paragraph(re.sub(r"^\s*\d+[.)]\s+", "", line), style="List Number")
        else:
            doc.add_paragraph(line)


def render_docx(note: MeetingNote, eng: Engagement) -> bytes:
    from docx import Document

    doc = Document()
    doc.core_properties.title = note.title
    doc.core_properties.author = note.author or "Vendetta Cyber"
    doc.add_heading(note.title, level=0)
    meta = doc.add_paragraph()
    meta.add_run(f"{eng.code}  {eng.name}").bold = True
    if eng.client_name:
        meta.add_run(f"\nClient: {eng.client_name}")
    meta.add_run(f"\nHeld: {note.held_at:%B %d, %Y %H:%M} UTC")
    if note.attendees:
        meta.add_run(f"\nAttendees: {note.attendees}")
    meta.add_run(f"\nRecorded by: {note.author}")
    if note.body:
        doc.add_heading("Notes", level=1)
        _add_markdown(doc, note.body)
    if note.decisions:
        doc.add_heading("Decisions", level=1)
        _add_markdown(doc, note.decisions)
    if note.action_items:
        doc.add_heading("Action items", level=1)
        for a in note.action_items:
            bits = [a.get("text", "")]
            if a.get("assignee"):
                bits.append(f"owner {a['assignee']}")
            if a.get("due_on"):
                bits.append(f"due {a['due_on']}")
            if a.get("card_ref"):
                bits.append(f"task #{a['card_ref']}")
            doc.add_paragraph("; ".join(b for b in bits if b), style="List Bullet")
    buf = io.BytesIO()
    doc.save(buf)
    return buf.getvalue()


# ---------------------------------------------------------------- mirror
def mirror(note: MeetingNote, eng: Engagement) -> MeetingNote:
    """Write (or overwrite) the note's document. Updates the note's sp_* fields and
    never raises; the caller commits."""
    if not configured_for(eng):
        note.sp_status, note.sp_error = "off", "SharePoint mirror is not configured"
        return note
    site_url, folder = target(eng)
    content = render_docx(note, eng)
    ctype = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    try:
        with httpx.Client(timeout=30.0, transport=TRANSPORT) as http:
            http.headers["Authorization"] = f"Bearer {_token(http)}"
            site = _site_id(http, site_url)
            if note.sp_item_id:
                url = f"{GRAPH}/sites/{site}/drive/items/{note.sp_item_id}/content"
            else:
                path = quote(f"{folder}/{filename(note)}")
                url = f"{GRAPH}/sites/{site}/drive/root:/{path}:/content"
            r = http.put(url, content=content, headers={"Content-Type": ctype})
            if r.status_code == 404 and note.sp_item_id:
                # The document was moved or deleted in SharePoint: write a fresh one.
                note.sp_item_id = ""
                path = quote(f"{folder}/{filename(note)}")
                r = http.put(f"{GRAPH}/sites/{site}/drive/root:/{path}:/content", content=content,
                             headers={"Content-Type": ctype})
            if r.status_code in (401, 403):
                raise SharePointError("The app may not write to that site's documents")
            if r.status_code not in (200, 201):
                raise SharePointError(f"Graph HTTP {r.status_code} uploading the note")
            item = r.json()
    except (SharePointError, httpx.HTTPError, KeyError, ValueError) as e:
        note.sp_status = "failed"
        note.sp_error = (str(e) if isinstance(e, SharePointError) else f"{type(e).__name__}: {e}")[:600]
        note.sp_at = utcnow()
        log.warning("sharepoint mirror failed for note %s: %s", note.id, note.sp_error)
        return note
    note.sp_status, note.sp_error, note.sp_at = "mirrored", "", utcnow()
    note.sp_item_id = item.get("id", "")
    note.sp_url = item.get("webUrl", "")
    return note


def start_retry_loop(session_factory, interval: int) -> None:
    import threading

    if interval <= 0:
        return

    def _loop():
        time.sleep(30)
        while True:
            db = session_factory()
            try:
                cutoff = utcnow() - dt.timedelta(seconds=interval)
                rows = db.query(MeetingNote).filter(MeetingNote.sp_status.in_(("failed", "pending"))).limit(25).all()
                for n in rows:
                    if n.sp_at and n.sp_at > cutoff:
                        continue
                    mirror(n, n.engagement)
                db.commit()
            except Exception as e:  # noqa: BLE001
                log.warning("sharepoint retry loop: %s", e)
            finally:
                db.close()
            time.sleep(interval)

    threading.Thread(target=_loop, name="sharepoint-retry", daemon=True).start()
