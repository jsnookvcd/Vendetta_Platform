"""The operations a PM performs, shared by the web board, the JSON API and the MCP
tools, so all three behave identically and every change is recorded the same way.

Functions take an open session and the acting staff email, flush their changes and
leave the commit to the caller. A user mistake (an unknown engagement, an ambiguous
column name, a column that still holds cards) raises ServiceError with a message
written for the PM, which the API returns as a 4xx and the MCP tools return as the
tool result so Claude can correct itself.
"""
from __future__ import annotations

import datetime as dt
import re

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from . import harvest, sharepoint
from .config import (DONE_COLUMN_NAMES, ENGAGEMENT_STATES, IR_WORKSTREAMS, PRACTICE_COLUMNS, PRACTICE_NAMES,
                     PRACTICES, PRIORITIES, TASK_COLUMNS)
from .db import (Board, BoardColumn, Card, CardEvent, Client, Engagement, MeetingNote, TimeLog, utcnow)


class ServiceError(Exception):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.message = message
        self.status = status


# ---------------------------------------------------------------- parsing
def parse_date(value) -> dt.date | None:
    if value is None or value == "":
        return None
    if isinstance(value, dt.datetime):
        return value.date()
    if isinstance(value, dt.date):
        return value
    v = str(value).strip().lower()
    today = dt.date.today()
    if v == "today":
        return today
    if v == "yesterday":
        return today - dt.timedelta(days=1)
    if v == "tomorrow":
        return today + dt.timedelta(days=1)
    try:
        return dt.date.fromisoformat(v[:10])
    except ValueError as e:
        raise ServiceError(f"'{value}' is not a date; use YYYY-MM-DD, today, yesterday or tomorrow") from e


def parse_datetime(value) -> dt.datetime:
    if value is None or value == "":
        return utcnow()
    if isinstance(value, dt.datetime):
        return value if value.tzinfo else value.replace(tzinfo=dt.timezone.utc)
    v = str(value).strip()
    try:
        d = dt.datetime.fromisoformat(v.replace("Z", "+00:00"))
    except ValueError:
        d0 = parse_date(v)
        d = dt.datetime.combine(d0, dt.time(12, 0))
    return d if d.tzinfo else d.replace(tzinfo=dt.timezone.utc)


def _labels(value) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        value = value.split(",")
    return [s.strip() for s in value if s and s.strip()][:12]


def _hours(value) -> float | None:
    if value in (None, ""):
        return None
    try:
        return float(value)
    except (TypeError, ValueError) as e:
        raise ServiceError(f"'{value}' is not a number of hours") from e


def _event(db: Session, card: Card, actor: str, kind: str, detail: str = "") -> None:
    db.add(CardEvent(card_id=card.id, card_ref=card.ref, engagement_id=card.engagement_id, actor=actor,
                     kind=kind, detail=detail[:2000]))


# ---------------------------------------------------------------- boards
def ensure_practice_boards(db: Session) -> None:
    for p in PRACTICES:
        practice_board(db, p)


def practice_board(db: Session, practice: str) -> Board:
    if practice not in PRACTICES:
        raise ServiceError(f"Practice must be one of: {', '.join(PRACTICES)}")
    b = db.execute(select(Board).where(Board.kind == "practice", Board.practice == practice)).scalar_one_or_none()
    if b is None:
        b = Board(name=f"{PRACTICE_NAMES[practice]} Delivery", kind="practice", practice=practice)
        db.add(b)
        db.flush()
        for i, name in enumerate(PRACTICE_COLUMNS[practice]):
            db.add(BoardColumn(board_id=b.id, name=name, position=i, is_done=name in DONE_COLUMN_NAMES))
        db.flush()
        db.refresh(b)
    return b


def find_board(db: Session, ref: str) -> Board:
    """A board by id, by practice ("ir", "proserv", "Incident Response"), or by an
    engagement reference (its task board)."""
    ref = (ref or "").strip()
    b = db.get(Board, ref)
    if b:
        return b
    low = ref.lower()
    for p, name in PRACTICE_NAMES.items():
        if low in (p, name.lower(), f"{p} board", f"{name.lower()} board", "ps" if p == "proserv" else p):
            return practice_board(db, p)
    eng = find_engagement(db, ref)
    return engagement_board(db, eng)


def engagement_board(db: Session, eng: Engagement) -> Board:
    b = db.execute(select(Board).where(Board.engagement_id == eng.id)).scalar_one_or_none()
    if b is None:
        b = Board(name=f"{eng.code} tasks", kind="engagement", practice=eng.practice, engagement_id=eng.id)
        db.add(b)
        db.flush()
        for i, name in enumerate(TASK_COLUMNS):
            db.add(BoardColumn(board_id=b.id, name=name, position=i, is_done=name in DONE_COLUMN_NAMES))
        db.flush()
        db.refresh(b)
    return b


def resolve_column(board: Board, ref: str | None) -> BoardColumn:
    cols = sorted(board.columns, key=lambda c: c.position)
    if not cols:
        raise ServiceError(f"Board '{board.name}' has no columns")
    if ref is None or str(ref).strip() == "":
        return cols[0]
    ref = str(ref).strip()
    for c in cols:
        if c.id == ref:
            return c
    low = ref.lower()
    exact = [c for c in cols if c.name.lower() == low]
    if len(exact) == 1:
        return exact[0]
    part = [c for c in cols if c.name.lower().startswith(low)] or [c for c in cols if low in c.name.lower()]
    if len(part) == 1:
        return part[0]
    names = ", ".join(c.name for c in cols)
    raise ServiceError(f"'{ref}' does not match one column on '{board.name}'. Columns: {names}")


def _cards_in(db: Session, column: BoardColumn, include_archived: bool = False) -> list[Card]:
    q = select(Card).where(Card.column_id == column.id)
    if not include_archived:
        q = q.where(Card.archived.is_(False))
    return list(db.execute(q.order_by(Card.position, Card.created_at)).scalars())


def _place(db: Session, card: Card, column: BoardColumn, position: int | None) -> None:
    siblings = [c for c in _cards_in(db, column) if c.id != card.id]
    idx = len(siblings) if position is None else max(0, min(int(position), len(siblings)))
    siblings.insert(idx, card)
    card.column_id = column.id
    for i, c in enumerate(siblings):
        c.position = i


def add_column(db: Session, actor: str, board: Board, name: str, position: int | None = None,
               wip_limit: int | None = None, is_done: bool | None = None) -> BoardColumn:
    name = (name or "").strip()
    if not name:
        raise ServiceError("A column needs a name")
    if any(c.name.lower() == name.lower() for c in board.columns):
        raise ServiceError(f"'{board.name}' already has a column named '{name}'")
    cols = sorted(board.columns, key=lambda c: c.position)
    idx = len(cols) if position is None else max(0, min(int(position), len(cols)))
    col = BoardColumn(board_id=board.id, name=name, wip_limit=wip_limit,
                      is_done=bool(is_done) if is_done is not None else name in DONE_COLUMN_NAMES)
    cols.insert(idx, col)
    db.add(col)
    for i, c in enumerate(cols):
        c.position = i
    db.flush()
    db.refresh(board)
    return col


def update_column(db: Session, actor: str, board: Board, column_ref: str, *, name: str | None = None,
                  position: int | None = None, wip_limit: int | None | str = "unchanged",
                  is_done: bool | None = None) -> BoardColumn:
    col = resolve_column(board, column_ref)
    if name is not None and name.strip() and name.strip() != col.name:
        if any(c.name.lower() == name.strip().lower() and c.id != col.id for c in board.columns):
            raise ServiceError(f"'{board.name}' already has a column named '{name.strip()}'")
        col.name = name.strip()
    if wip_limit != "unchanged":
        col.wip_limit = int(wip_limit) if wip_limit not in (None, "", 0) else None
    if is_done is not None:
        col.is_done = bool(is_done)
    if position is not None:
        cols = [c for c in sorted(board.columns, key=lambda c: c.position) if c.id != col.id]
        cols.insert(max(0, min(int(position), len(cols))), col)
        for i, c in enumerate(cols):
            c.position = i
    db.flush()
    return col


def delete_column(db: Session, actor: str, board: Board, column_ref: str, move_cards_to: str | None = None) -> dict:
    col = resolve_column(board, column_ref)
    if len(board.columns) <= 1:
        raise ServiceError("A board must keep at least one column")
    cards = _cards_in(db, col, include_archived=True)
    moved = 0
    if cards:
        if not move_cards_to:
            raise ServiceError(f"Column '{col.name}' holds {len(cards)} card(s). Say which column to move them to.")
        dest = resolve_column(board, move_cards_to)
        if dest.id == col.id:
            raise ServiceError("Cards cannot be moved into the column being removed")
        for c in cards:
            _place(db, c, dest, None)
            _event(db, c, actor, "moved", f"{col.name} -> {dest.name} (column removed)")
            moved += 1
    db.flush()
    removed_name = col.name
    rest = [c for c in sorted(board.columns, key=lambda c: c.position) if c.id != col.id]
    db.delete(col)
    for i, c in enumerate(rest):
        c.position = i
    db.flush()
    db.refresh(board)
    return {"removed": removed_name, "cards_moved": moved}


def board_dict(db: Session, board: Board, *, include_done: bool = True, assignee: str | None = None,
               label: str | None = None) -> dict:
    cols = []
    for col in sorted(board.columns, key=lambda c: c.position):
        cards = _cards_in(db, col)
        if assignee:
            cards = [c for c in cards if c.assignee.lower() == assignee.lower()]
        if label:
            cards = [c for c in cards if label.lower() in [x.lower() for x in (c.labels or [])]]
        if col.is_done and not include_done:
            cards = []
        cols.append({"id": col.id, "name": col.name, "position": col.position, "wip_limit": col.wip_limit,
                     "is_done": col.is_done, "count": len(cards),
                     "over_wip": bool(col.wip_limit and len(cards) > col.wip_limit),
                     "cards": [card_dict(c, brief=True) for c in cards]})
    eng = db.get(Engagement, board.engagement_id) if board.engagement_id else None
    return {"id": board.id, "name": board.name, "kind": board.kind, "practice": board.practice,
            "engagement": {"id": eng.id, "code": eng.code, "name": eng.name} if eng else None,
            "columns": cols}


# ---------------------------------------------------------------- engagements
def _next_code(db: Session, practice: str) -> str:
    year = dt.date.today().year
    prefix = f"VCD-{'IR' if practice == 'ir' else 'PS'}-{year}-"
    codes = db.execute(select(Engagement.code).where(Engagement.code.like(prefix + "%"))).scalars().all()
    nums = [int(m.group(1)) for c in codes if (m := re.match(re.escape(prefix) + r"(\d+)$", c))]
    return f"{prefix}{(max(nums) + 1) if nums else 1:03d}"


def _client_for(db: Session, client: str | None) -> tuple[Client | None, str]:
    if not client:
        return None, ""
    c = db.get(Client, client) or db.execute(
        select(Client).where(or_(Client.platform_client_id == client, func.lower(Client.name) == client.lower()))
    ).scalars().first()
    if c is None:
        rows = db.execute(select(Client).where(Client.name.ilike(f"%{client}%"), Client.active.is_(True))).scalars().all()
        if len(rows) == 1:
            c = rows[0]
    return (c, c.name) if c else (None, client.strip())


def find_engagement(db: Session, ref: str) -> Engagement:
    ref = (ref or "").strip()
    if not ref:
        raise ServiceError("Name the engagement (its code, like VCD-IR-2026-445, or part of its name)")
    e = db.get(Engagement, ref) or db.execute(
        select(Engagement).where(func.lower(Engagement.code) == ref.lower())).scalar_one_or_none()
    if e:
        return e
    rows = db.execute(select(Engagement).where(or_(Engagement.name.ilike(f"%{ref}%"),
                                                   Engagement.code.ilike(f"%{ref}%"),
                                                   Engagement.client_name.ilike(f"%{ref}%")))
                      .order_by(Engagement.status, Engagement.created_at.desc())).scalars().all()
    open_rows = [r for r in rows if r.status != "closed"]
    if len(rows) == 1:
        return rows[0]
    if len(open_rows) == 1:
        return open_rows[0]
    if not rows:
        raise ServiceError(f"No engagement matches '{ref}'", 404)
    listing = "; ".join(f"{r.code} {r.name}" for r in rows[:8])
    raise ServiceError(f"'{ref}' matches {len(rows)} engagements: {listing}. Use the code.")


def create_engagement(db: Session, actor: str, *, practice: str, name: str, code: str | None = None,
                      client: str | None = None, pm_email: str | None = None, description: str = "",
                      budget_hours=None, starts_on=None, ends_on=None, harvest_project_id: str = "",
                      sharepoint_site_url: str = "", sharepoint_folder: str = "", platform_ref: str = "",
                      column: str | None = None) -> Engagement:
    practice = (practice or "").strip().lower()
    practice = {"ps": "proserv", "professional services": "proserv", "incident response": "ir",
                "osp": "proserv"}.get(practice, practice)
    if practice not in PRACTICES:
        raise ServiceError("Practice must be ir (Incident Response) or proserv (Professional Services)")
    if not (name or "").strip():
        raise ServiceError("An engagement needs a name")
    code = (code or "").strip() or _next_code(db, practice)
    if db.execute(select(Engagement).where(func.lower(Engagement.code) == code.lower())).first():
        raise ServiceError(f"An engagement with code {code} already exists", 409)
    c, cname = _client_for(db, client)
    eng = Engagement(code=code, name=name.strip(), practice=practice, client_id=c.id if c else None,
                     client_name=cname, pm_email=(pm_email or actor).strip().lower(), description=description or "",
                     budget_hours=_hours(budget_hours), starts_on=parse_date(starts_on), ends_on=parse_date(ends_on),
                     harvest_project_id=str(harvest_project_id or "").strip(),
                     sharepoint_site_url=(sharepoint_site_url or "").strip(),
                     sharepoint_folder=(sharepoint_folder or "").strip(), platform_ref=platform_ref or "",
                     created_by=actor)
    db.add(eng)
    db.flush()
    if eng.harvest_project_id and harvest.configured():
        try:
            eng.harvest_project_name = harvest.get_project(eng.harvest_project_id)["name"] or ""
        except harvest.HarvestError:
            pass
    pboard = practice_board(db, practice)
    col = resolve_column(pboard, column)
    card = Card(board_id=pboard.id, column_id=col.id, engagement_id=eng.id, title=f"{eng.code} {eng.name}",
                description=eng.description, assignee=eng.pm_email, due_on=eng.ends_on,
                labels=[cname] if cname else [], created_by=actor)
    db.add(card)
    db.flush()
    _place(db, card, col, None)
    _event(db, card, actor, "created", f"engagement opened in {col.name}")
    engagement_board(db, eng)
    db.flush()
    return eng


def practice_card(db: Session, eng: Engagement) -> Card | None:
    pboard = practice_board(db, eng.practice)
    return db.execute(select(Card).where(Card.board_id == pboard.id, Card.engagement_id == eng.id)).scalars().first()


def update_engagement(db: Session, actor: str, eng: Engagement, **f) -> Engagement:
    changed = []
    for key in ("name", "description", "pm_email", "sharepoint_site_url", "sharepoint_folder", "platform_ref"):
        if f.get(key) is not None:
            val = f[key].strip() if isinstance(f[key], str) else f[key]
            if key == "pm_email":
                val = val.lower()
            setattr(eng, key, val)
            changed.append(key)
    if f.get("client") is not None:
        c, cname = _client_for(db, f["client"])
        eng.client_id, eng.client_name = (c.id if c else None), cname
        changed.append("client")
    if f.get("budget_hours") is not None:
        eng.budget_hours = _hours(f["budget_hours"])
        changed.append("budget_hours")
    for key in ("starts_on", "ends_on"):
        if f.get(key) is not None:
            setattr(eng, key, parse_date(f[key]))
            changed.append(key)
    if f.get("harvest_project_id") is not None:
        eng.harvest_project_id = str(f["harvest_project_id"]).strip()
        eng.harvest_project_name = ""
        if eng.harvest_project_id and harvest.configured():
            try:
                eng.harvest_project_name = harvest.get_project(eng.harvest_project_id)["name"] or ""
            except harvest.HarvestError as e:
                raise ServiceError(f"Harvest project {eng.harvest_project_id}: {e}") from e
        changed.append("harvest_project")
    if f.get("status") is not None:
        st = f["status"].strip().lower().replace(" ", "_")
        if st not in ENGAGEMENT_STATES:
            raise ServiceError(f"Status must be one of: {', '.join(ENGAGEMENT_STATES)}")
        eng.status = st
        eng.closed_at = utcnow() if st == "closed" else None
        changed.append("status")
    card = practice_card(db, eng)
    if card:
        card.title = f"{eng.code} {eng.name}"
        card.assignee = eng.pm_email
        card.due_on = eng.ends_on
        if eng.status == "closed":
            done = [c for c in card.board.columns if c.is_done]
            if done and card.column_id not in {c.id for c in done}:
                prev = card.column.name
                _place(db, card, done[-1], None)
                card.completed_at = utcnow()
                _event(db, card, actor, "moved", f"{prev} -> {done[-1].name} (engagement closed)")
        if changed:
            _event(db, card, actor, "updated", "engagement: " + ", ".join(changed))
    db.flush()
    return eng


def list_engagements(db: Session, *, practice: str | None = None, status: str | None = "open",
                     pm: str | None = None, query: str | None = None) -> list[Engagement]:
    q = select(Engagement)
    if practice:
        q = q.where(Engagement.practice == practice)
    if status == "open":
        q = q.where(Engagement.status != "closed")
    elif status and status != "all":
        q = q.where(Engagement.status == status)
    if pm:
        q = q.where(func.lower(Engagement.pm_email) == pm.lower())
    if query:
        q = q.where(or_(Engagement.name.ilike(f"%{query}%"), Engagement.code.ilike(f"%{query}%"),
                        Engagement.client_name.ilike(f"%{query}%")))
    return list(db.execute(q.order_by(Engagement.practice, Engagement.code)).scalars())


def engagement_dict(db: Session, eng: Engagement, *, detail: bool = False) -> dict:
    card = practice_card(db, eng)
    out = {"id": eng.id, "code": eng.code, "name": eng.name, "practice": eng.practice,
           "practice_name": PRACTICE_NAMES[eng.practice], "client": eng.client_name,
           "platform_client_id": eng.client.platform_client_id if eng.client else "",
           "pm": eng.pm_email, "status": eng.status, "phase": card.column.name if card else None,
           "budget_hours": eng.budget_hours,
           "starts_on": eng.starts_on.isoformat() if eng.starts_on else None,
           "ends_on": eng.ends_on.isoformat() if eng.ends_on else None,
           "harvest_project_id": eng.harvest_project_id or None,
           "harvest_project": eng.harvest_project_name or None, "platform_ref": eng.platform_ref or None}
    board = engagement_board(db, eng)
    tasks = db.execute(select(Card).where(Card.board_id == board.id, Card.archived.is_(False))).scalars().all()
    done_cols = {c.id for c in board.columns if c.is_done}
    today = dt.date.today()
    out["tasks"] = {"open": sum(1 for t in tasks if t.column_id not in done_cols),
                    "done": sum(1 for t in tasks if t.column_id in done_cols),
                    "overdue": sum(1 for t in tasks if t.column_id not in done_cols and t.due_on and t.due_on < today),
                    "blocked": sum(1 for t in tasks if t.column.name.lower() == "blocked")}
    if detail:
        out["description"] = eng.description
        out["sharepoint"] = {"site": sharepoint.target(eng)[0] or None, "folder": sharepoint.target(eng)[1]}
        out["by_column"] = {c.name: sum(1 for t in tasks if t.column_id == c.id)
                            for c in sorted(board.columns, key=lambda c: c.position)}
        out["recent_notes"] = [{"id": n.id, "title": n.title, "held_at": n.held_at.isoformat()}
                               for n in eng.notes[:5]]
        out["task_board_id"] = board.id
    return out


# ---------------------------------------------------------------- cards and tasks
def find_card(db: Session, ref) -> Card:
    s = str(ref or "").strip().lstrip("#")
    if not s:
        raise ServiceError("Name the task by its number, like 214")
    c = None
    if s.isdigit():
        c = db.execute(select(Card).where(Card.ref == int(s))).scalar_one_or_none()
    c = c or db.get(Card, s)
    if c is None:
        raise ServiceError(f"No task or card #{s}", 404)
    return c


def create_task(db: Session, actor: str, eng: Engagement, *, title: str, description: str = "",
                assignee: str | None = None, due_on=None, priority: str | None = None, labels=None,
                column: str | None = None, estimate_hours=None, checklist=None, position: int | None = None) -> Card:
    if not (title or "").strip():
        raise ServiceError("A task needs a title")
    board = engagement_board(db, eng)
    if column:
        col = resolve_column(board, column)
    else:
        # "To Do" when the board still has it, else the first column that is not
        # the backlog, else the first column.
        cols = sorted(board.columns, key=lambda c: c.position)
        col = next((c for c in cols if c.name.lower() == "to do"), None) \
            or next((c for c in cols if c.name.lower() != "backlog" and not c.is_done), cols[0])
    pr = (priority or "normal").lower()
    if pr not in PRIORITIES:
        raise ServiceError(f"Priority must be one of: {', '.join(PRIORITIES)}")
    items = []
    for it in checklist or []:
        items.append({"text": it, "done": False} if isinstance(it, str) else
                     {"text": str(it.get("text", "")), "done": bool(it.get("done"))})
    card = Card(board_id=board.id, column_id=col.id, engagement_id=eng.id, title=title.strip()[:400],
                description=description or "", assignee=(assignee or "").strip().lower(), due_on=parse_date(due_on),
                priority=pr, labels=_labels(labels), checklist=items, estimate_hours=_hours(estimate_hours),
                created_by=actor, completed_at=utcnow() if col.is_done else None)
    db.add(card)
    db.flush()
    _place(db, card, col, position)
    _event(db, card, actor, "created", f"in {col.name}" + (f", assigned {card.assignee}" if card.assignee else ""))
    db.flush()
    return card


def move_card(db: Session, actor: str, card: Card, column: str, position: int | None = None) -> Card:
    board = db.get(Board, card.board_id)
    dest = resolve_column(board, column)
    prev = card.column.name
    if dest.wip_limit and dest.id != card.column_id:
        n = len(_cards_in(db, dest))
        if n >= dest.wip_limit:
            raise ServiceError(f"'{dest.name}' is at its WIP limit of {dest.wip_limit}. Finish or move a card first.",
                               409)
    _place(db, card, dest, position)
    card.completed_at = utcnow() if dest.is_done else None
    card.updated_at = utcnow()
    if prev != dest.name:
        _event(db, card, actor, "moved", f"{prev} -> {dest.name}")
    db.flush()
    db.refresh(card)
    return card


def update_card(db: Session, actor: str, card: Card, **f) -> Card:
    changed = []
    if f.get("title") is not None and f["title"].strip():
        card.title = f["title"].strip()[:400]
        changed.append("title")
    if f.get("description") is not None:
        card.description = f["description"]
        changed.append("description")
    if f.get("assignee") is not None:
        new = f["assignee"].strip().lower()
        if new != card.assignee:
            _event(db, card, actor, "assigned", f"{card.assignee or 'nobody'} -> {new or 'nobody'}")
            card.assignee = new
    if f.get("due_on") is not None:
        card.due_on = parse_date(f["due_on"]) if f["due_on"] != "none" else None
        changed.append(f"due {card.due_on.isoformat() if card.due_on else 'cleared'}")
    if f.get("priority") is not None:
        pr = f["priority"].lower()
        if pr not in PRIORITIES:
            raise ServiceError(f"Priority must be one of: {', '.join(PRIORITIES)}")
        card.priority = pr
        changed.append(f"priority {pr}")
    if f.get("labels") is not None:
        card.labels = _labels(f["labels"])
        changed.append("labels")
    if f.get("add_labels"):
        card.labels = list(dict.fromkeys([*(card.labels or []), *_labels(f["add_labels"])]))
        changed.append("labels")
    if f.get("remove_labels"):
        drop = {x.lower() for x in _labels(f["remove_labels"])}
        card.labels = [x for x in card.labels or [] if x.lower() not in drop]
        changed.append("labels")
    if f.get("estimate_hours") is not None:
        card.estimate_hours = _hours(f["estimate_hours"])
        changed.append("estimate")
    if f.get("checklist_add"):
        card.checklist = [*(card.checklist or []), *({"text": str(t), "done": False} for t in f["checklist_add"])]
        changed.append("checklist")
    if f.get("checklist_check") is not None:
        items = list(card.checklist or [])
        for idx in f["checklist_check"]:
            i = int(idx) - 1
            if not 0 <= i < len(items):
                raise ServiceError(f"Checklist item {idx} does not exist (the task has {len(items)})")
            items[i] = {**items[i], "done": True}
        card.checklist = items
        changed.append("checklist")
    if changed:
        _event(db, card, actor, "updated", ", ".join(dict.fromkeys(changed)))
    if f.get("column"):
        dest = resolve_column(db.get(Board, card.board_id), f["column"])
        if dest.id != card.column_id or f.get("position") is not None:
            move_card(db, actor, card, dest.id, f.get("position"))
    card.updated_at = utcnow()
    db.flush()
    return card


def comment(db: Session, actor: str, card: Card, text: str) -> None:
    if not (text or "").strip():
        raise ServiceError("A comment needs text")
    _event(db, card, actor, "comment", text.strip())
    card.updated_at = utcnow()
    db.flush()


def archive_card(db: Session, actor: str, card: Card, archived: bool = True) -> Card:
    card.archived = archived
    card.updated_at = utcnow()
    _event(db, card, actor, "archived" if archived else "restored")
    if not archived:
        _place(db, card, card.column, None)
    db.flush()
    return card


def delete_card(db: Session, actor: str, card: Card) -> dict:
    if card.board.kind == "practice":
        raise ServiceError("An engagement's card on the practice board goes away when the engagement is "
                           "deleted; close the engagement instead.")
    info = {"deleted": card.ref, "title": card.title}
    _event(db, card, actor, "deleted", card.title)
    col = card.column
    db.delete(card)
    db.flush()
    for i, c in enumerate(_cards_in(db, col)):
        c.position = i
    db.flush()
    return info


def list_tasks(db: Session, *, engagement: Engagement | None = None, assignee: str | None = None,
               column: str | None = None, label: str | None = None, overdue: bool = False,
               due_within_days: int | None = None, include_done: bool = False, query: str | None = None,
               practice: str | None = None, limit: int = 200) -> list[Card]:
    q = select(Card).join(Board, Card.board_id == Board.id).join(BoardColumn, Card.column_id == BoardColumn.id) \
        .where(Board.kind == "engagement", Card.archived.is_(False))
    if engagement:
        q = q.where(Card.engagement_id == engagement.id)
    if practice:
        q = q.where(Board.practice == practice)
    if assignee:
        q = q.where(func.lower(Card.assignee) == assignee.lower())
    if column:
        q = q.where(func.lower(BoardColumn.name) == column.lower())
    if not include_done and not column:
        q = q.where(BoardColumn.is_done.is_(False))
    today = dt.date.today()
    if overdue:
        q = q.where(Card.due_on.isnot(None), Card.due_on < today)
    if due_within_days is not None:
        q = q.where(Card.due_on.isnot(None), Card.due_on <= today + dt.timedelta(days=int(due_within_days)))
    if query:
        q = q.where(or_(Card.title.ilike(f"%{query}%"), Card.description.ilike(f"%{query}%")))
    rows = list(db.execute(q.order_by(Card.due_on.is_(None), Card.due_on, Card.ref).limit(limit)).scalars())
    if label:
        rows = [c for c in rows if label.lower() in [x.lower() for x in c.labels or []]]
    return rows


def card_dict(card: Card, *, brief: bool = False) -> dict:
    today = dt.date.today()
    out = {"ref": card.ref, "id": card.id, "title": card.title, "column": card.column.name if card.column else None,
           "assignee": card.assignee or None, "due_on": card.due_on.isoformat() if card.due_on else None,
           "overdue": bool(card.due_on and card.due_on < today and not (card.column and card.column.is_done)),
           "priority": card.priority, "labels": card.labels or []}
    if card.engagement:
        out["engagement"] = card.engagement.code
    if card.checklist:
        out["checklist"] = f"{sum(1 for i in card.checklist if i.get('done'))}/{len(card.checklist)}"
    if not brief:
        out.update(description=card.description, estimate_hours=card.estimate_hours,
                   checklist_items=card.checklist or [], board=card.board.name,
                   created_by=card.created_by, created_at=card.created_at.isoformat(),
                   updated_at=card.updated_at.isoformat() if card.updated_at else None,
                   completed_at=card.completed_at.isoformat() if card.completed_at else None,
                   archived=card.archived)
    return out


def card_history(db: Session, card_id: str, limit: int = 100) -> list[dict]:
    rows = db.execute(select(CardEvent).where(CardEvent.card_id == card_id).order_by(CardEvent.at.desc())
                      .limit(limit)).scalars().all()
    return [{"at": e.at.isoformat(), "actor": e.actor, "kind": e.kind, "detail": e.detail} for e in rows]


def workstream_labels(eng: Engagement) -> list[str]:
    return list(IR_WORKSTREAMS) if eng.practice == "ir" else []


# ---------------------------------------------------------------- meeting notes
def _action_items(items) -> list[dict]:
    out = []
    for it in items or []:
        if isinstance(it, str):
            it = {"text": it}
        text = str(it.get("text") or "").strip()
        if text:
            out.append({"text": text, "assignee": (it.get("assignee") or "").strip().lower(),
                        "due_on": parse_date(it.get("due_on")).isoformat() if it.get("due_on") else ""})
    return out


def create_note(db: Session, actor: str, eng: Engagement, *, title: str, held_at=None, attendees: str = "",
                body: str = "", decisions: str = "", action_items=None, create_tasks: bool = True,
                mirror: bool = True) -> MeetingNote:
    if not (title or "").strip():
        raise ServiceError("A meeting note needs a title")
    items = _action_items(action_items)
    note = MeetingNote(engagement_id=eng.id, title=title.strip()[:300], held_at=parse_datetime(held_at),
                       attendees=attendees or "", body=body or "", decisions=decisions or "", author=actor,
                       action_items=[])
    db.add(note)
    db.flush()
    if create_tasks:
        for it in items:
            card = create_task(db, actor, eng, title=it["text"], assignee=it["assignee"] or None,
                               due_on=it["due_on"] or None, description=f"Action item from meeting: {note.title}",
                               labels=["action item"])
            it["card_id"], it["card_ref"] = card.id, card.ref
    note.action_items = items
    note.engagement = eng
    if mirror:
        sharepoint.mirror(note, eng)
    else:
        note.sp_status = "pending"
    db.flush()
    return note


def update_note(db: Session, actor: str, note: MeetingNote, *, mirror: bool = True, **f) -> MeetingNote:
    for key in ("title", "attendees", "body", "decisions"):
        if f.get(key) is not None:
            setattr(note, key, f[key])
    if f.get("append") :
        note.body = (note.body.rstrip() + "\n\n" + f["append"]).strip()
    if f.get("held_at") is not None:
        note.held_at = parse_datetime(f["held_at"])
    if f.get("action_items") is not None:
        note.action_items = [*(note.action_items or []), *_action_items(f["action_items"])]
    note.updated_at = utcnow()
    if mirror:
        sharepoint.mirror(note, note.engagement)
    db.flush()
    return note


def find_note(db: Session, ref: str) -> MeetingNote:
    n = db.get(MeetingNote, (ref or "").strip())
    if n is None:
        raise ServiceError(f"No meeting note {ref}", 404)
    return n


def list_notes(db: Session, *, engagement: Engagement | None = None, query: str | None = None,
               since=None, limit: int = 50) -> list[MeetingNote]:
    q = select(MeetingNote)
    if engagement:
        q = q.where(MeetingNote.engagement_id == engagement.id)
    if query:
        q = q.where(or_(MeetingNote.title.ilike(f"%{query}%"), MeetingNote.body.ilike(f"%{query}%"),
                        MeetingNote.decisions.ilike(f"%{query}%"), MeetingNote.attendees.ilike(f"%{query}%")))
    if since:
        q = q.where(MeetingNote.held_at >= parse_datetime(since))
    return list(db.execute(q.order_by(MeetingNote.held_at.desc()).limit(limit)).scalars())


def note_dict(note: MeetingNote, *, full: bool = True) -> dict:
    out = {"id": note.id, "title": note.title, "engagement": note.engagement.code,
           "held_at": note.held_at.isoformat(), "author": note.author,
           "sharepoint": {"status": note.sp_status, "url": note.sp_url or None, "error": note.sp_error or None}}
    if full:
        out.update(attendees=note.attendees, body=note.body, decisions=note.decisions,
                   action_items=note.action_items or [])
    return out


# ---------------------------------------------------------------- time
def _project_for(db: Session, engagement: str | None, project: str | None) -> tuple[str, Engagement | None]:
    if engagement:
        eng = find_engagement(db, engagement)
        if not eng.harvest_project_id:
            raise ServiceError(f"{eng.code} is not linked to a Harvest project. Link one with update_engagement "
                               "(harvest_project_id), or pass the Harvest project directly.")
        return eng.harvest_project_id, eng
    if not project:
        raise ServiceError("Name the engagement (or a Harvest project) to log time against")
    p = str(project).strip()
    if p.isdigit():
        eng = db.execute(select(Engagement).where(Engagement.harvest_project_id == p)).scalars().first()
        return p, eng
    rows = harvest.list_projects(p)
    if len(rows) != 1:
        names = "; ".join(f"{r['id']} {r['name']} ({r['client']})" for r in rows[:8]) or "none"
        raise ServiceError(f"'{p}' matches {len(rows)} Harvest projects: {names}. Use the project id.")
    eng = db.execute(select(Engagement).where(Engagement.harvest_project_id == rows[0]["id"])).scalars().first()
    return rows[0]["id"], eng


def _can_touch_entry(actor_email: str, actor_role: str, entry: dict) -> None:
    if actor_role == "admin":
        return
    if entry.get("user_id") != harvest.user_id_for(actor_email):
        raise ServiceError("You can change only your own Harvest entries; ask an admin for anyone else's", 403)


def log_time(db: Session, actor: str, actor_role: str, *, hours, task: str, spent_date=None,
             engagement: str | None = None, project: str | None = None, notes: str = "",
             user_email: str | None = None, card_ref=None) -> dict:
    try:
        project_id, eng = _project_for(db, engagement, project)
        who = (user_email or actor).strip().lower()
        if who != actor.lower() and actor_role != "admin":
            raise ServiceError("Only an admin can log time for someone else", 403)
        card = find_card(db, card_ref) if card_ref else None
        if card and not notes:
            notes = card.title
        elif card:
            notes = f"{notes} (task #{card.ref})"
        task_id = harvest.resolve_task(project_id, task)
        day = parse_date(spent_date) or dt.date.today()
        entry = harvest.create_entry(user_email=who, project_id=project_id, task_id=task_id, spent_date=day,
                                     hours=float(hours), notes=notes)
    except harvest.HarvestError as e:
        raise ServiceError(str(e), 502) from e
    db.add(TimeLog(action="created", actor=actor, user_email=who, harvest_entry_id=entry["id"],
                   harvest_project_id=project_id, harvest_task_id=task_id, engagement_id=eng.id if eng else None,
                   card_id=card.id if card else None, spent_date=day, hours=entry["hours"], notes=notes))
    if card:
        _event(db, card, actor, "time", f"{entry['hours']}h logged to Harvest by {who} ({entry['task']})")
    db.flush()
    return entry


def update_time(db: Session, actor: str, actor_role: str, entry_id: str, **changes) -> dict:
    try:
        entry = harvest.get_entry(entry_id)
        _can_touch_entry(actor, actor_role, entry)
        if changes.get("task"):
            changes["task_id"] = harvest.resolve_task(changes.get("project_id") or entry["project_id"],
                                                      changes.pop("task"))
        if changes.get("spent_date") is not None:
            changes["spent_date"] = parse_date(changes["spent_date"])
        new = harvest.update_entry(entry_id, **changes)
    except harvest.HarvestError as e:
        raise ServiceError(str(e), 502) from e
    db.add(TimeLog(action="updated", actor=actor, user_email=actor, harvest_entry_id=entry_id,
                   harvest_project_id=new["project_id"], harvest_task_id=new["task_id"],
                   spent_date=parse_date(new["spent_date"]), hours=new["hours"], notes=new["notes"]))
    db.flush()
    return new


def delete_time(db: Session, actor: str, actor_role: str, entry_id: str) -> dict:
    try:
        entry = harvest.get_entry(entry_id)
        _can_touch_entry(actor, actor_role, entry)
        if entry.get("is_locked"):
            raise ServiceError("That entry is locked in Harvest (approved or invoiced) and cannot be deleted", 409)
        harvest.delete_entry(entry_id)
    except harvest.HarvestError as e:
        raise ServiceError(str(e), 502) from e
    db.add(TimeLog(action="deleted", actor=actor, user_email=actor, harvest_entry_id=entry_id,
                   harvest_project_id=entry["project_id"], harvest_task_id=entry["task_id"],
                   spent_date=parse_date(entry["spent_date"]), hours=entry["hours"], notes=entry["notes"]))
    db.flush()
    return {"deleted": entry_id, "hours": entry["hours"], "spent_date": entry["spent_date"]}


def burn(db: Session, eng: Engagement) -> dict:
    if not eng.harvest_project_id:
        raise ServiceError(f"{eng.code} is not linked to a Harvest project")
    try:
        h = harvest.project_hours(eng.harvest_project_id)
    except harvest.HarvestError as e:
        raise ServiceError(str(e), 502) from e
    out = {"engagement": eng.code, "harvest_project": eng.harvest_project_name or eng.harvest_project_id, **h,
           "budget_hours": eng.budget_hours}
    if eng.budget_hours:
        out["remaining_hours"] = round(eng.budget_hours - h["total_hours"], 2)
        out["percent_used"] = round(100 * h["total_hours"] / eng.budget_hours, 1)
    return out
