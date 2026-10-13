"""Case board: Kanban cards per workstream, kept in step with the timeline.

The board is a grid. Each workstream is a lane and each card status is a column
(To do, In progress, Blocked or waiting, Done). The rules that keep the board, the
timeline and the workstream statuses aligned all live here:

- A case opens with the playbook cards (playbook.py). The first Scoping and
  Containment card starts in progress.
- Moving a card writes a timeline entry on its workstream. The entry is
  client-visible when the card is.
- A timeline entry logged against a card links to it. A card in To do moves to In
  progress on its first entry, and the analyst can move it to Blocked or Done in
  the same step. An entry can also create a new card.
- A finding escalated from another module adds a review card on its workstream,
  linked to the finding entry.
- A workstream's status follows its cards: all done is done; any card in progress,
  or some done, is in progress; otherwise blocked if any card is blocked; otherwise
  not started. A change is logged client-visible, so the client portal milestones
  move on their own. A workstream with no cards keeps the status set by hand.

Functions here mutate the case in the session and leave the commit to the caller."""
from __future__ import annotations

from .config import WORKSTREAMS
from .db import Case, CaseUpdate, Task, utcnow
from .playbook import PLAYBOOK

TASK_STATUSES = ["todo", "in_progress", "blocked", "done"]
TASK_LABELS = {"todo": "To do", "in_progress": "In progress", "blocked": "Blocked or waiting", "done": "Done"}
_MOVE_NOTE = {"todo": "Back to To do", "in_progress": "Started", "blocked": "Blocked or waiting", "done": "Completed"}


# ---------------------------------------------------------------- reads
def ws_tasks(case: Case, ws: str) -> list[Task]:
    return [t for t in case.tasks if t.workstream == ws]


def column(case: Case, ws: str, status: str) -> list[Task]:
    return sorted((t for t in case.tasks if t.workstream == ws and t.status == status), key=lambda t: t.position)


def derive(tasks: list[Task]) -> str | None:
    """Workstream status implied by its cards, or None when it has no cards."""
    if not tasks:
        return None
    states = {t.status for t in tasks}
    if states == {"done"}:
        return "done"
    if "in_progress" in states or "done" in states:
        return "in_progress"
    if "blocked" in states:
        return "blocked"
    return "not_started"


def lanes(case: Case) -> list[dict]:
    """Board rows for the template: one per workstream, cards grouped by column."""
    out = []
    for w in case.workstreams:
        cols = {s: column(case, w.name, s) for s in TASK_STATUSES}
        total = sum(len(v) for v in cols.values())
        out.append({"ws": w, "cols": cols, "total": total, "done": len(cols["done"]),
                    "blocked": len(cols["blocked"])})
    return out


def card_activity(case: Case) -> tuple[dict, dict]:
    """Latest note or finding per card, and how many there are. Card moves are
    left out; they are already shown by where the card sits."""
    latest: dict[str, CaseUpdate] = {}
    count: dict[str, int] = {}
    for u in case.updates:  # newest first
        if u.task_id and u.kind in ("note", "finding"):
            count[u.task_id] = count.get(u.task_id, 0) + 1
            latest.setdefault(u.task_id, u)
    return latest, count


def summary(case: Case) -> dict:
    total = len(case.tasks)
    done = sum(1 for t in case.tasks if t.status == "done")
    blocked = sum(1 for t in case.tasks if t.status == "blocked")
    return {"total": total, "done": done, "blocked": blocked}


# ---------------------------------------------------------------- writes
def seed_playbook(case: Case) -> None:
    for ws in WORKSTREAMS:
        for i, (title, client_visible) in enumerate(PLAYBOOK.get(ws, [])):
            case.tasks.append(Task(workstream=ws, title=title, client_visible=client_visible,
                                   source="playbook", position=i))
    first = next((t for t in case.tasks if t.workstream == WORKSTREAMS[0]), None)
    if first:
        first.status = "in_progress"
        first.position = 0
    for w in case.workstreams:
        w.status = derive(ws_tasks(case, w.name)) or w.status


def _log(case: Case, task: Task, note: str, actor: str, internal_only: bool | None = None) -> CaseUpdate:
    u = CaseUpdate(workstream=task.workstream, actor=actor, kind="task", note=note,
                   internal_only=(not task.client_visible) if internal_only is None else internal_only, task=task)
    case.updates.append(u)
    return u


def sync_workstream(case: Case, ws_name: str, actor: str) -> bool:
    """Set the workstream status from its cards. Returns True if it changed."""
    ws = next((w for w in case.workstreams if w.name == ws_name), None)
    if ws is None:
        return False
    new = derive(ws_tasks(case, ws_name))
    if new is None or new == ws.status:
        return False
    ws.status = new
    case.updates.append(CaseUpdate(workstream=ws_name, actor=actor, kind="status",
                                   note=f"{ws_name}: {new.replace('_', ' ')}.", internal_only=False))
    return True


def add_task(case: Case, ws: str, title: str, actor: str, *, status: str = "todo", source: str = "manual",
             client_visible: bool = False, owner: str = "", log: bool = True) -> Task:
    if ws not in WORKSTREAMS:
        raise ValueError(f"unknown workstream {ws!r}")
    title = " ".join(title.split())[:300]
    if not title:
        raise ValueError("card title is required")
    status = status if status in TASK_STATUSES else "todo"
    pos = max((t.position for t in column(case, ws, status)), default=-1) + 1
    t = Task(workstream=ws, title=title, status=status, source=source, client_visible=client_visible,
             owner=owner.strip()[:200], position=pos, completed_at=utcnow() if status == "done" else None)
    case.tasks.append(t)
    if log:
        _log(case, t, f"Card added: {t.title}", actor)
    sync_workstream(case, ws, actor)
    return t


def move_task(case: Case, task: Task, status: str, actor: str, *, workstream: str | None = None,
              before: str | None = None, log: bool = True) -> bool:
    """Move a card to a column (and optionally another lane), placing it before the
    card with id `before`, or last. Returns True if the status or lane changed."""
    if status not in TASK_STATUSES:
        raise ValueError(f"unknown card status {status!r}")
    new_ws = workstream if workstream in WORKSTREAMS else task.workstream
    old_status, old_ws = task.status, task.workstream
    col = [t for t in column(case, new_ws, status) if t is not task]
    idx = next((i for i, t in enumerate(col) if before and t.id == before), len(col))
    col.insert(idx, task)
    task.status, task.workstream = status, new_ws
    for i, t in enumerate(col):
        t.position = i
    if old_status == status and old_ws == new_ws:
        return False  # reorder within a column: not worth a timeline entry
    task.updated_at = utcnow()
    task.completed_at = utcnow() if status == "done" else None
    if log:
        if old_status == status:
            note = f"Card moved to {new_ws}: {task.title}"
        else:
            verb = _MOVE_NOTE[status]
            if status == "in_progress" and old_status in ("blocked", "done"):
                verb = "Resumed" if old_status == "blocked" else "Reopened"
            note = f"{verb}: {task.title}" + (f" (moved to {new_ws})" if new_ws != old_ws else "")
        _log(case, task, note, actor)
    sync_workstream(case, old_ws, actor)
    if new_ws != old_ws:
        sync_workstream(case, new_ws, actor)
    return True


def apply_update(case: Case, update: CaseUpdate, task: Task, move_to: str, actor: str) -> None:
    """Link a timeline entry to a card and move the card by the rules above."""
    update.task = task
    update.workstream = task.workstream
    target = move_to if move_to in TASK_STATUSES else ("in_progress" if task.status == "todo" else "")
    if not target or target == task.status:
        return
    old = task.status
    # The entry itself records the move for staff. When the entry is internal but the
    # card is client-visible, a separate client-visible line shares the step.
    move_task(case, task, target, actor, log=task.client_visible and update.internal_only)
    update.payload = {**(update.payload or {}), "card_moved": {"from": old, "to": target}}


def remove_task(case: Case, task: Task, actor: str) -> None:
    ws = task.workstream
    case.updates.append(CaseUpdate(workstream=ws, actor=actor, kind="task", note=f"Card removed: {task.title}",
                                   internal_only=True))
    for u in list(task.updates):
        u.task = None
    case.tasks.remove(task)
    sync_workstream(case, ws, actor)
