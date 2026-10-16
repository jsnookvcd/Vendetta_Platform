"""MARLOW's signed chain: one hash-chained, Ed25519-signed sequence of everything
it observed, proposed, was told, and did. Same scheme as the module evidence
chains (evidence.py), so the same standalone verifier checks it."""
from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import evidence
from .db import Ledger, utcnow


def append(db: Session, kind: str, actor: str, summary: str, detail: dict | None = None, ref: str = "") -> Ledger:
    head = db.execute(select(Ledger).order_by(Ledger.chain_seq.desc()).limit(1)).scalar_one_or_none()
    prev = head.content_hash if head else evidence.GENESIS
    seq = (head.chain_seq + 1) if head else 1
    row = Ledger(at=utcnow(), kind=kind, actor=actor, ref=ref, summary=summary[:500], detail=detail or {},
                 chain_seq=seq, prev_hash=prev)
    row.content_hash, row.signature, row.key_id = evidence.compute(row.fields(), prev)
    db.add(row)
    db.commit()
    return row


def verify(db: Session) -> dict:
    rows = db.execute(select(Ledger).order_by(Ledger.chain_seq)).scalars().all()
    records = [{"prev_hash": r.prev_hash, "content_hash": r.content_hash, "signature": r.signature,
                "fields": r.fields()} for r in rows]
    return evidence.verify_chain(records)


def export(db: Session) -> dict:
    rows = db.execute(select(Ledger).order_by(Ledger.chain_seq)).scalars().all()
    return {
        "scheme": evidence.SCHEME, "public_key": evidence.public_key_hex(), "key_id": evidence.key_id(),
        "records": [{"seq": r.chain_seq, "prev_hash": r.prev_hash, "content_hash": r.content_hash,
                     "signature": r.signature, "key_id": r.key_id, "fields": r.fields()} for r in rows],
    }


def count(db: Session) -> int:
    return db.scalar(select(func.count(Ledger.id))) or 0
