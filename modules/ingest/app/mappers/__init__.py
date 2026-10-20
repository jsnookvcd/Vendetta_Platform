"""Source mappers: one vendor record in, one OCSF event out.

Each source registers a Mapper with the key connectors and push deliveries use
(crowdstrike_alerts, entra_signins, cloudtrail, ...). A mapper is a pure function, so
every mapping is unit tested against recorded vendor fixtures and the same record
always normalizes to the same event, which the receipt hashes depend on.

The contract:

- map(raw: dict) -> dict | None returns one OCSF event (built with app.ocsf.event),
  or None when the record is deliberately skipped (a heartbeat, a no-op audit row).
  It raises ocsf.MappingError when the record is malformed. It never reads the clock,
  the network or the database, and it never sets the tenant: the pipeline does.
- uid(raw) -> str returns the vendor's stable id for the record, used to drop
  duplicates when polling windows overlap. Return "" when the vendor has none; the
  raw hash is used instead.
- One raw record yields at most one event. A vendor file or page that carries many
  records (CloudTrail's Records array, a Graph page) is split by the connector before
  the pipeline sees it, so every leaf of a receipt is exactly one vendor record.
"""
from __future__ import annotations

import dataclasses
import importlib
import pkgutil
from typing import Callable

from .. import ocsf


@dataclasses.dataclass(frozen=True)
class Mapper:
    key: str
    name: str               # display name, e.g. "CrowdStrike Falcon alerts"
    vendor: str             # e.g. "CrowdStrike"
    product: str            # e.g. "Falcon"
    family: str             # edr, identity, email, cloud, saas, network, vulnerability
    classes: tuple          # OCSF class keys this mapper can emit
    map: Callable[[dict], dict | None]
    uid: Callable[[dict], str] = lambda raw: ""
    doors: tuple = ("push",)  # pull, push, bucket, syslog
    detection: bool = False   # the vendor's own detections (become vendor detections)


REGISTRY: dict[str, Mapper] = {}


def register(m: Mapper) -> Mapper:
    if m.key in REGISTRY:
        raise RuntimeError(f"mapper {m.key} registered twice")
    for c in m.classes:
        if c not in ocsf.CLASSES:
            raise RuntimeError(f"mapper {m.key} declares unknown OCSF class {c}")
    REGISTRY[m.key] = m
    return m


def get(key: str) -> Mapper | None:
    _load()
    return REGISTRY.get(key)


def all_mappers() -> list[Mapper]:
    _load()
    return sorted(REGISTRY.values(), key=lambda m: (m.family, m.name))


_LOADED = False


def _load() -> None:
    global _LOADED
    if _LOADED:
        return
    _LOADED = True
    for info in pkgutil.iter_modules(__path__):
        if not info.name.startswith("_"):
            importlib.import_module(f"{__name__}.{info.name}")


def normalize(key: str, raw: dict) -> dict | None:
    m = get(key)
    if m is None:
        raise ocsf.MappingError(f"no mapper for source {key}")
    if not isinstance(raw, dict):
        raise ocsf.MappingError("record is not a JSON object")
    ev = m.map(raw)
    if ev is None:
        return None
    problems = ocsf.validate(ev)
    if problems:
        raise ocsf.MappingError("; ".join(problems))
    if ev["class_uid"] not in {ocsf.CLASSES[c][0] for c in m.classes}:
        raise ocsf.MappingError(f"mapper {key} emitted an undeclared class {ev['class_uid']}")
    return ev
