"""The detection engine: a pure function from signals, rules, per-client overrides,
suppressions and the currently open investigations to a plan of investigations to
open and signals to attach.

Nothing here touches the database or the network, so every decision the SOC sees is
reproducible from its inputs and covered by unit tests. detect.py feeds it from the
database and applies the plan.

Semantics:

- A signal belongs to a client by platform_client_id; a signal without one is ignored.
- A signal matched by an active suppression for its client is set aside and counted
  against that suppression. It never opens or joins an investigation.
- A rule matches a signal when every non-empty criterion holds: the tool is listed,
  the type is listed, any title substring appears (case-insensitive), and the
  severity is at least min_severity. A rule disabled globally, or for the client by
  an override, matches nothing for that client.
- Matching signals are grouped per (rule, client, group key), where the group key is
  the host, the normalized title, or empty for client-wide grouping.
- If an investigation is already open for that group, new signals attach to it.
- Otherwise an investigation opens when `threshold` matching signals fall inside any
  `window_minutes` span, and it takes every matching signal in the group that falls
  inside the lookback window.
- Only signals inside the lookback window can open an investigation; a pair
  (rule, signal) already linked is never reconsidered, so a closed investigation's
  signals do not reopen it.
"""
from __future__ import annotations

import dataclasses
import datetime as dt
from collections import defaultdict
from typing import Iterable

from .config import SEV_RANK


@dataclasses.dataclass(frozen=True)
class Signal:
    id: str
    platform_client_id: str
    client: str
    tool: str
    type: str
    severity: str
    title: str
    host: str
    occurred_at: dt.datetime


@dataclasses.dataclass(frozen=True)
class Rule:
    key: str
    name: str
    severity: str
    tools: tuple = ()
    types: tuple = ()
    title_any: tuple = ()
    min_severity: str = "low"
    group_by: str = "host"
    window_minutes: int = 60
    threshold: int = 1
    mitre: tuple = ()
    response: str = "none"
    enabled: bool = True
    version: int = 1

    @classmethod
    def from_dict(cls, d: dict) -> "Rule":
        m, c = d.get("match") or {}, d.get("correlation") or {}
        return cls(key=d["key"], name=d.get("name", d["key"]), severity=d.get("severity", "medium"),
                   tools=tuple(t.lower() for t in m.get("tools") or ()),
                   types=tuple(t.lower() for t in m.get("types") or ()),
                   title_any=tuple(s.lower() for s in m.get("title_any") or () if s),
                   min_severity=m.get("min_severity") or "low",
                   group_by=c.get("group_by") or "host",
                   window_minutes=max(1, int(c.get("window_minutes") or 60)),
                   threshold=max(1, int(c.get("threshold") or 1)),
                   mitre=tuple(d.get("mitre") or ()), response=d.get("response") or "none",
                   enabled=bool(d.get("enabled", True)), version=int(d.get("version") or 1))


@dataclasses.dataclass(frozen=True)
class Override:
    rule_key: str
    platform_client_id: str
    disabled: bool = False
    severity: str = ""


@dataclasses.dataclass(frozen=True)
class Suppression:
    id: str
    platform_client_id: str
    tool: str = ""
    title_contains: str = ""
    host: str = ""
    expires_at: dt.datetime | None = None

    def active(self, now: dt.datetime) -> bool:
        return self.expires_at is None or self.expires_at > now

    def matches(self, s: Signal) -> bool:
        if s.platform_client_id != self.platform_client_id:
            return False
        if not (self.tool or self.title_contains or self.host):
            return False  # an empty suppression would silence a whole client; never honored
        if self.tool and self.tool.lower() != s.tool.lower():
            return False
        if self.title_contains and self.title_contains.lower() not in s.title.lower():
            return False
        if self.host and self.host.lower() != s.host.lower():
            return False
        return True


@dataclasses.dataclass(frozen=True)
class OpenInvestigation:
    id: str
    rule_key: str
    platform_client_id: str
    group_key: str


@dataclasses.dataclass
class Open:
    rule_key: str
    platform_client_id: str
    client: str
    group_key: str
    severity: str
    title: str
    host: str
    mitre: list
    response: str
    rule_version: int
    signal_ids: list
    first_signal_at: dt.datetime
    last_signal_at: dt.datetime


@dataclasses.dataclass
class Attach:
    investigation_id: str
    rule_key: str
    signal_ids: list


@dataclasses.dataclass
class Plan:
    opens: list = dataclasses.field(default_factory=list)
    attaches: list = dataclasses.field(default_factory=list)
    suppressed: dict = dataclasses.field(default_factory=dict)  # signal id -> suppression id
    ignored: int = 0  # signals with no client

    def summary(self) -> dict:
        return {"opened": len(self.opens), "attached": sum(len(a.signal_ids) for a in self.attaches),
                "suppressed": len(self.suppressed), "ignored": self.ignored}


def sev_at_least(sev: str, floor: str) -> bool:
    return SEV_RANK.get((sev or "low").lower(), 0) >= SEV_RANK.get((floor or "low").lower(), 0)


def rule_matches(rule: Rule, s: Signal) -> bool:
    if rule.tools and s.tool.lower() not in {t.lower() for t in rule.tools}:
        return False
    if rule.types and s.type.lower() not in {t.lower() for t in rule.types}:
        return False
    if rule.title_any:
        t = s.title.lower()
        if not any(sub.lower() in t for sub in rule.title_any):
            return False
    return sev_at_least(s.severity, rule.min_severity)


def group_key(rule: Rule, s: Signal) -> str:
    if rule.group_by == "host":
        return (s.host or "").strip().lower()
    if rule.group_by == "title":
        return " ".join(s.title.lower().split())[:200]
    return ""


def threshold_met(times: list[dt.datetime], threshold: int, window_minutes: int) -> bool:
    """True when `threshold` timestamps fall inside some span of `window_minutes`."""
    if len(times) < threshold:
        return False
    ts = sorted(times)
    span = dt.timedelta(minutes=window_minutes)
    for i in range(len(ts) - threshold + 1):
        if ts[i + threshold - 1] - ts[i] <= span:
            return True
    return False


def _title(rule: Rule, client: str, gkey: str, sigs: list[Signal]) -> str:
    if rule.group_by == "host" and gkey:
        host = next((s.host for s in sigs if s.host), gkey)
        return f"{rule.name} on {host}"[:400]
    if rule.group_by == "title" and sigs:
        return f"{rule.name}: {sigs[0].title}"[:400]
    return f"{rule.name} at {client}"[:400]


def evaluate(signals: Iterable[Signal], rules: Iterable[Rule], *, overrides: Iterable[Override] = (),
             suppressions: Iterable[Suppression] = (), open_investigations: Iterable[OpenInvestigation] = (),
             linked: set | frozenset = frozenset(), already_suppressed: set | frozenset = frozenset(),
             now: dt.datetime, lookback_minutes: int = 1440) -> Plan:
    """Compute what to open and attach. `linked` holds (rule_key, signal_id) pairs
    already on an investigation; `already_suppressed` holds signal ids a previous run
    set aside, so a suppression's hit count is not inflated by re-runs."""
    plan = Plan()
    rules = [r for r in rules if r.enabled]
    ov = {(o.rule_key, o.platform_client_id): o for o in overrides}
    active_sup = [s for s in suppressions if s.active(now)]
    open_by_key = {(o.rule_key, o.platform_client_id, o.group_key): o for o in open_investigations}
    cutoff = now - dt.timedelta(minutes=lookback_minutes)
    linked_ids = {sid for _, sid in linked}

    eligible: list[Signal] = []
    for s in signals:
        if not s.platform_client_id:
            plan.ignored += 1
            continue
        if s.id in already_suppressed:
            continue
        sup = next((x for x in active_sup if x.matches(s)), None)
        if sup is not None:
            # A signal already on an investigation predates the suppression; it is
            # set aside from now on but does not count as a hit.
            if s.id not in linked_ids:
                plan.suppressed[s.id] = sup.id
            continue
        eligible.append(s)

    for rule in rules:
        groups: dict[tuple, list[Signal]] = defaultdict(list)
        for s in eligible:
            o = ov.get((rule.key, s.platform_client_id))
            if o is not None and o.disabled:
                continue
            if (rule.key, s.id) in linked:
                continue
            if not rule_matches(rule, s):
                continue
            groups[(s.platform_client_id, group_key(rule, s))].append(s)

        for (pid, gkey), sigs in sorted(groups.items()):
            sigs.sort(key=lambda x: (x.occurred_at, x.id))
            existing = open_by_key.get((rule.key, pid, gkey))
            if existing is not None:
                plan.attaches.append(Attach(existing.id, rule.key, [s.id for s in sigs]))
                continue
            recent = [s for s in sigs if s.occurred_at >= cutoff]
            if not recent or not threshold_met([s.occurred_at for s in recent], rule.threshold, rule.window_minutes):
                continue
            o = ov.get((rule.key, pid))
            severity = (o.severity if o is not None and o.severity else rule.severity)
            host = next((s.host for s in reversed(recent) if s.host), "") if rule.group_by != "client" else (
                recent[-1].host if len({s.host for s in recent}) == 1 else "")
            plan.opens.append(Open(
                rule_key=rule.key, platform_client_id=pid, client=recent[-1].client, group_key=gkey,
                severity=severity, title=_title(rule, recent[-1].client, gkey, recent), host=host,
                mitre=list(rule.mitre), response=rule.response, rule_version=rule.version,
                signal_ids=[s.id for s in recent], first_signal_at=recent[0].occurred_at,
                last_signal_at=recent[-1].occurred_at))
    return plan
