"""The skills catalog: every action SABINE can take, declared once.

A Skill is the unit of SABINE's ability. The reasoner raises proposals only for
skills in this registry, the executor dispatches by the skill's executor name,
the policy table reads risk and default autonomy from here, and the Ask page
matches a person's words against each skill's title and synonyms. Nothing else
in the module carries its own list of action strings.

Fields:
- key: the action string stored on proposals, policies and ledger rows.
- title, description: what it does, in one line each.
- domain: soc, admin (administration) or services (professional services).
- module: the module whose API the skill acts through, or "sabine" when the
  effect is a queue item or a document SABINE keeps itself.
- risk: low, medium or high. High can never be automatic and is never carried
  out by SABINE; approving it hands off to the module.
- default: the autonomy level when nobody has set one.
- executor: the executor.EXECUTORS entry that carries it out.
- inputs: the arguments the skill needs, as (name, type) pairs.
- chat: whether the Ask page may turn a sentence into this skill.
- reversible: whether the effect can be undone by a person afterwards (a queue
  item can be marked done, a document deleted; a case opened in the IR hub or an
  action on a host cannot be taken back).
- synonyms: phrases the Ask page parser recognises for this skill.
- client_visible: whether a carried-out action is listed in the client's "What
  SABINE did on your account". Internal business work and the drafts that are
  themselves client communications are not.
- person_decides: a person always makes this decision, so the skill can never be
  set to auto, globally or for one client, whatever its risk tier.
"""
from __future__ import annotations

from dataclasses import dataclass, field

DOMAINS = {"soc": "SOC", "admin": "Administration", "services": "Professional services"}
RISKS = ("low", "medium", "high")
RISK_RANK = {"low": 0, "medium": 1, "high": 2}


@dataclass(frozen=True)
class Input:
    name: str
    type: str          # finding_id | client | person | module | case | host | check
    required: bool = True


@dataclass(frozen=True)
class Skill:
    key: str
    title: str
    description: str
    domain: str
    module: str
    risk: str
    default: str
    executor: str
    inputs: tuple[Input, ...] = ()
    chat: bool = False
    reversible: bool = True
    synonyms: tuple[str, ...] = field(default_factory=tuple)
    client_visible: bool = True
    person_decides: bool = False

    @property
    def can_auto(self) -> bool:
        return self.risk != "high" and not self.person_decides

    @property
    def domain_label(self) -> str:
        return DOMAINS.get(self.domain, self.domain)

    def as_dict(self) -> dict:
        return {"key": self.key, "title": self.title, "description": self.description, "domain": self.domain,
                "domain_label": self.domain_label, "module": self.module, "risk": self.risk, "default": self.default,
                "inputs": [{"name": i.name, "type": i.type, "required": i.required} for i in self.inputs],
                "chat": self.chat, "reversible": self.reversible, "can_auto": self.can_auto,
                "synonyms": list(self.synonyms), "client_visible": self.client_visible,
                "person_decides": self.person_decides}


_SKILLS = (
    Skill("escalate_finding", "Escalate a finding into an IR case",
          "A critical or high finding left unescalated beyond the threshold is escalated to the IR hub through the module's own API, opening or linking a case.",
          "soc", "finding module", "medium", "propose", "escalate_finding",
          (Input("finding_id", "finding_id"),), chat=True, reversible=False,
          synonyms=("escalate", "open a case", "open an ir case", "raise a case", "page ir", "page the responder")),
    Skill("copilot_false_positive", "Queue a finding the triage copilot calls a false positive for confirmation",
          "When a module's triage copilot proposes false positive at high confidence and no case exists, SABINE does not escalate; it raises a low-severity work item so a responder confirms and closes it in the module, under that module's second-approver rule.",
          "soc", "sabine", "low", "auto", "raise_work_item",
          (Input("finding_id", "finding_id"),), chat=True, reversible=True,
          synonyms=("close as false positive", "false positive", "mark as false positive", "benign")),
    Skill("link_related_findings", "Note related findings across modules for one client",
          "When one client has active findings in more than one module that share a host, credential or title, a correlation note is raised as a work item so the responder sees the whole story.",
          "soc", "sabine", "low", "auto", "raise_work_item",
          (Input("client", "client"),), chat=True, reversible=True,
          synonyms=("correlate", "link related", "related findings", "link the findings")),
    Skill("host_action", "Recommend a response action on a host (isolate, contain, quarantine)",
          "SABINE never touches a host. It recommends the action with its reasoning and links the responder to the module page where the action is taken, under that module's approval rules.",
          "soc", "managed-services", "high", "propose", "handoff",
          (Input("finding_id", "finding_id"), Input("host", "host", required=False)), chat=True, reversible=False,
          synonyms=("isolate", "contain", "quarantine", "host action", "lock down the host")),
    Skill("page_oncall", "Page the on-call responder for an unacknowledged critical",
          "A critical MDR investigation or managed-services critical with no acknowledgement past the client's response commitment pages the on-call responder through the IR hub, at most once an hour per detection.",
          "soc", "incident-response", "low", "auto", "page_oncall",
          (Input("finding_id", "finding_id"),), chat=True, reversible=False,
          synonyms=("page on-call", "page oncall", "page on call", "page the on-call", "page the on call", "wake the on-call")),
    Skill("suggest_suppression", "Propose an MDR suppression for a pattern people keep calling noise",
          "When people have rejected or closed as false positive the same detection pattern for one client the set number of times, SABINE proposes a time-limited MDR suppression for that client; a person approves it.",
          "soc", "mdr", "medium", "propose", "suggest_suppression",
          (Input("finding_id", "finding_id"),), chat=True, reversible=True,
          synonyms=("suggest a suppression", "suggest suppression", "propose a suppression", "suppress this", "suppress the pattern", "this is noise"),
          person_decides=True),
    Skill("roster_sync", "Re-sync a module whose roster pull is failing",
          "When a module reports a failed roster pull, SABINE asks it to pull again; if it still fails the item stays in the queue for an operator.",
          "admin", "the module named", "low", "auto", "roster_sync",
          (Input("module", "module"),), chat=True, reversible=True,
          synonyms=("re-sync", "resync", "sync the roster", "roster sync", "pull the roster", "re-pull")),
    Skill("readiness_remediation", "Raise a blocking readiness item as work with the fix spelled out",
          "A red item on the go-live screen becomes a work item with the exact parameter or page to fix, assigned to the admin domain.",
          "admin", "sabine", "low", "auto", "raise_work_item",
          (Input("module", "module"), Input("check", "check")), chat=False, reversible=True),
    Skill("staff_hygiene", "Flag staff access that looks wrong",
          "An active person with no module grants, a module with nobody granted, or more than a handful of admins is raised for review.",
          "admin", "sabine", "low", "auto", "raise_work_item",
          (Input("person", "person", required=False), Input("module", "module", required=False)), chat=False, reversible=True),
    Skill("stale_case_nudge", "Nudge an IR case that has gone quiet",
          "An open case with no timeline update past the threshold is raised to its lead with what is outstanding.",
          "services", "sabine", "low", "auto", "raise_work_item",
          (Input("case", "case"), Input("person", "person", required=False)), chat=True, reversible=True,
          synonyms=("nudge", "poke", "chase", "remind")),
    Skill("retest_due", "Queue a pentest retest that is waiting",
          "Findings in retest_pending are queued to the engagement owner.",
          "services", "sabine", "low", "auto", "raise_work_item",
          (Input("finding_id", "finding_id"),), chat=False, reversible=True),
    Skill("remediation_overdue", "Flag a vulnerability past its remediation SLA",
          "A finding still remediating past the SLA for its severity is raised, grouped by client, with a draft client note.",
          "services", "sabine", "low", "auto", "raise_work_item",
          (Input("finding_id", "finding_id"),), chat=False, reversible=True),
    Skill("deliverable_acceptance_nudge", "Nudge a deliverable the client has not accepted",
          "A deliverable delivered in the Office of Special Projects and not accepted on the portal within the window is queued to the engagement lead with a note; nothing is sent to the client.",
          "services", "sabine", "low", "auto", "raise_work_item",
          (Input("deliverable", "deliverable"),), chat=False, reversible=True),
    Skill("engagement_overdue", "Flag a professional-services engagement past its planned end",
          "An engagement still open past its planned end date is raised to its lead with what is still outstanding.",
          "services", "sabine", "low", "auto", "raise_work_item",
          (Input("engagement", "engagement"),), chat=False, reversible=True),
    Skill("journey_suggest", "Propose a Security Journey item from evidence",
          "A recurring finding pattern, overdue remediation, a class of pentest findings or a posture gap becomes a proposed item on the client's Security Journey on the platform; a person accepts or declines it there.",
          "services", "platform", "low", "auto", "journey_suggest",
          (Input("client", "client"),), chat=False, reversible=True, client_visible=False),
    Skill("journey_progress", "Move a Security Journey item when its evidence resolves",
          "A planned or in-progress journey item SABINE raised is marked in progress when its evidence shrinks and done when the evidence it rested on is gone.",
          "services", "platform", "low", "auto", "journey_progress",
          (Input("client", "client"),), chat=False, reversible=True),
    Skill("posture_review", "Draft the monthly posture review",
          "Once a month per active client, SABINE drafts the posture review from live data and what she did on the account, redacted for the client, and posts it as a draft communication on the platform; a person approves it before the client sees it.",
          "services", "platform", "low", "auto", "posture_review",
          (Input("client", "client"),), chat=True, reversible=True, client_visible=False,
          synonyms=("posture review", "draft the posture review", "draft a posture review", "monthly review", "monthly posture review")),
    Skill("client_outreach", "Draft a client email for a person to approve",
          "When a cross-client campaign touches a client, a deliverable sits unaccepted, or a response commitment is at risk, SABINE drafts the email and posts it as an outreach draft on the platform; a person approves it and it sends.",
          "services", "platform", "low", "auto", "client_outreach",
          (Input("client", "client"),), chat=True, reversible=True, client_visible=False,
          synonyms=("draft an email", "draft outreach", "email the client", "write to the client", "reach out to", "client outreach")),
    Skill("engagement_budget_burn", "Flag an engagement burning through its budget",
          "A Harvest project past the budget-burn threshold is raised to the services queue with what is spent and what is left.",
          "services", "sabine", "low", "auto", "raise_work_item",
          (Input("project", "project"),), chat=False, reversible=True, client_visible=False),
    Skill("capacity_overload", "Flag a person booked past capacity this week",
          "Someone whose Harvest hours this week pass the capacity threshold is raised so the load can be rebalanced.",
          "services", "sabine", "low", "auto", "raise_work_item",
          (Input("person", "person"),), chat=False, reversible=True, client_visible=False),
    Skill("renewal_upcoming", "Flag a renewal coming up",
          "A HubSpot renewal closing inside the window is raised with the client's current posture, so the account lead walks in prepared.",
          "services", "sabine", "low", "auto", "raise_work_item",
          (Input("deal", "deal"),), chat=False, reversible=True, client_visible=False),
    Skill("won_not_onboarded", "Flag a won deal that is not onboarded",
          "A deal closed won in HubSpot whose company is not an active client on the platform after a few days is raised so onboarding starts.",
          "services", "sabine", "low", "auto", "raise_work_item",
          (Input("deal", "deal"),), chat=False, reversible=True, client_visible=False),
    Skill("client_brief", "Write a client brief",
          "A short posture brief per client from live data across every module, kept under Briefs for a person to send.",
          "services", "sabine", "low", "auto", "client_brief",
          (Input("client", "client"),), chat=True, reversible=True, client_visible=False,
          synonyms=("write a brief", "client brief", "brief for", "posture brief", "write up")),
    Skill("daily_summary", "Write the daily summary",
          "What SABINE saw, proposed and did in the last day, for the morning stand-up.",
          "admin", "sabine", "low", "auto", "daily_summary",
          (), chat=True, reversible=True, client_visible=False,
          synonyms=("daily summary", "stand-up summary", "standup summary", "write the summary", "morning summary")),
)

REGISTRY: dict[str, Skill] = {s.key: s for s in _SKILLS}
KEYS: tuple[str, ...] = tuple(REGISTRY)


def get(key: str) -> Skill:
    try:
        return REGISTRY[key]
    except KeyError:
        raise KeyError(f"unknown skill {key!r}") from None


def by_domain() -> list[tuple[str, str, list[Skill]]]:
    """[(domain key, domain label, skills)] in the order the catalog shows them."""
    return [(d, label, [s for s in _SKILLS if s.domain == d]) for d, label in DOMAINS.items()]


def chat_skills() -> list[Skill]:
    return [s for s in _SKILLS if s.chat]
