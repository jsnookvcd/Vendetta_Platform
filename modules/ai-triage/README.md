# AI Triage Copilot

Status: built and tested. Shared library, not a running service.

## Scope

An evidence-grounded triage assistant for the finding-bearing modules (managed services, vulnerability management, penetration testing, dark web monitoring). Given one finding, it proposes a verdict with a calibrated confidence and a written rationale. It never acts: a human analyst accepts, rejects or overrides the proposal, and a second approver is required for high-stakes or low-confidence verdicts. Both the copilot's proposal and the human's decision are written into the module's signed evidence chain, so the record shows what the copilot said, how sure it was, why, and who decided.

## Verdicts

true positive, false positive, needs investigation, duplicate, benign/expected.

## How it works

Two backends behind one `triage(finding, backend=None)` call:

- Rules backend (`rules-v1`): the default and the fallback. Deterministic, needs no model, no network and no key. Every point of score is tied to a named signal, and those signals become the rationale, so the verdict and confidence are reproducible and defensible. Conservative by design: weak or conflicting signals return needs_investigation at low confidence.
- LLM backend: optional, configured with `triage_llm_api_key` and `triage_llm_model`. Its output is validated and grounded against the rules, never trusted raw. On any failure it falls back to rules. When the model and the rules agree, confidence stands; when they disagree, confidence is damped, a second approver is forced, and the disagreement is recorded in the rationale and signals, so the model was second-guessed rather than followed blindly.

## Human in the loop

`requires_second_approver(verdict, confidence)` is true when acting on the verdict is high-stakes (closing or suppressing a finding) or when confidence is below 0.75. The copilot sets `requires_approval` on every proposal; the module enforces it with its existing RBAC and two-person control before any action executes.

## Signed evidence

`evidence_events.proposal_event(proposal)` and `evidence_events.decision_event(...)` return the `(kind, actor, detail, payload)` a module passes to its own `record_event`. The proposal is attributed to `copilot:<model>`; the decision is attributed to the human analyst, with the second approver named. A module calls these; it does not let the copilot mutate a finding.

## Using it from a module

    from triage import Finding, triage, build_backend
    from triage.evidence_events import proposal_event, decision_event

    backend = build_backend(settings)          # None unless an LLM is configured
    proposal = triage(Finding(title=f.title, description=f.description, severity=f.severity,
                              cvss=f.cvss, cve=f.cve, source=f.source, times_seen=f.times_seen,
                              prior_verdict=prior), backend=backend)
    record_event(db, client_id, ..., *proposal_event(proposal)[0:... ])  # write the proposal
    # later, when a human decides (and a second approver signs off if required):
    record_event(db, client_id, ..., *decision_event(decision="accepted", actor=analyst,
                                                      proposal=proposal, approver=lead))

Modules vendor this package into `app/triage/` the same copy-per-module way they vendor `evidence.py` and `evidence_export`.

## Adoption

- managed-services: the reference wiring. `app/copilot.py` maps an alert onto a Finding (title, detail, severity, host, tool, recurrence count for the same client, tool and title, and a human's most recent final verdict on that signature as `prior_verdict`). A proposal is computed when sync first sees an alert and on demand at `POST /api/alerts/{id}/copilot`; it is stored on the alert (`Alert.copilot`) and signed into the per-client action chain as a `triage_proposed` row attributed to `copilot:<model>`. The alert page shows the verdict, confidence and rationale with accept, override and reject controls; the queue shows a verdict badge. A human decision is signed as `triage_decided` with the approver named. Accepting or overriding to a closing verdict (false positive, benign, duplicate) resolves the alert and goes through the module's existing `can_act` / `can_approve` two-person rule; a true positive acknowledges it. `GET /api/findings` carries the proposal as a `copilot` sub-object (see docs/contracts/finding.schema.json), and SABINE reads it: a false positive at 0.9 or higher is queued for confirmation instead of escalated, a true positive at 0.85 or higher raises the escalation proposal's confidence.
- Not yet adopted: vulnerability-management, penetration-testing, dark-web-monitoring.

Settings in an adopting module: `triage_llm_api_key` and `triage_llm_model` (`TRIAGE_LLM_API_KEY`, `TRIAGE_LLM_MODEL` in `.env.example`); both blank means the rules backend.

## Tests

`pytest -q` from the module directory. No database; the rules backend and engine need no third-party packages (httpx is used only by the optional LLM backend).
