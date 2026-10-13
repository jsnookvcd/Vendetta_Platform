# Penetration Testing

Status: planned. Module spec, not a running service. Reference implementation: modules/dark-web-monitoring. Shared contracts: /docs/ARCHITECTURE.md.

## Scope

Runs penetration-testing engagements as structured records rather than a document. Each finding is captured with severity, affected asset, evidence and remediation, and carries a client-owned status and a retest action. The engagement report is rendered from the findings at close, the same way the dark web exposure report is rendered from its findings, so the report and the live record never drift.

## What it contributes

Findings of type `pentest-finding` with the engagement, asset, CWE, remediation and retest status; proof-of-concept material is the evidence. A finding can be escalated into an IR case when a test uncovers an active compromise.

## Roles

Analysts (the testers) manage findings. A client with the portal enabled sees their engagement's confirmed findings and retest progress. No carrier access by default.

## Enablement

MODULE_ENABLED for the module; the client view is per client.

## Build notes

Copy the dark web module shape: manifest with `enabled`, findings at /api/findings, the report rendered server-side from the findings, MODULE_ENABLED, and role-gated client access.
