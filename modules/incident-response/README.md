# Incident Response and Case Management

Status: planned. Module spec, not a running service. Reference implementation for the module shape: modules/dark-web-monitoring. Shared contracts: /docs/ARCHITECTURE.md.

## Scope

This is the engagement hub spine. It is the system of record for clients and IR cases, and it is where the other modules escalate findings. It runs IR cases on a fixed five-workstream template, holds GetZero retainers, and offers one-button incident declaration that opens a numbered case, pages the on-call responder and kicks off case-site provisioning.

## Role in the platform

Where the other modules produce findings, this module consumes them. A dark web credential exposure, an actively exploited vulnerability, a pentest-discovered compromise or an MDR detection all escalate into an IR case here, attached to the right workstream. The case ID is a firm-wide running sequence; the client name and incident type are not carried in the ID.

## Case model

Cases use the five workstreams: Scoping and Containment, Forensics and Analysis, Recovery and Restoration, Notification and Legal, Resilience and Hardening. Counsel-directed privileged work is issued under the Incident Response line.

## Roles

Internal staff run cases. Client executives see milestone-level progress, client technical users see case detail, breach counsel gets privileged control of counsel-directed cases, and carriers get scoped panel access.

## Build notes

This module provides the hub endpoints the others call (POST /api/ir-cases to open or link a case). Until it is live, modules run standalone and escalation is a no-op gated by PLATFORM_HUB_URL. Build it next after the first findings-producing modules, since it is what turns findings into engagements.
