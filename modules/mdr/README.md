# Managed Detection and Response

Status: planned. Module spec, not a running service. Reference implementation: modules/dark-web-monitoring. Shared contracts: /docs/ARCHITECTURE.md.

## Scope

Managed detection and response. Clients see investigations with analyst verdicts and the actions taken, not a stream of raw alerts. An investigation that turns out to be a real incident converts into a full IR case in the hub, carrying its evidence and analyst notes.

## What it contributes

Findings of type `investigation` with a verdict (benign, suspicious, malicious), the detection source, asset, technique and the analyst actions. Detection detail is the evidence. Escalation opens an IR case on the Scoping and Containment workstream.

## Roles

Analysts (the SOC) run investigations. A client with the portal enabled sees confirmed investigations with verdicts and actions, not raw telemetry. No carrier access by default.

## Enablement

MODULE_ENABLED for the module; the client view is per client.

## Build notes

Follow the dark web module: manifest with `enabled`, findings at /api/findings, MODULE_ENABLED, role-gated client access, and escalation to the hub. The detection pipeline feeding this module is separate; this module owns the investigation record, the verdict, the client surface and the escalation.
