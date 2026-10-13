# Network Operations

Status: planned. Module spec, not a running service. Reference implementation: modules/dark-web-monitoring. Shared contracts: /docs/ARCHITECTURE.md.

## Scope

Managed network and infrastructure operations. Tracks device and service health, change windows and maintenance, and operational incidents, and gives clients a health and maintenance view without exposing internal tooling. Covers managed IT and the operational side of managed security.

## What it contributes

Findings of type `event` for health events and operational incidents, with the device, service, metric, change window and maintenance context; monitoring detail and change records are the evidence. A security-relevant event escalates into an IR case on the Scoping and Containment workstream.

## Roles

Operations staff manage everything. A client with the portal enabled sees a service-health and maintenance summary. No carrier access by default.

## Enablement

MODULE_ENABLED for the module; the client view is per client.

## Build notes

Follow the dark web module: manifest with `enabled`, findings at /api/findings, MODULE_ENABLED, role-gated client access, and escalation to the hub. The monitoring and RMM systems feeding this module are separate; this module owns the operational record, the client surface and the escalation.
