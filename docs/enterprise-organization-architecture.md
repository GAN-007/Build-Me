# Enterprise Organization Architecture

## Purpose

Build-Me began as a trusted single-operator autonomous AI-company runtime. The organization package introduces the durable domain boundary required for multiple organizations, departments, human and AI identities, permissions, duties, and measurable performance without replacing the existing autonomous loop.

## Implemented foundation

The `organization.OrganizationService` provides:

- isolated organizations with stable UUID identities and lifecycle status;
- hierarchical departments with organization-scoped codes;
- human, AI, and service identities;
- department-scoped or organization-wide roles;
- normalized permissions, role grants, and user assignments;
- dynamic duties with cadence, priority, ownership, state, and structured metadata;
- KPIs with direction, target, current value, period, ownership, and lifecycle;
- transactional mutations, foreign-key enforcement, WAL journaling, uniqueness constraints, indexes, and bounded lock waits;
- append-only audit events for structural, access, duty, and KPI changes;
- organization snapshots for dashboards and orchestration decisions.

The package is dependency-free and stores its single-node state in `data/organization.db` by default. This allows existing workstation and dedicated-runner deployments to adopt the domain model without requiring a service migration.

## Security model

Permissions are deny-by-default. A user may act only when an active identity in the same organization has a role containing the exact permission key. Cross-organization role assignment is rejected. Actor-aware mutations enforce permissions before writes, and audit retrieval requires `audit.read`.

Bootstrap operations intentionally allow creation without an actor so a new organization can establish its first administrator. Hosted deployments must put bootstrap behind an authenticated owner-only installation path and disable anonymous bootstrap after initialization.

## Integration with the autonomous loop

The current `memories/consensus.md` baton remains compatible, but it should no longer be treated as the authoritative enterprise state. The loop should read an organization snapshot, select a department and duty, verify the assigned AI identity's permissions, execute within the permitted tool boundary, and append an execution result. Consensus can remain a human-readable summary generated from durable state.

A safe execution flow is:

1. resolve organization and active duty;
2. resolve assigned identity and roles;
3. authorize required capability;
4. acquire an idempotency key and duty lease;
5. execute the model/tool workflow;
6. persist result, evidence, cost, and status;
7. update KPI observations;
8. append an audit event;
9. generate the human-readable consensus summary.

## Remaining architecture required for high-volume hosted use

The repository cannot honestly be described as a finished high-volume multi-user SaaS yet. The following are mandatory engineering and operational launch gates:

- replace the single-node SQLite deployment with PostgreSQL and tenant-aware row-level security;
- add OIDC/SAML authentication, MFA, session management, invitation flows, recovery, and service-account credentials;
- add policy conditions, delegated administration, approval chains, temporary grants, and separation-of-duties controls;
- add an API layer with versioning, idempotency, optimistic concurrency, rate limiting, pagination, and schema validation;
- add a distributed job queue, leases, retries, dead-letter handling, cancellation, and deterministic workflow state machines;
- store artifacts and long-term memory in tenant-isolated object and vector stores;
- add model routing, prompt/version governance, tool sandboxes, egress controls, secrets management, and cost budgets;
- add real-time metrics, traces, logs, alerts, SLOs, incident response, backup restoration, and disaster recovery exercises;
- add billing, usage metering, quotas, invoices, entitlements, and subscription lifecycle controls;
- add privacy, retention, export, deletion, legal hold, consent, and regional data-residency controls;
- complete threat modeling, penetration testing, load testing, accessibility testing, and independent operational review.

## Department and market expansion

The domain model supports configurable departments rather than a fixed list. Likely packaged solutions include software delivery, sales operations, customer success, finance operations, procurement, compliance evidence collection, research intelligence, recruiting operations, field-service coordination, and executive portfolio management.

The strongest defensible niche is not generic autonomous agents. It is governed mixed workforces in which human and AI workers share duties, permissions, measurable KPIs, approval boundaries, and auditable outcomes. Industry packs can add domain-specific duties, KPI definitions, workflows, and policies without changing the core data model.

## Compatibility and migration

No existing runtime file, agent persona, skill, dashboard parser, or loop script is removed. Existing users can continue operating the legacy flow. New code should integrate through the service API rather than writing organization database tables directly. Database migrations must remain forward-only and covered by restore tests before hosted deployment.
