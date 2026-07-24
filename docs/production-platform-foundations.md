# Production Platform Foundations

## Scope

This tranche adds independently testable foundations for identity sessions, billing, entitlements, usage metering, PostgreSQL tenant isolation, and backup restoration. It preserves the existing autonomous runtime, organization service, enterprise API, workflow engine, dashboard, prompts, agents, skills, projects, and consensus memory.

## Identity sessions

`production.IdentityService` provides hashed, expiring, revocable sessions for passwordless, OIDC, SAML, and service-authenticated principals.

Security properties:

- session secrets are generated with the operating-system cryptographic random source;
- only a token prefix, random salt, and scrypt hash are stored;
- verification uses constant-time comparison;
- sessions have both idle and absolute expiration;
- assurance levels support step-up authorization;
- sessions can be individually revoked, rotated, or revoked for an entire user;
- security events record session creation and revocation.

This service is the session boundary after an upstream identity provider authenticates a user. It does not falsely implement an OIDC or SAML provider. Production deployment must configure a real provider, validate issuer and audience, pin accepted algorithms, verify signatures against rotating keys, enforce nonce and state, and test logout and deprovisioning.

## Billing, entitlements, and metering

`production.BillingService` implements:

- immutable versionable plans;
- integer-minor-unit prices;
- organization subscriptions;
- plan entitlements;
- quota limits and measurement periods;
- time-bounded contractual overrides;
- immutable idempotent usage events;
- quota enforcement before execution;
- provider identifiers without provider coupling.

The service deliberately does not store floating-point money. A payment processor remains an external integration. Provider webhook signatures, invoice taxation, reconciliation, refunds, disputes, and settlement accounting require configured provider accounts and finance approval.

## PostgreSQL tenant isolation

`deploy/postgres/001_enterprise_platform.sql` is an executable PostgreSQL 16 schema for organizations, users, sessions, billing, usage, entitlement overrides, and operational events.

Tenant-owned tables have row-level security enabled and forced. Policies use a transaction-local `app.organization_id` setting. The CI workflow applies the schema to a real PostgreSQL service, executes operations through a non-superuser role, verifies that only the selected tenant is visible, and confirms that a cross-tenant insert is rejected.

Application database connections must set the tenant and user context inside every transaction before issuing tenant queries:

```sql
SET LOCAL app.organization_id = '<authenticated-organization-uuid>';
SET LOCAL app.user_id = '<authenticated-user-uuid>';
```

Connection pools must reset session state on release. Migration and break-glass roles must remain separate from application roles and must be audited.

## Backup and restoration

`production.RecoveryService` creates consistent SQLite backups through the SQLite backup API rather than copying a live database file.

Every backup includes a manifest containing:

- backup identifier;
- creation timestamp;
- file size;
- SHA-256 checksum;
- table row counts;
- source and format metadata.

Verification performs checksum, size, integrity, foreign-key, and table-count checks. Restore drills copy the backup into an isolated temporary environment and verify it before reporting success. Destructive restore refuses to overwrite an existing destination unless explicitly authorized.

For hosted PostgreSQL, this local recovery implementation is not a substitute for managed point-in-time recovery. Production requires encrypted backups, retention policies, cross-region copies, key rotation, restoration into an isolated account, measured recovery objectives, and scheduled recovery exercises.

## Operational acceptance provided by CI

The repository CI now validates:

- Python compilation for dashboard, organization, enterprise, production, and tests;
- all unit and regression tests;
- Bash syntax;
- JavaScript syntax;
- committed-secret patterns;
- PostgreSQL schema application;
- PostgreSQL row-level security reads and writes through a non-superuser role.

## Remaining launch gates

The following require deployed systems and independent evidence before Build-Me can be represented as a high-volume public service:

1. A selected OIDC or SAML provider, MFA policy, SCIM provisioning, invitation and recovery flows, and tested deprovisioning.
2. Application migration from SQLite to PostgreSQL, connection pooling, tenant context middleware, zero-downtime migrations, replicas, and point-in-time recovery.
3. A durable distributed queue, worker registration, heartbeats, autoscaling, backpressure, regional routing, and poison-message operations.
4. A managed secret store, workload identities, key rotation, per-tool egress policy, sandboxing, malware controls, and data-loss prevention.
5. A configured payment processor, signed webhook ingestion, invoices, taxes, credits, refunds, disputes, accounting reconciliation, and finance approval.
6. OpenTelemetry collection, metrics, traces, centralized logs, alerting, service-level objectives, incident paging, and tested runbooks.
7. Load, soak, failover, chaos, penetration, dependency, privacy, accessibility, and disaster-recovery testing by appropriately independent reviewers.
8. Data retention, export, deletion, legal hold, consent, regional residency, acceptable-use, and regulatory policies approved by counsel.
9. Production infrastructure, environment separation, deployment approvals, rollback, vulnerability management, capacity planning, support staffing, and on-call ownership.

A repository can implement controls and tests, but it cannot certify its own legal compliance, processor configuration, external security posture, operational staffing, or independent assessment. Those remain explicit release gates.

## Market expansion

These foundations strengthen Build-Me's emerging position as a governed operating system for mixed human and AI workforces. Commercial opportunities include:

- usage-based AI workforce subscriptions;
- department-specific entitlements and budgets;
- auditable agent execution for regulated operations;
- managed workflow packs for finance, customer success, procurement, research, field operations, and software delivery;
- tenant-isolated private deployments;
- outcome-based pricing backed by immutable usage evidence;
- enterprise governance for third-party agents and tools.
