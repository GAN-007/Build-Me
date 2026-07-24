# Enterprise API and Workflow Architecture

## Implemented scope

This release extends the organization foundation with a versioned authenticated API and a durable workflow control plane. Existing agents, prompts, skills, dashboard behavior, shell orchestration, and consensus memory remain available.

Implemented capabilities:

- one-time API credentials stored only as scrypt hashes;
- credential scopes with exact and prefix-wildcard matching;
- expiry, revocation state, and last-used timestamps;
- organization-bound authenticated principals;
- deny-overrides policy rules layered over existing RBAC;
- workflow definitions with immutable versions and ordered dependency-aware steps;
- optional approval gates;
- idempotent workflow creation using organization-scoped idempotency keys;
- explicit run and step state machines;
- atomic worker leases with expiration and single-use lease tokens;
- bounded attempts, retry transitions, and dead-letter outcomes;
- append-only workflow events;
- versioned JSON endpoints under `/api/v1`;
- request body limits, bearer authentication, request IDs, security headers, no-store responses, and per-credential sliding-window rate limits.

## API lifecycle

Run the local API with:

```bash
make enterprise-api
```

The default listener is `127.0.0.1:8790`. Production deployments must place it behind a TLS reverse proxy or service mesh and must not expose an unencrypted listener to an untrusted network.

Principal endpoints:

- `GET /healthz`
- `GET /api/v1/me`
- `POST /api/v1/workflow-runs`
- `POST /api/v1/workflow-runs/{run_id}/approve`
- `GET /api/v1/workflow-runs/{run_id}`
- `POST /api/v1/worker/leases`
- `POST /api/v1/worker/steps/{step_id}/begin`
- `POST /api/v1/worker/steps/{step_id}/complete`
- `POST /api/v1/worker/steps/{step_id}/fail`

Workflow creation requires an `Idempotency-Key` header. Repeating the same key within one organization returns the original run instead of creating duplicate work.

## Authorization model

Authentication and authorization are separate:

1. the bearer credential must be valid, unexpired, unrevoked, and attached to an active user;
2. its scope must permit the API operation;
3. the user must have the required RBAC permission;
4. active policy rules must explicitly allow the action and resource when any policy rules exist;
5. any matching deny rule overrides all allows.

Supported policy conditions currently bind rules to `user_type`, `department_id`, or `owner_user_id`. Unsupported keys are rejected instead of silently ignored.

## Workflow state guarantees

Definitions are activated explicitly and retain version numbers. Runs reference a specific definition version. Step dependencies are checked before a dependent step becomes runnable.

Workers do not claim work by changing arbitrary rows. They acquire an atomic lease containing an opaque token and expiry. Beginning or completing a step requires the same worker and lease token. Expired leases can be reclaimed. Failed steps return to `runnable` until their attempt budget is exhausted; exhausted or non-retryable failures become `dead_letter` and stop the run.

## Integration with the autonomous loop

The shell loop can be upgraded incrementally:

1. authenticate a dedicated AI service identity;
2. request a worker lease;
3. map the step handler to an approved internal skill or executor;
4. begin the step;
5. execute inside the permitted tool and network boundary;
6. complete or fail the step with structured evidence;
7. render durable workflow state into `memories/consensus.md` for human readability.

The workflow database is authoritative. Consensus remains a projection and steering surface.

## Remaining high-volume production gates

This implementation is a tested single-node control-plane layer. A high-volume hosted service still requires:

- PostgreSQL migrations and tenant-aware row-level security;
- OIDC or SAML, MFA, browser sessions, invitations, recovery, SCIM, and device/session revocation;
- a distributed queue and worker pool with backpressure and regional placement;
- managed secret storage, envelope encryption, rotation, and audited secret access;
- tool sandboxes, egress allow-lists, filesystem isolation, and workload identities;
- metering, subscriptions, entitlements, quotas, invoices, taxes, and payment failure handling;
- OpenTelemetry metrics, logs, traces, dashboards, alerts, SLOs, and incident runbooks;
- encrypted backups, point-in-time recovery, restore drills, and multi-region disaster recovery;
- privacy retention, export, deletion, consent, residency, and legal-hold controls;
- independent threat modeling, penetration tests, load tests, chaos tests, accessibility audits, and compliance review.

These are not safe to claim through source code alone. They require deployed infrastructure, third-party identity and payment configuration, operational ownership, and verified test evidence.
