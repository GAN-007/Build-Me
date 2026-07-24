# Production Readiness Audit

## Executive conclusion

Build-Me is a capable single-operator autonomous-agent runtime. It is not yet a horizontally scalable, multi-tenant hosted service. Its strongest production use today is a controlled workstation or dedicated runner where one trusted operator owns the repository, model credentials, filesystem, and generated actions.

The runtime can be made reliable for that operating model. A public multi-user service requires a separate control plane, durable database, tenant isolation, job queue, policy engine, metering, identity system, secret manager, artifact store, and audited deployment infrastructure. Those requirements are launch gates rather than documentation gaps.

## Repository architecture

The repository contains five functional layers:

1. **Execution and infrastructure** — Claude Code or Codex CLI, Bash orchestration, launchd, systemd user services, Windows/WSL control scripts.
2. **State and orchestration** — `scripts/core/auto-loop.sh`, `memories/consensus.md`, PID/state files, cycle logs, timeout and circuit-breaker handling.
3. **Cognition** — fourteen role-specific agent definitions and reusable skills under `.claude/`.
4. **Workflow policy** — `PROMPT.md`, `CLAUDE.md`, team formation, convergence and handoff rules.
5. **Human control and observability** — local dashboard, monitor scripts, logs, status files and Git history.

The `projects/snapog` tree is a separate demonstration product and must not be confused with the orchestration platform's own control plane.

## Implemented hardening in this tranche

- Authenticated dashboard control endpoints.
- Constant-time bearer-token comparison.
- Mandatory token when binding beyond loopback.
- Origin allow-list enforcement for state-changing requests.
- Request-body size limits.
- Log-tail response limits.
- Browser security headers and strict content-security policy.
- Health endpoint for local supervisors.
- Daemonized request threads and reusable socket configuration.
- Core runtime CI covering Python, Bash, JavaScript and unit tests.
- Credential-pattern rejection in runtime source files.
- Standard `make test` and `make validate` commands.

## Critical gaps still blocking a hosted multi-user launch

### Identity and tenant isolation

There is no user database, organization model, role-based access control, session management, SSO, MFA, tenant-scoped encryption, or per-tenant filesystem boundary. File-based consensus and logs are global to one repository checkout. A hosted product must assign every company, run, artifact, secret, model credential and billing record to an immutable tenant identifier enforced in storage and authorization middleware.

### Durable orchestration

The primary state is Markdown plus local files. PID files are advisory, writes are not transactional across the entire cycle, and local disk is a single failure domain. Hosted execution needs a durable state machine, transactional run records, idempotency keys, leases, heartbeats, retry policy, dead-letter handling and resumable checkpoints.

### Safe execution

The default engine modes permit broad host access. That is appropriate only for a trusted local operator. Untrusted or multi-user workloads require per-run containers or microVMs, read-only base images, explicit writable mounts, egress controls, CPU/memory/time quotas, syscall restrictions, secret injection with short-lived credentials, malware scanning and artifact quarantine.

### Policy and approvals

The prompt provides behavioural guidance but is not an enforceable authorization system. High-impact actions such as publishing, spending, deleting data, changing infrastructure, sending communications or accessing customer records need machine-enforced policies, approval thresholds, separation of duties and immutable audit events.

### Data and secrets

There is no integrated secret manager, key rotation, envelope encryption, data-retention scheduler, legal hold, backup restore process or customer deletion workflow. Model credentials currently depend on the operator's CLI environment. Production hosting must use a managed secret store and never expose provider credentials to generated shell commands.

### Observability and support

Local text logs are useful but insufficient for a service. Required capabilities include structured events, correlation IDs, traces, metrics, SLOs, error budgets, alert routing, audit-log export, run replay, customer-visible incident status and support tooling.

### Scalability

One loop serially operates one company state. High-volume usage requires a scheduler and worker fleet with bounded concurrency, per-tenant fairness, backpressure, regional capacity, autoscaling, workload admission control and cost-aware model routing.

### Billing and commercial controls

There is no entitlement service, usage ledger, invoicing, tax handling, credit limits, plan enforcement, refund logic, payment-failure handling or margin protection. A commercial product needs metering at model, compute, storage and tool-call levels before public self-service onboarding.

### Compliance and governance

No certification is claimed. Depending on customer data and markets, launch may require privacy impact assessments, data-processing agreements, subprocessor disclosures, breach procedures, accessibility testing, export-control review, security testing and sector-specific controls.

## Partially implemented or fragile areas

- The dashboard delegates lifecycle actions to platform scripts and therefore inherits their platform-specific behaviour and error text.
- Linux support is oriented toward WSL/systemd-user rather than a generic server distribution.
- The loop's consensus validation checks headings, not semantic completeness or schema version.
- Rate-limit detection is string-based and provider-output dependent.
- Cost extraction is best-effort and not a billing-grade ledger.
- Log rotation is count- and size-based but lacks compression, retention classes and external archival.
- The accidental-artifact cleanup is pattern-specific rather than a general workspace policy.
- The demo project has its own lifecycle and needs independent dependency, security and deployment review.
- Agent personas encode useful heuristics but require versioning, evaluation datasets and regression tests to prove decision quality.

## Product and market opportunities

### Autonomous back-office operator

A governed version can operate repetitive research, reporting, content, QA and engineering workflows for small companies that cannot staff every specialist role. The differentiator is durable cross-role memory and execution, not merely a collection of prompts.

### Private company operating system

A locally deployed edition can serve privacy-sensitive consultancies, agencies, family offices and internal innovation teams. This niche values bring-your-own-model credentials, local artifacts and human approval more than public cloud convenience.

### Agent governance platform

The existing role, skill and consensus model can become a governance layer for other agent frameworks. Policy templates, evaluation suites, approval workflows and audit exports may be more defensible than competing as another general chatbot.

### Vertical operating packs

Industry-specific packs can combine agents, tools, schemas and approval policies for software delivery, ecommerce operations, collections analysis, procurement, marketing operations and due diligence. Each pack should have measurable outcomes and bounded permitted actions.

### Simulation and decision laboratory

The multi-role structure is suitable for structured pre-mortems, strategy reviews and scenario planning. A read-only simulation mode can become a lower-risk entry product before autonomous execution is enabled.

## Recommended product editions

1. **Local Community** — single trusted operator, local dashboard, bring-your-own CLI credentials.
2. **Team Private** — authenticated shared control plane, isolated runners, approvals, durable run history and organization roles.
3. **Enterprise Governed** — SSO, private networking, policy administration, audit export, customer-managed keys, regional data controls and support SLAs.

## Launch gates

The following evidence is required before describing the platform as production-ready for public multi-user consumption:

- Threat model and independent penetration test.
- Tenant-isolation tests and authorization test matrix.
- Restore-tested backups and disaster-recovery objectives.
- Load tests proving scheduler, worker and storage limits.
- Sandboxed execution with verified network and filesystem boundaries.
- Managed secrets and rotation procedures.
- Structured audit log with tamper-evident retention.
- SLOs, alerts, on-call ownership and incident runbooks.
- Usage ledger reconciled to provider and infrastructure costs.
- Privacy, terms, data-processing and subprocessor documentation.
- Accessibility review of all human-facing interfaces.
- Human review of model actions in every irreversible action class.

Until those gates are met, the accurate release claim is: **production-hardened for a trusted single-operator local environment**, not a universally production-ready high-volume SaaS platform.
