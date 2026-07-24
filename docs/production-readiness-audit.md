# Auto Company Production Readiness Audit

## Executive assessment

Auto Company is a strong local autonomous-agent orchestration runtime. It is not yet a production multi-user SaaS platform and should not be represented as one. The repository currently provides a durable local loop, dual Claude/Codex execution, cross-platform daemon tooling, a local control dashboard, agent personas, reusable skills, and one generated product project.

The safe production path is to preserve that local runtime as the worker/execution plane and add a separately secured control plane, durable state, isolated workspaces, policy enforcement, auditability, and tenant-aware APIs.

## Repository coverage

The audit covered the default branch and imported application history, including:

- `.claude/agents/`: 14 role-specialized agent definitions
- `.claude/skills/`: reusable execution, research, security, product, finance, marketing, and team skills
- `dashboard/`: local web control and observability surface
- `scripts/core/`: autonomous loop, stop and monitor logic
- `scripts/windows/`, `scripts/wsl/`, `scripts/macos/`: host-specific lifecycle management
- `tests/`: dashboard-focused unit tests
- `projects/snapog/`: generated TypeScript/Cloudflare product
- `docs/`, `memories/`, root governance files, Make targets and GitHub workflows

## Existing strengths

1. Cross-platform lifecycle support for macOS and Windows/WSL.
2. Dual-engine support for Claude Code and Codex CLI.
3. Consensus rollback, timeout handling, log rotation and circuit breaking.
4. Clear agent role separation and reusable skill catalogue.
5. Local operational dashboard and status parsing.
6. Strong documentation of operating philosophy and execution flow.
7. Existing guardrails against selected destructive commands.

## Critical production gaps

### 1. Trust and execution boundary

The runtime intentionally gives autonomous agents broad terminal access. Default Claude permission bypass and Codex danger-full-access are unsuitable for untrusted or multi-tenant workloads. Prompt-level prohibitions are not a security boundary.

Required production architecture:

- one isolated worker per organization or job
- rootless container or microVM execution
- read-only base image and ephemeral writable workspace
- explicit outbound network allowlists
- CPU, memory, process, disk and time quotas
- separate deployment credentials from development credentials
- brokered tool calls rather than raw host credentials
- immutable policy evaluation before every privileged action

### 2. Identity, access and tenancy

There is no account model, authentication, role-based authorization, organization boundary, tenant-scoped storage, session management, API-key lifecycle or administrative audit trail.

Required capabilities:

- OIDC/SAML-capable identity provider integration
- organizations, users, memberships and roles
- scoped service accounts and rotatable API keys
- tenant identifiers on every durable record
- authorization at both API and worker dispatch layers
- administrative break-glass controls with full auditing

### 3. Durable orchestration state

`memories/consensus.md`, PID files, state files and local logs are appropriate for one host, but not for high availability, concurrent work, failover or multi-user operation.

Required capabilities:

- PostgreSQL for tenants, projects, runs, tasks, approvals and audit events
- durable queue for run dispatch and retries
- object storage for artifacts and large logs
- optimistic concurrency or leases for workers
- idempotency keys for every external side effect
- resumable workflow checkpoints
- retention and deletion policies

### 4. Human approval and policy controls

The charter explicitly discourages human confirmation. That model cannot safely govern payments, production deployments, domain changes, customer communication, credential changes, destructive operations or legal commitments.

Required capabilities:

- policy-classified actions
- mandatory approval gates for high-risk operations
- configurable organization policies
- diff, cost and blast-radius preview before approval
- two-person approval for financial and credential actions
- emergency stop and global worker revocation

### 5. Secrets management

The repository relies on locally authenticated CLIs. Production needs short-lived credentials, central secrets management, access logging and strict separation by tenant and environment.

Required capabilities:

- managed secrets store
- workload identity where supported
- short-lived GitHub and cloud tokens
- no reusable production credentials inside worker filesystems
- secret scanning on inputs, outputs, commits and logs
- automatic revocation and rotation workflows

### 6. Observability and operations

Current observability is local file and dashboard based. Production requires structured telemetry and service-level objectives.

Required capabilities:

- structured JSON event logs
- trace and correlation IDs across API, queue and worker
- metrics for queue latency, run duration, success, retry, cost and policy denials
- centralized log ingestion with tenant-safe redaction
- SLOs, alerts, incident runbooks and status communication
- tamper-evident audit log

### 7. Testing and release engineering

Tests currently focus mainly on dashboard status parsing. The autonomous loop, daemon lifecycle, timeout behavior, rollback, rate-limit detection, command construction and platform scripts need dedicated automated coverage.

Required capabilities:

- unit tests for loop state transitions and failure classifications
- integration tests with fake Claude/Codex executables
- end-to-end lifecycle tests in disposable environments
- concurrency and race tests for PID/state handling
- security tests for dashboard and policy enforcement
- dependency, license and secret scanning
- signed releases, SBOM and provenance attestations
- staged deployment and rollback exercises

### 8. Product and user experience

The current user is a technical operator with local shell access. A broader market needs guided onboarding, project templates, transparent permissions, cost controls, approval inboxes, run histories, artifact review, team collaboration and support workflows.

## Partially implemented areas

1. Dashboard is operational but was originally unauthenticated. This branch adds authentication support, loopback-only defaults, guarded remote binding, rate limiting, request-size limits and security headers.
2. Circuit breaking exists, but state is not durable across restarts and has no distributed coordination.
3. Consensus validation exists, but semantic schema validation and versioned migrations do not.
4. Agent safety rules exist, but enforcement remains prompt-based rather than sandbox/policy based.
5. Logging exists, but lacks structured events, redaction guarantees, central storage and trace IDs.
6. Cross-platform scripts exist, but platform behavior is not covered by full lifecycle CI.
7. One finance workflow exists, but there is no general release-quality pipeline for all repository code. This branch adds cross-platform syntax and unit-test CI.

## Market and business opportunities

### Primary market

A self-hosted agent operations platform for technical founders, agencies and internal innovation teams that need persistent AI execution while retaining control over source code and credentials.

### Valuable niches

- autonomous software maintenance for small engineering teams
- managed research and competitive-intelligence workspaces
- agency delivery pods with client-isolated workers
- controlled internal automation for regulated organizations
- private deployment for data-residency-sensitive customers
- runbook automation for DevOps and support teams
- repeatable product-validation factories for venture studios

### Monetization paths

- self-hosted community edition plus paid enterprise control plane
- managed isolated workers billed by active run time and model usage
- organization plans with policy packs, SSO, audit retention and approvals
- vertical workflow packs for research, software maintenance, operations and agencies
- professional services for private-cloud and regulated deployments

### Business risks

- model and infrastructure costs can exceed subscription revenue without hard budgets
- autonomous side effects create liability without approvals and auditability
- dependence on CLI behavior creates compatibility risk
- personality-branded agents may create trademark, endorsement or trust concerns
- broad promises of fully autonomous commercial operation can exceed actual reliability
- public deployment before isolation would expose credentials and customer data

## Production target architecture

1. Web/API control plane with OIDC, organization RBAC and approval inbox.
2. PostgreSQL-backed orchestration service.
3. Durable queue with idempotent run dispatch.
4. Isolated worker manager using rootless containers or microVMs.
5. Tool broker issuing scoped, short-lived credentials.
6. Policy engine evaluating every privileged action.
7. Object storage for artifacts and logs.
8. OpenTelemetry-based metrics, logs and traces.
9. Billing and budget service that enforces hard limits before model calls.
10. Signed release pipeline with SBOM, provenance and rollback.

## Implemented in this hardening branch

- dashboard authentication through bearer or dedicated token header
- loopback-only default binding
- explicit remote-access opt-in requiring a token
- optional trusted-proxy handling
- per-client sliding-window rate limiting
- request-body limits
- security response headers
- health endpoint
- bounded log-tail requests
- dashboard security and rate-limit unit tests
- Linux, macOS and Windows CI for Python, JavaScript, Bash and PowerShell validation

## Remaining launch gates

The repository must not be called high-volume production-ready until the following are implemented and independently validated:

- isolated worker execution
- durable database and queue
- identity, tenancy and RBAC
- policy engine and approval gates
- managed secrets and short-lived credentials
- structured telemetry and audit retention
- billing and cost enforcement
- backup, disaster recovery and failover testing
- penetration testing and threat-model review
- legal, privacy, support and incident-response readiness
