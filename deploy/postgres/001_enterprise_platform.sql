BEGIN;

CREATE SCHEMA IF NOT EXISTS app;

CREATE OR REPLACE FUNCTION app.current_organization_id()
RETURNS uuid
LANGUAGE sql
STABLE
AS $$
    SELECT NULLIF(current_setting('app.organization_id', true), '')::uuid
$$;

CREATE OR REPLACE FUNCTION app.current_user_id()
RETURNS uuid
LANGUAGE sql
STABLE
AS $$
    SELECT NULLIF(current_setting('app.user_id', true), '')::uuid
$$;

CREATE TABLE IF NOT EXISTS organizations (
    id uuid PRIMARY KEY,
    name text NOT NULL,
    slug text NOT NULL UNIQUE,
    status text NOT NULL CHECK (status IN ('active','suspended','archived')),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS users (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    email citext NOT NULL,
    display_name text NOT NULL,
    user_type text NOT NULL CHECK (user_type IN ('human','ai','service')),
    status text NOT NULL CHECK (status IN ('active','suspended','disabled')),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (organization_id, email)
);

CREATE EXTENSION IF NOT EXISTS citext;

CREATE TABLE IF NOT EXISTS identity_sessions (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_prefix text NOT NULL UNIQUE,
    token_salt bytea NOT NULL,
    token_hash bytea NOT NULL,
    auth_method text NOT NULL CHECK (auth_method IN ('passwordless','oidc','saml','service')),
    assurance_level smallint NOT NULL CHECK (assurance_level BETWEEN 1 AND 3),
    ip_address inet,
    user_agent text,
    created_at timestamptz NOT NULL,
    last_seen_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    absolute_expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    revoked_reason text,
    rotated_from_session_id uuid REFERENCES identity_sessions(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS billing_plans (
    id uuid PRIMARY KEY,
    code text NOT NULL UNIQUE,
    name text NOT NULL,
    currency char(3) NOT NULL,
    recurring_amount_minor bigint NOT NULL CHECK (recurring_amount_minor >= 0),
    billing_interval text NOT NULL CHECK (billing_interval IN ('month','year')),
    status text NOT NULL CHECK (status IN ('active','retired')),
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS plan_entitlements (
    plan_id uuid NOT NULL REFERENCES billing_plans(id) ON DELETE CASCADE,
    entitlement_key text NOT NULL,
    enabled boolean NOT NULL,
    quota_limit bigint CHECK (quota_limit IS NULL OR quota_limit >= 0),
    quota_period text CHECK (quota_period IN ('day','month','year') OR quota_period IS NULL),
    PRIMARY KEY (plan_id, entitlement_key)
);

CREATE TABLE IF NOT EXISTS subscriptions (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    plan_id uuid NOT NULL REFERENCES billing_plans(id) ON DELETE RESTRICT,
    status text NOT NULL CHECK (status IN ('trialing','active','past_due','paused','cancelled','expired')),
    period_start timestamptz NOT NULL,
    period_end timestamptz NOT NULL,
    cancel_at_period_end boolean NOT NULL DEFAULT false,
    provider text,
    provider_customer_id text,
    provider_subscription_id text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CHECK (period_end > period_start),
    UNIQUE (provider, provider_subscription_id)
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_active_subscription_per_org
    ON subscriptions(organization_id)
    WHERE status IN ('trialing','active','past_due','paused');

CREATE TABLE IF NOT EXISTS usage_events (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    subscription_id uuid REFERENCES subscriptions(id) ON DELETE SET NULL,
    event_key text NOT NULL,
    meter_key text NOT NULL,
    quantity bigint NOT NULL CHECK (quantity > 0),
    amount_minor bigint NOT NULL DEFAULT 0 CHECK (amount_minor >= 0),
    occurred_at timestamptz NOT NULL,
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (organization_id, event_key)
);

CREATE TABLE IF NOT EXISTS entitlement_overrides (
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    entitlement_key text NOT NULL,
    enabled boolean NOT NULL,
    quota_limit bigint CHECK (quota_limit IS NULL OR quota_limit >= 0),
    expires_at timestamptz,
    reason text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, entitlement_key)
);

CREATE TABLE IF NOT EXISTS operational_events (
    id bigserial PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    event_type text NOT NULL,
    severity text NOT NULL CHECK (severity IN ('debug','info','warning','error','critical')),
    correlation_id text,
    payload jsonb NOT NULL DEFAULT '{}'::jsonb,
    occurred_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_usage_meter_period
    ON usage_events(organization_id, meter_key, occurred_at);
CREATE INDEX IF NOT EXISTS idx_sessions_user
    ON identity_sessions(organization_id, user_id, revoked_at, expires_at);
CREATE INDEX IF NOT EXISTS idx_operational_events_org_time
    ON operational_events(organization_id, occurred_at DESC);

ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE users FORCE ROW LEVEL SECURITY;
ALTER TABLE identity_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity_sessions FORCE ROW LEVEL SECURITY;
ALTER TABLE subscriptions ENABLE ROW LEVEL SECURITY;
ALTER TABLE subscriptions FORCE ROW LEVEL SECURITY;
ALTER TABLE usage_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE usage_events FORCE ROW LEVEL SECURITY;
ALTER TABLE entitlement_overrides ENABLE ROW LEVEL SECURITY;
ALTER TABLE entitlement_overrides FORCE ROW LEVEL SECURITY;
ALTER TABLE operational_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE operational_events FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS users_tenant_isolation ON users;
CREATE POLICY users_tenant_isolation ON users
    USING (organization_id = app.current_organization_id())
    WITH CHECK (organization_id = app.current_organization_id());

DROP POLICY IF EXISTS sessions_tenant_isolation ON identity_sessions;
CREATE POLICY sessions_tenant_isolation ON identity_sessions
    USING (organization_id = app.current_organization_id())
    WITH CHECK (organization_id = app.current_organization_id());

DROP POLICY IF EXISTS subscriptions_tenant_isolation ON subscriptions;
CREATE POLICY subscriptions_tenant_isolation ON subscriptions
    USING (organization_id = app.current_organization_id())
    WITH CHECK (organization_id = app.current_organization_id());

DROP POLICY IF EXISTS usage_tenant_isolation ON usage_events;
CREATE POLICY usage_tenant_isolation ON usage_events
    USING (organization_id = app.current_organization_id())
    WITH CHECK (organization_id = app.current_organization_id());

DROP POLICY IF EXISTS entitlement_overrides_tenant_isolation ON entitlement_overrides;
CREATE POLICY entitlement_overrides_tenant_isolation ON entitlement_overrides
    USING (organization_id = app.current_organization_id())
    WITH CHECK (organization_id = app.current_organization_id());

DROP POLICY IF EXISTS operational_events_tenant_isolation ON operational_events;
CREATE POLICY operational_events_tenant_isolation ON operational_events
    USING (organization_id = app.current_organization_id())
    WITH CHECK (organization_id = app.current_organization_id());

COMMIT;
