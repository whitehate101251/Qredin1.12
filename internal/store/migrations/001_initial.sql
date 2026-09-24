-- Durable source of truth for the Identity Service control plane.
-- Security-sensitive values are scoped by trust domain and tenant.

CREATE TABLE IF NOT EXISTS qredin_trust_domains (
    trust_domain TEXT PRIMARY KEY,
    environment_id TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('prepared', 'active', 'suspended', 'revoked')),
    revision BIGINT NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS qredin_authorities (
    authority_id TEXT PRIMARY KEY,
    trust_domain TEXT NOT NULL REFERENCES qredin_trust_domains(trust_domain),
    key_id TEXT NOT NULL,
    certificate_der BYTEA NOT NULL,
    lifecycle TEXT NOT NULL CHECK (lifecycle IN ('prepared', 'active', 'old', 'tainted', 'revoked')),
    not_before TIMESTAMPTZ NOT NULL,
    not_after TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (not_after > not_before),
    UNIQUE (trust_domain, key_id)
);

CREATE TABLE IF NOT EXISTS qredin_registrations (
    registration_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    environment_id TEXT NOT NULL,
    trust_domain TEXT NOT NULL REFERENCES qredin_trust_domains(trust_domain),
    workload_spiffe_id TEXT NOT NULL,
    parent_agent_spiffe_id TEXT NOT NULL,
    selectors JSONB NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('active', 'suspended', 'revoked')),
    revision BIGINT NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, environment_id, trust_domain, workload_spiffe_id)
);

CREATE INDEX IF NOT EXISTS qredin_registrations_scope_idx
    ON qredin_registrations(tenant_id, environment_id, trust_domain, status);

CREATE TABLE IF NOT EXISTS qredin_audit_events (
    event_id UUID PRIMARY KEY,
    event_type TEXT NOT NULL,
    tenant_id TEXT,
    environment_id TEXT,
    trust_domain TEXT,
    subject_spiffe_id TEXT,
    decision_id TEXT,
    policy_revision BIGINT,
    payload JSONB NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS qredin_audit_events_scope_idx
    ON qredin_audit_events(tenant_id, environment_id, occurred_at);