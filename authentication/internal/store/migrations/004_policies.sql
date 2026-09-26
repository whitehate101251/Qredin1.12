-- Durable policy store with approval workflow and lifecycle.

CREATE TABLE IF NOT EXISTS qredin_policies (
    id TEXT NOT NULL,
    version BIGINT NOT NULL,
    tenant_id TEXT NOT NULL,
    environment_id TEXT NOT NULL,
    trust_domain TEXT NOT NULL,
    subject_spiffe_id TEXT,
    rules JSONB NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('draft', 'pending', 'active', 'suspended', 'revoked')),
    approvers JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    activated_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    description TEXT,
    PRIMARY KEY (id, version)
);

CREATE INDEX IF NOT EXISTS qredin_policies_scope_status_idx
    ON qredin_policies(tenant_id, environment_id, trust_domain, status);

CREATE INDEX IF NOT EXISTS qredin_policies_active_idx
    ON qredin_policies(tenant_id, environment_id, trust_domain, status, version DESC);