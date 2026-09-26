-- Durable approval workflow for policy versions.

CREATE TABLE IF NOT EXISTS qredin_policy_approvals (
    policy_id TEXT NOT NULL,
    version BIGINT NOT NULL,
    approver_spiffe_id TEXT NOT NULL,
    approved_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (policy_id, version, approver_spiffe_id)
);

CREATE INDEX IF NOT EXISTS qredin_policy_approvals_idx
    ON qredin_policy_approvals(policy_id, version, approved_at);