CREATE TABLE IF NOT EXISTS qredin_registration_approvals (
    registration_id TEXT NOT NULL REFERENCES qredin_registrations(registration_id),
    approver_id TEXT NOT NULL,
    approved_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (registration_id, approver_id)
);