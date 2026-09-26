-- Add correlation and trace IDs to audit events for decision enforcement tracing.

ALTER TABLE qredin_audit_events
    ADD COLUMN IF NOT EXISTS trace_id TEXT,
    ADD COLUMN IF NOT EXISTS correlation_id TEXT;