ALTER TABLE qredin_authorities
    ADD COLUMN IF NOT EXISTS revision BIGINT NOT NULL DEFAULT 1;

ALTER TABLE qredin_authorities
    DROP CONSTRAINT IF EXISTS qredin_authorities_revision_positive;

ALTER TABLE qredin_authorities
    ADD CONSTRAINT qredin_authorities_revision_positive CHECK (revision > 0);