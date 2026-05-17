-- 003_advisory_support.sql
-- Add support for differentiating report types and capturing CISA's own
-- ATT&CK table mappings as a higher-confidence extraction source.

BEGIN;

-- Tag each report with a type so analytical queries can filter cleanly.
ALTER TABLE reports ADD COLUMN IF NOT EXISTS report_type TEXT;

-- Backfill existing KEV records.
UPDATE reports
SET report_type = 'cisa_kev'
WHERE source_id = (
    SELECT id FROM sources
    WHERE name = 'CISA Known Exploited Vulnerabilities'
)
AND report_type IS NULL;

CREATE INDEX IF NOT EXISTS idx_reports_type ON reports(report_type);

-- Extend extraction_method to include CISA's own structured ATT&CK tables.
ALTER TABLE technique_mentions
    DROP CONSTRAINT IF EXISTS technique_mentions_extraction_method_check;

ALTER TABLE technique_mentions
    ADD CONSTRAINT technique_mentions_extraction_method_check
    CHECK (extraction_method IN ('regex', 'spacy_phrase', 'manual', 'cisa_attack_table'));

COMMIT;
