-- 004_dfir_support.sql
-- Add DFIR Report as a recognized extraction source.
-- The new method 'dfir_attack_block' is used for techniques pulled from
-- the structured MITRE ATT&CK code block at the end of every DFIR report.

BEGIN;

ALTER TABLE technique_mentions
    DROP CONSTRAINT IF EXISTS technique_mentions_extraction_method_check;

ALTER TABLE technique_mentions
    ADD CONSTRAINT technique_mentions_extraction_method_check
    CHECK (extraction_method IN (
        'regex',
        'spacy_phrase',
        'manual',
        'cisa_attack_table',
        'dfir_attack_block'
    ));

COMMIT;
