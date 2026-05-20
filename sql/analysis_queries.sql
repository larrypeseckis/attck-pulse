-- analysis_queries.sql
-- Standalone versions of the queries used in notebooks/01_attck_pulse_overview.py
-- Useful for ad-hoc psql exploration without firing up Jupyter.
--
-- Usage:
--   psql -d threat_intel -f sql/analysis_queries.sql
-- Or run individual queries by copy-paste.

-- =============================================================================
-- 1. Dataset summary - confirms current scope before any analytical claims.
-- =============================================================================

SELECT
    r.report_type,
    COUNT(DISTINCT r.id) AS reports,
    COUNT(DISTINCT r.id) FILTER (WHERE r.id IN (
        SELECT report_id FROM technique_mentions
    )) AS reports_with_mentions,
    COALESCE((
        SELECT COUNT(*)
        FROM technique_mentions tm
        JOIN reports r2 ON r2.id = tm.report_id
        WHERE r2.report_type = r.report_type
    ), 0) AS mentions,
    COALESCE((
        SELECT COUNT(DISTINCT technique_id)
        FROM technique_mentions tm
        JOIN reports r2 ON r2.id = tm.report_id
        WHERE r2.report_type = r.report_type
    ), 0) AS unique_techniques
FROM reports r
GROUP BY r.report_type
ORDER BY r.report_type;

-- =============================================================================
-- 2. Cross-source attestation (Post 2).
--    Techniques cited in BOTH a CISA AA advisory AND a DFIR report.
-- =============================================================================

WITH per_source AS (
    SELECT
        tm.technique_id,
        CASE
            WHEN r.report_type = 'cisa_advisory_aa' THEN 'cisa'
            WHEN r.report_type LIKE 'dfir_%' THEN 'dfir'
        END AS source_group,
        COUNT(DISTINCT tm.report_id) AS reports_citing
    FROM technique_mentions tm
    JOIN reports r ON r.id = tm.report_id
    WHERE r.report_type IN ('cisa_advisory_aa', 'dfir_full_report', 'dfir_flash_alert')
    GROUP BY tm.technique_id, source_group
),
aggregated AS (
    SELECT
        technique_id,
        COUNT(DISTINCT source_group) AS distinct_source_groups,
        COALESCE(SUM(reports_citing) FILTER (WHERE source_group = 'cisa'), 0) AS cisa_reports,
        COALESCE(SUM(reports_citing) FILTER (WHERE source_group = 'dfir'), 0) AS dfir_reports,
        COALESCE(SUM(reports_citing), 0) AS total_reports
    FROM per_source
    GROUP BY technique_id
)
SELECT
    a.technique_id,
    t.name AS technique_name,
    t.tactic,
    a.cisa_reports,
    a.dfir_reports,
    a.total_reports
FROM aggregated a
JOIN techniques t ON t.technique_id = a.technique_id
WHERE a.distinct_source_groups >= 2
ORDER BY a.total_reports DESC, a.cisa_reports DESC
LIMIT 25;

-- =============================================================================
-- 3. Tactic distribution (Post 3).
-- =============================================================================

SELECT
    t.tactic,
    COUNT(*) AS mentions,
    COUNT(DISTINCT tm.technique_id) AS unique_techniques,
    COUNT(DISTINCT tm.report_id) AS reports
FROM technique_mentions tm
JOIN techniques t ON t.technique_id = tm.technique_id
JOIN reports r ON r.id = tm.report_id
WHERE r.report_type IN ('cisa_advisory_aa', 'dfir_full_report', 'dfir_flash_alert')
  AND t.tactic IS NOT NULL
GROUP BY t.tactic
ORDER BY mentions DESC;

-- =============================================================================
-- 4. Per-report yield (Post 3 bimodal DFIR finding).
-- =============================================================================

SELECT
    r.id,
    LEFT(r.title, 60) AS title,
    r.report_type,
    COALESCE(COUNT(tm.id), 0) AS mentions
FROM reports r
LEFT JOIN technique_mentions tm ON tm.report_id = r.id
WHERE r.report_type IN ('cisa_advisory_aa', 'dfir_full_report', 'dfir_flash_alert')
GROUP BY r.id, r.title, r.report_type
ORDER BY r.report_type, mentions DESC;

-- =============================================================================
-- 5. Extraction method comparison (validates Post 1's methodology claims).
-- =============================================================================

SELECT
    r.report_type,
    tm.extraction_method,
    COUNT(*) AS mentions,
    COUNT(DISTINCT tm.technique_id) AS unique_techniques
FROM technique_mentions tm
JOIN reports r ON r.id = tm.report_id
WHERE r.report_type IN ('cisa_advisory_aa', 'dfir_full_report', 'dfir_flash_alert')
GROUP BY r.report_type, tm.extraction_method
ORDER BY r.report_type, tm.extraction_method;

-- =============================================================================
-- 6. Source-uniqueness summary (techniques cited in only one source vs both).
-- =============================================================================

WITH per_source AS (
    SELECT
        tm.technique_id,
        CASE
            WHEN r.report_type = 'cisa_advisory_aa' THEN 'cisa'
            WHEN r.report_type LIKE 'dfir_%' THEN 'dfir'
        END AS source_group,
        COUNT(DISTINCT tm.report_id) AS reports_citing
    FROM technique_mentions tm
    JOIN reports r ON r.id = tm.report_id
    WHERE r.report_type IN ('cisa_advisory_aa', 'dfir_full_report', 'dfir_flash_alert')
    GROUP BY tm.technique_id, source_group
),
classified AS (
    SELECT
        technique_id,
        COUNT(DISTINCT source_group) AS distinct_source_groups,
        STRING_AGG(source_group, ',' ORDER BY source_group) AS sources,
        SUM(reports_citing) AS total_reports
    FROM per_source
    GROUP BY technique_id
)
SELECT
    c.sources AS appears_in,
    COUNT(*) AS technique_count,
    SUM(c.total_reports) AS total_report_mentions
FROM classified c
GROUP BY c.sources
ORDER BY technique_count DESC;
