-- 001_initial_schema.sql
-- Core tables for threat intel ingestion and ATT&CK technique extraction.

BEGIN;

CREATE TABLE IF NOT EXISTS sources (
    id          SERIAL PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    base_url    TEXT NOT NULL,
    feed_url    TEXT,
    feed_type   TEXT NOT NULL CHECK (feed_type IN ('rss', 'json', 'html_scrape')),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS reports (
    id              SERIAL PRIMARY KEY,
    source_id       INT NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
    url             TEXT NOT NULL UNIQUE,
    title           TEXT NOT NULL,
    published_at    TIMESTAMPTZ,
    ingested_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    raw_html        TEXT,
    extracted_text  TEXT,
    word_count      INT,
    -- Free-form metadata bag for source-specific fields (CVEs for KEV, etc).
    source_metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_reports_source ON reports(source_id);
CREATE INDEX IF NOT EXISTS idx_reports_published ON reports(published_at DESC);
CREATE INDEX IF NOT EXISTS idx_reports_ingested ON reports(ingested_at DESC);

CREATE TABLE IF NOT EXISTS techniques (
    technique_id        TEXT PRIMARY KEY,
    name                TEXT NOT NULL,
    tactic              TEXT,
    description         TEXT,
    is_subtechnique     BOOLEAN NOT NULL DEFAULT FALSE,
    parent_technique    TEXT REFERENCES techniques(technique_id),
    attack_version      TEXT NOT NULL,
    loaded_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_techniques_parent ON techniques(parent_technique);
CREATE INDEX IF NOT EXISTS idx_techniques_tactic ON techniques(tactic);

CREATE TABLE IF NOT EXISTS technique_mentions (
    id                  SERIAL PRIMARY KEY,
    report_id           INT NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
    technique_id        TEXT NOT NULL REFERENCES techniques(technique_id),
    context_snippet     TEXT,
    extraction_method   TEXT NOT NULL CHECK (extraction_method IN ('regex', 'spacy_phrase', 'manual')),
    confidence          REAL NOT NULL CHECK (confidence >= 0.0 AND confidence <= 1.0),
    extracted_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (report_id, technique_id, extraction_method)
);

CREATE INDEX IF NOT EXISTS idx_mentions_report ON technique_mentions(report_id);
CREATE INDEX IF NOT EXISTS idx_mentions_technique ON technique_mentions(technique_id);
CREATE INDEX IF NOT EXISTS idx_mentions_method ON technique_mentions(extraction_method);

CREATE TABLE IF NOT EXISTS actor_mentions (
    id              SERIAL PRIMARY KEY,
    report_id       INT NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
    actor_name      TEXT NOT NULL,
    context_snippet TEXT,
    extracted_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_actor_report ON actor_mentions(report_id);
CREATE INDEX IF NOT EXISTS idx_actor_name ON actor_mentions(actor_name);

COMMIT;
