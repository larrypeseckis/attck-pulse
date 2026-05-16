-- 002_pipeline_runs.sql
-- Track every ingester invocation so silent cron failures surface.

BEGIN;

CREATE TABLE IF NOT EXISTS pipeline_runs (
    id              SERIAL PRIMARY KEY,
    ingester_name   TEXT NOT NULL,
    started_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    finished_at     TIMESTAMPTZ,
    status          TEXT NOT NULL CHECK (status IN ('running', 'success', 'failure', 'partial')),
    records_seen    INT NOT NULL DEFAULT 0,
    records_new     INT NOT NULL DEFAULT 0,
    records_updated INT NOT NULL DEFAULT 0,
    error_message   TEXT,
    run_metadata    JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_runs_ingester ON pipeline_runs(ingester_name, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_runs_status ON pipeline_runs(status, started_at DESC);

-- Convenience view: last run per ingester
CREATE OR REPLACE VIEW v_last_run_per_ingester AS
SELECT DISTINCT ON (ingester_name)
    ingester_name,
    started_at,
    finished_at,
    status,
    records_seen,
    records_new,
    records_updated,
    error_message
FROM pipeline_runs
ORDER BY ingester_name, started_at DESC;

COMMIT;
