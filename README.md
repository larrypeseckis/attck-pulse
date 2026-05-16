# attck-pulse

A pipeline that ingests public threat intelligence reports, extracts MITRE ATT&CK technique references, and produces queryable trend analysis.

## What this is

Public threat intel reports (CISA advisories, vendor blogs, incident writeups) mention ATT&CK techniques constantly, but the mentions are scattered across hundreds of articles in unstructured form. This project pulls them into a single relational dataset so you can ask questions like:

- Which techniques are spiking in the last 90 days?
- Which sources cover which tactics?
- What techniques co-occur in reports about a given threat actor?

## What this is not

Not a replacement for commercial threat intel platforms. Not a real-time alerting system. Not an attribution engine. This is an analyst tool for trend analysis on public data.

## Status

v1 in development. Current scope:

- CISA Known Exploited Vulnerabilities catalog
- CISA Cybersecurity Advisories
- Microsoft Security Blog
- The DFIR Report

## Quickstart

Requires Python 3.12+ and PostgreSQL 16+.

```bash
# 1. Clone and enter
git clone <your-fork-url> attck-pulse
cd attck-pulse

# 2. Set up environment (using uv; conda works too)
uv venv
source .venv/bin/activate
uv pip install -e ".[dev]"

# 3. Configure
cp .env.example .env
# edit .env with your Postgres connection details

# 4. Initialize database
python scripts/init_db.py

# 5. Load MITRE ATT&CK techniques
python scripts/load_attack.py

# 6. Run first ingester
python scripts/run_ingester.py cisa_kev

# 7. Open notebook for analysis
jupyter lab notebooks/
```

## Architecture

```
┌─────────────────┐
│ Public sources  │  CISA KEV, CISA advisories, MS Security, DFIR Report
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│   Ingesters     │  Source-specific scrapers, normalize to common Report shape
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│   PostgreSQL    │  reports, technique_mentions, techniques, actor_mentions
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│   Extractors    │  Regex (T-numbers) + spaCy NER (technique names)
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│    Analysis     │  Jupyter notebooks, SQL views, ad-hoc queries
└─────────────────┘
```

## Operational notes

- Ingesters are idempotent. Re-running won't create duplicates (URL is the dedup key).
- All pipeline runs log to `pipeline_runs` table. Query this to verify the scheduler is alive.
- Regex extraction runs synchronously during ingest. spaCy extraction runs as a separate batch job.
- ATT&CK STIX bundle is pinned to a specific version (see `config/sources.yaml`). Bump deliberately.

## Methodology

See [METHODOLOGY.md](METHODOLOGY.md) for extraction approach, precision/recall validation, and known limitations.

## License

MIT
