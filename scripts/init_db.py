#!/usr/bin/env python
"""Initialize the database by running all migrations in order.

Idempotent. Safe to re-run.

Usage:
    python scripts/init_db.py
"""

from __future__ import annotations

import sys

from threat_intel.db import run_migration
from threat_intel.logging_setup import configure_logging, get_logger


MIGRATIONS = [
    "001_initial_schema.sql",
    "002_pipeline_runs.sql",
    "003_advisory_support.sql",
]


def main() -> int:
    configure_logging()
    logger = get_logger(__name__)

    for migration in MIGRATIONS:
        try:
            run_migration(migration)
        except Exception:
            logger.exception("Migration failed: %s", migration)
            return 1

    logger.info("Database initialized: %d migrations applied", len(MIGRATIONS))
    return 0


if __name__ == "__main__":
    sys.exit(main())
