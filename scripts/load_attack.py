#!/usr/bin/env python
"""Download the ATT&CK STIX bundle and load techniques into the database.

Idempotent. Re-running upserts existing rows with current bundle contents.

Usage:
    python scripts/load_attack.py
"""

from __future__ import annotations

import sys

from threat_intel.attack.loader import run
from threat_intel.logging_setup import configure_logging, get_logger


def main() -> int:
    configure_logging()
    logger = get_logger(__name__)

    try:
        run()
    except Exception:
        logger.exception("ATT&CK load failed")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
