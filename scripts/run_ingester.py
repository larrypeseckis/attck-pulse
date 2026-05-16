#!/usr/bin/env python
"""Run a single ingester by name.

Usage:
    python scripts/run_ingester.py cisa_kev
    python scripts/run_ingester.py cisa_advisories
"""

from __future__ import annotations

import argparse
import sys

from threat_intel.ingesters.base import BaseIngester
from threat_intel.ingesters.cisa_kev import CisaKevIngester
from threat_intel.logging_setup import configure_logging, get_logger


# Registry of available ingesters
INGESTERS: dict[str, type[BaseIngester]] = {
    "cisa_kev": CisaKevIngester,
    # Future: cisa_advisories, microsoft_security_blog, dfir_report
}


def main() -> int:
    configure_logging()
    logger = get_logger(__name__)

    parser = argparse.ArgumentParser(description="Run a threat intel ingester")
    parser.add_argument(
        "ingester",
        choices=sorted(INGESTERS.keys()),
        help="Name of the ingester to run",
    )
    args = parser.parse_args()

    ingester_class = INGESTERS[args.ingester]
    logger.info("Dispatching to ingester: %s", args.ingester)

    try:
        instance = ingester_class()
        instance.run()
    except Exception:
        logger.exception("Ingester run failed: %s", args.ingester)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
