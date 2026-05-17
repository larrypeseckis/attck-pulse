#!/usr/bin/env python
"""Capture real CISA advisory HTML for use as test fixtures.

CISA's HTML structure changes between site redesigns. Pinning tests against
captured fixtures means the parser tests don't fail when CISA goes down or
changes their layout - they fail only when *our parser* breaks against known
inputs.

Usage:
    # Capture a specific advisory
    python scripts/capture_advisory_fixture.py aa23-352a

    # Capture several at once
    python scripts/capture_advisory_fixture.py aa23-352a aa23-320a aa24-038a

Fixtures are written to tests/fixtures/cisa_{advisory_id}.html
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

import httpx

from threat_intel.config import settings
from threat_intel.logging_setup import configure_logging, get_logger


FIXTURE_DIR = settings.project_root / "tests" / "fixtures"
BASE_URL = "https://www.cisa.gov/news-events/cybersecurity-advisories/"


def capture(advisory_id: str, client: httpx.Client) -> Path | None:
    """Fetch one advisory and save it to fixtures. Returns path or None on failure."""
    logger = get_logger(__name__)
    advisory_id_lower = advisory_id.lower().strip()
    url = BASE_URL + advisory_id_lower

    logger.info("Fetching %s", url)
    try:
        response = client.get(url)
        response.raise_for_status()
    except httpx.HTTPStatusError as err:
        logger.error("HTTP %d for %s", err.response.status_code, url)
        return None
    except httpx.HTTPError:
        logger.exception("Network error for %s", url)
        return None

    fixture_path = FIXTURE_DIR / f"cisa_{advisory_id_lower}.html"
    fixture_path.write_text(response.text, encoding="utf-8")
    logger.info("Saved %s (%d bytes)", fixture_path, len(response.text))
    return fixture_path


def main() -> int:
    configure_logging()
    logger = get_logger(__name__)

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "advisory_ids",
        nargs="+",
        help="One or more advisory IDs (e.g., aa23-352a aa23-320a)",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=2.0,
        help="Seconds between requests (default: 2.0)",
    )
    args = parser.parse_args()

    FIXTURE_DIR.mkdir(parents=True, exist_ok=True)

    captured = 0
    failed = 0

    with httpx.Client(
        headers={"User-Agent": settings.http_user_agent},
        timeout=settings.http_timeout_seconds,
        follow_redirects=True,
    ) as client:
        for i, advisory_id in enumerate(args.advisory_ids):
            if i > 0:
                time.sleep(args.delay)
            result = capture(advisory_id, client)
            if result is not None:
                captured += 1
            else:
                failed += 1

    logger.info("Done: %d captured, %d failed", captured, failed)
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
