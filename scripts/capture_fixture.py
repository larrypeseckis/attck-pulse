#!/usr/bin/env python
"""Capture HTML fixtures from any source for use in parser tests.

Pins tests against captured HTML so parser tests fail only when *our parser*
breaks against known inputs, not when the source goes down or redesigns.

Two input modes:

  1. Full URL:
       python scripts/capture_fixture.py \\
           https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-352a \\
           https://thedfirreport.com/2025/12/17/cats-got-your-files-lynx-ransomware/

  2. CISA shorthand (preserved for backwards compat with capture_advisory_fixture.py):
       python scripts/capture_fixture.py --cisa aa23-352a aa23-320a

Output filenames are derived from the URL path. Fixtures land in tests/fixtures/.
"""

from __future__ import annotations

import argparse
import re
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

import httpx

from threat_intel.config import settings
from threat_intel.logging_setup import configure_logging, get_logger

FIXTURE_DIR = settings.project_root / "tests" / "fixtures"
CISA_BASE = "https://www.cisa.gov/news-events/cybersecurity-advisories/"


def fixture_name_from_url(url: str) -> str:
    """Derive a clean fixture filename from a URL.

    Examples:
      .../cybersecurity-advisories/aa23-352a -> cisa_aa23-352a.html
      .../2025/12/17/cats-got-your-files-lynx-ransomware/ -> dfir_cats-got-your-files-lynx-ransomware.html
      .../security/blog/2024/01/15/some-post/ -> microsoft_some-post.html
    """
    parsed = urlparse(url)
    host = parsed.netloc.lower()
    path = parsed.path.rstrip("/")

    # Source prefix based on hostname
    if "cisa.gov" in host:
        prefix = "cisa"
    elif "thedfirreport.com" in host:
        prefix = "dfir"
    elif "microsoft.com" in host:
        prefix = "microsoft"
    else:
        # Use the hostname's first label as a generic prefix
        prefix = host.split(".")[0]

    # Slug: last meaningful path segment
    segments = [seg for seg in path.split("/") if seg]
    slug = segments[-1] if segments else "index"

    # Sanitize: lowercase, replace anything weird with hyphen
    slug = re.sub(r"[^a-z0-9._-]+", "-", slug.lower()).strip("-")

    return f"{prefix}_{slug}.html"


def capture(url: str, client: httpx.Client) -> Path | None:
    """Fetch one URL and save it to fixtures. Returns path or None on failure."""
    logger = get_logger(__name__)

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

    fixture_path = FIXTURE_DIR / fixture_name_from_url(url)
    fixture_path.write_text(response.text, encoding="utf-8")
    logger.info("Saved %s (%d bytes)", fixture_path, len(response.text))
    return fixture_path


def expand_cisa_shorthand(advisory_ids: list[str]) -> list[str]:
    """Convert CISA advisory IDs (e.g. 'aa23-352a') into full URLs."""
    return [CISA_BASE + aid.lower().strip() for aid in advisory_ids]


def main() -> int:
    configure_logging()
    logger = get_logger(__name__)

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "urls",
        nargs="*",
        help="One or more full URLs to fetch",
    )
    parser.add_argument(
        "--cisa",
        nargs="+",
        default=[],
        metavar="AA-ID",
        help="CISA advisory IDs to fetch (e.g., aa23-352a)",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=2.0,
        help="Seconds between requests (default: 2.0)",
    )
    args = parser.parse_args()

    targets: list[str] = list(args.urls) + expand_cisa_shorthand(args.cisa)
    if not targets:
        parser.error("Provide at least one URL or --cisa shorthand")

    FIXTURE_DIR.mkdir(parents=True, exist_ok=True)

    captured = 0
    failed = 0

    with httpx.Client(
        headers={"User-Agent": settings.http_user_agent},
        timeout=settings.http_timeout_seconds,
        follow_redirects=True,
    ) as client:
        for i, url in enumerate(targets):
            if i > 0:
                time.sleep(args.delay)
            result = capture(url, client)
            if result is not None:
                captured += 1
            else:
                failed += 1

    logger.info("Done: %d captured, %d failed", captured, failed)
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
