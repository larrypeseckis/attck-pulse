"""CISA Known Exploited Vulnerabilities (KEV) ingester.

Source: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
Feed:   https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

The KEV catalog is a curated list of vulnerabilities known to be exploited in
the wild. Each entry includes CVE, vendor/product, vulnerability name,
required action, due date, and a short description. ATT&CK technique IDs are
sometimes present in the description, but most extraction value comes from
correlating CVEs to downstream sources that *do* discuss techniques.

Why include it anyway in v1:
1. Authoritative US-government source. Sets a strong baseline.
2. JSON-formatted, no scraping required. Smallest implementation risk.
3. Lets us build the "what's actively exploited right now" lens that downstream
   analyses (P2, P3) can join against.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any

import yaml
from dateutil import parser as dateparser

from threat_intel.config import settings
from threat_intel.ingesters.base import BaseIngester, NormalizedReport
from threat_intel.logging_setup import get_logger

logger = get_logger(__name__)


class CisaKevIngester(BaseIngester):
    """Ingester for the CISA Known Exploited Vulnerabilities catalog."""

    source_key = "cisa_kev"

    def __init__(self):
        super().__init__()
        config = self._load_source_config()
        self.source_name = config["name"]
        self.source_base_url = config["base_url"]
        self.source_feed_url = config["feed_url"]
        self.source_feed_type = config["feed_type"]

    @staticmethod
    def _load_source_config() -> dict[str, Any]:
        sources_file = settings.project_root / "config" / "sources.yaml"
        with sources_file.open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        return data["sources"]["cisa_kev"]

    def fetch_reports(self) -> Iterator[NormalizedReport]:
        """Pull the KEV catalog, yield one NormalizedReport per vulnerability."""
        assert self.source_feed_url is not None
        response = self.http_get(self.source_feed_url)
        catalog = response.json()

        catalog_version = catalog.get("catalogVersion", "unknown")
        date_released = catalog.get("dateReleased", "unknown")
        vuln_count = catalog.get("count", len(catalog.get("vulnerabilities", [])))

        logger.info(
            "CISA KEV catalog loaded: version=%s released=%s count=%d",
            catalog_version,
            date_released,
            vuln_count,
        )

        for vuln in catalog.get("vulnerabilities", []):
            try:
                yield self._normalize_vulnerability(vuln, catalog_version)
            except Exception:
                logger.exception(
                    "Failed to normalize KEV entry: %s",
                    vuln.get("cveID", "<unknown>"),
                )
                continue

    @staticmethod
    def _normalize_vulnerability(
        vuln: dict[str, Any],
        catalog_version: str,
    ) -> NormalizedReport:
        """Convert a KEV catalog entry to a NormalizedReport."""
        cve_id: str = vuln["cveID"]
        vendor: str = vuln.get("vendorProject", "")
        product: str = vuln.get("product", "")
        vuln_name: str = vuln.get("vulnerabilityName", "")
        description: str = vuln.get("shortDescription", "")
        required_action: str = vuln.get("requiredAction", "")
        date_added: str | None = vuln.get("dateAdded")
        due_date: str | None = vuln.get("dueDate")
        known_ransomware: str = vuln.get("knownRansomwareCampaignUse", "Unknown")
        notes: str = vuln.get("notes", "")
        cwes: list[str] = vuln.get("cwes", [])

        url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        title = f"{cve_id}: {vendor} {product} - {vuln_name}".strip()

        # Build the text body that the regex extractor will scan.
        # Concatenate fields rather than relying on description alone.
        extracted_text = "\n\n".join(
            part
            for part in [
                f"CVE: {cve_id}",
                f"Vendor: {vendor}",
                f"Product: {product}",
                f"Vulnerability: {vuln_name}",
                f"Description: {description}",
                f"Required Action: {required_action}",
                f"Known Ransomware Use: {known_ransomware}",
                f"Notes: {notes}" if notes else "",
            ]
            if part
        )

        published_at = _parse_date(date_added)

        metadata = {
            "cve_id": cve_id,
            "vendor": vendor,
            "product": product,
            "date_added": date_added,
            "due_date": due_date,
            "known_ransomware_use": known_ransomware,
            "cwes": cwes,
            "catalog_version": catalog_version,
            "notes_url": notes if notes.startswith("http") else None,
        }

        return NormalizedReport(
            url=url,
            title=title,
            published_at=published_at,
            raw_html=None,  # KEV is JSON, no HTML to preserve
            extracted_text=extracted_text,
            report_type="cisa_kev",
            source_metadata=metadata,
        )


def _parse_date(value: str | None) -> datetime | None:
    """Parse a YYYY-MM-DD string to a tz-aware datetime, or return None."""
    if not value:
        return None
    try:
        parsed = dateparser.parse(value)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
        return parsed
    except (ValueError, TypeError):
        logger.warning("Could not parse date: %r", value)
        return None
