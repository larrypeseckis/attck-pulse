"""The DFIR Report ingester.

Source: https://thedfirreport.com
Feed:   https://thedfirreport.com/feed/

Every DFIR Report public writeup is an intrusion case study that ends with a
structured `## MITRE ATT&CK` section. The section is rendered as a heading
followed by a code/preformatted block listing techniques in one of these formats:

    Technique Name - T####
    Technique Name - T####.###
    T#### - Technique Name      (less common; handled)

The ingester parses that closing block as the structured high-confidence source
('dfir_attack_block'), then strips the block from extracted_text so the base
regex extractor does not double-count its contents. Other content sections
(Detections, Indicators, Diamond Model, tactical narrative) are preserved in
extracted_text — they contain useful inline T-number references and the regex
extractor's word-boundary anchoring protects against hash/UUID false positives.

Subtype detection: titles prefixed with "Flash Alert:" map to
report_type='dfir_flash_alert'. All others map to 'dfir_full_report'.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any

import feedparser
import httpx
import yaml
from bs4 import BeautifulSoup, NavigableString, Tag
from dateutil import parser as dateparser

from threat_intel.config import settings
from threat_intel.ingesters.base import (
    AttackTableMention,
    BaseIngester,
    NormalizedReport,
)
from threat_intel.logging_setup import get_logger

logger = get_logger(__name__)


# Technique IDs as they appear in DFIR's MITRE ATT&CK block.
TECHNIQUE_ID_PATTERN = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

# Snippet window for ATT&CK block extractions.
BLOCK_SNIPPET_RADIUS = 120

# Title prefix identifying a Flash Alert subtype.
FLASH_ALERT_PREFIX = "flash alert:"

# Heading texts (lowercased, normalized) that mark the MITRE ATT&CK block.
ATTACK_HEADING_TEXTS = {"mitre att&ck", "mitre attack", "mitre att&ck mapping"}


class DfirReportIngester(BaseIngester):
    """Ingester for The DFIR Report public reports."""

    source_key = "dfir_report"
    inter_request_delay_seconds = 1.0
    attack_mention_method = "dfir_attack_block"

    def __init__(self) -> None:
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
        return data["sources"]["dfir_report"]

    # Main fetch loop

    def fetch_reports(self) -> Iterator[NormalizedReport]:
        assert self.source_feed_url is not None

        logger.info("Fetching DFIR Report RSS feed: %s", self.source_feed_url)
        self.polite_delay()
        feed_response = self.http_get(self.source_feed_url)
        feed = feedparser.parse(feed_response.text)

        if feed.bozo:
            logger.warning(
                "RSS feed parsed with errors: %s",
                getattr(feed, "bozo_exception", "unknown"),
            )

        logger.info("Feed contained %d entries", len(feed.entries))

        for entry in feed.entries:
            url = entry.get("link")
            if not url:
                continue

            try:
                self.polite_delay()
                page_response = self.http_get(url)
            except httpx.HTTPStatusError as err:
                status = err.response.status_code
                if status in (403, 404, 410, 451):
                    logger.warning("Skipping %s (permanent %d)", url, status)
                    continue
                logger.exception("Unexpected HTTP error fetching %s", url)
                continue
            except httpx.HTTPError:
                logger.exception("Network error fetching %s", url)
                continue

            try:
                yield self._parse_report(
                    url=url,
                    rss_title=entry.get("title", ""),
                    rss_published=entry.get("published", ""),
                    rss_summary=entry.get("summary", ""),
                    html=page_response.text,
                )
            except Exception:
                logger.exception("Failed to parse report: %s", url)
                continue

    # Parsing

    def _parse_report(
        self,
        *,
        url: str,
        rss_title: str,
        rss_published: str,
        rss_summary: str,
        html: str,
    ) -> NormalizedReport:
        """Parse a single DFIR report and produce a NormalizedReport."""
        soup = BeautifulSoup(html, "lxml")

        # Extract the ATT&CK block FIRST, while soup is intact, so we have its
        # raw text for the structured extractor.
        attack_block_text = self._extract_attack_block_text(soup)
        attack_mentions = self._extract_block_mentions(attack_block_text)

        # Strip the ATT&CK block from soup so it doesn't leak into body text.
        self._remove_attack_block(soup)

        body_text = self._extract_body_text(soup) or rss_summary

        title = self._clean_title(soup) or rss_title or url
        report_type = self._detect_report_type(title)
        published_at = self._parse_date(rss_published)

        metadata = {
            "attack_block_mention_count": len(attack_mentions),
            "rss_title": rss_title,
            "rss_summary": rss_summary,
            "has_attack_block": bool(attack_mentions),
        }

        return NormalizedReport(
            url=url,
            title=title,
            published_at=published_at,
            raw_html=html,
            extracted_text=body_text,
            report_type=report_type,
            source_metadata=metadata,
            attack_table_mentions=attack_mentions,
        )

    @staticmethod
    def _detect_report_type(title: str) -> str:
        """Return 'dfir_flash_alert' for Flash Alert titles, else 'dfir_full_report'."""
        if title.lower().lstrip().startswith(FLASH_ALERT_PREFIX):
            return "dfir_flash_alert"
        return "dfir_full_report"

    @staticmethod
    def _clean_title(soup: BeautifulSoup) -> str | None:
        """Pull page title from H1, then <title>."""
        h1 = soup.find("h1")
        if h1 and h1.get_text(strip=True):
            return h1.get_text(strip=True)
        title_tag = soup.find("title")
        if title_tag:
            text = title_tag.get_text(strip=True)
            # WordPress titles end with " - The DFIR Report"
            return re.sub(r"\s*-\s*The DFIR Report\s*$", "", text).strip()
        return None

    # ATT&CK block handling

    @staticmethod
    def _is_attack_heading(node: Tag) -> bool:
        """Does this heading mark the start of the MITRE ATT&CK section?"""
        if node.name not in {"h1", "h2", "h3", "h4"}:
            return False
        text = node.get_text(strip=True).lower()
        # Normalize: drop trailing colons, collapse whitespace
        text = re.sub(r"\s+", " ", text).rstrip(":").strip()
        return text in ATTACK_HEADING_TEXTS

    def _find_attack_heading(self, soup: BeautifulSoup) -> Tag | None:
        """Find the heading element that introduces the ATT&CK section, or None."""
        for heading in soup.find_all(["h1", "h2", "h3", "h4"]):
            if self._is_attack_heading(heading):
                return heading
        return None

    def _block_region_strings(self, soup: BeautifulSoup) -> list[NavigableString]:
        """NavigableStrings between the ATT&CK heading and the next heading.

        Walks document order, not the heading's DOM siblings. Recent DFIR
        posts wrap the ATT&CK heading in a table-of-contents container div, so
        the technique block is no longer a sibling of the <h2>. A sibling walk
        silently collects nothing and the report yields zero mentions; a
        document-order walk is robust to that wrapping.

        Strings are collected (not mutated) so callers can extract them safely
        after the walk completes.
        """
        heading = self._find_attack_heading(soup)
        if heading is None:
            return []

        strings: list[NavigableString] = []
        for node in heading.next_elements:
            if isinstance(node, Tag) and node.name in {"h1", "h2", "h3", "h4"}:
                break
            if isinstance(node, NavigableString) and str(node).strip():
                strings.append(node)
        return strings

    def _extract_attack_block_text(self, soup: BeautifulSoup) -> str:
        """Return the text of the ATT&CK block following the heading.

        One technique per line, e.g. ``Technique Name - T####``.
        """
        return "\n".join(str(s).strip() for s in self._block_region_strings(soup))

    def _remove_attack_block(self, soup: BeautifulSoup) -> None:
        """Strip the ATT&CK heading and its block from the soup, in place.

        Called after _extract_attack_block_text so the text written to
        extracted_text excludes this region — otherwise the base regex
        extractor re-reads the structured block and double-counts its
        techniques as 'regex' mentions.
        """
        heading = self._find_attack_heading(soup)
        if heading is None:
            return

        # Collect first, then mutate: extracting during the walk breaks it.
        for node in self._block_region_strings(soup):
            node.extract()
        heading.decompose()

    @staticmethod
    def _extract_block_mentions(block_text: str) -> list[AttackTableMention]:
        """Parse the raw ATT&CK block text into structured mentions.

        Block format is one technique per line:
            Technique Name - T####
            Technique Name - T####.###
        We also handle the reversed form (T#### first) since older posts use it.
        """
        if not block_text:
            return []

        mentions: dict[str, AttackTableMention] = {}

        for raw_line in block_text.splitlines():
            line = raw_line.strip()
            if not line:
                continue

            # Find all technique IDs on this line. Most lines have exactly one.
            ids = TECHNIQUE_ID_PATTERN.findall(line)
            if not ids:
                continue

            for technique_id in ids:
                if technique_id in mentions:
                    continue
                snippet = line[:BLOCK_SNIPPET_RADIUS * 2]
                mentions[technique_id] = AttackTableMention(
                    technique_id=technique_id,
                    context_snippet=snippet,
                )

        return list(mentions.values())

    # Body text

    def _extract_body_text(self, soup: BeautifulSoup) -> str:
        """Pull the main post body, skipping nav/footer/sidebar.

        Strategy: try the standard WordPress single-post containers in order
        of specificity, fall back to whole-page text minus head/script/style.
        """
        candidates = [
            ("div", {"class": "entry-content"}),
            ("article", {}),
            ("main", {}),
            ("div", {"class": "post-content"}),
            ("div", {"id": "main-content"}),
        ]

        for tag_name, attrs in candidates:
            node = soup.find(tag_name, attrs=attrs) if attrs else soup.find(tag_name)
            if node and len(node.get_text(strip=True)) > 200:
                # Strip obvious noise within the chosen container
                for noise in node.select(
                    "nav, footer, .related-posts, .share-buttons, .sharedaddy"
                ):
                    noise.decompose()
                return self._normalize_whitespace(node.get_text(separator=" "))

        # Fall back to whole-page text
        for noise in soup.select("script, style, nav, footer"):
            noise.decompose()
        return self._normalize_whitespace(soup.get_text(separator=" "))

    @staticmethod
    def _normalize_whitespace(text_in: str) -> str:
        return re.sub(r"\s+", " ", text_in or "").strip()

    @staticmethod
    def _parse_date(value: str | None) -> datetime | None:
        if not value:
            return None
        try:
            parsed = dateparser.parse(value)
            if parsed and parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=UTC)
            return parsed
        except (ValueError, TypeError):
            logger.warning("Could not parse date: %r", value)
            return None
