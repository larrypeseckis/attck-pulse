"""CISA Cybersecurity Advisories ingester (AA-numbered only for v1).

Source: https://www.cisa.gov/news-events/cybersecurity-advisories
Feed:   https://www.cisa.gov/cybersecurity-advisories/cybersecurity-advisories.xml

CISA publishes several advisory types under the same RSS feed. v1 ingests only
AA-numbered Joint Cybersecurity Advisories (URL pattern .../cybersecurity-advisories/aaYY-DDDx).
These are long-form, multi-agency advisories that frequently include explicit
ATT&CK technique tables, making them the highest-yield source for mention
extraction.

ICS Advisories (ICSA-), Medical (ICSMA-), Alerts (.../alerts/), and Bulletins
are skipped in v1. Each has its own structure and yield profile; add as
separate ingesters or expand this one in v2.

Operational notes:
- CISA returns 403 to bare/anonymous fetchers. The User-Agent in settings.http_user_agent
  identifies the project and includes a research contact. Keep it accurate or
  expect blocking.
- A 1.5s inter-request delay is applied between page fetches. Aggressive scraping
  gets the source IP blocked and is rude. Slow is fine.
- RSS gives 50ish recent entries. No backfill in v1 (per design decision).
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Iterator
from urllib.parse import urljoin

import feedparser
import httpx
import yaml
from bs4 import BeautifulSoup, Tag
from dateutil import parser as dateparser

from threat_intel.config import settings
from threat_intel.ingesters.base import (
    AttackTableMention,
    BaseIngester,
    NormalizedReport,
)
from threat_intel.logging_setup import get_logger


logger = get_logger(__name__)


# Matches a CISA AA advisory URL path segment.
# Examples: aa23-352a, aa25-061b, AA24-100A (we lowercase before checking)
AA_PATH_PATTERN = re.compile(r"/cybersecurity-advisories/aa\d{2}-\d{3}[a-z]?")

# Same pattern but anchored to ID extraction.
AA_ID_PATTERN = re.compile(r"aa(\d{2})-(\d{3})([a-z]?)", re.IGNORECASE)

# Technique IDs as they appear in CISA tables or prose.
TECHNIQUE_ID_PATTERN = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

# Tactic IDs (TA####) are intentionally NOT captured here - they're tactics,
# not techniques, and don't belong in technique_mentions.

# Snippet window for ATT&CK table extractions.
TABLE_SNIPPET_RADIUS = 150


class CisaAdvisoriesIngester(BaseIngester):
    """Ingester for CISA AA-numbered Joint Cybersecurity Advisories."""

    source_key = "cisa_advisories"
    inter_request_delay_seconds = 1.5

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
        return data["sources"]["cisa_advisories"]

    # Main fetch loop

    def fetch_reports(self) -> Iterator[NormalizedReport]:
        assert self.source_feed_url is not None

        logger.info("Fetching CISA Advisories RSS feed: %s", self.source_feed_url)
        self.polite_delay()
        feed_response = self.http_get(self.source_feed_url)
        feed = feedparser.parse(feed_response.text)

        if feed.bozo:
            logger.warning(
                "RSS feed parsed with errors: %s",
                getattr(feed, "bozo_exception", "unknown"),
            )

        entries_total = len(feed.entries)
        aa_entries = [
            entry for entry in feed.entries
            if AA_PATH_PATTERN.search(entry.get("link", "").lower())
        ]
        logger.info(
            "Feed contained %d entries; %d are AA-numbered advisories",
            entries_total,
            len(aa_entries),
        )

        for entry in aa_entries:
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
                yield self._parse_advisory(
                    url=url,
                    rss_title=entry.get("title", ""),
                    rss_published=entry.get("published", ""),
                    rss_summary=entry.get("summary", ""),
                    html=page_response.text,
                )
            except Exception:
                logger.exception("Failed to parse advisory: %s", url)
                continue

    # Parsing

    def _parse_advisory(
        self,
        *,
        url: str,
        rss_title: str,
        rss_published: str,
        rss_summary: str,
        html: str,
    ) -> NormalizedReport:
        """Parse a single advisory page and produce a NormalizedReport."""
        soup = BeautifulSoup(html, "lxml")

        # Extract the ATT&CK technique tables first, from the intact soup —
        # _extract_body_text then decomposes those tables, so the prose handed
        # to the regex extractor is independent of this table pass.
        attack_mentions = self._extract_attack_table_mentions(soup)
        body_text = self._extract_body_text(soup) or rss_summary

        advisory_id = self._extract_advisory_id(url)
        published_at = self._parse_date(rss_published)
        title = self._clean_title(soup) or rss_title or advisory_id or url

        metadata = {
            "advisory_id": advisory_id,
            "advisory_subtype": "AA",
            "attack_table_mention_count": len(attack_mentions),
            "rss_title": rss_title,
            "rss_summary": rss_summary,
        }

        return NormalizedReport(
            url=url,
            title=title,
            published_at=published_at,
            raw_html=html,
            extracted_text=body_text,
            report_type="cisa_advisory_aa",
            source_metadata=metadata,
            attack_table_mentions=attack_mentions,
        )

    @staticmethod
    def _extract_advisory_id(url: str) -> str | None:
        """Extract advisory ID like 'AA23-352A' from a CISA URL."""
        match = AA_ID_PATTERN.search(url)
        if not match:
            return None
        yy, ddd, letter = match.groups()
        return f"AA{yy}-{ddd}{letter.upper()}"

    @staticmethod
    def _clean_title(soup: BeautifulSoup) -> str | None:
        """Pull the page title from the H1, falling back to <title>."""
        h1 = soup.find("h1")
        if h1 and h1.get_text(strip=True):
            return h1.get_text(strip=True)
        title_tag = soup.find("title")
        if title_tag:
            return title_tag.get_text(strip=True).replace(" | CISA", "").strip()
        return None

    def _extract_body_text(self, soup: BeautifulSoup) -> str:
        """Extract main article prose, skipping nav/footer/sidebars and the
        ATT&CK technique tables.

        CISA pages are Drupal-built with multiple plausible content containers
        across redesigns. Try several selectors in order of specificity.

        ATT&CK tables are decomposed here (see ``_strip_attack_tables``) because
        they are captured separately as ``cisa_attack_table`` mentions. This
        method must run AFTER ``_extract_attack_table_mentions``, since it
        mutates the shared soup.
        """
        candidates = [
            ("div", {"class": "l-page-section--alerts"}),
            ("article", {}),
            ("main", {}),
            ("div", {"class": "field--name-body"}),
            ("div", {"class": "l-content"}),
            ("div", {"id": "main-content"}),
        ]

        for tag_name, attrs in candidates:
            node = soup.find(tag_name, attrs=attrs) if attrs else soup.find(tag_name)
            if node and len(node.get_text(strip=True)) > 200:
                # Remove obvious noise within the chosen container.
                for noise in node.select("nav, footer, .c-skip-nav, .visually-hidden"):
                    noise.decompose()
                self._strip_attack_tables(node)
                return self._normalize_whitespace(node.get_text(separator=" "))

        # Fall back to whole page text minus head/script/style.
        for noise in soup.select("script, style, nav, footer"):
            noise.decompose()
        self._strip_attack_tables(soup)
        return self._normalize_whitespace(soup.get_text(separator=" "))

    @staticmethod
    def _normalize_whitespace(text_in: str) -> str:
        return re.sub(r"\s+", " ", text_in or "").strip()

    @staticmethod
    def _strip_attack_tables(scope: Tag) -> None:
        """Decompose ATT&CK technique tables from ``scope`` in place.

        These tables are captured separately as ``cisa_attack_table`` mentions.
        Removing them from the body prose keeps the regex extraction pass
        independent of the table pass: a technique reported by both methods
        genuinely appears in CISA's structured table *and* in the advisory
        narrative, rather than the regex pass merely re-reading the same table.

        Uses the same ``_table_looks_like_attack`` heuristic the table
        extractor uses, so exactly the tables consumed there are removed here.
        """
        for table in scope.find_all("table"):
            if CisaAdvisoriesIngester._table_looks_like_attack(table):
                table.decompose()

    def _extract_attack_table_mentions(
        self,
        soup: BeautifulSoup,
    ) -> list[AttackTableMention]:
        """Find ATT&CK technique IDs in any table the page contains.

        A "table" qualifies if any cell contains a technique ID pattern or
        a link to attack.mitre.org. We collect unique technique IDs across
        all such tables, with snippets pulled from the cell context.

        This is high-precision: CISA explicitly mapped these techniques in
        a structured table, so confidence is 1.0.
        """
        mentions: dict[str, AttackTableMention] = {}

        for table in soup.find_all("table"):
            if not self._table_looks_like_attack(table):
                continue
            for cell in table.find_all(["td", "th"]):
                self._collect_techniques_from_cell(cell, mentions)

        # Also catch MITRE-linked anchors anywhere on the page, even outside tables.
        # These appear in some advisories as inline links rather than tables.
        for anchor in soup.find_all("a", href=True):
            href = anchor["href"]
            link_match = re.search(
                r"attack\.mitre\.org/techniques/(T\d{4}(?:/\d{3})?)",
                href,
            )
            if not link_match:
                continue
            raw = link_match.group(1)
            # Normalize "T1059/001" -> "T1059.001"
            technique_id = raw.replace("/", ".")
            if technique_id in mentions:
                continue
            snippet = anchor.get_text(separator=" ", strip=True) or technique_id
            mentions[technique_id] = AttackTableMention(
                technique_id=technique_id,
                context_snippet=snippet[:TABLE_SNIPPET_RADIUS * 2],
            )

        return list(mentions.values())

    @staticmethod
    def _table_looks_like_attack(table: Tag) -> bool:
        """Heuristic: does this table look like an ATT&CK technique table?

        A table qualifies if any of:
          - It contains a link to attack.mitre.org
          - It contains a cell matching the technique ID pattern
          - Its header row mentions 'technique' or 'tactic'
        """
        for link in table.find_all("a", href=True):
            if "attack.mitre.org" in link["href"]:
                return True

        text_blob = table.get_text(separator=" ", strip=True)
        if TECHNIQUE_ID_PATTERN.search(text_blob):
            return True

        # Header heuristic
        header = table.find("thead") or table.find("tr")
        if header:
            header_text = header.get_text(separator=" ").lower()
            if "technique" in header_text or "tactic" in header_text:
                return True

        return False

    @staticmethod
    def _collect_techniques_from_cell(
        cell: Tag,
        mentions: dict[str, AttackTableMention],
    ) -> None:
        """Pull technique IDs from a single cell, adding to mentions dict.

        Mentions dict is keyed by technique_id to dedup across cells/tables.
        """
        cell_text = cell.get_text(separator=" ", strip=True)
        if not cell_text:
            return

        for match in TECHNIQUE_ID_PATTERN.finditer(cell_text):
            technique_id = match.group(0)
            if technique_id in mentions:
                continue

            start = max(0, match.start() - TABLE_SNIPPET_RADIUS)
            end = min(len(cell_text), match.end() + TABLE_SNIPPET_RADIUS)
            snippet = cell_text[start:end].strip()

            mentions[technique_id] = AttackTableMention(
                technique_id=technique_id,
                context_snippet=snippet,
            )

    @staticmethod
    def _parse_date(value: str | None) -> datetime | None:
        if not value:
            return None
        try:
            parsed = dateparser.parse(value)
            if parsed and parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed
        except (ValueError, TypeError):
            logger.warning("Could not parse date: %r", value)
            return None


# urljoin imported but currently unused; kept for future when we resolve relative
# links in advisory bodies (CISA mixes absolute and relative URLs).
_ = urljoin
