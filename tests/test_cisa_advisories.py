"""Tests for the CISA Advisories ingester.

Parser tests against synthetic fixtures that approximate real CISA structure.
No HTTP, no DB. When real CISA fixtures are captured via
scripts/capture_advisory_fixture.py, add tests against those too.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from threat_intel.ingesters.cisa_advisories import (
    AA_PATH_PATTERN,
    CisaAdvisoriesIngester,
)

FIXTURE_DIR = Path(__file__).parent / "fixtures"


def load_fixture(name: str) -> str:
    return (FIXTURE_DIR / name).read_text(encoding="utf-8")


class TestAAUrlPattern:
    def test_matches_canonical_aa_url(self):
        url = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-352a"
        assert AA_PATH_PATTERN.search(url.lower()) is not None

    def test_matches_uppercase_after_lower(self):
        url = "https://www.cisa.gov/news-events/cybersecurity-advisories/AA24-038A"
        assert AA_PATH_PATTERN.search(url.lower()) is not None

    def test_does_not_match_ics_advisory(self):
        url = "https://www.cisa.gov/news-events/ics-advisories/icsa-24-100-01"
        assert AA_PATH_PATTERN.search(url.lower()) is None

    def test_does_not_match_alert(self):
        url = "https://www.cisa.gov/news-events/alerts/2024/04/15/urgent-patch"
        assert AA_PATH_PATTERN.search(url.lower()) is None

    def test_does_not_match_other_cisa_pages(self):
        url = "https://www.cisa.gov/news-events/news/about-cisa"
        assert AA_PATH_PATTERN.search(url.lower()) is None


class TestAdvisoryIdExtraction:
    def test_extracts_lowercase_id(self):
        url = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-352a"
        result = CisaAdvisoriesIngester._extract_advisory_id(url)
        assert result == "AA23-352A"

    def test_extracts_uppercase_id(self):
        url = "https://www.cisa.gov/news-events/cybersecurity-advisories/AA24-038A"
        result = CisaAdvisoriesIngester._extract_advisory_id(url)
        assert result == "AA24-038A"

    def test_returns_none_for_non_aa_url(self):
        url = "https://www.cisa.gov/news-events/alerts/2024/04/15/urgent-patch"
        result = CisaAdvisoriesIngester._extract_advisory_id(url)
        assert result is None


class TestParseAdvisoryWithAttackTables:
    """Tests against the synthetic Play-ransomware-style fixture."""

    @pytest.fixture
    def html(self) -> str:
        return load_fixture("cisa_aa23-352a_synthetic.html")

    @pytest.fixture
    def ingester(self) -> CisaAdvisoriesIngester:
        return CisaAdvisoriesIngester()

    def test_parser_produces_report(self, ingester, html):
        report = ingester._parse_advisory(
            url="https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-352a",
            rss_title="#StopRansomware: Play Ransomware",
            rss_published="Mon, 18 Dec 2023 12:00:00 +0000",
            rss_summary="Joint advisory on Play ransomware.",
            html=html,
        )
        assert report.url.endswith("aa23-352a")
        assert "Play Ransomware" in report.title
        assert report.report_type == "cisa_advisory_aa"
        assert report.published_at is not None
        assert report.word_count > 50

    def test_metadata_has_advisory_id(self, ingester, html):
        report = ingester._parse_advisory(
            url="https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-352a",
            rss_title="t", rss_published="", rss_summary="", html=html,
        )
        assert report.source_metadata["advisory_id"] == "AA23-352A"
        assert report.source_metadata["advisory_subtype"] == "AA"

    def test_extracts_techniques_from_tables(self, ingester, html):
        report = ingester._parse_advisory(
            url="https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-352a",
            rss_title="t", rss_published="", rss_summary="", html=html,
        )
        ids = {m.technique_id for m in report.attack_table_mentions}
        # Every technique that appears in the fixture's tables should be captured
        expected = {
            "T1595", "T1590",                  # Reconnaissance
            "T1190", "T1133", "T1078",          # Initial Access
            "T1059.001", "T1059.003",           # Execution
            "T1486",                            # Impact
        }
        assert expected.issubset(ids), f"Missing: {expected - ids}"

    def test_extracts_mitre_link_techniques(self, ingester, html):
        """Techniques referenced via attack.mitre.org links should be captured."""
        report = ingester._parse_advisory(
            url="https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-352a",
            rss_title="t", rss_published="", rss_summary="", html=html,
        )
        ids = {m.technique_id for m in report.attack_table_mentions}
        # These appear as <a href="https://attack.mitre.org/techniques/T#/"> links
        assert "T1078" in ids
        assert "T1595" in ids
        assert "T1133" in ids

    def test_dedup_within_advisory(self, ingester, html):
        """Same technique in multiple cells/links should only appear once."""
        report = ingester._parse_advisory(
            url="https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-352a",
            rss_title="t", rss_published="", rss_summary="", html=html,
        )
        ids = [m.technique_id for m in report.attack_table_mentions]
        # T1078 appears both in body text as a link and in a table; should be 1.
        assert ids.count("T1078") == 1

    def test_metadata_records_mention_count(self, ingester, html):
        report = ingester._parse_advisory(
            url="https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-352a",
            rss_title="t", rss_published="", rss_summary="", html=html,
        )
        assert report.source_metadata["attack_table_mention_count"] == len(
            report.attack_table_mentions
        )

    def test_body_text_does_not_contain_nav(self, ingester, html):
        report = ingester._parse_advisory(
            url="https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-352a",
            rss_title="t", rss_published="", rss_summary="", html=html,
        )
        # The fixture has a top nav with "Home"; the extracted body shouldn't
        # be dominated by it. Check that the actual content terms dominate.
        assert "Play" in report.extracted_text
        assert "ransomware" in report.extracted_text.lower()

    def test_attack_tables_excluded_from_body_text(self, ingester, html):
        """ATT&CK tables are captured separately as cisa_attack_table mentions;
        their text must not leak into extracted_text.

        Otherwise the base regex extractor re-finds table-only techniques as
        spurious 'regex' mentions, and 'regex' would stop meaning 'appeared in
        prose'. Techniques genuinely cited in prose must still survive.
        """
        report = ingester._parse_advisory(
            url="https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-352a",
            rss_title="t", rss_published="", rss_summary="", html=html,
        )
        # T1078 is cited in prose ("valid accounts (T1078)") — it stays.
        assert "T1078" in report.extracted_text
        # These appear only inside ATT&CK tables — gone from the prose body.
        for table_only in ["T1595", "T1590", "T1190", "T1133", "T1486"]:
            assert table_only not in report.extracted_text
        # ...but the table extractor still captured every one of them.
        table_ids = {m.technique_id for m in report.attack_table_mentions}
        assert {"T1595", "T1590", "T1190", "T1133", "T1486"}.issubset(table_ids)


class TestParseAdvisoryWithoutTables:
    """Tests against the inline-only fixture: T-numbers in prose, no ATT&CK table."""

    @pytest.fixture
    def html(self) -> str:
        return load_fixture("cisa_inline_only_synthetic.html")

    @pytest.fixture
    def ingester(self) -> CisaAdvisoriesIngester:
        return CisaAdvisoriesIngester()

    def test_no_attack_table_mentions(self, ingester, html):
        """When there's no table, attack_table_mentions should be empty.

        Inline T-numbers in prose get caught by the base regex extractor at
        DB-store time, not by the per-source table extractor.
        """
        report = ingester._parse_advisory(
            url="https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-999z",
            rss_title="t", rss_published="", rss_summary="", html=html,
        )
        assert report.attack_table_mentions == []

    def test_inline_techniques_in_extracted_text(self, ingester, html):
        """T-numbers in body prose should land in extracted_text for regex extraction."""
        report = ingester._parse_advisory(
            url="https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-999z",
            rss_title="t", rss_published="", rss_summary="", html=html,
        )
        for technique_id in ["T1190", "T1059.001", "T1543.003", "T1003"]:
            assert technique_id in report.extracted_text


class TestTactiIdsNotCaptured:
    """TA#### are tactic IDs, not techniques - they must not be stored as mentions."""

    @pytest.fixture
    def html(self) -> str:
        return load_fixture("cisa_inline_only_synthetic.html")

    def test_no_tactic_ids_in_table_mentions(self, html):
        ingester = CisaAdvisoriesIngester()
        report = ingester._parse_advisory(
            url="https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-999z",
            rss_title="t", rss_published="", rss_summary="", html=html,
        )
        ids = {m.technique_id for m in report.attack_table_mentions}
        # Fixture mentions [TA0001] and [TA0006] - these must not appear as techniques.
        assert not any(tid.startswith("TA") for tid in ids)


class TestRssFeedFiltering:
    """The ingester filters the RSS feed to AA-numbered entries only."""

    def test_aa_urls_pass_filter(self):
        aa_url = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-352a"
        assert AA_PATH_PATTERN.search(aa_url.lower())

    def test_ics_urls_blocked(self):
        ics_url = "https://www.cisa.gov/news-events/ics-advisories/icsa-24-100-01"
        assert not AA_PATH_PATTERN.search(ics_url.lower())

    def test_alerts_blocked(self):
        alert_url = "https://www.cisa.gov/news-events/alerts/2024/04/15/urgent"
        assert not AA_PATH_PATTERN.search(alert_url.lower())


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
