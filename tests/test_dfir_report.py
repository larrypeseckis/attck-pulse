"""Tests for the DFIR Report ingester.

Parser tests against synthetic fixtures approximating real DFIR report structure.
No HTTP, no DB. When real DFIR fixtures are captured via
scripts/capture_fixture.py, add tests against those too.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from threat_intel.ingesters.dfir_report import DfirReportIngester

FIXTURE_DIR = Path(__file__).parent / "fixtures"


def load_fixture(name: str) -> str:
    return (FIXTURE_DIR / name).read_text(encoding="utf-8")


@pytest.fixture
def ingester() -> DfirReportIngester:
    return DfirReportIngester()


class TestReportTypeDetection:
    """Title-prefix based subtype detection."""

    def test_flash_alert_prefix(self):
        result = DfirReportIngester._detect_report_type(
            "Flash Alert: EtherRat and TukTuk C2 End in The Gentleman Ransomware"
        )
        assert result == "dfir_flash_alert"

    def test_flash_alert_case_insensitive(self):
        assert DfirReportIngester._detect_report_type("flash alert: lower case") == "dfir_flash_alert"
        assert DfirReportIngester._detect_report_type("FLASH ALERT: shouty") == "dfir_flash_alert"

    def test_full_report_default(self):
        result = DfirReportIngester._detect_report_type(
            "Cat's Got Your Files: Lynx Ransomware"
        )
        assert result == "dfir_full_report"

    def test_no_prefix_substring_match(self):
        """A report whose title *contains* 'Flash Alert' but doesn't START with it
        should still be classified as a full report."""
        result = DfirReportIngester._detect_report_type(
            "Lessons from a Flash Alert: How We Got It Wrong"
        )
        assert result == "dfir_full_report"


class TestAttackBlockExtraction:
    """Full Lynx-style fixture: structured ATT&CK code block at the end."""

    @pytest.fixture
    def html(self) -> str:
        return load_fixture("dfir_lynx_synthetic.html")

    def test_parser_produces_report(self, ingester, html):
        report = ingester._parse_report(
            url="https://thedfirreport.com/2025/12/17/cats-got-your-files-lynx-ransomware/",
            rss_title="Cat's Got Your Files: Lynx Ransomware",
            rss_published="Wed, 17 Dec 2025 19:07:07 +0000",
            rss_summary="Lynx ransomware case study.",
            html=html,
        )
        assert "Lynx" in report.title
        assert report.report_type == "dfir_full_report"
        assert report.published_at is not None
        assert report.word_count > 100

    def test_metadata_records_block_presence(self, ingester, html):
        report = ingester._parse_report(
            url="https://thedfirreport.com/test/",
            rss_title="t", rss_published="", rss_summary="", html=html,
        )
        assert report.source_metadata["has_attack_block"] is True
        assert report.source_metadata["attack_block_mention_count"] == len(
            report.attack_table_mentions
        )

    def test_extracts_all_techniques_from_block(self, ingester, html):
        report = ingester._parse_report(
            url="https://thedfirreport.com/test/",
            rss_title="t", rss_published="", rss_summary="", html=html,
        )
        ids = {m.technique_id for m in report.attack_table_mentions}
        # All 20 techniques from the Lynx ATT&CK section
        expected = {
            "T1098.007", "T1560.001", "T1486", "T1136.002", "T1567",
            "T1133", "T1490", "T1087.001", "T1046", "T1135",
            "T1059.001", "T1012", "T1219", "T1021.001", "T1018",
            "T1082", "T1016", "T1078", "T1059.003", "T1543.003",
        }
        assert expected == ids, f"Missing: {expected - ids}, Extra: {ids - expected}"

    def test_block_is_stripped_from_body_text(self, ingester, html):
        """The ATT&CK closing block must NOT appear in extracted_text.

        This is the bug class we found and fixed in the CISA ingester.
        Letting the structured block leak into body text causes the regex
        extractor to double-count its contents and falsely inflate
        cross-method agreement.
        """
        report = ingester._parse_report(
            url="https://thedfirreport.com/test/",
            rss_title="t", rss_published="", rss_summary="", html=html,
        )
        # The structured block's distinctive content should NOT appear in body
        assert "T1098.007" not in report.extracted_text, (
            "ATT&CK block leaked into extracted_text - "
            "_remove_attack_block did not strip it"
        )
        assert "T1560.001" not in report.extracted_text
        assert "Inhibit System Recovery - T1490" not in report.extracted_text

    def test_inline_techniques_preserved_in_body(self, ingester, html):
        """T-numbers in narrative prose stay in extracted_text.

        The Lynx fixture's Case Summary mentions T1078 and T1021.001 inline.
        Those must survive the body extraction since they're legitimate prose
        references caught by the base regex extractor.
        """
        report = ingester._parse_report(
            url="https://thedfirreport.com/test/",
            rss_title="t", rss_published="", rss_summary="", html=html,
        )
        # Inline references in the Case Summary section
        assert "T1078" in report.extracted_text
        assert "T1021.001" in report.extracted_text

    def test_detections_section_preserved(self, ingester, html):
        """Per design decision: Detections section content stays in body."""
        report = ingester._parse_report(
            url="https://thedfirreport.com/test/",
            rss_title="t", rss_published="", rss_summary="", html=html,
        )
        # Sigma rule UUIDs and ET signatures should survive
        assert "Spamhaus" in report.extracted_text or "ET DROP" in report.extracted_text

    def test_indicators_section_preserved(self, ingester, html):
        """Per design decision: Indicators (hashes/IPs) stay in body."""
        report = ingester._parse_report(
            url="https://thedfirreport.com/test/",
            rss_title="t", rss_published="", rss_summary="", html=html,
        )
        assert "netscan.exe" in report.extracted_text


class TestFlashAlertParsing:
    """Shorter Flash Alert format."""

    @pytest.fixture
    def html(self) -> str:
        return load_fixture("dfir_flash_alert_synthetic.html")

    def test_subtype_detected(self, ingester, html):
        report = ingester._parse_report(
            url="https://thedfirreport.com/2026/05/11/flash-alert-etherrat-tuktuk/",
            rss_title="Flash Alert: EtherRat and TukTuk C2",
            rss_published="Mon, 11 May 2026 12:00:00 +0000",
            rss_summary="Flash alert.",
            html=html,
        )
        assert report.report_type == "dfir_flash_alert"

    def test_block_extraction_works(self, ingester, html):
        report = ingester._parse_report(
            url="https://thedfirreport.com/test/",
            rss_title="t", rss_published="", rss_summary="", html=html,
        )
        ids = {m.technique_id for m in report.attack_table_mentions}
        expected = {"T1190", "T1059.001", "T1105", "T1486"}
        assert expected == ids


class TestNoAttackSection:
    """Edge case: report with no MITRE ATT&CK section, only inline T-numbers."""

    @pytest.fixture
    def html(self) -> str:
        return load_fixture("dfir_no_attack_section_synthetic.html")

    def test_no_block_mentions(self, ingester, html):
        report = ingester._parse_report(
            url="https://thedfirreport.com/2026/01/01/brief-update/",
            rss_title="Brief Update: Threat Actor Observation",
            rss_published="", rss_summary="", html=html,
        )
        assert report.attack_table_mentions == []
        assert report.source_metadata["has_attack_block"] is False

    def test_inline_techniques_in_body(self, ingester, html):
        """Inline T-numbers in prose remain in extracted_text for regex extraction."""
        report = ingester._parse_report(
            url="https://thedfirreport.com/test/",
            rss_title="t", rss_published="", rss_summary="", html=html,
        )
        for technique_id in ["T1190", "T1059.003", "T1003", "T1021.001"]:
            assert technique_id in report.extracted_text


class TestAttackHeadingRecognition:
    """The _is_attack_heading helper handles common heading variants."""

    def test_recognizes_canonical_heading(self):
        from bs4 import BeautifulSoup
        soup = BeautifulSoup("<h2>MITRE ATT&CK</h2>", "lxml")
        h = soup.find("h2")
        assert DfirReportIngester._is_attack_heading(h)

    def test_recognizes_with_trailing_colon(self):
        from bs4 import BeautifulSoup
        soup = BeautifulSoup("<h2>MITRE ATT&CK:</h2>", "lxml")
        h = soup.find("h2")
        assert DfirReportIngester._is_attack_heading(h)

    def test_recognizes_alternate_spelling(self):
        from bs4 import BeautifulSoup
        soup = BeautifulSoup("<h2>MITRE ATTACK</h2>", "lxml")
        h = soup.find("h2")
        assert DfirReportIngester._is_attack_heading(h)

    def test_rejects_unrelated_heading(self):
        from bs4 import BeautifulSoup
        soup = BeautifulSoup("<h2>Indicators</h2>", "lxml")
        h = soup.find("h2")
        assert not DfirReportIngester._is_attack_heading(h)

    def test_rejects_paragraph(self):
        from bs4 import BeautifulSoup
        soup = BeautifulSoup("<p>MITRE ATT&CK</p>", "lxml")
        p = soup.find("p")
        assert not DfirReportIngester._is_attack_heading(p)


class TestBlockMentionDedup:
    """A single technique appearing twice in the block produces one mention."""

    def test_dedup_within_block(self):
        block = """
        PowerShell - T1059.001
        Network Service Discovery - T1046
        PowerShell again - T1059.001
        """
        mentions = DfirReportIngester._extract_block_mentions(block)
        ids = [m.technique_id for m in mentions]
        assert ids.count("T1059.001") == 1
        assert "T1046" in ids


class TestFixtureNameFromUrl:
    """The generalized capture script derives clean filenames from URLs."""

    def test_cisa_url(self):
        from scripts.capture_fixture import fixture_name_from_url
        url = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-352a"
        assert fixture_name_from_url(url) == "cisa_aa23-352a.html"

    def test_dfir_url(self):
        from scripts.capture_fixture import fixture_name_from_url
        url = "https://thedfirreport.com/2025/12/17/cats-got-your-files-lynx-ransomware/"
        assert fixture_name_from_url(url) == "dfir_cats-got-your-files-lynx-ransomware.html"

    def test_unknown_host_uses_first_label(self):
        from scripts.capture_fixture import fixture_name_from_url
        url = "https://example.com/blog/post-slug/"
        assert fixture_name_from_url(url) == "example_post-slug.html"


class TestRealFixtureRegression:
    """Regression test pinned to a real captured DFIR report.

    Recent DFIR posts wrap the ATT&CK <h2> in a table-of-contents container
    div, so the heading is no longer a DOM sibling of the technique block. A
    sibling-only walk silently yields zero mentions; this guards the
    document-order walk in _block_region_strings that fixes it.
    """

    def test_toc_wrapped_heading_still_yields_block(self, ingester):
        from bs4 import BeautifulSoup

        html = load_fixture("dfir_cats-got-your-files-lynx-ransomware.html")
        soup = BeautifulSoup(html, "lxml")
        block = ingester._extract_attack_block_text(soup)
        mentions = ingester._extract_block_mentions(block)
        # This real report (Dec 2025, TOC-wrapped heading) maps ~20 techniques.
        # A sibling-only walk returns 0 here; assert we recover a real block.
        assert len(mentions) > 10

    def test_block_mentions_labelled_dfir_attack_block(self):
        """Block mentions must persist as extraction_method 'dfir_attack_block'.

        base.py stores a report's structured-ATT&CK mentions using the
        ingester's attack_mention_method; if DFIR doesn't override the base
        default, its mentions are mislabelled 'cisa_attack_table'.
        """
        assert DfirReportIngester.attack_mention_method == "dfir_attack_block"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
