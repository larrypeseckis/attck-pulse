"""Tests for CISA KEV record normalization.

Pure-function tests against the static method. No HTTP, no DB.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from threat_intel.ingesters.cisa_kev import CisaKevIngester

SAMPLE_VULN = {
    "cveID": "CVE-2024-12345",
    "vendorProject": "Acme",
    "product": "FooServer",
    "vulnerabilityName": "Acme FooServer Remote Code Execution Vulnerability",
    "dateAdded": "2024-08-15",
    "shortDescription": (
        "Acme FooServer contains a deserialization vulnerability that allows "
        "an unauthenticated attacker to execute arbitrary code. Associated with "
        "exploitation technique T1190 and T1059.001."
    ),
    "requiredAction": "Apply mitigations per vendor instructions.",
    "dueDate": "2024-09-05",
    "knownRansomwareCampaignUse": "Known",
    "notes": "https://example.com/advisory",
    "cwes": ["CWE-502"],
}


class TestKevNormalize:
    def test_url_uses_nvd(self):
        report = CisaKevIngester._normalize_vulnerability(SAMPLE_VULN, "2024.08.15")
        assert report.url == "https://nvd.nist.gov/vuln/detail/CVE-2024-12345"

    def test_title_contains_key_fields(self):
        report = CisaKevIngester._normalize_vulnerability(SAMPLE_VULN, "2024.08.15")
        assert "CVE-2024-12345" in report.title
        assert "Acme" in report.title
        assert "FooServer" in report.title

    def test_extracted_text_includes_description(self):
        report = CisaKevIngester._normalize_vulnerability(SAMPLE_VULN, "2024.08.15")
        assert "deserialization vulnerability" in report.extracted_text
        # And the technique IDs are present so regex extraction will catch them
        assert "T1190" in report.extracted_text
        assert "T1059.001" in report.extracted_text

    def test_published_at_parsed(self):
        report = CisaKevIngester._normalize_vulnerability(SAMPLE_VULN, "2024.08.15")
        assert report.published_at == datetime(2024, 8, 15, tzinfo=UTC)

    def test_metadata_preserves_kev_fields(self):
        report = CisaKevIngester._normalize_vulnerability(SAMPLE_VULN, "2024.08.15")
        meta = report.source_metadata
        assert meta["cve_id"] == "CVE-2024-12345"
        assert meta["vendor"] == "Acme"
        assert meta["product"] == "FooServer"
        assert meta["due_date"] == "2024-09-05"
        assert meta["known_ransomware_use"] == "Known"
        assert meta["cwes"] == ["CWE-502"]
        assert meta["catalog_version"] == "2024.08.15"

    def test_missing_optional_fields(self):
        minimal = {
            "cveID": "CVE-2024-00001",
            "vendorProject": "Vendor",
            "product": "Product",
            "vulnerabilityName": "Name",
            "dateAdded": "2024-01-01",
        }
        report = CisaKevIngester._normalize_vulnerability(minimal, "2024.01.01")
        assert report.title.startswith("CVE-2024-00001")
        assert report.source_metadata["cve_id"] == "CVE-2024-00001"

    def test_bad_date_does_not_crash(self):
        bad = dict(SAMPLE_VULN)
        bad["dateAdded"] = "not a date"
        report = CisaKevIngester._normalize_vulnerability(bad, "2024.08.15")
        assert report.published_at is None

    def test_word_count_computed(self):
        report = CisaKevIngester._normalize_vulnerability(SAMPLE_VULN, "2024.08.15")
        assert report.word_count > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
