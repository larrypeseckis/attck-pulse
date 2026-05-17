"""Tests for the regex-based ATT&CK ID extractor."""

from __future__ import annotations

import pytest

from threat_intel.extractors.regex_extractor import (
    ATTACK_ID_PATTERN,
    extract_attack_ids,
)

VALID_IDS = {"T1059", "T1059.001", "T1078", "T1486", "T1190"}


class TestAttackIdPattern:
    def test_matches_base_technique(self):
        assert ATTACK_ID_PATTERN.findall("see T1059 for details") == ["T1059"]

    def test_matches_subtechnique(self):
        assert ATTACK_ID_PATTERN.findall("uses T1059.001") == ["T1059.001"]

    def test_matches_multiple(self):
        text = "Chain: T1190 -> T1078 -> T1486"
        assert ATTACK_ID_PATTERN.findall(text) == ["T1190", "T1078", "T1486"]

    def test_does_not_match_too_short(self):
        assert ATTACK_ID_PATTERN.findall("T123 is not valid") == []

    def test_does_not_match_too_long(self):
        # T12345 is not a real ATT&CK ID format
        assert ATTACK_ID_PATTERN.findall("T12345 nope") == []

    def test_word_boundary_prevents_partial_match(self):
        # "XT1059" should not match
        assert ATTACK_ID_PATTERN.findall("XT1059 prefix") == []

    def test_case_sensitive(self):
        # Lowercase t shouldn't match
        assert ATTACK_ID_PATTERN.findall("t1059 lowercase") == []


class TestExtractAttackIds:
    def test_empty_text(self):
        assert extract_attack_ids("", VALID_IDS) == []

    def test_none_text(self):
        assert extract_attack_ids(None, VALID_IDS) == []  # type: ignore[arg-type]

    def test_no_matches(self):
        assert extract_attack_ids("nothing to find here", VALID_IDS) == []

    def test_single_valid_match(self):
        result = extract_attack_ids("attacker used T1059 for execution", VALID_IDS)
        assert len(result) == 1
        assert result[0].technique_id == "T1059"
        assert result[0].confidence == 1.0
        assert "T1059" in result[0].context_snippet

    def test_drops_unknown_id(self):
        # T9999 is not in VALID_IDS -> should be dropped
        result = extract_attack_ids("T9999 is not real", VALID_IDS)
        assert result == []

    def test_keeps_only_valid_in_mixed_text(self):
        text = "Real: T1059. Fake: T9999. Real: T1078."
        result = extract_attack_ids(text, VALID_IDS)
        ids = sorted(m.technique_id for m in result)
        assert ids == ["T1059", "T1078"]

    def test_dedup_by_position(self):
        # Same technique mentioned at two different positions counts twice.
        text = "T1059 appears here and T1059 also here."
        result = extract_attack_ids(text, VALID_IDS)
        assert len(result) == 2

    def test_snippet_window(self):
        text = ("x" * 200) + " T1059 in the middle " + ("y" * 200)
        result = extract_attack_ids(text, VALID_IDS)
        assert len(result) == 1
        # Snippet should be bounded, not the full text
        assert len(result[0].context_snippet) < len(text)
        assert "T1059" in result[0].context_snippet

    def test_subtechnique_extraction(self):
        result = extract_attack_ids("attacker used T1059.001 for PowerShell", VALID_IDS)
        assert len(result) == 1
        assert result[0].technique_id == "T1059.001"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
