"""Regex-based extractor for ATT&CK technique IDs.

High precision (≥95% target). Catches explicit T#### or T####.### mentions.
Validates against the techniques table to drop false positives like part numbers.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from sqlalchemy import text
from sqlalchemy.orm import Session

from threat_intel.logging_setup import get_logger

logger = get_logger(__name__)


# Word-boundary anchored ATT&CK ID pattern.
ATTACK_ID_PATTERN = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

# Snippet window in characters around the match
SNIPPET_RADIUS = 100


@dataclass(frozen=True)
class ExtractedMention:
    technique_id: str
    context_snippet: str
    confidence: float


def extract_attack_ids(
    text_body: str,
    valid_technique_ids: set[str],
) -> list[ExtractedMention]:
    """Find all valid ATT&CK technique IDs in text_body.

    A match is only returned if the matched ID exists in valid_technique_ids.
    """
    if not text_body:
        return []

    mentions: list[ExtractedMention] = []
    seen_per_text: set[tuple[str, int]] = set()  # (technique_id, position)

    for match in ATTACK_ID_PATTERN.finditer(text_body):
        technique_id = match.group(0)
        if technique_id not in valid_technique_ids:
            continue

        start = max(0, match.start() - SNIPPET_RADIUS)
        end = min(len(text_body), match.end() + SNIPPET_RADIUS)
        snippet = text_body[start:end].replace("\n", " ").strip()

        key = (technique_id, match.start())
        if key in seen_per_text:
            continue
        seen_per_text.add(key)

        mentions.append(
            ExtractedMention(
                technique_id=technique_id,
                context_snippet=snippet,
                confidence=1.0,
            )
        )

    return mentions


def load_valid_technique_ids(session: Session) -> set[str]:
    """Load the set of known ATT&CK technique IDs from the database."""
    result = session.execute(text("SELECT technique_id FROM techniques"))
    return {row[0] for row in result}


def extract_and_store(
    session: Session,
    report_id: int,
    text_body: str,
    valid_technique_ids: set[str],
) -> int:
    """Extract mentions and insert them. Returns count of new mentions stored."""
    mentions = extract_attack_ids(text_body, valid_technique_ids)
    if not mentions:
        return 0

    inserted = 0
    for mention in mentions:
        result = session.execute(
            text(
                """
                INSERT INTO technique_mentions (
                    report_id, technique_id, context_snippet,
                    extraction_method, confidence
                )
                VALUES (:report_id, :technique_id, :snippet, 'regex', :confidence)
                ON CONFLICT (report_id, technique_id, extraction_method) DO NOTHING
                RETURNING id
                """
            ),
            {
                "report_id": report_id,
                "technique_id": mention.technique_id,
                "snippet": mention.context_snippet,
                "confidence": mention.confidence,
            },
        )
        if result.scalar() is not None:
            inserted += 1

    logger.debug(
        "Regex extraction for report_id=%d: %d mentions found, %d new",
        report_id,
        len(mentions),
        inserted,
    )
    return inserted
