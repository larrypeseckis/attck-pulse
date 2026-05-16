#!/usr/bin/env python
"""Manual validation harness for extracted technique mentions.

Samples N mentions from the database stratified by extraction method,
displays them with context, and lets the analyst mark each true/false positive.
Writes results to a CSV for precision calculation.

Usage:
    python scripts/validate_extraction.py --n 50 --method regex
    python scripts/validate_extraction.py --n 50 --method spacy_phrase
"""

from __future__ import annotations

import argparse
import csv
import sys
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import text

from threat_intel.config import settings
from threat_intel.db import session_scope
from threat_intel.logging_setup import configure_logging, get_logger


def sample_mentions(method: str, sample_size: int) -> list[dict]:
    """Pull a random sample of mentions for a given extraction method."""
    with session_scope() as session:
        result = session.execute(
            text(
                """
                SELECT
                    tm.id, tm.technique_id, tm.context_snippet, tm.confidence,
                    t.name AS technique_name, t.tactic,
                    r.url AS report_url, r.title AS report_title
                FROM technique_mentions tm
                JOIN techniques t ON t.technique_id = tm.technique_id
                JOIN reports r ON r.id = tm.report_id
                WHERE tm.extraction_method = :method
                ORDER BY random()
                LIMIT :n
                """
            ),
            {"method": method, "n": sample_size},
        )
        return [dict(row._mapping) for row in result]


def prompt_review(mention: dict) -> tuple[str, str]:
    """Display mention, collect verdict. Returns (verdict, note)."""
    print("\n" + "=" * 80)
    print(f"Mention #{mention['id']}")
    print(f"Technique: {mention['technique_id']} - {mention['technique_name']}")
    print(f"Tactic:    {mention['tactic']}")
    print(f"Source:    {mention['report_title']}")
    print(f"URL:       {mention['report_url']}")
    print(f"Confidence: {mention['confidence']:.2f}")
    print("-" * 80)
    print("Context:")
    print(mention["context_snippet"])
    print("-" * 80)

    while True:
        verdict = input("Verdict [t]rue positive, [f]alse positive, [s]kip, [q]uit: ").strip().lower()
        if verdict in {"t", "f", "s", "q"}:
            break
        print("Invalid input. Use t, f, s, or q.")

    note = ""
    if verdict in {"t", "f"}:
        note = input("Note (optional): ").strip()

    return verdict, note


def main() -> int:
    configure_logging()
    logger = get_logger(__name__)

    parser = argparse.ArgumentParser()
    parser.add_argument("--n", type=int, default=50, help="Sample size")
    parser.add_argument(
        "--method",
        choices=["regex", "spacy_phrase", "manual"],
        required=True,
        help="Extraction method to validate",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=settings.project_root / "validation",
        help="Where to write the CSV results",
    )
    args = parser.parse_args()

    mentions = sample_mentions(args.method, args.n)
    if not mentions:
        logger.error("No mentions found for method=%s", args.method)
        return 1

    logger.info("Sampled %d mentions for review", len(mentions))

    args.output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    csv_file = args.output_dir / f"validation_{args.method}_{timestamp}.csv"

    results: list[dict] = []
    quit_early = False

    for idx, mention in enumerate(mentions, start=1):
        print(f"\n[{idx}/{len(mentions)}]")
        verdict, note = prompt_review(mention)
        if verdict == "q":
            quit_early = True
            break
        if verdict == "s":
            continue
        results.append(
            {
                "mention_id": mention["id"],
                "technique_id": mention["technique_id"],
                "verdict": "tp" if verdict == "t" else "fp",
                "note": note,
            }
        )

    if results:
        with csv_file.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=["mention_id", "technique_id", "verdict", "note"])
            writer.writeheader()
            writer.writerows(results)
        logger.info("Wrote %d verdicts to %s", len(results), csv_file)

        tp = sum(1 for r in results if r["verdict"] == "tp")
        total = len(results)
        precision = tp / total if total else 0.0
        print(f"\nReviewed: {total}")
        print(f"True positives: {tp}")
        print(f"False positives: {total - tp}")
        print(f"Precision: {precision:.2%}")

    if quit_early:
        logger.info("Validation quit early by user")

    return 0


if __name__ == "__main__":
    sys.exit(main())
