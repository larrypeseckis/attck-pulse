"""Base ingester class.

Each source-specific ingester subclasses this. The base handles common concerns:
HTTP client lifecycle, retry policy, dedup checks, mention extraction.
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Iterator

import httpx
from sqlalchemy import text
from sqlalchemy.orm import Session
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type

from threat_intel.config import settings
from threat_intel.db import PipelineRun, session_scope, upsert_source
from threat_intel.extractors.regex_extractor import (
    extract_and_store,
    load_valid_technique_ids,
)
from threat_intel.logging_setup import get_logger


logger = get_logger(__name__)


@dataclass
class NormalizedReport:
    """Common shape produced by every ingester before DB write."""

    url: str
    title: str
    published_at: datetime | None
    raw_html: str | None
    extracted_text: str
    source_metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def word_count(self) -> int:
        return len(self.extracted_text.split()) if self.extracted_text else 0


class BaseIngester(ABC):
    """Abstract base for source-specific ingesters.

    Subclass and implement:
      - source_key: matches the key in config/sources.yaml
      - fetch_reports(): yields NormalizedReport instances
    """

    source_key: str
    source_name: str
    source_base_url: str
    source_feed_url: str | None
    source_feed_type: str  # 'rss', 'json', 'html_scrape'

    def __init__(self):
        self._client: httpx.Client | None = None
        self._source_id: int | None = None
        self._valid_technique_ids: set[str] | None = None

    # Subclass hook

    @abstractmethod
    def fetch_reports(self) -> Iterator[NormalizedReport]:
        """Yield normalized reports. Implemented per source."""

    # Lifecycle

    def __enter__(self) -> "BaseIngester":
        self._client = httpx.Client(
            headers={"User-Agent": settings.http_user_agent},
            timeout=settings.http_timeout_seconds,
            follow_redirects=True,
        )
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        if self._client is not None:
            self._client.close()

    # Public entry point

    def run(self) -> None:
        """Run the ingester. Records progress in pipeline_runs."""
        with PipelineRun(self.source_key) as run, self:
            # Register/refresh source row, get its id
            with session_scope() as session:
                self._source_id = upsert_source(
                    session=session,
                    name=self.source_name,
                    base_url=self.source_base_url,
                    feed_url=self.source_feed_url,
                    feed_type=self.source_feed_type,
                )
                self._valid_technique_ids = load_valid_technique_ids(session)

            if not self._valid_technique_ids:
                msg = "techniques table is empty; run scripts/load_attack.py first"
                logger.error(msg)
                raise RuntimeError(msg)

            for report in self.fetch_reports():
                run.records_seen += 1
                try:
                    stored = self._store_report(report)
                    if stored == "new":
                        run.records_new += 1
                    elif stored == "updated":
                        run.records_updated += 1
                except Exception:
                    logger.exception("Failed to store report: %s", report.url)
                    # Continue to next report rather than failing the whole run
                    continue

    # HTTP helpers

    @retry(
        retry=retry_if_exception_type(httpx.HTTPError),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=30),
        reraise=True,
    )
    def http_get(self, url: str) -> httpx.Response:
        """GET with retries on transient HTTP errors."""
        assert self._client is not None, "Ingester must be used as a context manager"
        logger.debug("GET %s", url)
        response = self._client.get(url)
        response.raise_for_status()
        return response

    # Storage

    def _store_report(self, report: NormalizedReport) -> str | None:
        """Insert or update a report. Returns 'new', 'updated', or None.

        Also runs regex extraction on the stored report.
        """
        assert self._source_id is not None
        assert self._valid_technique_ids is not None

        with session_scope() as session:
            # Check if exists
            existing = session.execute(
                text("SELECT id, extracted_text FROM reports WHERE url = :url"),
                {"url": report.url},
            ).fetchone()

            if existing is None:
                result = session.execute(
                    text(
                        """
                        INSERT INTO reports (
                            source_id, url, title, published_at,
                            raw_html, extracted_text, word_count, source_metadata
                        )
                        VALUES (
                            :source_id, :url, :title, :published_at,
                            :raw_html, :extracted_text, :word_count, :metadata
                        )
                        RETURNING id
                        """
                    ),
                    {
                        "source_id": self._source_id,
                        "url": report.url,
                        "title": report.title,
                        "published_at": report.published_at,
                        "raw_html": report.raw_html,
                        "extracted_text": report.extracted_text,
                        "word_count": report.word_count,
                        "metadata": json.dumps(report.source_metadata),
                    },
                )
                report_id = result.scalar_one()
                outcome = "new"
                logger.info("New report stored: %s", report.url)
            else:
                report_id = existing[0]
                # Re-extract only if text changed
                if existing[1] != report.extracted_text:
                    session.execute(
                        text(
                            """
                            UPDATE reports SET
                                title = :title,
                                published_at = :published_at,
                                raw_html = :raw_html,
                                extracted_text = :extracted_text,
                                word_count = :word_count,
                                source_metadata = :metadata
                            WHERE id = :report_id
                            """
                        ),
                        {
                            "title": report.title,
                            "published_at": report.published_at,
                            "raw_html": report.raw_html,
                            "extracted_text": report.extracted_text,
                            "word_count": report.word_count,
                            "metadata": json.dumps(report.source_metadata),
                            "report_id": report_id,
                        },
                    )
                    outcome = "updated"
                    logger.info("Report updated: %s", report.url)
                else:
                    outcome = None
                    logger.debug("Report unchanged, skipping: %s", report.url)

            if outcome is not None:
                extract_and_store(
                    session=session,
                    report_id=report_id,
                    text_body=report.extracted_text,
                    valid_technique_ids=self._valid_technique_ids,
                )

            return outcome
