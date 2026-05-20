"""Base ingester class.

Each source-specific ingester subclasses this. The base handles common concerns:
HTTP client lifecycle, retry policy, dedup checks, mention extraction (regex +
optional structured table mentions provided by the subclass).
"""

from __future__ import annotations

import json
import time
from abc import ABC, abstractmethod
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

import httpx
from sqlalchemy import text
from sqlalchemy.orm import Session
from tenacity import (
    retry,
    retry_if_exception,
    stop_after_attempt,
    wait_exponential,
)

from threat_intel.config import settings
from threat_intel.db import PipelineRun, session_scope, upsert_source
from threat_intel.extractors.regex_extractor import (
    extract_and_store,
    load_valid_technique_ids,
)
from threat_intel.logging_setup import get_logger

logger = get_logger(__name__)


# HTTP status codes that are permanent failures - do not retry.
PERMANENT_HTTP_ERRORS = {400, 401, 403, 404, 410, 451}


def _is_transient_http_error(exc: BaseException) -> bool:
    """Return True if the exception is worth retrying.

    Network errors and 5xx responses retry. 4xx responses (especially 403/404)
    are permanent and should not retry.
    """
    if isinstance(exc, httpx.HTTPStatusError):
        return exc.response.status_code not in PERMANENT_HTTP_ERRORS
    # Any other httpx error (network/timeout/etc.) is transient and retryable.
    return isinstance(exc, httpx.HTTPError)


@dataclass
class AttackTableMention:
    """A technique mention extracted from a structured source-provided table.

    Confidence is typically 1.0 since the source explicitly mapped this
    technique. Distinct from regex matches because the extraction method
    is more reliable.
    """

    technique_id: str
    context_snippet: str
    confidence: float = 1.0


@dataclass
class NormalizedReport:
    """Common shape produced by every ingester before DB write."""

    url: str
    title: str
    published_at: datetime | None
    raw_html: str | None
    extracted_text: str
    report_type: str
    source_metadata: dict[str, Any] = field(default_factory=dict)
    # Optional: structured technique mentions a subclass extracted from
    # tables/lists in the source itself (e.g., CISA ATT&CK tables).
    attack_table_mentions: list[AttackTableMention] = field(default_factory=list)

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

    # Inter-request delay used by polite_delay(). Subclasses that fetch many
    # pages from the same origin should set this to a positive value.
    inter_request_delay_seconds: float = 0.0

    # extraction_method label for mentions from this source's structured ATT&CK
    # section (table, code block, etc.). Overridden per source.
    attack_mention_method: str = "cisa_attack_table"

    def __init__(self):
        self._client: httpx.Client | None = None
        self._source_id: int | None = None
        self._valid_technique_ids: set[str] | None = None
        self._last_request_ts: float = 0.0

    # Subclass hook

    @abstractmethod
    def fetch_reports(self) -> Iterator[NormalizedReport]:
        """Yield normalized reports. Implemented per source."""

    # Lifecycle

    def __enter__(self) -> BaseIngester:
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
                    continue

    # HTTP helpers

    @retry(
        retry=retry_if_exception(_is_transient_http_error),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=30),
        reraise=True,
    )
    def http_get(self, url: str) -> httpx.Response:
        """GET with retries on transient errors, no retry on 4xx (except 429)."""
        assert self._client is not None, "Ingester must be used as a context manager"
        logger.debug("GET %s", url)
        response = self._client.get(url)
        response.raise_for_status()
        return response

    def polite_delay(self) -> None:
        """Sleep so consecutive requests respect inter_request_delay_seconds.

        Subclasses should call this *before* each request to a per-page resource.
        Wall-clock based so backoff during retries doesn't double-count.
        """
        if self.inter_request_delay_seconds <= 0:
            return
        elapsed = time.monotonic() - self._last_request_ts
        sleep_for = self.inter_request_delay_seconds - elapsed
        if sleep_for > 0:
            time.sleep(sleep_for)
        self._last_request_ts = time.monotonic()

    # Storage

    def _store_report(self, report: NormalizedReport) -> str | None:
        """Insert or update a report. Returns 'new', 'updated', or None.

        After storage, runs regex extraction and persists any structured
        ATT&CK table mentions provided by the subclass.
        """
        assert self._source_id is not None
        assert self._valid_technique_ids is not None

        with session_scope() as session:
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
                            raw_html, extracted_text, word_count,
                            source_metadata, report_type
                        )
                        VALUES (
                            :source_id, :url, :title, :published_at,
                            :raw_html, :extracted_text, :word_count,
                            :metadata, :report_type
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
                        "report_type": report.report_type,
                    },
                )
                report_id = result.scalar_one()
                outcome = "new"
                logger.info("New report stored: %s", report.url)
            else:
                report_id = existing[0]
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
                                source_metadata = :metadata,
                                report_type = :report_type
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
                            "report_type": report.report_type,
                            "report_id": report_id,
                        },
                    )
                    outcome = "updated"
                    logger.info("Report updated: %s", report.url)
                else:
                    outcome = None
                    logger.debug("Report unchanged, skipping: %s", report.url)

            if outcome is not None:
                # Regex pass over the full text body.
                extract_and_store(
                    session=session,
                    report_id=report_id,
                    text_body=report.extracted_text,
                    valid_technique_ids=self._valid_technique_ids,
                )

                # Structured-source mentions, if the subclass provided any.
                self._store_attack_table_mentions(
                    session=session,
                    report_id=report_id,
                    mentions=report.attack_table_mentions,
                )

            return outcome

    def _store_attack_table_mentions(
        self,
        session: Session,
        report_id: int,
        mentions: list[AttackTableMention],
    ) -> int:
        """Persist mentions from a source-provided ATT&CK table.

        Drops any technique_id that isn't a known technique.
        """
        if not mentions:
            return 0

        assert self._valid_technique_ids is not None
        inserted = 0
        for mention in mentions:
            if mention.technique_id not in self._valid_technique_ids:
                logger.warning(
                    "ATT&CK table referenced unknown technique: %s (report_id=%d)",
                    mention.technique_id,
                    report_id,
                )
                continue

            result = session.execute(
                text(
                    """
                    INSERT INTO technique_mentions (
                        report_id, technique_id, context_snippet,
                        extraction_method, confidence
                    )
                    VALUES (
                        :report_id, :technique_id, :snippet,
                        :method, :confidence
                    )
                    ON CONFLICT (report_id, technique_id, extraction_method)
                    DO NOTHING
                    RETURNING id
                    """
                ),
                {
                    "report_id": report_id,
                    "technique_id": mention.technique_id,
                    "snippet": mention.context_snippet,
                    "method": self.attack_mention_method,
                    "confidence": mention.confidence,
                },
            )
            if result.scalar() is not None:
                inserted += 1

        logger.debug(
            "Stored %d ATT&CK table mentions for report_id=%d", inserted, report_id
        )
        return inserted
