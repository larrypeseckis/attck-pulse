"""Database access layer.

SQLAlchemy Core (not ORM). Queries are visible SQL.
"""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Generator

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from threat_intel.config import settings
from threat_intel.logging_setup import get_logger


logger = get_logger(__name__)


_engine: Engine | None = None
_SessionLocal: sessionmaker[Session] | None = None


def get_engine() -> Engine:
    """Lazy-init engine. One per process."""
    global _engine
    if _engine is None:
        _engine = create_engine(
            settings.postgres_dsn,
            pool_pre_ping=True,
            pool_size=5,
            max_overflow=5,
            echo=False,
        )
    return _engine


def get_session_factory() -> sessionmaker[Session]:
    global _SessionLocal
    if _SessionLocal is None:
        _SessionLocal = sessionmaker(
            bind=get_engine(),
            autoflush=False,
            autocommit=False,
            expire_on_commit=False,
        )
    return _SessionLocal


@contextmanager
def session_scope() -> Generator[Session, None, None]:
    """Transactional session. Commits on success, rolls back on exception."""
    session = get_session_factory()()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def run_migration(migration_file: str) -> None:
    """Execute a SQL migration file. Used by init_db.py."""
    migration_text = (settings.project_root / "sql" / "migrations" / migration_file).read_text()
    logger.info("Running migration: %s", migration_file)
    with get_engine().begin() as conn:
        conn.execute(text(migration_text))
    logger.info("Migration complete: %s", migration_file)


def upsert_source(
    session: Session,
    name: str,
    base_url: str,
    feed_url: str | None,
    feed_type: str,
) -> int:
    """Insert or update a source. Returns source id."""
    result = session.execute(
        text(
            """
            INSERT INTO sources (name, base_url, feed_url, feed_type)
            VALUES (:name, :base_url, :feed_url, :feed_type)
            ON CONFLICT (name) DO UPDATE SET
                base_url = EXCLUDED.base_url,
                feed_url = EXCLUDED.feed_url,
                feed_type = EXCLUDED.feed_type
            RETURNING id
            """
        ),
        {
            "name": name,
            "base_url": base_url,
            "feed_url": feed_url,
            "feed_type": feed_type,
        },
    )
    return result.scalar_one()


class PipelineRun:
    """Context manager for tracking a pipeline run.

    Usage:
        with PipelineRun("cisa_kev") as run:
            # do work
            run.records_seen += 1
            run.records_new += 1
    """

    def __init__(self, ingester_name: str):
        self.ingester_name = ingester_name
        self.records_seen = 0
        self.records_new = 0
        self.records_updated = 0
        self.metadata: dict[str, Any] = {}
        self._run_id: int | None = None

    def __enter__(self) -> "PipelineRun":
        with session_scope() as session:
            result = session.execute(
                text(
                    """
                    INSERT INTO pipeline_runs (ingester_name, status)
                    VALUES (:name, 'running')
                    RETURNING id
                    """
                ),
                {"name": self.ingester_name},
            )
            self._run_id = result.scalar_one()
        logger.info("Pipeline run started: %s (run_id=%s)", self.ingester_name, self._run_id)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        if exc_type is None:
            status = "success"
            error_message = None
        else:
            status = "failure"
            error_message = f"{exc_type.__name__}: {exc_val}"

        with session_scope() as session:
            session.execute(
                text(
                    """
                    UPDATE pipeline_runs SET
                        finished_at = :finished,
                        status = :status,
                        records_seen = :seen,
                        records_new = :new,
                        records_updated = :updated,
                        error_message = :err,
                        run_metadata = :meta
                    WHERE id = :run_id
                    """
                ),
                {
                    "finished": datetime.now(tz=timezone.utc),
                    "status": status,
                    "seen": self.records_seen,
                    "new": self.records_new,
                    "updated": self.records_updated,
                    "err": error_message,
                    "meta": __import__("json").dumps(self.metadata),
                    "run_id": self._run_id,
                },
            )

        logger.info(
            "Pipeline run finished: %s status=%s seen=%d new=%d updated=%d",
            self.ingester_name,
            status,
            self.records_seen,
            self.records_new,
            self.records_updated,
        )
        # Don't suppress exceptions
        return None
