"""SQLAlchemy engine factory for DomainRaptor storage backends.

Resolves the database URL via :meth:`AppConfig.resolve_database_url` and
builds a SQLAlchemy ``Engine`` with sensible defaults per dialect.

This module is intentionally backend-agnostic. The legacy SQLite
``DatabaseManager`` continues to use :mod:`sqlite3` directly for backwards
compatibility; this engine is the entry point for the new SQL backend story
(schema initialization via SQLAlchemy metadata, Alembic migrations).
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine, make_url

if TYPE_CHECKING:
    from domainraptor.core.config import AppConfig

logger = logging.getLogger(__name__)


def create_engine_from_url(database_url: str, *, echo: bool = False) -> Engine:
    """Create a SQLAlchemy ``Engine`` from a URL string."""
    url = make_url(database_url)
    kwargs: dict[str, object] = {"future": True, "echo": echo}

    if url.get_backend_name() == "sqlite":
        # SQLite needs ``check_same_thread=False`` to be safe across threads
        # used by the orchestrator's ThreadPoolExecutor (Phase 4).
        kwargs["connect_args"] = {"check_same_thread": False}
    else:
        # Pool sizing for networked backends. Conservative defaults; can be
        # tuned per-deployment via env later.
        kwargs["pool_pre_ping"] = True
        kwargs["pool_size"] = 5
        kwargs["max_overflow"] = 10

    logger.debug("Creating engine for %s://...", url.get_backend_name())
    return create_engine(url, **kwargs)


def create_engine_from_config(config: AppConfig, *, echo: bool = False) -> Engine:
    """Create a SQLAlchemy ``Engine`` from an :class:`AppConfig`."""
    return create_engine_from_url(config.resolve_database_url(), echo=echo)


def init_schema(engine: Engine) -> None:
    """Create all tables defined in :mod:`._metadata` if they don't yet exist.

    This is the cross-dialect equivalent of :meth:`DatabaseManager.initialize`
    for Postgres/MySQL deployments. For SQLite, prefer
    :class:`DatabaseManager` which manages the legacy migration ladder.
    """
    from domainraptor.storage._metadata import metadata

    metadata.create_all(engine)
    logger.info("SQLAlchemy schema ensured on %s", engine.url.get_backend_name())
