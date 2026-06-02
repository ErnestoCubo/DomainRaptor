"""Factories for storage repositories.

Selects the appropriate repository implementation based on the configured
``database_url``. SQLite URLs (the default) keep using the legacy
:mod:`sqlite3`-based :class:`~domainraptor.storage.repository.ScanRepository`
and :class:`~domainraptor.storage.repository.WatchRepository`. Non-SQLite
URLs return the SQLAlchemy-backed
:class:`~domainraptor.storage._sql_repository.SqlScanRepository` and
:class:`~domainraptor.storage._sql_repository.SqlWatchRepository`.

The legacy repositories remain the default to keep behaviour backwards
compatible for the existing user base. To opt into PostgreSQL or MySQL,
set ``DOMAINRAPTOR_DATABASE_URL`` or ``database_url`` in the config file.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from domainraptor.core.config import AppConfig
    from domainraptor.storage._sql_repository import (
        SqlScanRepository,
        SqlWatchRepository,
    )
    from domainraptor.storage.repository import ScanRepository, WatchRepository


@runtime_checkable
class ScanRepositoryProtocol(Protocol):
    """Subset of methods every scan repository must implement."""

    def save(self, scan): ...  # type: ignore[no-untyped-def]
    def get_by_id(self, scan_id: int): ...  # type: ignore[no-untyped-def]
    def list_scans(self, **kwargs): ...  # type: ignore[no-untyped-def]


def _is_sqlite_url(url: str) -> bool:
    return url.startswith("sqlite:")


def get_scan_repository(
    config: AppConfig | None = None,
) -> ScanRepository | SqlScanRepository:
    """Return a scan repository appropriate for the configured backend."""
    if config is None:
        from domainraptor.core.config import AppConfig as _AppConfig

        config = _AppConfig.load()

    url = config.resolve_database_url()
    if _is_sqlite_url(url):
        from domainraptor.storage.repository import ScanRepository

        return ScanRepository()

    from domainraptor.storage._engine import create_engine_from_config, init_schema
    from domainraptor.storage._sql_repository import SqlScanRepository

    engine = create_engine_from_config(config)
    init_schema(engine)
    return SqlScanRepository(engine)


def get_watch_repository(
    config: AppConfig | None = None,
) -> WatchRepository | SqlWatchRepository:
    """Return a watch repository appropriate for the configured backend."""
    if config is None:
        from domainraptor.core.config import AppConfig as _AppConfig

        config = _AppConfig.load()

    url = config.resolve_database_url()
    if _is_sqlite_url(url):
        from domainraptor.storage.repository import WatchRepository

        return WatchRepository()

    from domainraptor.storage._engine import create_engine_from_config, init_schema
    from domainraptor.storage._sql_repository import SqlWatchRepository

    engine = create_engine_from_config(config)
    init_schema(engine)
    return SqlWatchRepository(engine)


__all__ = [
    "ScanRepositoryProtocol",
    "get_scan_repository",
    "get_watch_repository",
]
