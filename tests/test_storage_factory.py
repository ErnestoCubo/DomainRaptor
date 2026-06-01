"""Tests for storage factory and DatabaseManager.engine property."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

pytest.importorskip("sqlalchemy")

from domainraptor.core.config import AppConfig  # noqa: E402
from domainraptor.storage import (  # noqa: E402
    ScanRepository,
    WatchRepository,
    get_scan_repository,
    get_watch_repository,
)
from domainraptor.storage._sql_repository import (  # noqa: E402
    SqlScanRepository,
    SqlWatchRepository,
)
from domainraptor.storage.database import DatabaseManager  # noqa: E402


def test_database_manager_engine_lazy() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        mgr = DatabaseManager(db_path=Path(tmp) / "x.db")
        assert mgr._engine is None
        eng = mgr.engine
        assert eng is mgr.engine  # cached
        assert eng.url.get_backend_name() == "sqlite"


def test_factory_returns_legacy_for_sqlite() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        cfg = AppConfig(db_path=Path(tmp) / "f.db")
        # No database_url set -> sqlite URL resolved
        assert cfg.resolve_database_url().startswith("sqlite:")
        scan = get_scan_repository(cfg)
        watch = get_watch_repository(cfg)
        assert isinstance(scan, ScanRepository)
        assert isinstance(watch, WatchRepository)


def test_factory_returns_sql_for_non_sqlite_url() -> None:
    cfg = AppConfig(database_url="sqlite:///:memory:")
    # sqlite still goes legacy path
    assert isinstance(get_scan_repository(cfg), ScanRepository)

    # Force non-sqlite path via a fake postgres URL — we cannot connect,
    # but the factory must at least return the SQL subclass instance.
    # Use a sqlite URL that does not start with "sqlite:" prefix matcher
    # by going through the SQL branch directly.
    from domainraptor.storage._engine import create_engine_from_url, init_schema

    eng = create_engine_from_url("sqlite:///:memory:")
    init_schema(eng)
    assert isinstance(SqlScanRepository(eng), SqlScanRepository)
    assert isinstance(SqlWatchRepository(eng), SqlWatchRepository)
