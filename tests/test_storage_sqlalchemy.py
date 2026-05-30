"""Tests for SQLAlchemy schema mirror and engine factory."""

from __future__ import annotations

from sqlalchemy import inspect

from domainraptor.core.config import AppConfig
from domainraptor.storage._engine import (
    create_engine_from_config,
    create_engine_from_url,
    init_schema,
)
from domainraptor.storage._metadata import SCHEMA_VERSION, metadata


def test_metadata_contains_all_tables() -> None:
    expected = {
        "metadata",
        "scans",
        "assets",
        "dns_records",
        "certificates",
        "config_issues",
        "vulnerabilities",
        "watch_targets",
        "services",
    }
    assert expected.issubset(set(metadata.tables.keys()))


def test_schema_version_constant() -> None:
    assert SCHEMA_VERSION == 3


def test_create_engine_from_url_sqlite_memory() -> None:
    engine = create_engine_from_url("sqlite:///:memory:")
    assert engine.url.get_backend_name() == "sqlite"
    engine.dispose()


def test_create_engine_from_config_uses_db_path(tmp_path) -> None:
    cfg = AppConfig(db_path=tmp_path / "test.db")
    engine = create_engine_from_config(cfg)
    assert engine.url.get_backend_name() == "sqlite"
    assert "test.db" in str(engine.url)
    engine.dispose()


def test_create_engine_from_config_respects_database_url(tmp_path) -> None:
    cfg = AppConfig(db_path=tmp_path / "ignored.db", database_url="sqlite:///:memory:")
    engine = create_engine_from_config(cfg)
    assert ":memory:" in str(engine.url)
    engine.dispose()


def test_init_schema_creates_all_tables() -> None:
    engine = create_engine_from_url("sqlite:///:memory:")
    init_schema(engine)
    inspector = inspect(engine)
    tables = set(inspector.get_table_names())
    assert {
        "metadata",
        "scans",
        "assets",
        "dns_records",
        "certificates",
        "config_issues",
        "vulnerabilities",
        "watch_targets",
        "services",
    }.issubset(tables)
    engine.dispose()


def test_init_schema_creates_expected_indexes() -> None:
    engine = create_engine_from_url("sqlite:///:memory:")
    init_schema(engine)
    inspector = inspect(engine)
    scan_indexes = {idx["name"] for idx in inspector.get_indexes("scans")}
    assert {"idx_scans_target", "idx_scans_type", "idx_scans_status"}.issubset(scan_indexes)
    engine.dispose()
