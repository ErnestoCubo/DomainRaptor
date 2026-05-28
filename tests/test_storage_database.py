"""Tests for database manager module."""

from __future__ import annotations

import sqlite3
import tempfile
from pathlib import Path

import pytest

from domainraptor.storage.database import (
    DEFAULT_DB_PATH,
    SCHEMA_VERSION,
    DatabaseManager,
)


class TestDefaultDatabasePath:
    """Tests for default database path constants."""

    def test_default_path_in_home(self) -> None:
        """Test default DB path is in user home."""
        assert str(Path.home()) in str(DEFAULT_DB_PATH)

    def test_default_path_has_extension(self) -> None:
        """Test default DB path has .db extension."""
        assert DEFAULT_DB_PATH.suffix == ".db"

    def test_schema_version_defined(self) -> None:
        """Test schema version is defined."""
        assert SCHEMA_VERSION >= 1


class TestDatabaseManager:
    """Tests for DatabaseManager class."""

    def test_manager_creation_default_path(self) -> None:
        """Test manager creation with default path."""
        manager = DatabaseManager()
        assert manager.db_path == DEFAULT_DB_PATH

    def test_manager_creation_custom_path(self) -> None:
        """Test manager creation with custom path."""
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test.db"
            manager = DatabaseManager(db_path=db_path)
            assert manager.db_path == db_path

    def test_manager_creation_string_path(self) -> None:
        """Test manager creation with string path."""
        with tempfile.TemporaryDirectory() as tmp:
            db_path = f"{tmp}/test.db"
            manager = DatabaseManager(db_path=db_path)
            assert str(manager.db_path) == db_path

    def test_manager_creates_parent_directory(self) -> None:
        """Test manager creates parent directory."""
        with tempfile.TemporaryDirectory() as tmp:
            nested_path = Path(tmp) / "nested" / "dir" / "test.db"
            DatabaseManager(db_path=nested_path)
            assert nested_path.parent.exists()

    def test_get_connection_returns_connection(self) -> None:
        """Test get_connection returns a connection."""
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test.db"
            manager = DatabaseManager(db_path=db_path)

            with manager.get_connection() as conn:
                assert isinstance(conn, sqlite3.Connection)
                # Should have row factory set
                assert conn.row_factory == sqlite3.Row

    def test_get_connection_commits_on_success(self) -> None:
        """Test get_connection commits on success."""
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test.db"
            manager = DatabaseManager(db_path=db_path)

            with manager.get_connection() as conn:
                conn.execute("CREATE TABLE test (id INTEGER)")
                conn.execute("INSERT INTO test VALUES (1)")

            # Verify data persisted
            with manager.get_connection() as conn:
                cursor = conn.execute("SELECT * FROM test")
                row = cursor.fetchone()
                assert row["id"] == 1

    def test_get_connection_rollback_on_error(self) -> None:
        """Test get_connection rolls back on error."""
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test.db"
            manager = DatabaseManager(db_path=db_path)

            # Create table first
            with manager.get_connection() as conn:
                conn.execute("CREATE TABLE test (id INTEGER)")

            # Try to insert and fail
            with pytest.raises(RuntimeError), manager.get_connection() as conn:
                conn.execute("INSERT INTO test VALUES (1)")
                raise RuntimeError("Trigger rollback")

            # Verify data was not persisted
            with manager.get_connection() as conn:
                cursor = conn.execute("SELECT COUNT(*) as cnt FROM test")
                row = cursor.fetchone()
                assert row["cnt"] == 0


class TestDatabaseManagerInitialize:
    """Tests for DatabaseManager.initialize method."""

    def test_initialize_creates_schema(self) -> None:
        """Test initialize creates database schema."""
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test.db"
            manager = DatabaseManager(db_path=db_path)
            manager.initialize()

            # Verify tables were created
            with manager.get_connection() as conn:
                cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
                tables = {row["name"] for row in cursor.fetchall()}

                assert "scans" in tables
                assert "assets" in tables
                assert "dns_records" in tables
                assert "certificates" in tables
                assert "config_issues" in tables
                assert "vulnerabilities" in tables
                assert "metadata" in tables

    def test_initialize_sets_schema_version(self) -> None:
        """Test initialize sets schema version."""
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test.db"
            manager = DatabaseManager(db_path=db_path)
            manager.initialize()

            with manager.get_connection() as conn:
                cursor = conn.execute("SELECT value FROM metadata WHERE key = 'schema_version'")
                row = cursor.fetchone()
                assert int(row["value"]) == SCHEMA_VERSION

    def test_initialize_idempotent(self) -> None:
        """Test initialize is idempotent."""
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test.db"
            manager = DatabaseManager(db_path=db_path)

            # Initialize twice
            manager.initialize()
            manager.initialize()

            # Should still work
            with manager.get_connection() as conn:
                cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
                tables = {row["name"] for row in cursor.fetchall()}
                assert "scans" in tables

    def test_initialize_creates_indexes(self) -> None:
        """Test initialize creates indexes."""
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test.db"
            manager = DatabaseManager(db_path=db_path)
            manager.initialize()

            with manager.get_connection() as conn:
                cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='index'")
                indexes = {row["name"] for row in cursor.fetchall()}

                assert "idx_scans_target" in indexes
                assert "idx_assets_scan_id" in indexes


class TestDatabaseManagerSchemaVersion:
    """Tests for schema version methods."""

    def test_get_schema_version_empty_db(self) -> None:
        """Test _get_schema_version returns 0 for empty database."""
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test.db"
            manager = DatabaseManager(db_path=db_path)

            with manager.get_connection() as conn:
                version = manager._get_schema_version(conn)
                assert version == 0

    def test_get_schema_version_after_init(self) -> None:
        """Test _get_schema_version after initialize."""
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test.db"
            manager = DatabaseManager(db_path=db_path)
            manager.initialize()

            with manager.get_connection() as conn:
                version = manager._get_schema_version(conn)
                assert version == SCHEMA_VERSION

    def test_set_schema_version(self) -> None:
        """Test _set_schema_version."""
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test.db"
            manager = DatabaseManager(db_path=db_path)
            manager.initialize()

            with manager.get_connection() as conn:
                manager._set_schema_version(conn, 99)
                version = manager._get_schema_version(conn)
                assert version == 99


class TestDatabaseForeignKeys:
    """Tests for foreign key constraints."""

    def test_foreign_keys_enabled(self) -> None:
        """Test foreign keys are enabled."""
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test.db"
            manager = DatabaseManager(db_path=db_path)
            manager.initialize()

            with manager.get_connection() as conn:
                cursor = conn.execute("PRAGMA foreign_keys")
                row = cursor.fetchone()
                assert row[0] == 1
