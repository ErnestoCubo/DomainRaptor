"""SQLite database manager for DomainRaptor."""

from __future__ import annotations

import logging
import sqlite3
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Current schema version for migrations
SCHEMA_VERSION = 1

# Default database location
DEFAULT_DB_PATH = Path.home() / ".domainraptor" / "domainraptor.db"


class DatabaseManager:
    """Manages SQLite database connections and schema."""

    def __init__(self, db_path: Path | str | None = None) -> None:
        """Initialize database manager.

        Args:
            db_path: Path to database file. Defaults to ~/.domainraptor/domainraptor.db
        """
        self.db_path = Path(db_path) if db_path else DEFAULT_DB_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._connection: sqlite3.Connection | None = None

    @contextmanager
    def get_connection(self) -> Generator[sqlite3.Connection, None, None]:
        """Get a database connection with row factory."""
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def initialize(self) -> None:
        """Initialize database schema."""
        with self.get_connection() as conn:
            # Check current version
            current_version = self._get_schema_version(conn)

            if current_version == 0:
                # Fresh install
                self._create_schema(conn)
                self._set_schema_version(conn, SCHEMA_VERSION)
                logger.info(f"Database initialized at {self.db_path}")
            elif current_version < SCHEMA_VERSION:
                # Migration needed
                self._migrate_schema(conn, current_version, SCHEMA_VERSION)
                self._set_schema_version(conn, SCHEMA_VERSION)
                logger.info(f"Database migrated to version {SCHEMA_VERSION}")

    def _get_schema_version(self, conn: sqlite3.Connection) -> int:
        """Get current schema version."""
        try:
            cursor = conn.execute("SELECT value FROM metadata WHERE key = 'schema_version'")
            row = cursor.fetchone()
            return int(row["value"]) if row else 0
        except sqlite3.OperationalError:
            return 0

    def _set_schema_version(self, conn: sqlite3.Connection, version: int) -> None:
        """Set schema version in metadata."""
        conn.execute(
            """
            INSERT OR REPLACE INTO metadata (key, value)
            VALUES ('schema_version', ?)
            """,
            (str(version),),
        )

    def _create_schema(self, conn: sqlite3.Connection) -> None:
        """Create database schema from scratch."""
        conn.executescript(
            """
            -- Metadata table for schema versioning
            CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            -- Scans table - main scan records
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                scan_type TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'running',
                started_at TEXT NOT NULL,
                completed_at TEXT,
                duration_seconds REAL,
                error_count INTEGER DEFAULT 0,
                metadata TEXT DEFAULT '{}',
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target);
            CREATE INDEX IF NOT EXISTS idx_scans_type ON scans(scan_type);
            CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
            CREATE INDEX IF NOT EXISTS idx_scans_started_at ON scans(started_at);

            -- Assets table - discovered assets
            CREATE TABLE IF NOT EXISTS assets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                type TEXT NOT NULL,
                value TEXT NOT NULL,
                parent TEXT,
                source TEXT DEFAULT 'unknown',
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                metadata TEXT DEFAULT '{}',
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
                UNIQUE (scan_id, type, value)
            );

            CREATE INDEX IF NOT EXISTS idx_assets_scan_id ON assets(scan_id);
            CREATE INDEX IF NOT EXISTS idx_assets_type ON assets(type);
            CREATE INDEX IF NOT EXISTS idx_assets_value ON assets(value);

            -- DNS records table
            CREATE TABLE IF NOT EXISTS dns_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                record_type TEXT NOT NULL,
                value TEXT NOT NULL,
                ttl INTEGER,
                priority INTEGER,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_dns_scan_id ON dns_records(scan_id);

            -- Certificates table
            CREATE TABLE IF NOT EXISTS certificates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                subject TEXT NOT NULL,
                issuer TEXT NOT NULL,
                serial_number TEXT NOT NULL,
                not_before TEXT NOT NULL,
                not_after TEXT NOT NULL,
                san TEXT DEFAULT '[]',
                fingerprint_sha256 TEXT,
                is_expired INTEGER DEFAULT 0,
                days_until_expiry INTEGER,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_certs_scan_id ON certificates(scan_id);

            -- Config issues table
            CREATE TABLE IF NOT EXISTS config_issues (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                issue_id TEXT NOT NULL,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                category TEXT NOT NULL,
                description TEXT,
                affected_asset TEXT,
                current_value TEXT,
                recommended_value TEXT,
                remediation TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_issues_scan_id ON config_issues(scan_id);
            CREATE INDEX IF NOT EXISTS idx_issues_severity ON config_issues(severity);
            CREATE INDEX IF NOT EXISTS idx_issues_category ON config_issues(category);

            -- Vulnerabilities table
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                vuln_id TEXT NOT NULL,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT,
                affected_asset TEXT,
                cvss_score REAL,
                cvss_vector TEXT,
                vuln_references TEXT DEFAULT '[]',
                remediation TEXT,
                detected_at TEXT NOT NULL,
                source TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_vulns_scan_id ON vulnerabilities(scan_id);
            CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulnerabilities(severity);

            -- Watch targets table
            CREATE TABLE IF NOT EXISTS watch_targets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL UNIQUE,
                watch_type TEXT NOT NULL DEFAULT 'domain',
                interval_hours INTEGER NOT NULL DEFAULT 24,
                last_check TEXT,
                next_check TEXT,
                enabled INTEGER NOT NULL DEFAULT 1,
                notify_on TEXT DEFAULT '["new", "removed", "modified"]',
                metadata TEXT DEFAULT '{}',
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE INDEX IF NOT EXISTS idx_watch_target ON watch_targets(target);
            CREATE INDEX IF NOT EXISTS idx_watch_enabled ON watch_targets(enabled);
            CREATE INDEX IF NOT EXISTS idx_watch_next_check ON watch_targets(next_check);
            """
        )

    def _migrate_schema(self, conn: sqlite3.Connection, from_version: int, to_version: int) -> None:
        """Run schema migrations."""
        # Add migrations here as needed
        # for version in range(from_version + 1, to_version + 1):
        #     if version == 2:
        #         self._migrate_to_v2(conn)
        pass

    def get_stats(self) -> dict[str, Any]:
        """Get database statistics."""
        with self.get_connection() as conn:
            stats = {}

            # Count records in each table
            for table in [
                "scans",
                "assets",
                "dns_records",
                "certificates",
                "config_issues",
                "vulnerabilities",
                "watch_targets",
            ]:
                cursor = conn.execute(f"SELECT COUNT(*) as count FROM {table}")
                stats[table] = cursor.fetchone()["count"]

            # Database file size
            stats["file_size_bytes"] = self.db_path.stat().st_size if self.db_path.exists() else 0

            return stats

    def vacuum(self) -> None:
        """Compact the database."""
        with self.get_connection() as conn:
            conn.execute("VACUUM")
            logger.info("Database vacuumed")


# Singleton instance
_db_manager: DatabaseManager | None = None


def get_database(db_path: Path | str | None = None) -> DatabaseManager:
    """Get or create the database manager singleton."""
    global _db_manager
    if _db_manager is None:
        _db_manager = DatabaseManager(db_path)
        _db_manager.initialize()
    return _db_manager


def reset_database() -> None:
    """Reset the singleton (for testing)."""
    global _db_manager
    _db_manager = None
