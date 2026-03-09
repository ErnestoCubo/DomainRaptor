"""Repository classes for database operations."""

from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import Any

from domainraptor.core.types import (
    Asset,
    AssetType,
    Certificate,
    ConfigIssue,
    DnsRecord,
    ScanResult,
    SeverityLevel,
    Vulnerability,
    WatchTarget,
)
from domainraptor.storage.database import DatabaseManager, get_database

logger = logging.getLogger(__name__)


def _datetime_to_str(dt: datetime | None) -> str | None:
    """Convert datetime to ISO string."""
    return dt.isoformat() if dt else None


def _str_to_datetime(s: str | None) -> datetime | None:
    """Convert ISO string to datetime."""
    if not s:
        return None
    try:
        return datetime.fromisoformat(s)
    except ValueError:
        return None


class ScanRepository:
    """Repository for scan operations."""

    def __init__(self, db: DatabaseManager | None = None) -> None:
        self.db = db or get_database()

    def save(self, scan: ScanResult) -> int:
        """Save a scan result and all related data.

        Returns the scan ID.
        """
        with self.db.get_connection() as conn:
            # Insert scan
            cursor = conn.execute(
                """
                INSERT INTO scans (target, scan_type, status, started_at, completed_at,
                                   duration_seconds, error_count, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan.target,
                    scan.scan_type,
                    scan.status,
                    _datetime_to_str(scan.started_at),
                    _datetime_to_str(scan.completed_at),
                    scan.duration_seconds,
                    len(scan.errors),
                    json.dumps(scan.metadata),
                ),
            )
            scan_id = cursor.lastrowid
            assert scan_id is not None

            # Insert assets
            for asset in scan.assets:
                conn.execute(
                    """
                    INSERT OR IGNORE INTO assets
                    (scan_id, type, value, parent, source, first_seen, last_seen, metadata)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        scan_id,
                        asset.type.value,
                        asset.value,
                        asset.parent,
                        asset.source,
                        _datetime_to_str(asset.first_seen),
                        _datetime_to_str(asset.last_seen),
                        json.dumps(asset.metadata),
                    ),
                )

            # Insert DNS records
            for record in scan.dns_records:
                conn.execute(
                    """
                    INSERT INTO dns_records (scan_id, record_type, value, ttl, priority)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (scan_id, record.record_type, record.value, record.ttl, record.priority),
                )

            # Insert certificates
            for cert in scan.certificates:
                conn.execute(
                    """
                    INSERT INTO certificates
                    (scan_id, subject, issuer, serial_number, not_before, not_after,
                     san, fingerprint_sha256, is_expired, days_until_expiry)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        scan_id,
                        cert.subject,
                        cert.issuer,
                        cert.serial_number,
                        _datetime_to_str(cert.not_before),
                        _datetime_to_str(cert.not_after),
                        json.dumps(cert.san),
                        cert.fingerprint_sha256,
                        1 if cert.is_expired else 0,
                        cert.days_until_expiry,
                    ),
                )

            # Insert config issues
            for issue in scan.config_issues:
                conn.execute(
                    """
                    INSERT INTO config_issues
                    (scan_id, issue_id, title, severity, category, description,
                     affected_asset, current_value, recommended_value, remediation)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        scan_id,
                        issue.id,
                        issue.title,
                        issue.severity.value,
                        issue.category,
                        issue.description,
                        issue.affected_asset,
                        issue.current_value,
                        issue.recommended_value,
                        issue.remediation,
                    ),
                )

            # Insert vulnerabilities
            for vuln in scan.vulnerabilities:
                conn.execute(
                    """
                    INSERT INTO vulnerabilities
                    (scan_id, vuln_id, title, severity, description, affected_asset,
                     cvss_score, cvss_vector, vuln_references, remediation, detected_at, source)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        scan_id,
                        vuln.id,
                        vuln.title,
                        vuln.severity.value,
                        vuln.description,
                        vuln.affected_asset,
                        vuln.cvss_score,
                        vuln.cvss_vector,
                        json.dumps(vuln.references),
                        vuln.remediation,
                        _datetime_to_str(vuln.detected_at),
                        vuln.source,
                    ),
                )

            logger.info(f"Saved scan {scan_id} for target {scan.target}")
            return scan_id

    def get_by_id(self, scan_id: int) -> ScanResult | None:
        """Get a scan by ID with all related data."""
        with self.db.get_connection() as conn:
            # Get scan
            cursor = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
            row = cursor.fetchone()
            if not row:
                return None

            scan = ScanResult(
                target=row["target"],
                scan_type=row["scan_type"],
                status=row["status"],
                started_at=_str_to_datetime(row["started_at"]) or datetime.now(),
                completed_at=_str_to_datetime(row["completed_at"]),
                metadata=json.loads(row["metadata"] or "{}"),
            )

            # Load assets
            for asset_row in conn.execute(
                "SELECT * FROM assets WHERE scan_id = ?", (scan_id,)
            ):
                scan.assets.append(
                    Asset(
                        type=AssetType(asset_row["type"]),
                        value=asset_row["value"],
                        parent=asset_row["parent"],
                        source=asset_row["source"],
                        first_seen=_str_to_datetime(asset_row["first_seen"]) or datetime.now(),
                        last_seen=_str_to_datetime(asset_row["last_seen"]) or datetime.now(),
                        metadata=json.loads(asset_row["metadata"] or "{}"),
                    )
                )

            # Load DNS records
            for dns_row in conn.execute(
                "SELECT * FROM dns_records WHERE scan_id = ?", (scan_id,)
            ):
                scan.dns_records.append(
                    DnsRecord(
                        record_type=dns_row["record_type"],
                        value=dns_row["value"],
                        ttl=dns_row["ttl"],
                        priority=dns_row["priority"],
                    )
                )

            # Load certificates
            for cert_row in conn.execute(
                "SELECT * FROM certificates WHERE scan_id = ?", (scan_id,)
            ):
                scan.certificates.append(
                    Certificate(
                        subject=cert_row["subject"],
                        issuer=cert_row["issuer"],
                        serial_number=cert_row["serial_number"],
                        not_before=_str_to_datetime(cert_row["not_before"]) or datetime.now(),
                        not_after=_str_to_datetime(cert_row["not_after"]) or datetime.now(),
                        san=json.loads(cert_row["san"] or "[]"),
                        fingerprint_sha256=cert_row["fingerprint_sha256"] or "",
                        is_expired=bool(cert_row["is_expired"]),
                        days_until_expiry=cert_row["days_until_expiry"] or 0,
                    )
                )

            # Load config issues
            for issue_row in conn.execute(
                "SELECT * FROM config_issues WHERE scan_id = ?", (scan_id,)
            ):
                scan.config_issues.append(
                    ConfigIssue(
                        id=issue_row["issue_id"],
                        title=issue_row["title"],
                        severity=SeverityLevel(issue_row["severity"]),
                        category=issue_row["category"],
                        description=issue_row["description"] or "",
                        affected_asset=issue_row["affected_asset"] or "",
                        current_value=issue_row["current_value"] or "",
                        recommended_value=issue_row["recommended_value"] or "",
                        remediation=issue_row["remediation"] or "",
                    )
                )

            # Load vulnerabilities
            for vuln_row in conn.execute(
                "SELECT * FROM vulnerabilities WHERE scan_id = ?", (scan_id,)
            ):
                scan.vulnerabilities.append(
                    Vulnerability(
                        id=vuln_row["vuln_id"],
                        title=vuln_row["title"],
                        severity=SeverityLevel(vuln_row["severity"]),
                        description=vuln_row["description"] or "",
                        affected_asset=vuln_row["affected_asset"] or "",
                        cvss_score=vuln_row["cvss_score"],
                        cvss_vector=vuln_row["cvss_vector"] or "",
                        references=json.loads(vuln_row["vuln_references"] or "[]"),
                        remediation=vuln_row["remediation"] or "",
                        detected_at=_str_to_datetime(vuln_row["detected_at"]) or datetime.now(),
                        source=vuln_row["source"] or "",
                    )
                )

            return scan

    def list_scans(
        self,
        target: str | None = None,
        scan_type: str | None = None,
        status: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """List scans with optional filters.

        Returns summary dicts (not full ScanResult objects).
        """
        with self.db.get_connection() as conn:
            query = """
                SELECT s.*,
                       (SELECT COUNT(*) FROM assets WHERE scan_id = s.id) as asset_count,
                       (SELECT COUNT(*) FROM config_issues WHERE scan_id = s.id) as issue_count,
                       (SELECT COUNT(*) FROM vulnerabilities WHERE scan_id = s.id) as vuln_count
                FROM scans s
                WHERE 1=1
            """
            params: list[Any] = []

            if target:
                query += " AND s.target LIKE ?"
                params.append(f"%{target}%")
            if scan_type:
                query += " AND s.scan_type = ?"
                params.append(scan_type)
            if status:
                query += " AND s.status = ?"
                params.append(status)

            query += " ORDER BY s.started_at DESC LIMIT ? OFFSET ?"
            params.extend([limit, offset])

            cursor = conn.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]

    def get_latest_for_target(self, target: str, scan_type: str | None = None) -> ScanResult | None:
        """Get the most recent scan for a target."""
        with self.db.get_connection() as conn:
            query = """
                SELECT id FROM scans
                WHERE target = ?
            """
            params: list[Any] = [target]

            if scan_type:
                query += " AND scan_type = ?"
                params.append(scan_type)

            query += " ORDER BY started_at DESC LIMIT 1"

            cursor = conn.execute(query, params)
            row = cursor.fetchone()
            if row:
                return self.get_by_id(row["id"])
            return None

    def delete(self, scan_id: int) -> bool:
        """Delete a scan and all related data."""
        with self.db.get_connection() as conn:
            cursor = conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
            deleted = cursor.rowcount > 0
            if deleted:
                logger.info(f"Deleted scan {scan_id}")
            return deleted

    def prune(self, older_than_days: int) -> int:
        """Delete scans older than specified days.

        Returns number of scans deleted.
        """
        with self.db.get_connection() as conn:
            cutoff = datetime.now()
            cutoff = cutoff.replace(
                day=cutoff.day - older_than_days if cutoff.day > older_than_days else 1
            )
            # Use date arithmetic in SQL for proper handling
            cursor = conn.execute(
                """
                DELETE FROM scans
                WHERE datetime(started_at) < datetime('now', ?)
                """,
                (f"-{older_than_days} days",),
            )
            count = cursor.rowcount
            if count > 0:
                logger.info(f"Pruned {count} scans older than {older_than_days} days")
            return count

    def count_by_target(self, target: str) -> int:
        """Count scans for a target."""
        with self.db.get_connection() as conn:
            cursor = conn.execute(
                "SELECT COUNT(*) as count FROM scans WHERE target = ?",
                (target,),
            )
            return cursor.fetchone()["count"]

    def export_to_json(self, scan_id: int) -> dict[str, Any] | None:
        """Export a scan to JSON-serializable dict."""
        scan = self.get_by_id(scan_id)
        if not scan:
            return None

        return {
            "target": scan.target,
            "scan_type": scan.scan_type,
            "status": scan.status,
            "started_at": _datetime_to_str(scan.started_at),
            "completed_at": _datetime_to_str(scan.completed_at),
            "duration_seconds": scan.duration_seconds,
            "summary": {
                "assets": len(scan.assets),
                "dns_records": len(scan.dns_records),
                "certificates": len(scan.certificates),
                "config_issues": len(scan.config_issues),
                "vulnerabilities": len(scan.vulnerabilities),
            },
            "assets": [
                {
                    "type": a.type.value,
                    "value": a.value,
                    "parent": a.parent,
                    "source": a.source,
                }
                for a in scan.assets
            ],
            "dns_records": [
                {
                    "type": r.record_type,
                    "value": r.value,
                    "ttl": r.ttl,
                    "priority": r.priority,
                }
                for r in scan.dns_records
            ],
            "certificates": [
                {
                    "subject": c.subject,
                    "issuer": c.issuer,
                    "not_after": _datetime_to_str(c.not_after),
                    "san": c.san,
                    "is_expired": c.is_expired,
                    "days_until_expiry": c.days_until_expiry,
                }
                for c in scan.certificates
            ],
            "config_issues": [
                {
                    "id": i.id,
                    "title": i.title,
                    "severity": i.severity.value,
                    "category": i.category,
                    "affected_asset": i.affected_asset,
                    "remediation": i.remediation,
                }
                for i in scan.config_issues
            ],
            "vulnerabilities": [
                {
                    "id": v.id,
                    "title": v.title,
                    "severity": v.severity.value,
                    "cvss_score": v.cvss_score,
                    "affected_asset": v.affected_asset,
                }
                for v in scan.vulnerabilities
            ],
            "metadata": scan.metadata,
        }


class WatchRepository:
    """Repository for watch target operations."""

    def __init__(self, db: DatabaseManager | None = None) -> None:
        self.db = db or get_database()

    def add(self, target: WatchTarget) -> int:
        """Add a watch target. Returns the ID."""
        with self.db.get_connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO watch_targets
                (target, watch_type, interval_hours, last_check, next_check,
                 enabled, notify_on, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    target.target,
                    target.watch_type,
                    target.interval_hours,
                    _datetime_to_str(target.last_check),
                    _datetime_to_str(target.next_check),
                    1 if target.enabled else 0,
                    json.dumps(target.notify_on),
                    json.dumps(target.metadata),
                ),
            )
            return cursor.lastrowid or 0

    def get_by_target(self, target: str) -> WatchTarget | None:
        """Get watch target by target name."""
        with self.db.get_connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM watch_targets WHERE target = ?", (target,)
            )
            row = cursor.fetchone()
            if not row:
                return None

            return WatchTarget(
                target=row["target"],
                watch_type=row["watch_type"],
                interval_hours=row["interval_hours"],
                last_check=_str_to_datetime(row["last_check"]),
                next_check=_str_to_datetime(row["next_check"]),
                enabled=bool(row["enabled"]),
                notify_on=json.loads(row["notify_on"] or "[]"),
                metadata=json.loads(row["metadata"] or "{}"),
            )

    def list_all(self, enabled_only: bool = False) -> list[WatchTarget]:
        """List all watch targets."""
        with self.db.get_connection() as conn:
            query = "SELECT * FROM watch_targets"
            if enabled_only:
                query += " WHERE enabled = 1"
            query += " ORDER BY target"

            targets = []
            for row in conn.execute(query):
                targets.append(
                    WatchTarget(
                        target=row["target"],
                        watch_type=row["watch_type"],
                        interval_hours=row["interval_hours"],
                        last_check=_str_to_datetime(row["last_check"]),
                        next_check=_str_to_datetime(row["next_check"]),
                        enabled=bool(row["enabled"]),
                        notify_on=json.loads(row["notify_on"] or "[]"),
                        metadata=json.loads(row["metadata"] or "{}"),
                    )
                )
            return targets

    def get_due_for_check(self) -> list[WatchTarget]:
        """Get watch targets due for checking."""
        with self.db.get_connection() as conn:
            cursor = conn.execute(
                """
                SELECT * FROM watch_targets
                WHERE enabled = 1
                  AND (next_check IS NULL OR datetime(next_check) <= datetime('now'))
                ORDER BY next_check
                """
            )

            targets = []
            for row in cursor:
                targets.append(
                    WatchTarget(
                        target=row["target"],
                        watch_type=row["watch_type"],
                        interval_hours=row["interval_hours"],
                        last_check=_str_to_datetime(row["last_check"]),
                        next_check=_str_to_datetime(row["next_check"]),
                        enabled=bool(row["enabled"]),
                        notify_on=json.loads(row["notify_on"] or "[]"),
                        metadata=json.loads(row["metadata"] or "{}"),
                    )
                )
            return targets

    def update_check_time(self, target: str, checked_at: datetime) -> None:
        """Update last check time and calculate next check."""
        watch_target = self.get_by_target(target)
        if not watch_target:
            return

        from datetime import timedelta
        next_check = checked_at + timedelta(hours=watch_target.interval_hours)

        with self.db.get_connection() as conn:
            conn.execute(
                """
                UPDATE watch_targets
                SET last_check = ?, next_check = ?
                WHERE target = ?
                """,
                (_datetime_to_str(checked_at), _datetime_to_str(next_check), target),
            )

    def remove(self, target: str) -> bool:
        """Remove a watch target."""
        with self.db.get_connection() as conn:
            cursor = conn.execute(
                "DELETE FROM watch_targets WHERE target = ?", (target,)
            )
            return cursor.rowcount > 0

    def set_enabled(self, target: str, enabled: bool) -> bool:
        """Enable or disable a watch target."""
        with self.db.get_connection() as conn:
            cursor = conn.execute(
                "UPDATE watch_targets SET enabled = ? WHERE target = ?",
                (1 if enabled else 0, target),
            )
            return cursor.rowcount > 0

    def count(self) -> int:
        """Count total watch targets."""
        with self.db.get_connection() as conn:
            cursor = conn.execute("SELECT COUNT(*) as count FROM watch_targets")
            return cursor.fetchone()["count"]
