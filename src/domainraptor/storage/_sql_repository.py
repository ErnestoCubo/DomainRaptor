"""SQLAlchemy Core implementation of the storage repositories.

This module mirrors the public API of
:class:`domainraptor.storage.repository.ScanRepository` and
:class:`~domainraptor.storage.repository.WatchRepository` but uses a
SQLAlchemy ``Engine`` instead of raw :mod:`sqlite3`. It works against any
backend supported by the schema mirror in :mod:`._metadata`
(SQLite, PostgreSQL, MySQL).

The legacy SQLite-only repositories continue to exist for backwards
compatibility and as the default for users who have not configured a
``database_url``. Callers wanting cross-dialect support should construct
these classes directly with an :class:`~sqlalchemy.engine.Engine` produced
by :func:`domainraptor.storage._engine.create_engine_from_config`.
"""

from __future__ import annotations

import contextlib
import logging
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any

from sqlalchemy import delete, func, insert, select, update
from sqlalchemy.exc import IntegrityError

from domainraptor.core.types import (
    Asset,
    AssetType,
    Certificate,
    ConfigIssue,
    DnsRecord,
    ScanResult,
    Service,
    SeverityLevel,
    Vulnerability,
    WatchTarget,
)
from domainraptor.storage._metadata import (
    assets_table,
    certificates_table,
    config_issues_table,
    dns_records_table,
    scans_table,
    services_table,
    vulnerabilities_table,
    watch_targets_table,
)
from domainraptor.utils._serialization import json_dumps, json_loads_dict, json_loads_list

if TYPE_CHECKING:
    from sqlalchemy.engine import Engine, Row

logger = logging.getLogger(__name__)


def _dt_str(dt: datetime | None) -> str | None:
    return dt.isoformat() if dt else None


def _str_dt(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s)
    except ValueError:
        return None


class SqlScanRepository:
    """SQLAlchemy-backed implementation of ``ScanRepository``."""

    def __init__(self, engine: Engine) -> None:
        self.engine = engine

    # ------------------------------------------------------------------ save
    def save(self, scan: ScanResult) -> int:
        """Insert a scan and all related rows; return the new scan id."""
        with self.engine.begin() as conn:
            result = conn.execute(
                insert(scans_table).values(
                    target=scan.target,
                    scan_type=scan.scan_type,
                    status=scan.status,
                    started_at=_dt_str(scan.started_at),
                    completed_at=_dt_str(scan.completed_at),
                    duration_seconds=scan.duration_seconds,
                    error_count=len(scan.errors),
                    metadata=json_dumps(scan.metadata),
                )
            )
            scan_id = result.inserted_primary_key[0]
            if scan_id is None:
                raise RuntimeError("Failed to obtain scan_id from INSERT")

            for asset in scan.assets:
                self._insert_asset_ignore(conn, scan_id, asset)

            if scan.dns_records:
                conn.execute(
                    insert(dns_records_table),
                    [
                        {
                            "scan_id": scan_id,
                            "record_type": r.record_type,
                            "value": r.value,
                            "ttl": r.ttl,
                            "priority": r.priority,
                        }
                        for r in scan.dns_records
                    ],
                )

            if scan.certificates:
                conn.execute(
                    insert(certificates_table),
                    [
                        {
                            "scan_id": scan_id,
                            "subject": c.subject,
                            "issuer": c.issuer,
                            "serial_number": c.serial_number,
                            "not_before": _dt_str(c.not_before),
                            "not_after": _dt_str(c.not_after),
                            "san": json_dumps(c.san),
                            "fingerprint_sha256": c.fingerprint_sha256,
                            "is_expired": c.is_expired,
                            "days_until_expiry": c.days_until_expiry,
                        }
                        for c in scan.certificates
                    ],
                )

            if scan.config_issues:
                conn.execute(
                    insert(config_issues_table),
                    [
                        {
                            "scan_id": scan_id,
                            "issue_id": i.id,
                            "title": i.title,
                            "severity": i.severity.value,
                            "category": i.category,
                            "description": i.description,
                            "affected_asset": i.affected_asset,
                            "current_value": i.current_value,
                            "recommended_value": i.recommended_value,
                            "remediation": i.remediation,
                        }
                        for i in scan.config_issues
                    ],
                )

            if scan.vulnerabilities:
                conn.execute(
                    insert(vulnerabilities_table),
                    [
                        {
                            "scan_id": scan_id,
                            "vuln_id": v.id,
                            "title": v.title,
                            "severity": v.severity.value,
                            "description": v.description,
                            "affected_asset": v.affected_asset,
                            "cvss_score": v.cvss_score,
                            "cvss_vector": v.cvss_vector,
                            "vuln_references": json_dumps(v.references),
                            "remediation": v.remediation,
                            "detected_at": _dt_str(v.detected_at),
                            "source": v.source,
                            "epss_score": v.epss_score,
                            "in_cisa_kev": v.in_cisa_kev,
                            "exploit_refs": json_dumps(v.exploit_refs),
                        }
                        for v in scan.vulnerabilities
                    ],
                )

            if scan.services:
                conn.execute(
                    insert(services_table),
                    [
                        {
                            "scan_id": scan_id,
                            "ip": s.metadata.get("ip", ""),
                            "port": s.port,
                            "protocol": s.protocol,
                            "service_name": s.service_name,
                            "version": s.version,
                            "banner": s.banner,
                            "product": s.metadata.get("product", ""),
                            "os": s.metadata.get("os", ""),
                            "cpe": json_dumps(s.cpe),
                            "metadata": json_dumps(s.metadata),
                            "source": s.metadata.get("source", "shodan"),
                        }
                        for s in scan.services
                    ],
                )

            logger.info("Saved scan %s for target %s", scan_id, scan.target)
            return int(scan_id)

    def _insert_asset_ignore(self, conn: Any, scan_id: int, asset: Asset) -> None:
        """INSERT OR IGNORE-equivalent across dialects, for assets uniqueness."""
        values = {
            "scan_id": scan_id,
            "type": asset.type.value,
            "value": asset.value,
            "parent": asset.parent,
            "source": asset.source,
            "first_seen": _dt_str(asset.first_seen),
            "last_seen": _dt_str(asset.last_seen),
            "metadata": json_dumps(asset.metadata),
        }
        dialect = conn.dialect.name
        if dialect == "sqlite":
            from sqlalchemy.dialects.sqlite import insert as sqlite_insert

            stmt = (
                sqlite_insert(assets_table)
                .values(**values)
                .on_conflict_do_nothing(
                    index_elements=["scan_id", "type", "value"],
                )
            )
            conn.execute(stmt)
        elif dialect == "postgresql":
            from sqlalchemy.dialects.postgresql import insert as pg_insert

            stmt = (
                pg_insert(assets_table)
                .values(**values)
                .on_conflict_do_nothing(
                    index_elements=["scan_id", "type", "value"],
                )
            )
            conn.execute(stmt)
        elif dialect == "mysql":
            from sqlalchemy.dialects.mysql import insert as mysql_insert

            stmt = mysql_insert(assets_table).values(**values).prefix_with("IGNORE")
            conn.execute(stmt)
        else:
            with contextlib.suppress(IntegrityError):
                conn.execute(insert(assets_table).values(**values))

    # ---------------------------------------------------------------- get_by_id
    def get_by_id(self, scan_id: int) -> ScanResult | None:
        with self.engine.connect() as conn:
            row = (
                conn.execute(select(scans_table).where(scans_table.c.id == scan_id))
                .mappings()
                .first()
            )
            if not row:
                return None

            scan = ScanResult(
                target=row["target"],
                scan_type=row["scan_type"],
                status=row["status"],
                started_at=_str_dt(row["started_at"]) or datetime.now(),
                completed_at=_str_dt(row["completed_at"]),
                metadata=json_loads_dict(row["metadata"]),
            )

            for a in conn.execute(
                select(assets_table).where(assets_table.c.scan_id == scan_id)
            ).mappings():
                scan.assets.append(
                    Asset(
                        type=AssetType(a["type"]),
                        value=a["value"],
                        parent=a["parent"],
                        source=a["source"],
                        first_seen=_str_dt(a["first_seen"]) or datetime.now(),
                        last_seen=_str_dt(a["last_seen"]) or datetime.now(),
                        metadata=json_loads_dict(a["metadata"]),
                    )
                )

            for d in conn.execute(
                select(dns_records_table).where(dns_records_table.c.scan_id == scan_id)
            ).mappings():
                scan.dns_records.append(
                    DnsRecord(
                        record_type=d["record_type"],
                        value=d["value"],
                        ttl=d["ttl"],
                        priority=d["priority"],
                    )
                )

            for c in conn.execute(
                select(certificates_table).where(certificates_table.c.scan_id == scan_id)
            ).mappings():
                scan.certificates.append(
                    Certificate(
                        subject=c["subject"],
                        issuer=c["issuer"],
                        serial_number=c["serial_number"],
                        not_before=_str_dt(c["not_before"]) or datetime.now(),
                        not_after=_str_dt(c["not_after"]) or datetime.now(),
                        san=json_loads_list(c["san"]),
                        fingerprint_sha256=c["fingerprint_sha256"] or "",
                        is_expired=bool(c["is_expired"]),
                        days_until_expiry=c["days_until_expiry"] or 0,
                    )
                )

            for i in conn.execute(
                select(config_issues_table).where(config_issues_table.c.scan_id == scan_id)
            ).mappings():
                scan.config_issues.append(
                    ConfigIssue(
                        id=i["issue_id"],
                        title=i["title"],
                        severity=SeverityLevel(i["severity"]),
                        category=i["category"],
                        description=i["description"] or "",
                        affected_asset=i["affected_asset"] or "",
                        current_value=i["current_value"] or "",
                        recommended_value=i["recommended_value"] or "",
                        remediation=i["remediation"] or "",
                    )
                )

            for v in conn.execute(
                select(vulnerabilities_table).where(vulnerabilities_table.c.scan_id == scan_id)
            ).mappings():
                scan.vulnerabilities.append(
                    Vulnerability(
                        id=v["vuln_id"],
                        title=v["title"],
                        severity=SeverityLevel(v["severity"]),
                        description=v["description"] or "",
                        affected_asset=v["affected_asset"] or "",
                        cvss_score=v["cvss_score"],
                        cvss_vector=v["cvss_vector"] or "",
                        references=json_loads_list(v["vuln_references"]),
                        remediation=v["remediation"] or "",
                        detected_at=_str_dt(v["detected_at"]) or datetime.now(),
                        source=v["source"] or "",
                        epss_score=v["epss_score"],
                        in_cisa_kev=bool(v["in_cisa_kev"]),
                        exploit_refs=json_loads_list(v["exploit_refs"]),
                    )
                )

            for s in conn.execute(
                select(services_table).where(services_table.c.scan_id == scan_id)
            ).mappings():
                metadata = json_loads_dict(s["metadata"])
                metadata["ip"] = s["ip"]
                metadata["product"] = s["product"] or ""
                metadata["os"] = s["os"] or ""
                metadata["source"] = s["source"] or "shodan"
                scan.services.append(
                    Service(
                        port=s["port"],
                        protocol=s["protocol"] or "tcp",
                        service_name=s["service_name"] or "",
                        version=s["version"] or "",
                        banner=s["banner"] or "",
                        cpe=json_loads_list(s["cpe"]),
                        metadata=metadata,
                    )
                )

            return scan

    # ---------------------------------------------------------------- listings
    def list_scans(
        self,
        target: str | None = None,
        scan_type: str | None = None,
        status: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """List scans with optional filters, returning summary dicts."""
        asset_count = (
            select(func.count())
            .select_from(assets_table)
            .where(assets_table.c.scan_id == scans_table.c.id)
            .scalar_subquery()
            .label("asset_count")
        )
        issue_count = (
            select(func.count())
            .select_from(config_issues_table)
            .where(config_issues_table.c.scan_id == scans_table.c.id)
            .scalar_subquery()
            .label("issue_count")
        )
        vuln_count = (
            select(func.count())
            .select_from(vulnerabilities_table)
            .where(vulnerabilities_table.c.scan_id == scans_table.c.id)
            .scalar_subquery()
            .label("vuln_count")
        )

        stmt = select(scans_table, asset_count, issue_count, vuln_count)
        if target:
            stmt = stmt.where(scans_table.c.target.like(f"%{target}%"))
        if scan_type:
            stmt = stmt.where(scans_table.c.scan_type == scan_type)
        if status:
            stmt = stmt.where(scans_table.c.status == status)
        stmt = stmt.order_by(scans_table.c.started_at.desc()).limit(limit).offset(offset)

        with self.engine.connect() as conn:
            return [dict(row) for row in conn.execute(stmt).mappings()]

    def get_latest_for_target(self, target: str, scan_type: str | None = None) -> ScanResult | None:
        stmt = select(scans_table.c.id).where(scans_table.c.target == target)
        if scan_type:
            stmt = stmt.where(scans_table.c.scan_type == scan_type)
        stmt = stmt.order_by(scans_table.c.started_at.desc()).limit(1)

        with self.engine.connect() as conn:
            row = conn.execute(stmt).first()
        if row is None:
            return None
        return self.get_by_id(int(row[0]))

    def list_by_target(self, target: str, limit: int = 10) -> list[ScanResult]:
        stmt = (
            select(scans_table.c.id)
            .where(scans_table.c.target == target)
            .order_by(scans_table.c.started_at.desc())
            .limit(limit)
        )
        with self.engine.connect() as conn:
            ids = [int(r[0]) for r in conn.execute(stmt)]
        results: list[ScanResult] = []
        for sid in ids:
            s = self.get_by_id(sid)
            if s:
                results.append(s)
        return results

    # ------------------------------------------------------------------ writes
    def delete(self, scan_id: int) -> bool:
        with self.engine.begin() as conn:
            # Cascade not portable across all dialects/configurations; emulate
            # by explicitly deleting children first.
            for child in (
                assets_table,
                dns_records_table,
                certificates_table,
                config_issues_table,
                vulnerabilities_table,
                services_table,
            ):
                conn.execute(delete(child).where(child.c.scan_id == scan_id))
            result = conn.execute(delete(scans_table).where(scans_table.c.id == scan_id))
            deleted = (result.rowcount or 0) > 0
        if deleted:
            logger.info("Deleted scan %s", scan_id)
        return deleted

    def prune(self, older_than_days: int) -> int:
        cutoff = (datetime.now() - timedelta(days=older_than_days)).isoformat()
        # Select target ids first so we can use `delete()` and cascade in Python.
        with self.engine.connect() as conn:
            ids = [
                int(r[0])
                for r in conn.execute(
                    select(scans_table.c.id).where(scans_table.c.started_at < cutoff)
                )
            ]
        count = 0
        for sid in ids:
            if self.delete(sid):
                count += 1
        if count > 0:
            logger.info("Pruned %s scans older than %s days", count, older_than_days)
        return count

    def count_by_target(self, target: str) -> int:
        with self.engine.connect() as conn:
            return int(
                conn.execute(
                    select(func.count())
                    .select_from(scans_table)
                    .where(scans_table.c.target == target)
                ).scalar_one()
            )

    # --------------------------------------------------------------- export
    def export_to_json(self, scan_id: int) -> dict[str, Any] | None:
        scan = self.get_by_id(scan_id)
        if not scan:
            return None
        return {
            "target": scan.target,
            "scan_type": scan.scan_type,
            "status": scan.status,
            "started_at": _dt_str(scan.started_at),
            "completed_at": _dt_str(scan.completed_at),
            "duration_seconds": scan.duration_seconds,
            "summary": {
                "assets": len(scan.assets),
                "dns_records": len(scan.dns_records),
                "certificates": len(scan.certificates),
                "config_issues": len(scan.config_issues),
                "vulnerabilities": len(scan.vulnerabilities),
            },
            "assets": [
                {"type": a.type.value, "value": a.value, "parent": a.parent, "source": a.source}
                for a in scan.assets
            ],
            "dns_records": [
                {"type": r.record_type, "value": r.value, "ttl": r.ttl, "priority": r.priority}
                for r in scan.dns_records
            ],
            "certificates": [
                {
                    "subject": c.subject,
                    "issuer": c.issuer,
                    "not_after": _dt_str(c.not_after),
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


def _row_to_watch_target(row: Row[Any] | Any) -> WatchTarget:
    return WatchTarget(
        target=row["target"],
        watch_type=row["watch_type"],
        interval_hours=row["interval_hours"],
        last_check=_str_dt(row["last_check"]),
        next_check=_str_dt(row["next_check"]),
        enabled=bool(row["enabled"]),
        notify_on=json_loads_list(row["notify_on"]),
        metadata=json_loads_dict(row["metadata"]),
    )


class SqlWatchRepository:
    """SQLAlchemy-backed implementation of ``WatchRepository``."""

    def __init__(self, engine: Engine) -> None:
        self.engine = engine

    def add(self, target: WatchTarget) -> int:
        with self.engine.begin() as conn:
            result = conn.execute(
                insert(watch_targets_table).values(
                    target=target.target,
                    watch_type=target.watch_type,
                    interval_hours=target.interval_hours,
                    last_check=_dt_str(target.last_check),
                    next_check=_dt_str(target.next_check),
                    enabled=target.enabled,
                    notify_on=json_dumps(target.notify_on),
                    metadata=json_dumps(target.metadata),
                )
            )
            return int(result.inserted_primary_key[0] or 0)

    def get_by_target(self, target: str) -> WatchTarget | None:
        with self.engine.connect() as conn:
            row = (
                conn.execute(
                    select(watch_targets_table).where(watch_targets_table.c.target == target)
                )
                .mappings()
                .first()
            )
            return _row_to_watch_target(row) if row else None

    def list_all(self, enabled_only: bool = False) -> list[WatchTarget]:
        stmt = select(watch_targets_table)
        if enabled_only:
            stmt = stmt.where(watch_targets_table.c.enabled.is_(True))
        stmt = stmt.order_by(watch_targets_table.c.target)
        with self.engine.connect() as conn:
            return [_row_to_watch_target(r) for r in conn.execute(stmt).mappings()]

    def get_due_for_check(self) -> list[WatchTarget]:
        now_iso = datetime.now().isoformat()
        stmt = (
            select(watch_targets_table)
            .where(watch_targets_table.c.enabled.is_(True))
            .where(
                (watch_targets_table.c.next_check.is_(None))
                | (watch_targets_table.c.next_check <= now_iso)
            )
            .order_by(watch_targets_table.c.next_check)
        )
        with self.engine.connect() as conn:
            return [_row_to_watch_target(r) for r in conn.execute(stmt).mappings()]

    def update_check_time(self, target: str, checked_at: datetime) -> None:
        wt = self.get_by_target(target)
        if not wt:
            return
        next_check = checked_at + timedelta(hours=wt.interval_hours)
        with self.engine.begin() as conn:
            conn.execute(
                update(watch_targets_table)
                .where(watch_targets_table.c.target == target)
                .values(
                    last_check=_dt_str(checked_at),
                    next_check=_dt_str(next_check),
                )
            )

    def remove(self, target: str) -> bool:
        with self.engine.begin() as conn:
            result = conn.execute(
                delete(watch_targets_table).where(watch_targets_table.c.target == target)
            )
            return (result.rowcount or 0) > 0

    def set_enabled(self, target: str, enabled: bool) -> bool:
        with self.engine.begin() as conn:
            result = conn.execute(
                update(watch_targets_table)
                .where(watch_targets_table.c.target == target)
                .values(enabled=enabled)
            )
            return (result.rowcount or 0) > 0

    def count(self) -> int:
        with self.engine.connect() as conn:
            return int(
                conn.execute(select(func.count()).select_from(watch_targets_table)).scalar_one()
            )


__all__ = ["SqlScanRepository", "SqlWatchRepository"]
