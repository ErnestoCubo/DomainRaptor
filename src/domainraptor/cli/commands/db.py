"""Database management commands."""

from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Annotated

import typer
from rich.table import Table

from domainraptor.utils.output import (
    console,
    print_config_issues_table,
    print_error,
    print_info,
    print_success,
    print_vulnerabilities_table,
    print_warning,
)

logger = logging.getLogger(__name__)

app = typer.Typer(
    name="db",
    help="💾 Database management commands",
    no_args_is_help=True,
)


@app.command("list")
def list_scans_cmd(
    target: Annotated[
        str | None,
        typer.Option("--target", "-t", help="Filter by target domain"),
    ] = None,
    scan_type: Annotated[
        str | None,
        typer.Option("--type", help="Filter by scan type (discover, assess)"),
    ] = None,
    limit: Annotated[
        int,
        typer.Option("--limit", "-n", help="Maximum number of results"),
    ] = 20,
) -> None:
    """
    📋 List stored scans.

    [bold cyan]Examples:[/bold cyan]

        [dim]# List recent scans[/dim]
        domainraptor db list

        [dim]# Filter by target[/dim]
        domainraptor db list --target example.com

        [dim]# List discovery scans only[/dim]
        domainraptor db list --type discover
    """
    from domainraptor.storage import ScanRepository

    repo = ScanRepository()
    scans = repo.list_scans(target=target, scan_type=scan_type, limit=limit)

    if not scans:
        print_warning("No scans found")
        return

    table = Table(title="Stored Scans")
    table.add_column("ID", style="cyan", justify="right")
    table.add_column("Target", style="green")
    table.add_column("Type", style="yellow")
    table.add_column("Status", style="dim")
    table.add_column("Date", style="dim")
    table.add_column("Assets", justify="right")
    table.add_column("Issues", justify="right")
    table.add_column("Vulns", justify="right")

    for scan in scans:
        started = scan.get("started_at", "")
        if started:
            try:
                dt = datetime.fromisoformat(started)
                started = dt.strftime("%Y-%m-%d %H:%M")
            except ValueError:
                logger.debug(f"Failed to parse date: {started}")

        table.add_row(
            str(scan["id"]),
            scan["target"],
            scan["scan_type"],
            scan["status"],
            started,
            str(scan.get("asset_count", 0)),
            str(scan.get("issue_count", 0)),
            str(scan.get("vuln_count", 0)),
        )

    console.print(table)
    print_info(f"Showing {len(scans)} scan(s)")


@app.command("show")
def show_scan_cmd(
    scan_id: Annotated[int, typer.Argument(help="Scan ID to display")],
    full: Annotated[
        bool,
        typer.Option("--full", "-f", help="Show full details including all assets"),
    ] = False,
) -> None:
    """
    🔍 Show details of a specific scan.

    [bold cyan]Examples:[/bold cyan]

        [dim]# Show scan summary[/dim]
        domainraptor db show 1

        [dim]# Show full scan details[/dim]
        domainraptor db show 1 --full
    """
    from rich.panel import Panel

    from domainraptor.storage import ScanRepository

    repo = ScanRepository()
    scan = repo.get_by_id(scan_id)

    if not scan:
        print_error(f"Scan {scan_id} not found")
        raise typer.Exit(1)

    # Header info
    started = scan.started_at.strftime("%Y-%m-%d %H:%M:%S") if scan.started_at else "N/A"
    completed = scan.completed_at.strftime("%Y-%m-%d %H:%M:%S") if scan.completed_at else "N/A"
    duration = f"{scan.duration_seconds:.1f}s" if scan.duration_seconds else "N/A"

    info_table = Table(show_header=False, box=None)
    info_table.add_column("Field", style="cyan")
    info_table.add_column("Value", style="green")

    info_table.add_row("Target", scan.target)
    info_table.add_row("Type", scan.scan_type)
    info_table.add_row("Status", scan.status)
    info_table.add_row("Started", started)
    info_table.add_row("Completed", completed)
    info_table.add_row("Duration", duration)

    console.print(Panel(info_table, title=f"Scan #{scan_id}"))

    # Summary counts
    console.print("\n[bold]Summary:[/bold]")
    console.print(f"  Assets: {len(scan.assets)}")
    console.print(f"  DNS Records: {len(scan.dns_records)}")
    console.print(f"  Certificates: {len(scan.certificates)}")
    console.print(f"  Config Issues: {len(scan.config_issues)}")
    console.print(f"  Vulnerabilities: {len(scan.vulnerabilities)}")

    if full:
        # Show assets
        if scan.assets:
            asset_table = Table(title="\nAssets")
            asset_table.add_column("Type", style="cyan")
            asset_table.add_column("Value", style="green")
            asset_table.add_column("Source", style="dim")

            for asset in scan.assets[:50]:  # Limit to 50
                asset_table.add_row(asset.type.value, asset.value, asset.source or "-")

            console.print(asset_table)
            if len(scan.assets) > 50:
                print_info(f"... and {len(scan.assets) - 50} more assets")

        # Show issues
        if scan.config_issues:
            console.print()
            print_config_issues_table(scan.config_issues)

        # Show vulnerabilities
        if scan.vulnerabilities:
            console.print()
            print_vulnerabilities_table(scan.vulnerabilities)


@app.command("delete")
def delete_scan_cmd(
    scan_id: Annotated[int, typer.Argument(help="Scan ID to delete")],
    force: Annotated[
        bool,
        typer.Option("--force", "-f", help="Skip confirmation"),
    ] = False,
) -> None:
    """
    🗑️ Delete a scan from the database.

    [bold cyan]Examples:[/bold cyan]

        [dim]# Delete with confirmation[/dim]
        domainraptor db delete 1

        [dim]# Force delete without confirmation[/dim]
        domainraptor db delete 1 --force
    """
    from domainraptor.storage import ScanRepository

    repo = ScanRepository()

    # Check if scan exists
    scan = repo.get_by_id(scan_id)
    if not scan:
        print_error(f"Scan {scan_id} not found")
        raise typer.Exit(1)

    if not force:
        confirm = typer.confirm(f"Delete scan {scan_id} ({scan.target}, {scan.scan_type})?")
        if not confirm:
            print_info("Cancelled")
            raise typer.Exit(0)

    if repo.delete(scan_id):
        print_success(f"Deleted scan {scan_id}")
    else:
        print_error(f"Failed to delete scan {scan_id}")


@app.command("export")
def export_scan_cmd(
    scan_id: Annotated[int, typer.Argument(help="Scan ID to export")],
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Output file path"),
    ] = None,
    format: Annotated[
        str,
        typer.Option("--format", "-f", help="Output format: json, csv"),
    ] = "json",
) -> None:
    """
    📤 Export a scan to file.

    [bold cyan]Examples:[/bold cyan]

        [dim]# Export to JSON (stdout)[/dim]
        domainraptor db export 1

        [dim]# Export to file[/dim]
        domainraptor db export 1 -o scan_results.json

        [dim]# Export as CSV[/dim]
        domainraptor db export 1 -f csv -o results.csv
    """
    from domainraptor.storage import ScanRepository

    repo = ScanRepository()
    data = repo.export_to_json(scan_id)

    if not data:
        print_error(f"Scan {scan_id} not found")
        raise typer.Exit(1)

    if format == "json":
        json_str = json.dumps(data, indent=2)
        if output:
            output.write_text(json_str)
            print_success(f"Exported scan {scan_id} to {output}")
        else:
            console.print(json_str)

    elif format == "csv":
        import csv
        import io

        # Flatten for CSV
        rows: list[dict[str, str]] = []

        # Assets
        rows.extend(
            {
                "category": "asset",
                "type": asset["type"],
                "value": asset["value"],
                "source": asset.get("source", ""),
            }
            for asset in data.get("assets", [])
        )

        # DNS records
        rows.extend(
            {
                "category": "dns",
                "type": rec["type"],
                "value": rec["value"],
                "extra": str(rec.get("ttl", "")),
            }
            for rec in data.get("dns_records", [])
        )

        # Issues
        rows.extend(
            {
                "category": "issue",
                "type": issue["category"],
                "value": issue["title"],
                "severity": issue["severity"],
            }
            for issue in data.get("config_issues", [])
        )

        # Vulnerabilities
        rows.extend(
            {
                "category": "vulnerability",
                "type": vuln["id"],
                "value": vuln["title"],
                "severity": vuln["severity"],
            }
            for vuln in data.get("vulnerabilities", [])
        )

        if output:
            with output.open("w", newline="") as f:
                if rows:
                    writer = csv.DictWriter(f, fieldnames=rows[0].keys())
                    writer.writeheader()
                    writer.writerows(rows)
            print_success(f"Exported scan {scan_id} to {output}")
        else:
            # Write to stdout
            output_buffer = io.StringIO()
            if rows:
                writer = csv.DictWriter(output_buffer, fieldnames=rows[0].keys())
                writer.writeheader()
                writer.writerows(rows)
            console.print(output_buffer.getvalue())
    else:
        print_error(f"Unknown format: {format}")
        raise typer.Exit(1)


@app.command("prune")
def prune_scans_cmd(
    older_than: Annotated[
        int,
        typer.Option("--older-than", "-d", help="Delete scans older than N days"),
    ] = 30,
    force: Annotated[
        bool,
        typer.Option("--force", "-f", help="Skip confirmation"),
    ] = False,
) -> None:
    """
    🧹 Delete old scans from the database.

    [bold cyan]Examples:[/bold cyan]

        [dim]# Delete scans older than 30 days[/dim]
        domainraptor db prune

        [dim]# Delete scans older than 7 days[/dim]
        domainraptor db prune --older-than 7

        [dim]# Force prune without confirmation[/dim]
        domainraptor db prune -d 14 --force
    """
    from domainraptor.storage import ScanRepository

    repo = ScanRepository()

    if not force:
        confirm = typer.confirm(f"Delete all scans older than {older_than} days?")
        if not confirm:
            print_info("Cancelled")
            raise typer.Exit(0)

    count = repo.prune(older_than)
    if count > 0:
        print_success(f"Pruned {count} old scan(s)")
    else:
        print_info("No scans to prune")


@app.command("stats")
def stats_cmd() -> None:
    """
    📊 Show database statistics.

    Displays storage statistics including total scans, targets,
    and database size.
    """
    from domainraptor.storage import ScanRepository, WatchRepository, get_database

    scan_repo = ScanRepository()
    watch_repo = WatchRepository()

    scans = scan_repo.list_scans(limit=10000)

    # Count unique targets
    targets = {s["target"] for s in scans}

    # Count by type
    by_type: dict[str, int] = {}
    for scan in scans:
        scan_type = scan["scan_type"]
        by_type[scan_type] = by_type.get(scan_type, 0) + 1

    # Watch targets
    watch_count = watch_repo.count()

    # Database file size
    db = get_database()
    db_size = "Unknown"
    db_path = db.db_path
    if db_path and db_path.exists():
        size_bytes = db_path.stat().st_size
        if size_bytes < 1024:
            db_size = f"{size_bytes} B"
        elif size_bytes < 1024 * 1024:
            db_size = f"{size_bytes / 1024:.1f} KB"
        else:
            db_size = f"{size_bytes / (1024 * 1024):.1f} MB"

    console.print("[bold]Database Statistics[/bold]\n")
    console.print(f"  Total scans: {len(scans)}")
    console.print(f"  Unique targets: {len(targets)}")
    console.print(f"  Watch targets: {watch_count}")
    console.print(f"  Database size: {db_size}")

    if by_type:
        console.print("\n[bold]Scans by Type:[/bold]")
        for scan_type, count in sorted(by_type.items()):
            console.print(f"  {scan_type}: {count}")

    print_info(f"\nDatabase location: {db_path}")
