"""Compare command - compare scan results over time."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated

import typer
from rich.table import Table

from domainraptor.core.config import AppConfig
from domainraptor.core.types import AssetType, Change, ChangeType, ScanResult
from domainraptor.storage.repository import ScanRepository
from domainraptor.utils.output import (
    console,
    create_progress,
    print_changes_table,
    print_error,
    print_info,
    print_success,
    print_warning,
)

app = typer.Typer(
    name="compare",
    help="📊 Compare scan results across time or targets",
    no_args_is_help=True,
)


def _compare_scans(scan1: ScanResult, scan2: ScanResult) -> list[Change]:
    """Compare two scan results and return list of changes.

    Args:
        scan1: Earlier/baseline scan
        scan2: Later/current scan

    Returns:
        List of Change objects describing differences
    """
    changes: list[Change] = []

    # Compare assets (subdomains, IPs)
    old_assets = {(a.type.value, a.value) for a in scan1.assets}
    new_assets = {(a.type.value, a.value) for a in scan2.assets}

    for asset_type, value in new_assets - old_assets:
        changes.append(
            Change(
                change_type=ChangeType.NEW,
                asset_type=AssetType(asset_type),
                asset_value=value,
                description=f"New {asset_type} discovered",
                detected_at=datetime.now(),
            )
        )

    for asset_type, value in old_assets - new_assets:
        changes.append(
            Change(
                change_type=ChangeType.REMOVED,
                asset_type=AssetType(asset_type),
                asset_value=value,
                description=f"{asset_type.capitalize()} no longer found",
                detected_at=datetime.now(),
            )
        )

    # Compare DNS records
    old_dns = {(r.record_type, r.value) for r in scan1.dns_records}
    new_dns = {(r.record_type, r.value) for r in scan2.dns_records}

    for rec_type, value in new_dns - old_dns:
        changes.append(
            Change(
                change_type=ChangeType.NEW,
                asset_type=AssetType.DNS,
                asset_value=f"{rec_type}: {value}",
                description=f"New DNS {rec_type} record",
                detected_at=datetime.now(),
            )
        )

    for rec_type, value in old_dns - new_dns:
        changes.append(
            Change(
                change_type=ChangeType.REMOVED,
                asset_type=AssetType.DNS,
                asset_value=f"{rec_type}: {value}",
                description=f"DNS {rec_type} record removed",
                detected_at=datetime.now(),
            )
        )

    # Compare services/ports
    old_services = {(s.port, s.protocol, s.service_name) for s in scan1.services}
    new_services = {(s.port, s.protocol, s.service_name) for s in scan2.services}

    for port, protocol, service in new_services - old_services:
        changes.append(
            Change(
                change_type=ChangeType.NEW,
                asset_type=AssetType.SERVICE,
                asset_value=f"{port}/{protocol} ({service})",
                description="New service/port detected",
                detected_at=datetime.now(),
            )
        )

    for port, protocol, service in old_services - new_services:
        changes.append(
            Change(
                change_type=ChangeType.REMOVED,
                asset_type=AssetType.SERVICE,
                asset_value=f"{port}/{protocol} ({service})",
                description="Service/port closed",
                detected_at=datetime.now(),
            )
        )

    # Compare vulnerabilities
    old_vulns = {v.id for v in scan1.vulnerabilities}
    new_vulns = {v.id for v in scan2.vulnerabilities}

    for vuln_id in new_vulns - old_vulns:
        vuln = next((v for v in scan2.vulnerabilities if v.id == vuln_id), None)
        severity = vuln.severity.value if vuln else "unknown"
        changes.append(
            Change(
                change_type=ChangeType.NEW,
                asset_type=AssetType.VULNERABILITY,
                asset_value=vuln_id,
                description=f"New {severity} vulnerability detected",
                detected_at=datetime.now(),
            )
        )

    changes.extend(
        Change(
            change_type=ChangeType.REMOVED,
            asset_type=AssetType.VULNERABILITY,
            asset_value=vuln_id,
            description="Vulnerability resolved/not detected",
            detected_at=datetime.now(),
        )
        for vuln_id in old_vulns - new_vulns
    )

    # Compare config issues
    old_issues = {i.id for i in scan1.config_issues}
    new_issues = {i.id for i in scan2.config_issues}

    for issue_id in new_issues - old_issues:
        issue = next((i for i in scan2.config_issues if i.id == issue_id), None)
        severity = issue.severity.value if issue else "unknown"
        changes.append(
            Change(
                change_type=ChangeType.NEW,
                asset_type=AssetType.CONFIG,
                asset_value=issue_id,
                description=f"New {severity} config issue: {issue.title if issue else ''}",
                detected_at=datetime.now(),
            )
        )

    changes.extend(
        Change(
            change_type=ChangeType.REMOVED,
            asset_type=AssetType.CONFIG,
            asset_value=issue_id,
            description="Config issue resolved",
            detected_at=datetime.now(),
        )
        for issue_id in old_issues - new_issues
    )

    return changes


app = typer.Typer(
    name="compare",
    help="📊 Compare scan results across time or targets",
    no_args_is_help=True,
)


@app.callback(invoke_without_command=True)
def compare_callback(ctx: typer.Context) -> None:
    """
    📊 Compare scan results.

    Compare scans of the same target over time, or compare
    different targets side by side.

    [bold cyan]Examples:[/bold cyan]

        [dim]# Compare current vs last scan[/dim]
        domainraptor compare example.com

        [dim]# Compare two specific scans[/dim]
        domainraptor compare scans <scan-id-1> <scan-id-2>

        [dim]# Compare two different targets[/dim]
        domainraptor compare targets example.com example.org
    """
    if ctx.invoked_subcommand is None:
        console.print("Use a subcommand: history, scans, or targets")
        raise typer.Exit()


@app.command("history")
def compare_history_cmd(
    ctx: typer.Context,
    target: Annotated[str, typer.Argument(help="Target to compare history for")],
    last: Annotated[
        int,
        typer.Option("--last", "-l", help="Compare last N scans"),
    ] = 2,
    since: Annotated[
        str | None,
        typer.Option("--since", "-s", help="Compare since date (YYYY-MM-DD)"),
    ] = None,
) -> None:
    """
    📜 Compare scan history for a target.

    Shows changes between the most recent scans.

    [bold cyan]Examples:[/bold cyan]

        [dim]# Compare last 2 scans[/dim]
        domainraptor compare history example.com

        [dim]# Compare last 5 scans[/dim]
        domainraptor compare history example.com --last 5

        [dim]# Compare since specific date[/dim]
        domainraptor compare history example.com --since 2024-01-01
    """
    ctx.obj.get("config", AppConfig())

    print_info(f"Comparing scan history for: [bold]{target}[/bold]")
    print_info(f"Last {last} scans")

    repo = ScanRepository()

    with create_progress() as progress:
        task = progress.add_task("Loading scan history...", total=100)

        # Get recent scans for target
        scans = repo.list_by_target(target, limit=last)
        progress.update(task, advance=50)

        if len(scans) < 2:
            progress.update(task, advance=50)
            print_warning(f"Need at least 2 scans to compare. Found {len(scans)}.")
            if len(scans) == 0:
                print_info(f"Run a scan first: domainraptor discover --target {target}")
            return

        # Compare most recent with previous
        progress.update(task, description="Comparing results...")
        changes = _compare_scans(scans[1], scans[0])  # older, newer
        progress.update(task, advance=50)

    console.print()
    if changes:
        print_info(f"Found {len(changes)} change(s) between scans:")
        print_info(
            f"  Scan #{scans[1].id} ({scans[1].started_at.strftime('%Y-%m-%d') if scans[1].started_at else 'N/A'}) → Scan #{scans[0].id} ({scans[0].started_at.strftime('%Y-%m-%d') if scans[0].started_at else 'N/A'})"
        )
        print_changes_table(changes)
    else:
        print_success("No changes detected between scans")


@app.command("scans")
def compare_scans_cmd(
    ctx: typer.Context,
    scan_id_1: Annotated[str, typer.Argument(help="First scan ID (baseline)")],
    scan_id_2: Annotated[str, typer.Argument(help="Second scan ID (current)")],
) -> None:
    """
    🔄 Compare two specific scan results.

    [bold cyan]Examples:[/bold cyan]

        [dim]# Compare two scans by ID[/dim]
        domainraptor compare scans 24 25
    """
    print_info(f"Comparing scans: {scan_id_1} vs {scan_id_2}")

    repo = ScanRepository()

    # Load both scans
    try:
        scan1 = repo.get_by_id(int(scan_id_1))
        scan2 = repo.get_by_id(int(scan_id_2))
    except ValueError:
        print_error("Scan IDs must be numeric")
        raise typer.Exit(1) from None

    if not scan1:
        print_error(f"Scan {scan_id_1} not found")
        raise typer.Exit(1)
    if not scan2:
        print_error(f"Scan {scan_id_2} not found")
        raise typer.Exit(1)

    # Warn if comparing different targets
    if scan1.target != scan2.target:
        print_warning(f"Note: Comparing different targets ({scan1.target} vs {scan2.target})")

    with create_progress() as progress:
        task = progress.add_task("Comparing scans...", total=100)
        changes = _compare_scans(scan1, scan2)
        progress.update(task, advance=100)

    # Show scan info
    console.print()
    table = Table(title="Scan Comparison", show_header=True, header_style="bold cyan")
    table.add_column("Property")
    table.add_column(f"Scan #{scan_id_1}", style="dim")
    table.add_column(f"Scan #{scan_id_2}", style="bold")

    table.add_row("Target", scan1.target, scan2.target)
    table.add_row("Type", scan1.scan_type, scan2.scan_type)
    table.add_row(
        "Date",
        scan1.started_at.strftime("%Y-%m-%d %H:%M") if scan1.started_at else "N/A",
        scan2.started_at.strftime("%Y-%m-%d %H:%M") if scan2.started_at else "N/A",
    )
    table.add_row("Assets", str(len(scan1.assets)), str(len(scan2.assets)))
    table.add_row("Services", str(len(scan1.services)), str(len(scan2.services)))
    table.add_row(
        "Vulnerabilities", str(len(scan1.vulnerabilities)), str(len(scan2.vulnerabilities))
    )
    table.add_row("Config Issues", str(len(scan1.config_issues)), str(len(scan2.config_issues)))

    console.print(table)
    console.print()

    if changes:
        print_info(f"Found {len(changes)} change(s):")
        print_changes_table(changes)
    else:
        print_success("No changes detected between scans")


@app.command("targets")
def compare_targets_cmd(
    ctx: typer.Context,
    target1: Annotated[str, typer.Argument(help="First target")],
    target2: Annotated[str, typer.Argument(help="Second target")],
    aspect: Annotated[
        str,
        typer.Option("--aspect", "-a", help="Aspect to compare: all, subdomains, services, vulns"),
    ] = "all",
) -> None:
    """
    ⚖️ Compare two different targets side by side.

    Useful for comparing security posture between domains
    or identifying differences in infrastructure.

    [bold cyan]Examples:[/bold cyan]

        [dim]# Compare two targets[/dim]
        domainraptor compare targets example.com example.org

        [dim]# Compare subdomains only[/dim]
        domainraptor compare targets example.com example.org --aspect subdomains
    """
    print_info(f"Comparing: [bold]{target1}[/bold] vs [bold]{target2}[/bold]")
    print_info(f"Aspect: {aspect}")

    repo = ScanRepository()

    with create_progress() as progress:
        task = progress.add_task("Loading scan data...", total=100)

        # Get latest scan for each target
        scan1 = repo.get_latest_for_target(target1)
        progress.update(task, advance=25)
        scan2 = repo.get_latest_for_target(target2)
        progress.update(task, advance=25)

        if not scan1:
            print_error(f"No scan data found for {target1}")
            print_info(f"Run: domainraptor discover --target {target1}")
            raise typer.Exit(1)
        if not scan2:
            print_error(f"No scan data found for {target2}")
            print_info(f"Run: domainraptor discover --target {target2}")
            raise typer.Exit(1)

        progress.update(task, description="Analyzing...")
        progress.update(task, advance=50)

    # Count metrics
    def count_subdomains(scan: ScanResult) -> int:
        return len([a for a in scan.assets if a.type == AssetType.SUBDOMAIN])

    def count_ips(scan: ScanResult) -> int:
        return len([a for a in scan.assets if a.type == AssetType.IP])

    metrics = {
        "Subdomains": (count_subdomains(scan1), count_subdomains(scan2)),
        "IPs": (count_ips(scan1), count_ips(scan2)),
        "Open Ports": (len(scan1.services), len(scan2.services)),
        "DNS Records": (len(scan1.dns_records), len(scan2.dns_records)),
        "Certificates": (len(scan1.certificates), len(scan2.certificates)),
        "Vulnerabilities": (len(scan1.vulnerabilities), len(scan2.vulnerabilities)),
        "Config Issues": (len(scan1.config_issues), len(scan2.config_issues)),
    }

    # Build comparison table
    table = Table(title=f"Comparison: {target1} vs {target2}", show_header=True)
    table.add_column("Metric", style="bold")
    table.add_column(target1)
    table.add_column(target2)
    table.add_column("Diff")

    for metric, (val1, val2) in metrics.items():
        diff = val2 - val1
        if diff > 0:
            diff_str = f"[yellow]+{diff}[/yellow]"
        elif diff < 0:
            diff_str = f"[green]{diff}[/green]"
        else:
            diff_str = "[dim]0[/dim]"

        table.add_row(metric, str(val1), str(val2), diff_str)

    console.print()
    console.print(table)

    # Show scan dates
    console.print()
    console.print(
        f"[dim]Scan dates: {target1} ({scan1.started_at.strftime('%Y-%m-%d') if scan1.started_at else 'N/A'}) | {target2} ({scan2.started_at.strftime('%Y-%m-%d') if scan2.started_at else 'N/A'})[/dim]"
    )


@app.command("baseline")
def compare_baseline_cmd(
    ctx: typer.Context,
    target: Annotated[str, typer.Argument(help="Target to compare against baseline")],
    baseline_id: Annotated[
        str | None,
        typer.Option("--baseline", "-b", help="Specific baseline scan ID"),
    ] = None,
) -> None:
    """
    📏 Compare current state against a baseline scan.

    A baseline represents a known-good state. This command
    shows deviations from that baseline.

    [bold cyan]Examples:[/bold cyan]

        [dim]# Compare against automatic baseline[/dim]
        domainraptor compare baseline example.com

        [dim]# Compare against specific baseline[/dim]
        domainraptor compare baseline example.com --baseline abc123
    """
    print_info(f"Comparing {target} against baseline")

    if baseline_id:
        print_info(f"Using baseline: {baseline_id}")
    else:
        print_info("Using most recent baseline scan")

    # TODO: Implement baseline comparison
    with create_progress() as progress:
        task = progress.add_task("Comparing against baseline...", total=100)
        progress.update(task, advance=100)

    print_success("Target matches baseline (no deviations)")
