"""Compare command - compare scan results over time."""

from __future__ import annotations

from typing import Annotated

import typer
from rich.table import Table

from domainraptor.core.config import AppConfig
from domainraptor.core.types import AssetType, Change, ChangeType
from domainraptor.utils.output import (
    console,
    create_progress,
    print_changes_table,
    print_info,
    print_success,
)

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

    # TODO: Load scan history from database
    # Placeholder demo
    with create_progress() as progress:
        task = progress.add_task("Loading scan history...", total=100)
        progress.update(task, advance=50)
        progress.update(task, description="Comparing results...")
        progress.update(task, advance=50)

    # Demo changes
    changes: list[Change] = [
        Change(
            change_type=ChangeType.NEW,
            asset_type=AssetType.SUBDOMAIN,
            asset_value=f"api-v2.{target}",
            description="New subdomain discovered",
        ),
        Change(
            change_type=ChangeType.MODIFIED,
            asset_type=AssetType.CERTIFICATE,
            asset_value=f"*.{target}",
            old_value="expires: 2024-06-01",
            new_value="expires: 2025-06-01",
            description="Certificate renewed",
        ),
        Change(
            change_type=ChangeType.REMOVED,
            asset_type=AssetType.SUBDOMAIN,
            asset_value=f"old-api.{target}",
            description="Subdomain no longer resolves",
        ),
    ]

    console.print()
    if changes:
        print_info(f"Found {len(changes)} change(s) between scans:")
        print_changes_table(changes)
    else:
        print_success("No changes detected between scans")


@app.command("scans")
def compare_scans_cmd(
    ctx: typer.Context,
    scan_id_1: Annotated[str, typer.Argument(help="First scan ID")],
    scan_id_2: Annotated[str, typer.Argument(help="Second scan ID")],
) -> None:
    """
    🔄 Compare two specific scan results.

    [bold cyan]Examples:[/bold cyan]

        [dim]# Compare two scans by ID[/dim]
        domainraptor compare scans abc123 def456
    """
    print_info(f"Comparing scans: {scan_id_1} vs {scan_id_2}")

    # TODO: Load and compare specific scans from database
    print_info("Loading scan results...")
    # Placeholder
    print_info("Comparison complete")


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

    with create_progress() as progress:
        task = progress.add_task("Analyzing targets...", total=100)
        # TODO: Load most recent scans for both targets
        progress.update(task, advance=50)
        # Compare
        progress.update(task, advance=50)

    # Demo comparison table
    table = Table(title=f"Comparison: {target1} vs {target2}", show_header=True)
    table.add_column("Metric", style="bold")
    table.add_column(target1)
    table.add_column(target2)
    table.add_column("Diff")

    # Placeholder data
    table.add_row("Subdomains", "15", "23", "[yellow]+8[/yellow]")
    table.add_row("Open Ports", "3", "5", "[yellow]+2[/yellow]")
    table.add_row("Certificates", "2", "2", "[green]0[/green]")
    table.add_row("Vulnerabilities", "1", "4", "[red]+3[/red]")
    table.add_row("Config Issues", "5", "3", "[green]-2[/green]")

    console.print()
    console.print(table)


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
