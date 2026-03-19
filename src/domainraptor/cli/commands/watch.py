"""Watch command - continuous monitoring for changes."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Annotated

import typer
from rich.table import Table

from domainraptor.core.config import AppConfig
from domainraptor.core.types import AssetType, Change, ChangeType, WatchTarget
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
    name="watch",
    help="👁️ Monitor targets for changes and anomalies",
    no_args_is_help=True,
)


# In-memory storage for demo (will be replaced with database)
_watch_targets: dict[str, WatchTarget] = {}


@app.callback(invoke_without_command=True)
def watch_callback(ctx: typer.Context) -> None:
    """
    👁️ Monitor targets for changes.

    Set up continuous monitoring to detect:
    • New/removed subdomains
    • DNS record changes
    • Certificate expirations
    • New open ports
    • Configuration changes

    [bold cyan]Examples:[/bold cyan]

        [dim]# Add a domain to watch list[/dim]
        domainraptor watch add example.com

        [dim]# List all watched targets[/dim]
        domainraptor watch list

        [dim]# Run checks on watched targets[/dim]
        domainraptor watch run

        [dim]# Remove a target[/dim]
        domainraptor watch remove example.com
    """
    if ctx.invoked_subcommand is None:
        # Show list by default
        list_cmd(ctx)


@app.command("add")
def add_cmd(
    ctx: typer.Context,
    target: Annotated[str, typer.Argument(help="Target to watch")],
    interval: Annotated[
        str,
        typer.Option("--interval", "-i", help="Check interval (e.g., 1h, 6h, 24h, 7d)"),
    ] = "24h",
    watch_type: Annotated[
        str,
        typer.Option("--type", "-t", help="Watch type: domain, ip, certificate"),
    ] = "domain",
    notify: Annotated[
        str | None,
        typer.Option("--notify", "-n", help="Notification channel (email, webhook, slack)"),
    ] = None,
    tags: Annotated[
        str | None,
        typer.Option("--tags", help="Comma-separated tags for organization"),
    ] = None,
) -> None:
    """
    [+] Add a target to the watch list.

    [bold cyan]Interval formats:[/bold cyan]
        • 1h  - Every hour
        • 6h  - Every 6 hours
        • 24h - Daily (default)
        • 7d  - Weekly

    [bold cyan]Examples:[/bold cyan]

        [dim]# Watch domain daily[/dim]
        domainraptor watch add example.com

        [dim]# Watch every 6 hours[/dim]
        domainraptor watch add example.com --interval 6h

        [dim]# Watch certificate expiration[/dim]
        domainraptor watch add example.com --type certificate
    """
    ctx.obj.get("config", AppConfig())

    # Parse interval
    interval_hours = _parse_interval(interval)
    if interval_hours is None:
        print_error(f"Invalid interval format: {interval}")
        raise typer.Exit(1)

    # Check if already watching
    if target in _watch_targets:
        print_warning(f"Already watching: {target}")
        if not typer.confirm("Update existing watch?"):
            raise typer.Exit(0)

    # Create watch target
    watch_target = WatchTarget(
        target=target,
        watch_type=watch_type,
        interval_hours=interval_hours,
        next_check=datetime.now(),
        metadata={
            "notify": notify,
            "tags": tags.split(",") if tags else [],
        },
    )

    _watch_targets[target] = watch_target

    # Perform initial scan
    print_info(f"Adding {target} to watch list (interval: {interval})")

    with create_progress() as progress:
        task = progress.add_task("Performing initial scan...", total=100)
        # TODO: Perform actual initial scan
        progress.update(task, advance=100)

    print_success(f"Now watching: {target}")
    print_info(f"Next check: {watch_target.next_check}")

    # TODO: Save to database


@app.command("remove")
def remove_cmd(
    ctx: typer.Context,
    target: Annotated[str, typer.Argument(help="Target to remove from watch list")],
    force: Annotated[
        bool,
        typer.Option("--force", "-f", help="Remove without confirmation"),
    ] = False,
) -> None:
    """[-] Remove a target from the watch list."""
    if target not in _watch_targets:
        print_error(f"Not watching: {target}")
        raise typer.Exit(1)

    if not force and not typer.confirm(f"Remove {target} from watch list?"):
        raise typer.Exit(0)

    del _watch_targets[target]
    print_success(f"Removed: {target}")
    # TODO: Remove from database


@app.command("list")
def list_cmd(ctx: typer.Context) -> None:
    """📋 List all watched targets."""
    # TODO: Load from database
    if not _watch_targets:
        print_info("No targets being watched")
        print_info("Add targets with: domainraptor watch add <target>")
        return

    table = Table(title="Watched Targets", show_header=True, header_style="bold cyan")
    table.add_column("Target", style="bold")
    table.add_column("Type")
    table.add_column("Interval")
    table.add_column("Last Check")
    table.add_column("Next Check")
    table.add_column("Status")

    for target, wt in _watch_targets.items():
        last_check = wt.last_check.strftime("%Y-%m-%d %H:%M") if wt.last_check else "Never"
        next_check = wt.next_check.strftime("%Y-%m-%d %H:%M") if wt.next_check else "-"
        status = "[green]Active[/green]" if wt.enabled else "[dim]Paused[/dim]"

        table.add_row(
            target,
            wt.watch_type,
            f"{wt.interval_hours}h",
            last_check,
            next_check,
            status,
        )

    console.print(table)


@app.command("run")
def run_cmd(
    ctx: typer.Context,
    target: Annotated[
        str | None,
        typer.Argument(help="Specific target to check (default: all due)"),
    ] = None,
    force: Annotated[
        bool,
        typer.Option("--force", "-f", help="Force check even if not due"),
    ] = False,
) -> None:
    """
    ▶️ Run checks on watched targets.

    By default, only checks targets that are due for checking.
    Use --force to check regardless of schedule.

    [bold cyan]Examples:[/bold cyan]

        [dim]# Check all due targets[/dim]
        domainraptor watch run

        [dim]# Force check specific target[/dim]
        domainraptor watch run example.com --force

        [dim]# Force check all targets[/dim]
        domainraptor watch run --force
    """
    config: AppConfig = ctx.obj.get("config", AppConfig())

    targets_to_check = []

    if target:
        if target not in _watch_targets:
            print_error(f"Not watching: {target}")
            raise typer.Exit(1)
        targets_to_check = [_watch_targets[target]]
    else:
        now = datetime.now()
        for wt in _watch_targets.values():
            if force or (wt.next_check and wt.next_check <= now):
                targets_to_check.append(wt)

    if not targets_to_check:
        print_info("No targets due for checking")
        return

    print_info(f"Checking {len(targets_to_check)} target(s)...")

    all_changes: list[Change] = []

    with create_progress() as progress:
        task = progress.add_task("Running checks...", total=len(targets_to_check))

        for wt in targets_to_check:
            progress.update(task, description=f"Checking {wt.target}...")

            # Perform check
            changes = _check_target(wt, config)
            all_changes.extend(changes)

            # Update schedule
            wt.last_check = datetime.now()
            wt.next_check = datetime.now() + timedelta(hours=wt.interval_hours)

            progress.update(task, advance=1)

    # Show results
    console.print()
    if all_changes:
        print_warning(f"Detected {len(all_changes)} change(s)!")
        print_changes_table(all_changes)
    else:
        print_success("No changes detected")


@app.command("pause")
def pause_cmd(
    ctx: typer.Context,
    target: Annotated[str, typer.Argument(help="Target to pause")],
) -> None:
    """⏸️ Pause monitoring for a target."""
    if target not in _watch_targets:
        print_error(f"Not watching: {target}")
        raise typer.Exit(1)

    _watch_targets[target].enabled = False
    print_info(f"Paused monitoring: {target}")


@app.command("resume")
def resume_cmd(
    ctx: typer.Context,
    target: Annotated[str, typer.Argument(help="Target to resume")],
) -> None:
    """▶️ Resume monitoring for a paused target."""
    if target not in _watch_targets:
        print_error(f"Not watching: {target}")
        raise typer.Exit(1)

    _watch_targets[target].enabled = True
    _watch_targets[target].next_check = datetime.now()
    print_info(f"Resumed monitoring: {target}")


@app.command("status")
def status_cmd(
    ctx: typer.Context,
    target: Annotated[str, typer.Argument(help="Target to show status for")],
) -> None:
    """[i] Show detailed status for a watched target."""
    if target not in _watch_targets:
        print_error(f"Not watching: {target}")
        raise typer.Exit(1)

    wt = _watch_targets[target]

    console.print(f"\n[bold]Watch Status: {target}[/bold]\n")
    console.print(f"  Type: {wt.watch_type}")
    console.print(f"  Interval: {wt.interval_hours} hours")
    console.print(f"  Enabled: {'Yes' if wt.enabled else 'No'}")
    console.print(
        f"  Last Check: {wt.last_check.strftime('%Y-%m-%d %H:%M') if wt.last_check else 'Never'}"
    )
    console.print(
        f"  Next Check: {wt.next_check.strftime('%Y-%m-%d %H:%M') if wt.next_check else '-'}"
    )

    # TODO: Show historical changes


# ============================================
# Helper functions
# ============================================


def _parse_interval(interval: str) -> int | None:
    """Parse interval string to hours."""
    try:
        value = int(interval[:-1])
        unit = interval[-1].lower()

        if unit == "h":
            return value
        if unit == "d":
            return value * 24
        if unit == "m":
            return max(1, value // 60)  # Convert minutes to hours, min 1
        return None
    except (ValueError, IndexError):
        return None


def _check_target(watch_target: WatchTarget, config: AppConfig) -> list[Change]:
    """Perform a check on a watch target and return detected changes."""
    changes: list[Change] = []

    # Placeholder - will implement actual change detection
    # This would:
    # 1. Load previous scan result from database
    # 2. Perform new scan
    # 3. Compare and detect changes
    # 4. Save new result

    # Example change for demo
    if watch_target.target == "example.com":
        changes.append(
            Change(
                change_type=ChangeType.NEW,
                asset_type=AssetType.SUBDOMAIN,
                asset_value=f"new-api.{watch_target.target}",
                description="New subdomain detected",
            )
        )

    return changes
