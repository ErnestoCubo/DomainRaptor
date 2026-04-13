"""Watch command - continuous monitoring for changes."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Annotated, Any

import typer
from rich.table import Table

from domainraptor.core.config import AppConfig
from domainraptor.core.types import AssetType, Change, ChangeType, ScanResult, WatchTarget
from domainraptor.storage.repository import ScanRepository, WatchRepository
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


# Repository for persistent storage
_watch_repo: WatchRepository | None = None
_scan_repo: ScanRepository | None = None


def _get_watch_repo() -> WatchRepository:
    """Get or create watch target repository."""
    global _watch_repo
    if _watch_repo is None:
        _watch_repo = WatchRepository()
    return _watch_repo


def _get_scan_repo() -> ScanRepository:
    """Get or create scan repository."""
    global _scan_repo
    if _scan_repo is None:
        _scan_repo = ScanRepository()
    return _scan_repo


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
    repo = _get_watch_repo()

    # Parse interval
    interval_hours = _parse_interval(interval)
    if interval_hours is None:
        print_error(f"Invalid interval format: {interval}")
        raise typer.Exit(1)

    # Check if already watching
    existing = repo.get_by_target(target)
    if existing:
        print_warning(f"Already watching: {target}")
        if not typer.confirm("Update existing watch?"):
            raise typer.Exit(0)
        # Remove old entry to update
        repo.remove(target)

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

    # Save to database
    repo.add(watch_target)

    # Perform initial scan
    print_info(f"Adding {target} to watch list (interval: {interval})")

    with create_progress() as progress:
        task = progress.add_task("Performing initial scan...", total=100)
        # Perform actual initial baseline scan
        _perform_initial_scan(target, watch_target, progress, task)
        progress.update(task, advance=100)

    print_success(f"Now watching: {target}")
    print_info(f"Next check: {watch_target.next_check}")


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
    repo = _get_watch_repo()

    if not repo.get_by_target(target):
        print_error(f"Not watching: {target}")
        raise typer.Exit(1)

    if not force and not typer.confirm(f"Remove {target} from watch list?"):
        raise typer.Exit(0)

    repo.remove(target)
    print_success(f"Removed: {target}")


@app.command("list")
def list_cmd(ctx: typer.Context) -> None:
    """📋 List all watched targets."""
    repo = _get_watch_repo()
    watch_targets = repo.list_all()

    if not watch_targets:
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

    for wt in watch_targets:
        last_check = wt.last_check.strftime("%Y-%m-%d %H:%M") if wt.last_check else "Never"
        next_check = wt.next_check.strftime("%Y-%m-%d %H:%M") if wt.next_check else "-"
        status = "[green]Active[/green]" if wt.enabled else "[dim]Paused[/dim]"

        table.add_row(
            wt.target,
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
    repo = _get_watch_repo()

    targets_to_check: list[WatchTarget] = []

    if target:
        wt = repo.get_by_target(target)
        if not wt:
            print_error(f"Not watching: {target}")
            raise typer.Exit(1)
        targets_to_check = [wt]
    elif force:
        # Get all enabled targets
        targets_to_check = repo.list_all(enabled_only=True)
    else:
        # Get only due targets
        targets_to_check = repo.get_due_for_check()

    if not targets_to_check:
        print_info("No targets due for checking")
        return

    print_info(f"Checking {len(targets_to_check)} target(s)...")

    all_changes: list[Change] = []

    with create_progress() as progress:
        task = progress.add_task("Running checks...", total=len(targets_to_check))

        for wt in targets_to_check:
            progress.update(task, description=f"Checking {wt.target}...")

            # Perform check and detect changes
            changes = _check_target(wt, config)
            all_changes.extend(changes)

            # Update check time in database
            repo.update_check_time(wt.target, datetime.now())

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
    repo = _get_watch_repo()

    if not repo.get_by_target(target):
        print_error(f"Not watching: {target}")
        raise typer.Exit(1)

    repo.set_enabled(target, False)
    print_info(f"Paused monitoring: {target}")


@app.command("resume")
def resume_cmd(
    ctx: typer.Context,
    target: Annotated[str, typer.Argument(help="Target to resume")],
) -> None:
    """▶️ Resume monitoring for a paused target."""
    repo = _get_watch_repo()

    if not repo.get_by_target(target):
        print_error(f"Not watching: {target}")
        raise typer.Exit(1)

    repo.set_enabled(target, True)
    # Update next check to now
    repo.update_check_time(target, datetime.now() - timedelta(hours=24))
    print_info(f"Resumed monitoring: {target}")


@app.command("status")
def status_cmd(
    ctx: typer.Context,
    target: Annotated[str, typer.Argument(help="Target to show status for")],
) -> None:
    """[i] Show detailed status for a watched target."""
    repo = _get_watch_repo()

    wt = repo.get_by_target(target)
    if not wt:
        print_error(f"Not watching: {target}")
        raise typer.Exit(1)

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

    # Show historical changes
    _show_historical_changes(target)


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


def _perform_initial_scan(
    target: str,
    watch_target: WatchTarget,
    progress: Any,
    task: Any,
) -> None:
    """Perform initial baseline scan for a watch target."""
    from domainraptor.core.types import ScanResult

    scan_repo = _get_scan_repo()

    # Create initial scan result
    scan = ScanResult(
        target=target,
        scan_type="watch_baseline",
        status="running",
        started_at=datetime.now(),
    )

    try:
        # Perform DNS enumeration
        from domainraptor.discovery.dns_resolver import DNSResolver

        resolver = DNSResolver()
        scan.dns_records = resolver.resolve_all(target)
        progress.update(task, advance=30)

        # Discover subdomains from crt.sh
        from domainraptor.discovery.crtsh import CrtShClient

        try:
            crt_client = CrtShClient()
            scan.assets.extend(crt_client.query(target))
        except Exception:  # noqa: S110
            pass  # Continue even if crt.sh fails
        progress.update(task, advance=40)

        # Get certificates
        from domainraptor.discovery.cert_scanner import CertScanner

        try:
            cert_scanner = CertScanner()
            scan.certificates = cert_scanner.get_certificate(target)
        except Exception:  # noqa: S110
            pass
        progress.update(task, advance=20)

        scan.status = "completed"
        scan.completed_at = datetime.now()
        scan.duration_seconds = (scan.completed_at - scan.started_at).total_seconds()

        # Save baseline scan
        scan_repo.save(scan)

    except Exception as e:
        scan.status = "failed"
        scan.errors.append(str(e))
        scan.completed_at = datetime.now()


def _check_target(watch_target: WatchTarget, config: AppConfig) -> list[Change]:
    """Perform a check on a watch target and return detected changes.

    This performs:
    1. Load previous scan results from database
    2. Perform new scan
    3. Compare and detect changes
    4. Save new result
    """
    from domainraptor.core.types import ScanResult

    changes: list[Change] = []
    scan_repo = _get_scan_repo()

    # Get last scan for this target
    previous_scan = scan_repo.get_latest_for_target(watch_target.target)

    # Perform new scan
    new_scan = ScanResult(
        target=watch_target.target,
        scan_type="watch",
        status="running",
        started_at=datetime.now(),
    )

    try:
        # DNS enumeration
        from domainraptor.discovery.dns_resolver import DNSResolver

        resolver = DNSResolver()
        new_scan.dns_records = resolver.resolve_all(watch_target.target)

        # Subdomain discovery
        from domainraptor.discovery.crtsh import CrtShClient

        try:
            crt_client = CrtShClient()
            new_scan.assets.extend(crt_client.query(watch_target.target))
        except Exception:  # noqa: S110
            pass

        # Certificate check
        from domainraptor.discovery.cert_scanner import CertScanner

        try:
            cert_scanner = CertScanner()
            new_scan.certificates = cert_scanner.get_certificate(watch_target.target)
        except Exception:  # noqa: S110
            pass

        new_scan.status = "completed"
        new_scan.completed_at = datetime.now()
        new_scan.duration_seconds = (new_scan.completed_at - new_scan.started_at).total_seconds()

        # Compare with previous scan
        if previous_scan:
            changes = _compare_scans(previous_scan, new_scan)

        # Save new scan
        scan_repo.save(new_scan)

    except Exception as e:
        new_scan.status = "failed"
        new_scan.errors.append(str(e))
        new_scan.completed_at = datetime.now()

    return changes


def _compare_scans(old_scan: ScanResult, new_scan: ScanResult) -> list[Change]:
    """Compare two scans and detect changes."""
    changes: list[Change] = []

    # Get asset values
    old_assets = {(a.type, a.value) for a in old_scan.assets}
    new_assets = {(a.type, a.value) for a in new_scan.assets}

    # Find new assets
    for asset_type, value in new_assets - old_assets:
        changes.append(
            Change(
                change_type=ChangeType.NEW,
                asset_type=asset_type,
                asset_value=value,
                description=f"New {asset_type.value} discovered",
                detected_at=datetime.now(),
            )
        )

    # Find removed assets
    for asset_type, value in old_assets - new_assets:
        changes.append(
            Change(
                change_type=ChangeType.REMOVED,
                asset_type=asset_type,
                asset_value=value,
                description=f"{asset_type.value} no longer found",
                detected_at=datetime.now(),
            )
        )

    # Compare DNS records
    old_dns = {(r.record_type, r.value) for r in old_scan.dns_records}
    new_dns = {(r.record_type, r.value) for r in new_scan.dns_records}

    for rtype, value in new_dns - old_dns:
        changes.append(
            Change(
                change_type=ChangeType.NEW,
                asset_type=AssetType.DNS_RECORD,
                asset_value=f"{rtype}: {value}",
                description=f"New DNS {rtype} record",
                detected_at=datetime.now(),
            )
        )

    for rtype, value in old_dns - new_dns:
        changes.append(
            Change(
                change_type=ChangeType.REMOVED,
                asset_type=AssetType.DNS_RECORD,
                asset_value=f"{rtype}: {value}",
                description=f"DNS {rtype} record removed",
                detected_at=datetime.now(),
            )
        )

    # Check certificate changes
    old_certs = {c.fingerprint_sha256 for c in old_scan.certificates if c.fingerprint_sha256}
    new_certs = {c.fingerprint_sha256 for c in new_scan.certificates if c.fingerprint_sha256}

    if old_certs != new_certs:
        # Check for expiring certificates
        for cert in new_scan.certificates:
            if cert.is_expired:
                changes.append(
                    Change(
                        change_type=ChangeType.MODIFIED,
                        asset_type=AssetType.CERTIFICATE,
                        asset_value=cert.subject,
                        description="Certificate has expired",
                        detected_at=datetime.now(),
                    )
                )
            elif cert.days_until_expiry is not None and cert.days_until_expiry <= 30:
                changes.append(
                    Change(
                        change_type=ChangeType.MODIFIED,
                        asset_type=AssetType.CERTIFICATE,
                        asset_value=cert.subject,
                        description=f"Certificate expires in {cert.days_until_expiry} days",
                        detected_at=datetime.now(),
                    )
                )

    return changes


def _show_historical_changes(target: str) -> None:
    """Show historical changes for a watched target."""
    scan_repo = _get_scan_repo()
    scans = scan_repo.list_by_target(target, limit=5)

    if len(scans) < 2:
        console.print("\n  [dim]No history available yet[/dim]")
        return

    console.print("\n  [bold]Recent Activity:[/bold]")
    for _i, scan in enumerate(scans):
        status_icon = "✓" if scan.status == "completed" else "⚠"
        date_str = scan.started_at.strftime("%Y-%m-%d %H:%M") if scan.started_at else "-"
        console.print(f"    {status_icon} {date_str} - {scan.scan_type}")
