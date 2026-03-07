"""Output formatting utilities for CLI."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Any

from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table

if TYPE_CHECKING:
    from domainraptor.core.types import (
        Asset,
        Certificate,
        Change,
        ConfigIssue,
        ScanResult,
        Service,
        Vulnerability,
    )

console = Console()
error_console = Console(stderr=True)


def print_banner() -> None:
    """Print the DomainRaptor ASCII banner."""
    banner = """
[bold cyan]╔═══════════════════════════════════════════════════════════════╗
║                                                                 ║
║   ██████╗  ██████╗ ███╗   ███╗ █████╗ ██╗███╗   ██╗            ║
║   ██╔══██╗██╔═══██╗████╗ ████║██╔══██╗██║████╗  ██║            ║
║   ██║  ██║██║   ██║██╔████╔██║███████║██║██╔██╗ ██║            ║
║   ██║  ██║██║   ██║██║╚██╔╝██║██╔══██║██║██║╚██╗██║            ║
║   ██████╔╝╚██████╔╝██║ ╚═╝ ██║██║  ██║██║██║ ╚████║            ║
║   ╚═════╝  ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝            ║
║   ██████╗  █████╗ ██████╗ ████████╗ ██████╗ ██████╗            ║
║   ██╔══██╗██╔══██╗██╔══██╗╚══██╔══╝██╔═══██╗██╔══██╗           ║
║   ██████╔╝███████║██████╔╝   ██║   ██║   ██║██████╔╝           ║
║   ██╔══██╗██╔══██║██╔═══╝    ██║   ██║   ██║██╔══██╗           ║
║   ██║  ██║██║  ██║██║        ██║   ╚██████╔╝██║  ██║           ║
║   ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝        ╚═╝    ╚═════╝ ╚═╝  ╚═╝           ║
║                                                                 ║
║            [white]Cyber Intelligence Tool v0.2.0[/white]                     ║
╚═══════════════════════════════════════════════════════════════╝[/bold cyan]
"""
    console.print(banner)


def create_progress() -> Progress:
    """Create a Rich progress bar for long-running operations."""
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
    )


def print_success(message: str) -> None:
    """Print a success message."""
    console.print(f"[bold green]✓[/bold green] {message}")


def print_error(message: str) -> None:
    """Print an error message."""
    error_console.print(f"[bold red]✗[/bold red] {message}")


def print_warning(message: str) -> None:
    """Print a warning message."""
    console.print(f"[bold yellow]⚠[/bold yellow] {message}")


def print_info(message: str) -> None:
    """Print an info message."""
    console.print(f"[bold blue]ℹ[/bold blue] {message}")


def print_assets_table(assets: list[Asset]) -> None:
    """Print discovered assets in a table format."""
    if not assets:
        print_warning("No assets found")
        return

    table = Table(title="Discovered Assets", show_header=True, header_style="bold cyan")
    table.add_column("Type", style="dim")
    table.add_column("Value", style="bold")
    table.add_column("Parent")
    table.add_column("Source")
    table.add_column("First Seen")

    for asset in assets:
        table.add_row(
            asset.type.value,
            asset.value,
            asset.parent or "-",
            asset.source,
            asset.first_seen.strftime("%Y-%m-%d %H:%M"),
        )

    console.print(table)


def print_services_table(services: list[Service]) -> None:
    """Print discovered services in a table format."""
    if not services:
        return

    table = Table(title="Discovered Services", show_header=True, header_style="bold cyan")
    table.add_column("Port", style="dim")
    table.add_column("Protocol")
    table.add_column("Service", style="bold")
    table.add_column("Version")
    table.add_column("Banner")

    for svc in services:
        table.add_row(
            str(svc.port),
            svc.protocol,
            svc.service_name or "unknown",
            svc.version or "-",
            (svc.banner[:40] + "...") if len(svc.banner) > 40 else svc.banner or "-",
        )

    console.print(table)


def print_certificates_table(certificates: list[Certificate]) -> None:
    """Print SSL certificates in a table format."""
    if not certificates:
        return

    table = Table(title="SSL/TLS Certificates", show_header=True, header_style="bold cyan")
    table.add_column("Subject", style="bold")
    table.add_column("Issuer")
    table.add_column("Valid Until")
    table.add_column("Days Left")
    table.add_column("Status")

    for cert in certificates:
        days_style = "green"
        if cert.days_until_expiry < 30:
            days_style = "yellow"
        if cert.days_until_expiry < 7 or cert.is_expired:
            days_style = "red"

        status = "[green]Valid[/green]" if not cert.is_expired else "[red]Expired[/red]"

        table.add_row(
            cert.subject,
            cert.issuer[:30] + "..." if len(cert.issuer) > 30 else cert.issuer,
            cert.not_after.strftime("%Y-%m-%d"),
            f"[{days_style}]{cert.days_until_expiry}[/{days_style}]",
            status,
        )

    console.print(table)


def severity_color(severity: str) -> str:
    """Get color for severity level."""
    colors = {
        "critical": "bold red",
        "high": "red",
        "medium": "yellow",
        "low": "blue",
        "info": "dim",
    }
    return colors.get(severity.lower(), "white")


def print_vulnerabilities_table(vulnerabilities: list[Vulnerability]) -> None:
    """Print vulnerabilities in a table format."""
    if not vulnerabilities:
        return

    table = Table(title="Vulnerabilities", show_header=True, header_style="bold cyan")
    table.add_column("ID", style="dim")
    table.add_column("Severity")
    table.add_column("Title", style="bold")
    table.add_column("Asset")
    table.add_column("CVSS")
    table.add_column("Source")

    for vuln in vulnerabilities:
        color = severity_color(vuln.severity.value)
        table.add_row(
            vuln.id,
            f"[{color}]{vuln.severity.value.upper()}[/{color}]",
            vuln.title[:40] + "..." if len(vuln.title) > 40 else vuln.title,
            vuln.affected_asset,
            str(vuln.cvss_score) if vuln.cvss_score else "-",
            vuln.source,
        )

    console.print(table)


def print_config_issues_table(issues: list[ConfigIssue]) -> None:
    """Print configuration issues in a table format."""
    if not issues:
        return

    table = Table(title="Configuration Issues", show_header=True, header_style="bold cyan")
    table.add_column("ID", style="dim")
    table.add_column("Severity")
    table.add_column("Category")
    table.add_column("Title", style="bold")
    table.add_column("Asset")

    for issue in issues:
        color = severity_color(issue.severity.value)
        table.add_row(
            issue.id,
            f"[{color}]{issue.severity.value.upper()}[/{color}]",
            issue.category,
            issue.title[:40] + "..." if len(issue.title) > 40 else issue.title,
            issue.affected_asset,
        )

    console.print(table)


def print_changes_table(changes: list[Change]) -> None:
    """Print detected changes in a table format."""
    if not changes:
        print_info("No changes detected")
        return

    table = Table(title="Detected Changes", show_header=True, header_style="bold cyan")
    table.add_column("Type")
    table.add_column("Asset Type")
    table.add_column("Value", style="bold")
    table.add_column("Details")
    table.add_column("Detected")

    type_colors = {"new": "green", "removed": "red", "modified": "yellow"}

    for change in changes:
        color = type_colors.get(change.change_type.value, "white")
        details = change.description or "-"
        if change.change_type.value == "modified" and change.old_value and change.new_value:
            details = f"{change.old_value} → {change.new_value}"

        table.add_row(
            f"[{color}]{change.change_type.value.upper()}[/{color}]",
            change.asset_type.value,
            change.asset_value,
            details[:30] + "..." if len(details) > 30 else details,
            change.detected_at.strftime("%Y-%m-%d %H:%M"),
        )

    console.print(table)


def print_scan_summary(result: ScanResult) -> None:
    """Print a summary panel of a scan result."""
    summary = f"""[bold]Target:[/bold] {result.target}
[bold]Type:[/bold] {result.scan_type}
[bold]Status:[/bold] {result.status}
[bold]Duration:[/bold] {result.duration_seconds:.1f}s

[bold]Findings:[/bold]
  • Assets: {len(result.assets)}
  • Services: {len(result.services)}
  • Certificates: {len(result.certificates)}
  • Vulnerabilities: {len(result.vulnerabilities)}
  • Config Issues: {len(result.config_issues)}
  • Changes: {len(result.changes)}
  • Errors: {len(result.errors)}"""

    status_color = "green" if result.status == "completed" else "red"
    console.print(
        Panel(
            summary,
            title=f"[{status_color}]Scan Summary[/{status_color}]",
            border_style=status_color,
        )
    )


def format_json(data: Any) -> str:
    """Format data as JSON."""
    import json

    def default_serializer(obj: Any) -> Any:
        if isinstance(obj, datetime):
            return obj.isoformat()
        if hasattr(obj, "__dict__"):
            return obj.__dict__
        return str(obj)

    return json.dumps(data, indent=2, default=default_serializer)


def format_yaml(data: Any) -> str:
    """Format data as YAML."""
    import yaml

    def default_representer(dumper: yaml.Dumper, obj: Any) -> Any:
        if isinstance(obj, datetime):
            return dumper.represent_str(obj.isoformat())
        if hasattr(obj, "__dict__"):
            return dumper.represent_dict(obj.__dict__)
        return dumper.represent_str(str(obj))

    yaml.add_representer(object, default_representer)
    return yaml.dump(data, default_flow_style=False, sort_keys=False)
