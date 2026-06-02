"""Enrich command - third-party enrichment sources (URLScan, etc.)."""

from __future__ import annotations

from typing import Annotated

import typer
from rich.panel import Panel
from rich.table import Table

from domainraptor.cli._base import get_app_config
from domainraptor.core.config import AppConfig
from domainraptor.utils.output import (
    console,
    print_error,
    print_info,
    print_success,
    print_warning,
)

app = typer.Typer(
    name="enrich",
    help="🔬 Enrich assets with third-party intelligence sources",
    no_args_is_help=True,
)


@app.command("urlscan")
def enrich_urlscan_cmd(
    ctx: typer.Context,
    target: Annotated[str, typer.Argument(help="Target domain")],
    limit: Annotated[
        int,
        typer.Option("--limit", "-l", help="Maximum scans to display"),
    ] = 25,
) -> None:
    """Enrich a domain with public URLScan.io data."""
    _config: AppConfig = get_app_config(ctx)

    from domainraptor.enrichment.urlscan_client import UrlscanClient

    print_info(f"URLScan.io enrichment for: [bold]{target}[/bold]")

    client = UrlscanClient()
    try:
        enrichment = client.enrich(target)
    except Exception as exc:
        print_error(f"URLScan query failed: {exc}")
        raise typer.Exit(1) from None

    if enrichment.total_scans == 0:
        print_warning(f"No public URLScan results for {target}")
        return

    summary = Table.grid(padding=(0, 2))
    summary.add_row("Total scans", str(enrichment.total_scans))
    summary.add_row("Unique IPs", str(len(enrichment.unique_ips)))
    summary.add_row("Unique ASNs", str(len(enrichment.unique_asns)))
    summary.add_row("Unique servers", str(len(enrichment.unique_servers)))
    summary.add_row("Countries", ", ".join(enrichment.countries) or "-")
    console.print(Panel(summary, title=f"URLScan summary: {target}"))

    table = Table(title=f"Recent URLScan scans for {target}")
    table.add_column("Indexed", style="dim")
    table.add_column("Domain", style="cyan")
    table.add_column("IP", style="green")
    table.add_column("ASN", style="yellow")
    table.add_column("Server", style="magenta")
    table.add_column("Country", style="blue")
    for entry in enrichment.results[:limit]:
        table.add_row(
            entry.indexed_at[:10],
            entry.domain,
            entry.ip or "-",
            f"{entry.asn} {entry.asn_name}".strip() or "-",
            entry.server or "-",
            entry.country or "-",
        )
    console.print(table)
    print_success(f"{enrichment.total_scans} scans, {len(enrichment.unique_ips)} unique IPs")


@app.command("all")
def enrich_all_cmd(
    ctx: typer.Context,
    target: Annotated[str, typer.Argument(help="Target domain")],
) -> None:
    """Run every available enrichment source for the target."""
    print_info(f"Running all enrichment sources for: [bold]{target}[/bold]")
    enrich_urlscan_cmd(ctx, target, 25)
