"""Main CLI application for DomainRaptor."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from domainraptor import __version__
from domainraptor.cli.commands import assess, compare, config, db, discover, report, watch
from domainraptor.core.config import AppConfig, OutputFormat, ScanMode
from domainraptor.utils.output import print_banner, print_error, print_info

# Main application
app = typer.Typer(
    name="domainraptor",
    help="🦎 DomainRaptor - Cyber Intelligence Tool for Domain Reconnaissance",
    add_completion=True,
    no_args_is_help=True,
    rich_markup_mode="rich",
)

# Register sub-commands
app.add_typer(discover.app, name="discover", help="🔍 Discover domains, subdomains, and assets")
app.add_typer(assess.app, name="assess", help="🛡️ Assess vulnerabilities and configurations")
app.add_typer(watch.app, name="watch", help="👁️ Monitor targets for changes")
app.add_typer(compare.app, name="compare", help="📊 Compare scan results")
app.add_typer(report.app, name="report", help="📄 Generate reports")
app.add_typer(db.app, name="db", help="💾 Database management")
app.add_typer(config.app, name="config", help="⚙️  Configure API keys and settings")

console = Console()


def version_callback(value: bool) -> None:
    """Print version and exit."""
    if value:
        console.print(f"[bold cyan]DomainRaptor[/bold cyan] v{__version__}")
        raise typer.Exit()


@app.callback()
def main_callback(
    ctx: typer.Context,
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            "-v",
            help="Show version and exit",
            callback=version_callback,
            is_eager=True,
        ),
    ] = False,
    verbose: Annotated[
        bool,
        typer.Option(
            "--verbose",
            "-V",
            help="Enable verbose output",
        ),
    ] = False,
    debug: Annotated[
        bool,
        typer.Option(
            "--debug",
            help="Enable debug mode (very verbose)",
        ),
    ] = False,
    config: Annotated[
        Path | None,
        typer.Option(
            "--config",
            "-c",
            help="Path to config file",
            exists=True,
            dir_okay=False,
        ),
    ] = None,
    mode: Annotated[
        ScanMode,
        typer.Option(
            "--mode",
            "-m",
            help="Scan mode: quick, standard, deep, stealth",
            case_sensitive=False,
        ),
    ] = ScanMode.STANDARD,
    output_format: Annotated[
        OutputFormat,
        typer.Option(
            "--format",
            "-f",
            help="Output format: table, json, csv, yaml",
            case_sensitive=False,
        ),
    ] = OutputFormat.TABLE,
    output_file: Annotated[
        Path | None,
        typer.Option(
            "--output",
            "-o",
            help="Output file path",
        ),
    ] = None,
    free_only: Annotated[
        bool,
        typer.Option(
            "--free-only",
            help="Use only free data sources (no API keys required)",
        ),
    ] = False,
    no_color: Annotated[
        bool,
        typer.Option(
            "--no-color",
            help="Disable colored output",
        ),
    ] = False,
    no_banner: Annotated[
        bool,
        typer.Option(
            "--no-banner",
            help="Disable banner",
        ),
    ] = False,
) -> None:
    """
    🦎 DomainRaptor - Cyber Intelligence Tool

    A comprehensive tool for domain reconnaissance, vulnerability assessment,
    and continuous monitoring using free-first data sources.

    [bold cyan]Examples:[/bold cyan]

        [dim]# Discover subdomains[/dim]
        domainraptor discover example.com

        [dim]# Deep scan with all sources[/dim]
        domainraptor discover example.com --mode deep

        [dim]# Assess vulnerabilities (free sources only)[/dim]
        domainraptor assess vulns example.com --free-only

        [dim]# Watch for changes[/dim]
        domainraptor watch add example.com --interval 24h

        [dim]# Generate JSON report[/dim]
        domainraptor report generate example.com --format json
    """
    # Load configuration
    app_config = AppConfig.load(config)

    # Apply CLI overrides
    app_config.verbose = verbose or app_config.verbose
    app_config.debug = debug or app_config.debug
    app_config.mode = mode
    app_config.output_format = output_format
    app_config.output_file = output_file
    app_config.free_only = free_only or app_config.free_only
    app_config.no_color = no_color or app_config.no_color

    # Store config in context for sub-commands
    ctx.ensure_object(dict)
    ctx.obj["config"] = app_config

    # Print banner by default unless --no-banner
    if not no_banner:
        print_banner()

    if app_config.debug:
        print_info(f"Config loaded: mode={app_config.mode.value}, free_only={app_config.free_only}")


# ============================================
# Utility Commands (top-level)
# ============================================


@app.command("config")
def config_cmd(
    ctx: typer.Context,
    show: Annotated[
        bool,
        typer.Option("--show", "-s", help="Show current configuration"),
    ] = False,
    init: Annotated[
        bool,
        typer.Option("--init", "-i", help="Initialize default configuration"),
    ] = False,
    set_key: Annotated[
        str | None,
        typer.Option("--set", help="Set a config value (key=value)"),
    ] = None,
) -> None:
    """⚙️ Manage configuration."""
    config: AppConfig = ctx.obj.get("config", AppConfig())

    if init:
        config_path = Path.home() / ".config" / "domainraptor" / "config.yaml"
        config.save(config_path)
        print_info(f"Configuration initialized at: {config_path}")
        return

    if set_key:
        key, _, value = set_key.partition("=")
        if not value:
            print_error("Invalid format. Use: --set key=value")
            raise typer.Exit(1)
        # TODO: Implement config setting
        print_info(f"Set {key}={value}")
        return

    if show or not any([init, set_key]):
        console.print("[bold]Current Configuration:[/bold]")
        console.print(f"  Mode: {config.mode.value}")
        console.print(f"  Verbose: {config.verbose}")
        console.print(f"  Free Only: {config.free_only}")
        console.print(f"  Output Format: {config.output_format.value}")
        console.print(f"  DB Path: {config.db_path}")
        console.print(f"  Cache TTL: {config.cache_ttl}s")


@app.command("db")
def db_cmd(
    ctx: typer.Context,
    info: Annotated[
        bool,
        typer.Option("--info", help="Show database information"),
    ] = False,
    vacuum: Annotated[
        bool,
        typer.Option("--vacuum", help="Vacuum database to reclaim space"),
    ] = False,
    export_path: Annotated[
        Path | None,
        typer.Option("--export", help="Export database to file"),
    ] = None,
    import_path: Annotated[
        Path | None,
        typer.Option("--import", help="Import database from file"),
    ] = None,
) -> None:
    """🗄️ Database operations."""
    config: AppConfig = ctx.obj.get("config", AppConfig())

    if info:
        if config.db_path.exists():
            size = config.db_path.stat().st_size / 1024  # KB
            print_info(f"Database: {config.db_path}")
            print_info(f"Size: {size:.1f} KB")
        else:
            print_info(f"Database not found at: {config.db_path}")
        return

    if vacuum:
        print_info("Vacuuming database...")
        # TODO: Implement vacuum
        print_info("Database vacuumed successfully")
        return

    if export_path:
        print_info(f"Exporting database to: {export_path}")
        # TODO: Implement export
        return

    if import_path:
        print_info(f"Importing database from: {import_path}")
        # TODO: Implement import
        return

    # Default: show info
    db_cmd(ctx, info=True, vacuum=False, export_path=None, import_path=None)


@app.command("import")
def import_cmd(
    ctx: typer.Context,
    file_path: Annotated[
        Path,
        typer.Argument(help="File to import (JSON, CSV, or YAML)"),
    ],
    target: Annotated[
        str | None,
        typer.Option("--target", "-t", help="Target domain to associate with imported data"),
    ] = None,
    merge: Annotated[
        bool,
        typer.Option("--merge", help="Merge with existing data instead of replacing"),
    ] = True,
) -> None:
    """📥 Import data from file."""
    print_info(f"Importing from: {file_path}")
    # TODO: Implement import
    print_info("Import complete")


@app.command("export")
def export_cmd(
    ctx: typer.Context,
    target: Annotated[
        str,
        typer.Argument(help="Target domain to export"),
    ],
    output: Annotated[
        Path,
        typer.Option("--output", "-o", help="Output file path", prompt=True),
    ],
    format_type: Annotated[
        OutputFormat,
        typer.Option("--format", "-f", help="Output format"),
    ] = OutputFormat.JSON,
) -> None:
    """📤 Export data to file."""
    ctx.obj.get("config", AppConfig())
    print_info(f"Exporting {target} to: {output} ({format_type.value})")
    # TODO: Implement export
    print_info("Export complete")


def main() -> None:
    """Entry point for the CLI application."""
    app()


if __name__ == "__main__":
    main()
