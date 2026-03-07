"""Report command - generate and export reports."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Annotated, Optional

import typer

from domainraptor.core.config import AppConfig, OutputFormat
from domainraptor.utils.output import (
    console,
    create_progress,
    format_json,
    format_yaml,
    print_error,
    print_info,
    print_success,
)
from rich.panel import Panel

app = typer.Typer(
    name="report",
    help="📄 Generate and export reports",
    no_args_is_help=True,
)


@app.callback(invoke_without_command=True)
def report_callback(ctx: typer.Context) -> None:
    """
    📄 Generate comprehensive reports.

    Create detailed reports in various formats including
    executive summaries, technical details, and compliance reports.

    [bold cyan]Examples:[/bold cyan]

        [dim]# Generate full report[/dim]
        domainraptor report generate example.com

        [dim]# Executive summary only[/dim]
        domainraptor report summary example.com

        [dim]# Export to PDF[/dim]
        domainraptor report generate example.com --format pdf --output report.pdf
    """
    if ctx.invoked_subcommand is None:
        console.print("Use a subcommand: generate, summary, or list")
        raise typer.Exit()


@app.command("generate")
def generate_cmd(
    ctx: typer.Context,
    target: Annotated[str, typer.Argument(help="Target to generate report for")],
    output: Annotated[
        Optional[Path],
        typer.Option("--output", "-o", help="Output file path"),
    ] = None,
    format_type: Annotated[
        str,
        typer.Option("--format", "-f", help="Output format: json, yaml, html, md, pdf"),
    ] = "json",
    include_history: Annotated[
        bool,
        typer.Option("--history", "-H", help="Include scan history"),
    ] = False,
    include_remediation: Annotated[
        bool,
        typer.Option("--remediation", "-r", help="Include remediation steps"),
    ] = True,
    scan_id: Annotated[
        Optional[str],
        typer.Option("--scan", "-s", help="Specific scan ID to report on"),
    ] = None,
    template: Annotated[
        Optional[str],
        typer.Option("--template", "-t", help="Report template to use"),
    ] = None,
) -> None:
    """
    📝 Generate a comprehensive report.

    [bold cyan]Formats:[/bold cyan]
        • json - Machine-readable JSON
        • yaml - Human-readable YAML
        • html - Styled HTML report
        • md   - Markdown document
        • pdf  - PDF document (requires wkhtmltopdf)

    [bold cyan]Examples:[/bold cyan]

        [dim]# JSON report to stdout[/dim]
        domainraptor report generate example.com

        [dim]# HTML report to file[/dim]
        domainraptor report generate example.com -f html -o report.html

        [dim]# Include history and remediation[/dim]
        domainraptor report generate example.com --history --remediation
    """
    config: AppConfig = ctx.obj.get("config", AppConfig())

    print_info(f"Generating {format_type.upper()} report for: [bold]{target}[/bold]")

    with create_progress() as progress:
        task = progress.add_task("Generating report...", total=100)

        # Load data
        progress.update(task, description="Loading scan data...")
        report_data = _build_report_data(target, include_history, include_remediation, scan_id)
        progress.update(task, advance=40)

        # Format report
        progress.update(task, description=f"Formatting as {format_type}...")
        formatted = _format_report(report_data, format_type)
        progress.update(task, advance=40)

        # Output
        if output:
            progress.update(task, description="Writing file...")
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(formatted)
            progress.update(task, advance=20)
            print_success(f"Report saved to: {output}")
        else:
            progress.update(task, advance=20)
            console.print()
            console.print(formatted)


@app.command("summary")
def summary_cmd(
    ctx: typer.Context,
    target: Annotated[str, typer.Argument(help="Target to summarize")],
    output: Annotated[
        Optional[Path],
        typer.Option("--output", "-o", help="Output file path"),
    ] = None,
) -> None:
    """
    📋 Generate an executive summary.

    A condensed overview suitable for management reporting,
    highlighting key findings and risk levels.

    [bold cyan]Examples:[/bold cyan]

        [dim]# Display summary[/dim]
        domainraptor report summary example.com

        [dim]# Save to file[/dim]
        domainraptor report summary example.com -o summary.md
    """
    print_info(f"Generating executive summary for: [bold]{target}[/bold]")

    # Placeholder summary
    summary = f"""
# Executive Summary: {target}
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}

## Overview
Target analyzed with standard scan mode.

## Key Findings
- **Total Assets**: 18 discovered
- **Critical Vulnerabilities**: 0
- **High Vulnerabilities**: 1
- **Configuration Issues**: 5

## Risk Level: MEDIUM

## Recommendations
1. Update nginx to latest version
2. Configure DMARC records
3. Enable HSTS preloading
4. Review and update TLS configuration

## Next Steps
- Schedule follow-up scan in 7 days
- Review remediation progress
- Update baseline after fixes
"""

    console.print()
    console.print(
        Panel(
            summary,
            title="[bold]Executive Summary[/bold]",
            border_style="cyan",
        )
    )

    if output:
        output.write_text(summary)
        print_success(f"Summary saved to: {output}")


@app.command("list")
def list_cmd(
    ctx: typer.Context,
    target: Annotated[
        Optional[str],
        typer.Argument(help="Filter by target"),
    ] = None,
    limit: Annotated[
        int,
        typer.Option("--limit", "-l", help="Maximum reports to show"),
    ] = 10,
) -> None:
    """📂 List available reports and scans."""
    print_info("Available reports:")

    # TODO: Load from database
    # Placeholder
    from rich.table import Table

    table = Table(title="Recent Scans", show_header=True, header_style="bold cyan")
    table.add_column("Scan ID", style="dim")
    table.add_column("Target", style="bold")
    table.add_column("Type")
    table.add_column("Date")
    table.add_column("Status")
    table.add_column("Findings")

    # Placeholder data
    table.add_row(
        "abc123", "example.com", "discover", "2024-06-01 10:30", "[green]Complete[/green]", "18"
    )
    table.add_row(
        "def456", "example.com", "assess", "2024-06-01 11:00", "[green]Complete[/green]", "6"
    )
    table.add_row(
        "ghi789", "example.org", "discover", "2024-05-28 09:15", "[green]Complete[/green]", "23"
    )

    console.print()
    console.print(table)


@app.command("export")
def export_cmd(
    ctx: typer.Context,
    target: Annotated[str, typer.Argument(help="Target to export")],
    output: Annotated[
        Path,
        typer.Option("--output", "-o", help="Output file", prompt=True),
    ],
    format_type: Annotated[
        OutputFormat,
        typer.Option("--format", "-f", help="Export format"),
    ] = OutputFormat.JSON,
    all_scans: Annotated[
        bool,
        typer.Option("--all", "-a", help="Export all scans, not just latest"),
    ] = False,
) -> None:
    """
    💾 Export raw scan data.

    Export complete scan data for backup, analysis, or
    integration with other tools.
    """
    print_info(f"Exporting data for: {target}")
    print_info(f"Format: {format_type.value}")
    print_info(f"Output: {output}")

    # TODO: Implement actual export
    with create_progress() as progress:
        task = progress.add_task("Exporting...", total=100)
        progress.update(task, advance=100)

    print_success(f"Exported to: {output}")


@app.command("schedule")
def schedule_cmd(
    ctx: typer.Context,
    target: Annotated[str, typer.Argument(help="Target for scheduled reports")],
    frequency: Annotated[
        str,
        typer.Option("--frequency", "-f", help="Report frequency: daily, weekly, monthly"),
    ] = "weekly",
    recipients: Annotated[
        Optional[str],
        typer.Option("--recipients", "-r", help="Comma-separated email recipients"),
    ] = None,
) -> None:
    """
    ⏰ Schedule automated reports.

    Set up recurring report generation and delivery.
    """
    print_info(f"Scheduling {frequency} reports for: {target}")

    if recipients:
        print_info(f"Recipients: {recipients}")

    # TODO: Implement report scheduling
    print_success("Report scheduled successfully")


# ============================================
# Helper functions
# ============================================


def _build_report_data(
    target: str,
    include_history: bool,
    include_remediation: bool,
    scan_id: str | None,
) -> dict:
    """Build report data structure."""
    # Placeholder - will load from database
    return {
        "target": target,
        "generated_at": datetime.now().isoformat(),
        "scan_id": scan_id or "latest",
        "summary": {
            "total_assets": 18,
            "total_subdomains": 15,
            "total_services": 5,
            "total_vulnerabilities": 3,
            "critical": 0,
            "high": 1,
            "medium": 2,
            "low": 0,
            "config_issues": 5,
        },
        "assets": [
            {"type": "subdomain", "value": f"www.{target}"},
            {"type": "subdomain", "value": f"api.{target}"},
            {"type": "subdomain", "value": f"mail.{target}"},
        ],
        "vulnerabilities": [
            {
                "id": "CVE-2024-1234",
                "severity": "high",
                "title": "Example vulnerability",
                "remediation": "Update to latest version" if include_remediation else None,
            }
        ],
        "config_issues": [
            {
                "id": "SSL-001",
                "severity": "medium",
                "title": "TLS 1.0 enabled",
                "remediation": "Disable TLS 1.0 and 1.1" if include_remediation else None,
            }
        ],
    }


def _format_report(data: dict, format_type: str) -> str:
    """Format report data into requested format."""
    if format_type == "json":
        return format_json(data)
    elif format_type == "yaml":
        return format_yaml(data)
    elif format_type == "md":
        return _format_markdown(data)
    elif format_type == "html":
        return _format_html(data)
    else:
        return format_json(data)


def _format_markdown(data: dict) -> str:
    """Format report as Markdown."""
    md = f"""# Security Report: {data['target']}

Generated: {data['generated_at']}

## Summary

| Metric | Count |
|--------|-------|
| Total Assets | {data['summary']['total_assets']} |
| Subdomains | {data['summary']['total_subdomains']} |
| Services | {data['summary']['total_services']} |
| Vulnerabilities | {data['summary']['total_vulnerabilities']} |
| Config Issues | {data['summary']['config_issues']} |

## Vulnerabilities

| ID | Severity | Title |
|----|----------|-------|
"""
    for vuln in data.get("vulnerabilities", []):
        md += f"| {vuln['id']} | {vuln['severity']} | {vuln['title']} |\n"

    md += "\n## Configuration Issues\n\n"
    md += "| ID | Severity | Title |\n"
    md += "|----|----------|-------|\n"
    for issue in data.get("config_issues", []):
        md += f"| {issue['id']} | {issue['severity']} | {issue['title']} |\n"

    return md


def _format_html(data: dict) -> str:
    """Format report as HTML."""
    html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Security Report: {data['target']}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 40px; }}
        h1 {{ color: #2563eb; }}
        table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
        th, td {{ border: 1px solid #e5e7eb; padding: 12px; text-align: left; }}
        th {{ background: #f3f4f6; }}
        .critical {{ color: #dc2626; font-weight: bold; }}
        .high {{ color: #ea580c; }}
        .medium {{ color: #ca8a04; }}
        .low {{ color: #2563eb; }}
    </style>
</head>
<body>
    <h1>Security Report: {data['target']}</h1>
    <p>Generated: {data['generated_at']}</p>

    <h2>Summary</h2>
    <table>
        <tr><th>Metric</th><th>Count</th></tr>
        <tr><td>Total Assets</td><td>{data['summary']['total_assets']}</td></tr>
        <tr><td>Vulnerabilities</td><td>{data['summary']['total_vulnerabilities']}</td></tr>
        <tr><td>Config Issues</td><td>{data['summary']['config_issues']}</td></tr>
    </table>

    <h2>Vulnerabilities</h2>
    <table>
        <tr><th>ID</th><th>Severity</th><th>Title</th></tr>
"""
    for vuln in data.get("vulnerabilities", []):
        html += f'        <tr><td>{vuln["id"]}</td><td class="{vuln["severity"]}">{vuln["severity"]}</td><td>{vuln["title"]}</td></tr>\n'

    html += """    </table>
</body>
</html>"""

    return html
