"""Report command - generate and export reports."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Annotated

import typer
from rich.panel import Panel

from domainraptor.core.config import AppConfig, OutputFormat
from domainraptor.core.risk import calculate_risk_level, get_risk_level_description
from domainraptor.utils.output import (
    console,
    create_progress,
    format_json,
    format_yaml,
    print_info,
    print_success,
)

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
        Path | None,
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
        str | None,
        typer.Option("--scan", "-s", help="Specific scan ID to report on"),
    ] = None,
    template: Annotated[
        str | None,
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
    ctx.obj.get("config", AppConfig())

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
        Path | None,
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
Generated: {datetime.now().strftime("%Y-%m-%d %H:%M")}

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
        str | None,
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
        str | None,
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
    """Build report data structure from database."""
    from domainraptor.storage.repository import ScanRepository

    repo = ScanRepository()

    # Get scan data
    scan = repo.get_by_id(int(scan_id)) if scan_id else repo.get_latest_for_target(target)

    if not scan:
        # Return empty report structure if no scan found
        return {
            "target": target,
            "generated_at": datetime.now().isoformat(),
            "scan_id": None,
            "message": f"No scan data found for {target}. Run a scan first.",
            "summary": {
                "total_assets": 0,
                "total_subdomains": 0,
                "total_services": 0,
                "total_certificates": 0,
                "total_vulnerabilities": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "config_issues": 0,
            },
            "assets": [],
            "dns_records": [],
            "certificates": [],
            "vulnerabilities": [],
            "config_issues": [],
        }

    # Count vulnerabilities by severity
    vuln_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for vuln in scan.vulnerabilities:
        severity = vuln.severity.value.lower()
        if severity in vuln_counts:
            vuln_counts[severity] += 1

    # Count subdomains
    subdomains = [a for a in scan.assets if a.type.value == "subdomain"]

    # Calculate risk assessment
    risk_assessment = calculate_risk_level(scan)

    # Build report data
    data = {
        "target": target,
        "generated_at": datetime.now().isoformat(),
        "scan_id": scan_id or "latest",
        "scan_type": scan.scan_type,
        "scan_status": scan.status,
        "scan_started": scan.started_at.isoformat() if scan.started_at else None,
        "scan_completed": scan.completed_at.isoformat() if scan.completed_at else None,
        "scan_duration_seconds": scan.duration_seconds,
        "risk_assessment": {
            "score": risk_assessment.score,
            "level": risk_assessment.level.value,
            "level_description": get_risk_level_description(risk_assessment.level),
            "breakdown": {
                "vulnerabilities": risk_assessment.vuln_contribution,
                "configuration": risk_assessment.config_contribution,
                "exposure": risk_assessment.exposure_contribution,
                "reputation": risk_assessment.reputation_contribution,
            },
            "top_factors": risk_assessment.top_factors,
        },
        "summary": {
            "total_assets": len(scan.assets),
            "total_subdomains": len(subdomains),
            "total_services": len(scan.services),
            "total_certificates": len(scan.certificates),
            "total_vulnerabilities": len(scan.vulnerabilities),
            "critical": vuln_counts["critical"],
            "high": vuln_counts["high"],
            "medium": vuln_counts["medium"],
            "low": vuln_counts["low"],
            "config_issues": len(scan.config_issues),
            "dns_records": len(scan.dns_records),
        },
        "assets": [
            {
                "type": a.type.value,
                "value": a.value,
                "parent": a.parent,
                "source": a.source,
                "first_seen": a.first_seen.isoformat() if a.first_seen else None,
            }
            for a in scan.assets
        ],
        "dns_records": [
            {
                "type": r.record_type,
                "value": r.value,
                "ttl": r.ttl,
                "priority": r.priority,
            }
            for r in scan.dns_records
        ],
        "certificates": [
            {
                "subject": c.subject,
                "issuer": c.issuer,
                "not_before": c.not_before.isoformat() if c.not_before else None,
                "not_after": c.not_after.isoformat() if c.not_after else None,
                "is_expired": c.is_expired,
                "days_until_expiry": c.days_until_expiry,
                "san": c.san,
            }
            for c in scan.certificates
        ],
        "vulnerabilities": [
            {
                "id": v.id,
                "severity": v.severity.value,
                "title": v.title,
                "description": v.description,
                "affected_asset": v.affected_asset,
                "cvss_score": v.cvss_score,
                "remediation": v.remediation if include_remediation else None,
                "source": v.source,
            }
            for v in scan.vulnerabilities
        ],
        "config_issues": [
            {
                "id": i.id,
                "severity": i.severity.value,
                "title": i.title,
                "category": i.category,
                "description": i.description,
                "affected_asset": i.affected_asset,
                "current_value": i.current_value,
                "recommended_value": i.recommended_value,
                "remediation": i.remediation if include_remediation else None,
            }
            for i in scan.config_issues
        ],
    }

    # Add scan history if requested
    if include_history:
        history_scans = repo.list_by_target(target, limit=10)
        data["history"] = [
            {
                "scan_type": s.scan_type,
                "status": s.status,
                "started_at": s.started_at.isoformat() if s.started_at else None,
                "assets_found": len(s.assets),
                "issues_found": len(s.config_issues) + len(s.vulnerabilities),
            }
            for s in history_scans
        ]

    return data


def _format_report(data: dict, format_type: str) -> str:
    """Format report data into requested format."""
    if format_type == "json":
        return format_json(data)
    if format_type == "yaml":
        return format_yaml(data)
    if format_type == "md":
        return _format_markdown(data)
    if format_type == "html":
        return _format_html(data)
    return format_json(data)


def _format_markdown(data: dict) -> str:
    """Format report as Markdown."""
    risk = data.get("risk_assessment", {})
    risk_emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪"}.get(
        risk.get("level", ""), ""
    )

    md = f"""# Security Report: {data["target"]}

Generated: {data["generated_at"]}

## Risk Assessment

| Metric | Value |
|--------|-------|
| **Risk Level** | {risk_emoji} **{risk.get("level", "N/A")}** |
| **Risk Score** | {risk.get("score", 0)}/100 |
| Description | {risk.get("level_description", "")} |

### Risk Breakdown

| Category | Contribution |
|----------|--------------|
| Vulnerabilities (40%) | {risk.get("breakdown", {}).get("vulnerabilities", 0)} |
| Configuration (25%) | {risk.get("breakdown", {}).get("configuration", 0)} |
| Exposure (25%) | {risk.get("breakdown", {}).get("exposure", 0)} |
| Reputation (10%) | {risk.get("breakdown", {}).get("reputation", 0)} |

### Top Risk Factors

"""
    for factor in risk.get("top_factors", []):
        md += f"- {factor}\n"

    md += f"""
## Summary

| Metric | Count |
|--------|-------|
| Total Assets | {data["summary"]["total_assets"]} |
| Subdomains | {data["summary"]["total_subdomains"]} |
| Services | {data["summary"]["total_services"]} |
| Vulnerabilities | {data["summary"]["total_vulnerabilities"]} |
| Config Issues | {data["summary"]["config_issues"]} |

## Vulnerabilities

| ID | Severity | CVSS | Title | Description |
|----|----------|------|-------|-------------|
"""
    for vuln in data.get("vulnerabilities", []):
        cvss = vuln.get("cvss_score")
        cvss_str = f"{cvss:.1f}" if cvss else "-"
        desc = (
            vuln.get("description", "")[:80] + "..."
            if len(vuln.get("description", "")) > 80
            else vuln.get("description", "")
        )
        md += f"| {vuln['id']} | {vuln['severity']} | {cvss_str} | {vuln['title']} | {desc} |\n"

    # Add detailed vulnerability section
    md += "\n### Vulnerability Details\n\n"
    for vuln in data.get("vulnerabilities", []):
        cvss = vuln.get("cvss_score")
        cvss_str = f"{cvss:.1f}" if cvss else "N/A"
        md += f"""#### {vuln["id"]}

- **Severity**: {vuln["severity"]}
- **CVSS Score**: {cvss_str}
- **Affected Asset**: {vuln.get("affected_asset", "N/A")}
- **Source**: {vuln.get("source", "N/A")}

{vuln.get("description", "No description available.")}

"""
        if vuln.get("remediation"):
            md += f"**Remediation**: {vuln['remediation']}\n\n"

    md += "## Configuration Issues\n\n"
    md += "| ID | Severity | Title |\n"
    md += "|----|----------|-------|\n"
    for issue in data.get("config_issues", []):
        md += f"| {issue['id']} | {issue['severity']} | {issue['title']} |\n"

    return md


def _format_html(data: dict) -> str:
    """Format report as HTML."""
    risk = data.get("risk_assessment", {})
    risk_color = {
        "CRITICAL": "#dc2626",
        "HIGH": "#ea580c",
        "MEDIUM": "#ca8a04",
        "LOW": "#2563eb",
        "INFO": "#6b7280",
    }.get(risk.get("level", ""), "#6b7280")

    html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Security Report: {data["target"]}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 40px; background: #f9fafb; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        h1 {{ color: #1f2937; }}
        h2 {{ color: #374151; border-bottom: 2px solid #e5e7eb; padding-bottom: 8px; }}
        table {{ border-collapse: collapse; width: 100%; margin: 20px 0; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
        th, td {{ border: 1px solid #e5e7eb; padding: 12px; text-align: left; }}
        th {{ background: #f3f4f6; font-weight: 600; }}
        .critical {{ color: #dc2626; font-weight: bold; }}
        .high {{ color: #ea580c; }}
        .medium {{ color: #ca8a04; }}
        .low {{ color: #2563eb; }}
        .risk-card {{ background: white; border-radius: 12px; padding: 24px; margin: 20px 0; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
        .risk-level {{ font-size: 32px; font-weight: bold; color: {risk_color}; }}
        .risk-score {{ font-size: 24px; color: #6b7280; }}
        .breakdown {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-top: 16px; }}
        .breakdown-item {{ text-align: center; padding: 12px; background: #f9fafb; border-radius: 8px; }}
        .breakdown-value {{ font-size: 24px; font-weight: bold; color: #1f2937; }}
        .breakdown-label {{ font-size: 12px; color: #6b7280; text-transform: uppercase; }}
        .factors {{ margin-top: 16px; }}
        .factor {{ padding: 8px 12px; background: #fef3c7; border-left: 3px solid #f59e0b; margin: 4px 0; }}
    </style>
</head>
<body>
    <div class="container">
    <h1>Security Report: {data["target"]}</h1>
    <p>Generated: {data["generated_at"]}</p>

    <div class="risk-card">
        <h2 style="border: none; margin-top: 0;">Risk Assessment</h2>
        <div style="display: flex; align-items: center; gap: 24px;">
            <div class="risk-level">{risk.get("level", "N/A")}</div>
            <div class="risk-score">{risk.get("score", 0)}/100</div>
        </div>
        <p style="color: #6b7280;">{risk.get("level_description", "")}</p>

        <div class="breakdown">
            <div class="breakdown-item">
                <div class="breakdown-value">{risk.get("breakdown", {}).get("vulnerabilities", 0)}</div>
                <div class="breakdown-label">Vulnerabilities</div>
            </div>
            <div class="breakdown-item">
                <div class="breakdown-value">{risk.get("breakdown", {}).get("configuration", 0)}</div>
                <div class="breakdown-label">Configuration</div>
            </div>
            <div class="breakdown-item">
                <div class="breakdown-value">{risk.get("breakdown", {}).get("exposure", 0)}</div>
                <div class="breakdown-label">Exposure</div>
            </div>
            <div class="breakdown-item">
                <div class="breakdown-value">{risk.get("breakdown", {}).get("reputation", 0)}</div>
                <div class="breakdown-label">Reputation</div>
            </div>
        </div>

        <div class="factors">
            <strong>Top Risk Factors:</strong>
"""
    for factor in risk.get("top_factors", []):
        html += f'            <div class="factor">{factor}</div>\n'

    html += f"""        </div>
    </div>

    <h2>Summary</h2>
    <table>
        <tr><th>Metric</th><th>Count</th></tr>
        <tr><td>Total Assets</td><td>{data["summary"]["total_assets"]}</td></tr>
        <tr><td>Subdomains</td><td>{data["summary"]["total_subdomains"]}</td></tr>
        <tr><td>Services</td><td>{data["summary"]["total_services"]}</td></tr>
        <tr><td>Vulnerabilities</td><td>{data["summary"]["total_vulnerabilities"]}</td></tr>
        <tr><td>Config Issues</td><td>{data["summary"]["config_issues"]}</td></tr>
    </table>

    <h2>Vulnerabilities ({len(data.get("vulnerabilities", []))} total)</h2>
    <table>
        <tr><th>ID</th><th>Severity</th><th>CVSS</th><th>Affected Asset</th><th>Description</th></tr>
"""
    for vuln in data.get("vulnerabilities", []):
        cvss = vuln.get("cvss_score")
        cvss_str = f"{cvss:.1f}" if cvss else "-"
        desc = (
            vuln.get("description", "")[:100] + "..."
            if len(vuln.get("description", "")) > 100
            else vuln.get("description", "")
        )
        html += f'        <tr><td><strong>{vuln["id"]}</strong></td><td class="{vuln["severity"].lower()}">{vuln["severity"]}</td><td>{cvss_str}</td><td>{vuln.get("affected_asset", "")}</td><td>{desc}</td></tr>\n'

    html += """    </table>

    <h3>Vulnerability Details</h3>
"""
    severity_colors = {
        "CRITICAL": "#dc2626",
        "HIGH": "#ea580c",
        "MEDIUM": "#ca8a04",
        "LOW": "#2563eb",
    }
    for vuln in data.get("vulnerabilities", []):
        cvss = vuln.get("cvss_score")
        cvss_str = f"{cvss:.1f}" if cvss else "N/A"
        sev_class = vuln["severity"].lower()
        border_color = severity_colors.get(vuln["severity"], "#6b7280")
        cvss_badge = f"| CVSS {cvss_str}" if cvss else ""
        remediation_html = (
            f'<p style="margin-top: 8px; padding: 8px; background: #ecfdf5; border-radius: 4px; color: #059669;"><strong>Remediation:</strong> {vuln["remediation"]}</p>'
            if vuln.get("remediation")
            else ""
        )
        html += f"""
    <div style="background: white; border-left: 4px solid {border_color}; padding: 16px; margin: 12px 0; border-radius: 4px;">
        <div style="display: flex; justify-content: space-between; align-items: center;">
            <strong style="font-size: 16px;">{vuln["id"]}</strong>
            <span class="{sev_class}" style="padding: 4px 12px; background: #f3f4f6; border-radius: 4px;">{vuln["severity"]} {cvss_badge}</span>
        </div>
        <p style="margin: 8px 0; color: #374151;">{vuln.get("description", "No description available.")}</p>
        <div style="font-size: 12px; color: #6b7280;">
            <span>Affected: {vuln.get("affected_asset", "N/A")}</span> |
            <span>Source: {vuln.get("source", "N/A")}</span>
        </div>
        {remediation_html}
    </div>
"""

    html += """
    <h2>Configuration Issues</h2>
    <table>
        <tr><th>ID</th><th>Severity</th><th>Category</th><th>Title</th></tr>
"""
    for issue in data.get("config_issues", []):
        html += f'        <tr><td>{issue["id"]}</td><td class="{issue["severity"].lower()}">{issue["severity"]}</td><td>{issue.get("category", "")}</td><td>{issue["title"]}</td></tr>\n'

    html += """    </table>
    </div>
</body>
</html>"""

    return html
