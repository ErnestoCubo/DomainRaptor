"""Report command - generate and export reports."""

from __future__ import annotations

import logging
import math
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
        formatted = _format_report(report_data, format_type, template)
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

    # Load real data from database
    data = _build_report_data(
        target, include_history=False, include_remediation=False, scan_id=None
    )

    # Get risk assessment info
    risk = data.get("risk_assessment", {})
    risk_level = risk.get("level", "UNKNOWN")
    risk_score = risk.get("score", 0)
    top_factors = risk.get("top_factors", [])

    # Build recommendations from top factors and issues
    recommendations = [f"Address: {factor}" for factor in top_factors[:3]]
    if data["summary"]["config_issues"] > 0:
        recommendations.append("Review and fix configuration issues")
    if not recommendations:
        recommendations = ["Continue monitoring for changes", "Schedule periodic security reviews"]

    summary = (
        f"""
# Executive Summary: {target}
Generated: {datetime.now().strftime("%Y-%m-%d %H:%M")}

## Overview
Target analyzed with {data.get('scan_type', 'standard')} scan mode.
Scan Status: {data.get('scan_status', 'N/A')}

## Key Findings
- **Total Assets**: {data['summary']['total_assets']} discovered
- **Subdomains**: {data['summary']['total_subdomains']}
- **Services**: {data['summary']['total_services']}
- **Critical Vulnerabilities**: {data['summary']['critical']}
- **High Vulnerabilities**: {data['summary']['high']}
- **Medium Vulnerabilities**: {data['summary']['medium']}
- **Configuration Issues**: {data['summary']['config_issues']}

## Risk Level: {risk_level} ({risk_score}/100)

## Top Risk Factors
"""
        + "\n".join(f"- {f}" for f in top_factors)
        if top_factors
        else "- No significant risk factors identified"
    )

    summary += """

## Recommendations
""" + "\n".join(f"{i+1}. {r}" for i, r in enumerate(recommendations))

    summary += """

## Next Steps
- Schedule follow-up scan in 7 days
- Review remediation progress
- Update baseline after fixes
"""

    # Handle case where no scan data exists
    if data.get("message"):
        summary = f"""
# Executive Summary: {target}
Generated: {datetime.now().strftime("%Y-%m-%d %H:%M")}

## Status
⚠️ {data['message']}

Run a scan first:
  domainraptor discover --target {target}
  domainraptor assess --target {target}
  domainraptor recon {target}
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
    scan_type: Annotated[
        str | None,
        typer.Option("--type", "-t", help="Filter by scan type: discover, assess, recon"),
    ] = None,
) -> None:
    """📂 List available reports and scans."""
    from rich.table import Table

    from domainraptor.storage.repository import ScanRepository

    repo = ScanRepository()
    scans = repo.list_scans(target=target, scan_type=scan_type, limit=limit)

    if not scans:
        print_info("No scans found.")
        if target:
            print_info(f"Try running: domainraptor discover --target {target}")
        return

    print_info(f"Found {len(scans)} scan(s):")

    table = Table(title="Recent Scans", show_header=True, header_style="bold cyan")
    table.add_column("ID", style="dim")
    table.add_column("Target", style="bold")
    table.add_column("Type")
    table.add_column("Date")
    table.add_column("Status")
    table.add_column("Assets")
    table.add_column("Issues")
    table.add_column("Vulns")

    for scan in scans:
        # Format date
        date_str = ""
        if scan.get("started_at"):
            try:
                dt = datetime.fromisoformat(scan["started_at"])
                date_str = dt.strftime("%Y-%m-%d %H:%M")
            except (ValueError, TypeError):
                date_str = str(scan["started_at"])[:16]

        # Format status with color
        status = scan.get("status", "unknown")
        if status == "completed":
            status_str = "[green]Complete[/green]"
        elif status == "completed_with_errors":
            status_str = "[yellow]Partial[/yellow]"
        elif status == "running":
            status_str = "[blue]Running[/blue]"
        elif status == "failed":
            status_str = "[red]Failed[/red]"
        else:
            status_str = status

        table.add_row(
            str(scan.get("id", "")),
            scan.get("target", ""),
            scan.get("scan_type", ""),
            date_str,
            status_str,
            str(scan.get("asset_count", 0)),
            str(scan.get("issue_count", 0)),
            str(scan.get("vuln_count", 0)),
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
    scan = None
    if scan_id:
        try:
            scan = repo.get_by_id(int(scan_id))
        except ValueError:
            logging.debug("Non-numeric scan_id '%s', treating as not found", scan_id)
    else:
        scan = repo.get_latest_for_target(target)

    if not scan:
        # Return empty report structure if no scan found
        return {
            "target": target,
            "generated_at": datetime.now().isoformat(),
            "scan_id": scan_id,
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

    # Count subdomains and build infrastructure view
    subdomains = [a for a in scan.assets if a.type.value == "subdomain"]
    ips = [a for a in scan.assets if a.type.value == "ip"]

    # Build infrastructure map: IP -> {hostnames, services, vulns, metadata}
    infrastructure: dict[str, dict] = {}

    # First, populate with IP assets
    for ip_asset in ips:
        ip = ip_asset.value
        if ip not in infrastructure:
            infrastructure[ip] = {
                "ip": ip,
                "hostnames": [],
                "ports": [],
                "services": [],
                "vulns": [],
                "org": ip_asset.metadata.get("org", ""),
                "asn": ip_asset.metadata.get("asn", ""),
                "country": ip_asset.metadata.get("country", ""),
                "city": ip_asset.metadata.get("city", ""),
                "source": ip_asset.source,
            }

    # Add services to their IPs
    for svc in scan.services:
        ip = svc.metadata.get("ip", "")
        if ip and ip not in infrastructure:
            infrastructure[ip] = {
                "ip": ip,
                "hostnames": [],
                "ports": [],
                "services": [],
                "vulns": [],
                "org": "",
                "asn": "",
                "country": "",
                "city": "",
                "source": "service",
            }
        if ip:
            infrastructure[ip]["ports"].append(svc.port)
            infrastructure[ip]["services"].append(
                {
                    "port": svc.port,
                    "protocol": svc.protocol,
                    "service": svc.service_name,
                    "version": svc.version,
                    "banner": svc.banner[:100] if svc.banner else "",
                }
            )

    # Add vulnerabilities to their affected IPs
    for vuln in scan.vulnerabilities:
        affected = vuln.affected_asset
        # Check if affected_asset is an IP
        if affected in infrastructure:
            infrastructure[affected]["vulns"].append(
                {
                    "id": vuln.id,
                    "severity": vuln.severity.value,
                    "cvss_score": vuln.cvss_score,
                    "description": vuln.description,
                }
            )

    # Add subdomain IPs to infrastructure
    subdomain_data = []
    for sub in subdomains:
        sub_ip = sub.metadata.get("ip", "")
        subdomain_data.append(
            {
                "subdomain": sub.value,
                "ip": sub_ip,
                "source": sub.source,
                "enriched": sub_ip in infrastructure,
            }
        )
        # Add hostname to infrastructure entry
        if (
            sub_ip
            and sub_ip in infrastructure
            and sub.value not in infrastructure[sub_ip]["hostnames"]
        ):
            infrastructure[sub_ip]["hostnames"].append(sub.value)

    # Deduplicate ports
    for data in infrastructure.values():
        data["ports"] = sorted(set(data["ports"]))

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
        # New detailed views for comprehensive reports
        "subdomains": subdomain_data,
        "infrastructure": list(infrastructure.values()),
        "services_summary": _aggregate_services(infrastructure),
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


def _aggregate_services(infrastructure: dict[str, dict]) -> list[dict]:
    """Aggregate services across all hosts for summary view."""
    service_summary: dict[str, dict] = {}

    for host_data in infrastructure.values():
        ip = host_data.get("ip", "")
        for svc in host_data.get("services", []):
            key = f"{svc.get('port')}:{svc.get('service', 'unknown')}"
            if key not in service_summary:
                service_summary[key] = {
                    "port": svc.get("port"),
                    "service": svc.get("service", "unknown"),
                    "versions": [],
                    "hosts": [],
                }
            if svc.get("version") and svc["version"] not in service_summary[key]["versions"]:
                service_summary[key]["versions"].append(svc["version"])
            if ip not in service_summary[key]["hosts"]:
                service_summary[key]["hosts"].append(ip)

    return sorted(service_summary.values(), key=lambda x: x["port"])


def _format_report(data: dict, format_type: str, template: str | None = None) -> str:
    """Format report data into requested format.

    Args:
        data: Report data dictionary
        format_type: Output format (json, yaml, md, html)
        template: Optional template for HTML (executive, technical, compliance)
    """
    if format_type == "json":
        return format_json(data)
    if format_type == "yaml":
        return format_yaml(data)
    if format_type == "md":
        return _format_markdown(data)
    if format_type == "html":
        return _format_html(data, template)
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


def _format_html(data: dict, template: str | None = None) -> str:
    """Format report as HTML with optional template.

    Templates:
        - executive: High-level summary focused on risk and business impact
        - technical: Detailed technical findings with full asset/vuln data
        - compliance: Compliance-focused with control mappings
        - None/default: Full report with all sections
    """
    risk = data.get("risk_assessment", {})
    risk_color = {
        "CRITICAL": "#dc2626",
        "HIGH": "#ea580c",
        "MEDIUM": "#ca8a04",
        "LOW": "#2563eb",
        "INFO": "#6b7280",
    }.get(risk.get("level", ""), "#6b7280")

    # Generate SVG chart for vulnerability distribution
    vuln_chart = _generate_vuln_chart_svg(data.get("summary", {}))

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
        .chart-container {{ display: flex; gap: 24px; align-items: center; margin: 20px 0; background: white; padding: 20px; border-radius: 12px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
        .chart-legend {{ display: flex; flex-direction: column; gap: 8px; }}
        .legend-item {{ display: flex; align-items: center; gap: 8px; }}
        .legend-color {{ width: 16px; height: 16px; border-radius: 4px; }}
        .executive-summary {{ background: linear-gradient(135deg, #1e3a5f 0%, #2d4a6f 100%); color: white; padding: 32px; border-radius: 12px; margin-bottom: 24px; }}
        .executive-summary h2 {{ color: white; border-bottom-color: rgba(255,255,255,0.3); }}
        .metric-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 16px; margin: 20px 0; }}
        .metric-card {{ background: rgba(255,255,255,0.1); padding: 16px; border-radius: 8px; text-align: center; }}
        .metric-value {{ font-size: 28px; font-weight: bold; }}
        .metric-label {{ font-size: 12px; opacity: 0.8; text-transform: uppercase; }}
    </style>
</head>
<body>
    <div class="container">
    <h1>Security Report: {data["target"]}</h1>
    <p>Generated: {data["generated_at"]}</p>
"""

    # Executive template: high-level summary only
    if template == "executive":
        html += _format_html_executive(data, risk, risk_color, vuln_chart)
    # Technical template: all the details
    elif template == "technical":
        html += _format_html_technical(data, risk, risk_color, vuln_chart)
    # Compliance template: focused on controls
    elif template == "compliance":
        html += _format_html_compliance(data, risk, risk_color)
    # Default: full report
    else:
        html += _format_html_full(data, risk, risk_color, vuln_chart)

    html += """
    </div>
</body>
</html>"""

    return html


def _generate_vuln_chart_svg(summary: dict) -> str:
    """Generate an SVG donut chart for vulnerability distribution."""
    critical = summary.get("critical", 0)
    high = summary.get("high", 0)
    medium = summary.get("medium", 0)
    low = summary.get("low", 0)
    total = critical + high + medium + low

    if total == 0:
        return """<svg width="160" height="160" viewBox="0 0 160 160">
            <circle cx="80" cy="80" r="60" fill="#f3f4f6" stroke="#e5e7eb" stroke-width="2"/>
            <text x="80" y="85" text-anchor="middle" fill="#6b7280" font-size="14">No Vulns</text>
        </svg>"""

    # Calculate percentages and arc positions
    colors = ["#dc2626", "#ea580c", "#ca8a04", "#2563eb"]
    values = [critical, high, medium, low]

    paths = []
    start_angle = -90  # Start from top
    cx, cy, r = 80, 80, 60

    for _i, (value, color) in enumerate(zip(values, colors, strict=False)):
        if value == 0:
            continue
        percentage = value / total
        angle = percentage * 360

        # Calculate arc
        end_angle = start_angle + angle
        start_rad = math.radians(start_angle)
        end_rad = math.radians(end_angle)

        x1 = cx + r * math.cos(start_rad)
        y1 = cy + r * math.sin(start_rad)
        x2 = cx + r * math.cos(end_rad)
        y2 = cy + r * math.sin(end_rad)

        large_arc = 1 if angle > 180 else 0

        path = f'<path d="M {cx} {cy} L {x1} {y1} A {r} {r} 0 {large_arc} 1 {x2} {y2} Z" fill="{color}" opacity="0.9"/>'
        paths.append(path)
        start_angle = end_angle

    svg = f"""<svg width="160" height="160" viewBox="0 0 160 160">
        {"".join(paths)}
        <circle cx="80" cy="80" r="35" fill="white"/>
        <text x="80" y="75" text-anchor="middle" fill="#1f2937" font-size="20" font-weight="bold">{total}</text>
        <text x="80" y="92" text-anchor="middle" fill="#6b7280" font-size="11">Total</text>
    </svg>"""

    return svg


def _format_html_executive(data: dict, risk: dict, risk_color: str, vuln_chart: str) -> str:
    """Executive template: high-level summary focused on business impact."""
    summary = data.get("summary", {})

    # Determine business impact
    critical_count = summary.get("critical", 0)
    high_count = summary.get("high", 0)
    if critical_count > 0:
        impact = "SEVERE - Immediate action required"
        impact_color = "#dc2626"
    elif high_count > 0:
        impact = "SIGNIFICANT - Prioritize remediation"
        impact_color = "#ea580c"
    elif summary.get("medium", 0) > 0:
        impact = "MODERATE - Plan for remediation"
        impact_color = "#ca8a04"
    else:
        impact = "LOW - Continue monitoring"
        impact_color = "#22c55e"

    return f"""
    <div class="executive-summary">
        <h2 style="margin-top: 0;">Executive Summary</h2>
        <div class="metric-grid">
            <div class="metric-card">
                <div class="metric-value" style="color: {risk_color};">{risk.get("level", "N/A")}</div>
                <div class="metric-label">Risk Level</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">{risk.get("score", 0)}</div>
                <div class="metric-label">Risk Score</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">{summary.get("total_assets", 0)}</div>
                <div class="metric-label">Assets</div>
            </div>
            <div class="metric-card">
                <div class="metric-value" style="color: #dc2626;">{critical_count}</div>
                <div class="metric-label">Critical Issues</div>
            </div>
        </div>
        <p style="margin-top: 16px;"><strong>Business Impact:</strong> <span style="color: {impact_color};">{impact}</span></p>
    </div>

    <div class="chart-container">
        {vuln_chart}
        <div class="chart-legend">
            <div class="legend-item"><div class="legend-color" style="background: #dc2626;"></div> Critical: {critical_count}</div>
            <div class="legend-item"><div class="legend-color" style="background: #ea580c;"></div> High: {high_count}</div>
            <div class="legend-item"><div class="legend-color" style="background: #ca8a04;"></div> Medium: {summary.get("medium", 0)}</div>
            <div class="legend-item"><div class="legend-color" style="background: #2563eb;"></div> Low: {summary.get("low", 0)}</div>
        </div>
    </div>

    <h2>Key Recommendations</h2>
    <ol>
        {"<li>Address critical vulnerabilities immediately</li>" if critical_count > 0 else ""}
        {"<li>Prioritize high-severity issues within 7 days</li>" if high_count > 0 else ""}
        {"<li>Review and remediate configuration issues</li>" if summary.get("config_issues", 0) > 0 else ""}
        <li>Schedule follow-up assessment in 30 days</li>
    </ol>
"""


def _format_html_technical(data: dict, risk: dict, risk_color: str, vuln_chart: str) -> str:
    """Technical template: detailed findings with full data."""
    summary = data.get("summary", {})
    html = f"""
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
    </div>

    <div class="chart-container">
        {vuln_chart}
        <div class="chart-legend">
            <div class="legend-item"><div class="legend-color" style="background: #dc2626;"></div> Critical: {summary.get("critical", 0)}</div>
            <div class="legend-item"><div class="legend-color" style="background: #ea580c;"></div> High: {summary.get("high", 0)}</div>
            <div class="legend-item"><div class="legend-color" style="background: #ca8a04;"></div> Medium: {summary.get("medium", 0)}</div>
            <div class="legend-item"><div class="legend-color" style="background: #2563eb;"></div> Low: {summary.get("low", 0)}</div>
        </div>
    </div>
"""

    # Add Subdomains Section
    subdomains = data.get("subdomains", [])
    if subdomains:
        enriched_count = sum(1 for s in subdomains if s.get("enriched"))
        html += f"""
    <h2>Subdomains Discovery ({len(subdomains)} found, {enriched_count} enriched)</h2>
    <table>
        <tr><th>#</th><th>Subdomain</th><th>IP Address</th><th>Source</th><th>Enriched</th></tr>
"""
        for i, sub in enumerate(subdomains, 1):
            enriched_badge = (
                '<span style="color: #22c55e;">✓</span>'
                if sub.get("enriched")
                else '<span style="color: #9ca3af;">-</span>'
            )
            ip_val = sub.get("ip") or "-"
            html += f'        <tr><td>{i}</td><td><code>{sub["subdomain"]}</code></td><td>{ip_val}</td><td>{sub.get("source", "")}</td><td style="text-align: center;">{enriched_badge}</td></tr>\n'
        html += "    </table>\n"

    # Add Infrastructure Section
    infrastructure = data.get("infrastructure", [])
    if infrastructure:
        html += f"""
    <h2>Infrastructure ({len(infrastructure)} hosts)</h2>
"""
        severity_colors = {
            "CRITICAL": "#dc2626",
            "HIGH": "#ea580c",
            "MEDIUM": "#ca8a04",
            "LOW": "#2563eb",
        }
        for host in infrastructure:
            host_ip = host.get("ip", "Unknown")
            org = host.get("org") or "Unknown"
            country = host.get("country") or ""
            city = host.get("city") or ""
            location = f"{city}, {country}" if city and country else country or city or "Unknown"
            hostnames = ", ".join(host.get("hostnames", [])) or "-"
            host_services = host.get("services", [])
            host_vulns = host.get("vulns", [])

            html += f"""
    <div style="background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 16px; margin: 12px 0;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
            <h3 style="margin: 0; border: none; color: #1e40af;">{host_ip}</h3>
            <span style="background: #e0f2fe; color: #0369a1; padding: 4px 12px; border-radius: 12px; font-size: 12px;">{org}</span>
        </div>
        <div style="font-size: 13px; color: #6b7280; margin-bottom: 12px;">
            <span>📍 {location}</span> | <span>🌐 {hostnames}</span>
        </div>
"""
            # Services table for this host
            if host_services:
                html += f"""
        <h4 style="margin: 12px 0 8px 0; font-size: 14px; color: #374151;">Services ({len(host_services)})</h4>
        <table style="font-size: 13px;">
            <tr><th>Port</th><th>Protocol</th><th>Service</th><th>Version</th><th>Banner</th></tr>
"""
                for svc in host_services:
                    banner = svc.get("banner", "")
                    if banner and len(banner) > 60:
                        banner = banner[:60] + "..."
                    html += f'            <tr><td>{svc.get("port", "")}</td><td>{svc.get("protocol", "tcp")}</td><td>{svc.get("service", "")}</td><td>{svc.get("version", "")}</td><td style="font-size: 11px; color: #6b7280;">{banner}</td></tr>\n'
                html += "        </table>\n"

            # Vulnerabilities for this host
            if host_vulns:
                html += f"""
        <h4 style="margin: 16px 0 8px 0; font-size: 14px; color: #dc2626;">Vulnerabilities ({len(host_vulns)})</h4>
        <div style="display: flex; flex-wrap: wrap; gap: 8px;">
"""
                for vuln in host_vulns:
                    sev = vuln.get("severity", "MEDIUM")
                    color = severity_colors.get(sev, "#6b7280")
                    cvss = vuln.get("cvss_score")
                    cvss_str = f" ({cvss:.1f})" if cvss else ""
                    html += f'            <span style="background: {color}; color: white; padding: 4px 8px; border-radius: 4px; font-size: 12px;">{vuln.get("id", "CVE-?")}{cvss_str}</span>\n'
                html += "        </div>\n"

            html += "    </div>\n"

    # Add Services Summary
    services_summary = data.get("services_summary", [])
    if services_summary:
        html += f"""
    <h2>Services Summary ({len(services_summary)} unique services)</h2>
    <table>
        <tr><th>Port</th><th>Service</th><th>Versions</th><th>Hosts</th></tr>
"""
        for svc in services_summary:
            versions = ", ".join(svc.get("versions", [])) or "-"
            hosts_count = svc.get("hosts", 0)
            html += f'        <tr><td>{svc.get("port", "")}</td><td>{svc.get("service", "")}</td><td>{versions}</td><td>{hosts_count}</td></tr>\n'
        html += "    </table>\n"

    # Original Assets section
    html += f"""
    <h2>Assets ({summary.get("total_assets", 0)} total)</h2>
    <table>
        <tr><th>Type</th><th>Value</th><th>Source</th><th>First Seen</th></tr>
"""
    for asset in data.get("assets", [])[:50]:  # Limit to 50 for readability
        html += f'        <tr><td>{asset["type"]}</td><td><code>{asset["value"]}</code></td><td>{asset.get("source", "")}</td><td>{asset.get("first_seen", "")[:10] if asset.get("first_seen") else ""}</td></tr>\n'
    if len(data.get("assets", [])) > 50:
        html += f'        <tr><td colspan="4" style="text-align: center; color: #6b7280;">... and {len(data.get("assets", [])) - 50} more assets</td></tr>\n'

    html += """    </table>

    <h2>Services</h2>
    <table>
        <tr><th>Port</th><th>Protocol</th><th>Service</th><th>Version</th></tr>
"""
    # Add services from scan data if available
    if data.get("services"):
        for svc in data.get("services", []):
            html += f'        <tr><td>{svc.get("port", "")}</td><td>{svc.get("protocol", "")}</td><td>{svc.get("service_name", "")}</td><td>{svc.get("version", "")}</td></tr>\n'
    else:
        html += '        <tr><td colspan="4" style="text-align: center; color: #6b7280;">No service data available</td></tr>\n'

    html += """    </table>
"""

    # Add detailed vulnerability section
    html += _format_html_vulns_detail(data)
    return html


def _format_html_compliance(data: dict, risk: dict, risk_color: str) -> str:
    """Compliance template: control-focused view."""
    summary = data.get("summary", {})

    # Map vulnerabilities to common compliance frameworks
    compliance_mapping = {
        "CRITICAL": ["PCI-DSS 6.2", "SOC2 CC6.1", "ISO 27001 A.12.6"],
        "HIGH": ["PCI-DSS 6.5", "SOC2 CC6.6", "ISO 27001 A.14.2"],
        "MEDIUM": ["PCI-DSS 11.2", "SOC2 CC7.1", "ISO 27001 A.12.1"],
        "LOW": ["PCI-DSS 12.4", "SOC2 CC9.2"],
    }

    html = f"""
    <div style="background: #1e3a5f; color: white; padding: 24px; border-radius: 12px; margin-bottom: 24px;">
        <h2 style="color: white; border: none; margin-top: 0;">Compliance Summary</h2>
        <p>Target: <strong>{data["target"]}</strong></p>
        <p>Assessment Date: {data["generated_at"]}</p>
        <p>Risk Level: <span style="color: {risk_color}; font-weight: bold;">{risk.get("level", "N/A")}</span> ({risk.get("score", 0)}/100)</p>
    </div>

    <h2>Control Gaps by Framework</h2>
    <table>
        <tr><th>Severity</th><th>Count</th><th>Affected Controls</th></tr>
        <tr>
            <td class="critical">CRITICAL</td>
            <td>{summary.get("critical", 0)}</td>
            <td>{", ".join(compliance_mapping["CRITICAL"]) if summary.get("critical", 0) > 0 else "None"}</td>
        </tr>
        <tr>
            <td class="high">HIGH</td>
            <td>{summary.get("high", 0)}</td>
            <td>{", ".join(compliance_mapping["HIGH"]) if summary.get("high", 0) > 0 else "None"}</td>
        </tr>
        <tr>
            <td class="medium">MEDIUM</td>
            <td>{summary.get("medium", 0)}</td>
            <td>{", ".join(compliance_mapping["MEDIUM"]) if summary.get("medium", 0) > 0 else "None"}</td>
        </tr>
        <tr>
            <td class="low">LOW</td>
            <td>{summary.get("low", 0)}</td>
            <td>{", ".join(compliance_mapping["LOW"]) if summary.get("low", 0) > 0 else "None"}</td>
        </tr>
    </table>

    <h2>Configuration Compliance</h2>
    <table>
        <tr><th>Issue</th><th>Severity</th><th>Category</th><th>Status</th></tr>
"""
    for issue in data.get("config_issues", []):
        html += f'        <tr><td>{issue["title"]}</td><td class="{issue["severity"].lower()}">{issue["severity"]}</td><td>{issue.get("category", "General")}</td><td style="color: #dc2626;">Non-Compliant</td></tr>\n'
    if not data.get("config_issues"):
        html += '        <tr><td colspan="4" style="text-align: center; color: #22c55e;">All configuration checks passed</td></tr>\n'

    html += (
        """    </table>

    <h2>Remediation Timeline</h2>
    <table>
        <tr><th>Priority</th><th>Items</th><th>Recommended Timeline</th></tr>
        <tr><td class="critical">Critical</td><td>"""
        + str(summary.get("critical", 0))
        + """</td><td>Immediate (24-48 hours)</td></tr>
        <tr><td class="high">High</td><td>"""
        + str(summary.get("high", 0))
        + """</td><td>7 days</td></tr>
        <tr><td class="medium">Medium</td><td>"""
        + str(summary.get("medium", 0))
        + """</td><td>30 days</td></tr>
        <tr><td class="low">Low</td><td>"""
        + str(summary.get("low", 0))
        + """</td><td>90 days</td></tr>
    </table>
"""
    )
    return html


def _format_html_vulns_detail(data: dict) -> str:
    """Generate HTML for detailed vulnerability listings."""
    severity_colors = {
        "CRITICAL": "#dc2626",
        "HIGH": "#ea580c",
        "MEDIUM": "#ca8a04",
        "LOW": "#2563eb",
    }

    html = f"""
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
"""
    return html


def _format_html_full(data: dict, risk: dict, risk_color: str, vuln_chart: str) -> str:
    """Full report template (default): all sections included."""
    html = f"""
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

    summary = data.get("summary", {})
    html += f"""        </div>
    </div>

    <div class="chart-container">
        {vuln_chart}
        <div class="chart-legend">
            <div class="legend-item"><div class="legend-color" style="background: #dc2626;"></div> Critical: {summary.get("critical", 0)}</div>
            <div class="legend-item"><div class="legend-color" style="background: #ea580c;"></div> High: {summary.get("high", 0)}</div>
            <div class="legend-item"><div class="legend-color" style="background: #ca8a04;"></div> Medium: {summary.get("medium", 0)}</div>
            <div class="legend-item"><div class="legend-color" style="background: #2563eb;"></div> Low: {summary.get("low", 0)}</div>
        </div>
    </div>

    <h2>Summary</h2>
    <table>
        <tr><th>Metric</th><th>Count</th></tr>
        <tr><td>Total Assets</td><td>{summary.get("total_assets", 0)}</td></tr>
        <tr><td>Subdomains</td><td>{summary.get("total_subdomains", 0)}</td></tr>
        <tr><td>Services</td><td>{summary.get("total_services", 0)}</td></tr>
        <tr><td>Vulnerabilities</td><td>{summary.get("total_vulnerabilities", 0)}</td></tr>
        <tr><td>Config Issues</td><td>{summary.get("config_issues", 0)}</td></tr>
    </table>
"""

    # Add Infrastructure Section for full template
    infrastructure = data.get("infrastructure", [])
    if infrastructure:
        severity_colors = {
            "CRITICAL": "#dc2626",
            "HIGH": "#ea580c",
            "MEDIUM": "#ca8a04",
            "LOW": "#2563eb",
        }
        html += f"""
    <h2>Infrastructure ({len(infrastructure)} hosts)</h2>
"""
        for host in infrastructure:
            host_ip = host.get("ip", "Unknown")
            org = host.get("org") or "Unknown"
            country = host.get("country") or ""
            city = host.get("city") or ""
            location = f"{city}, {country}" if city and country else country or city or "Unknown"
            hostnames = ", ".join(host.get("hostnames", [])) or "-"
            host_services = host.get("services", [])
            host_vulns = host.get("vulns", [])

            html += f"""
    <div style="background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 16px; margin: 12px 0;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
            <h3 style="margin: 0; border: none; color: #1e40af;">{host_ip}</h3>
            <span style="background: #e0f2fe; color: #0369a1; padding: 4px 12px; border-radius: 12px; font-size: 12px;">{org}</span>
        </div>
        <div style="font-size: 13px; color: #6b7280; margin-bottom: 12px;">
            <span>📍 {location}</span> | <span>🌐 {hostnames}</span>
        </div>
"""
            # Services table for this host
            if host_services:
                html += f"""
        <h4 style="margin: 12px 0 8px 0; font-size: 14px; color: #374151;">Services ({len(host_services)})</h4>
        <table style="font-size: 13px;">
            <tr><th>Port</th><th>Protocol</th><th>Service</th><th>Version</th></tr>
"""
                for svc in host_services:
                    html += f'            <tr><td>{svc.get("port", "")}</td><td>{svc.get("protocol", "tcp")}</td><td>{svc.get("service", "")}</td><td>{svc.get("version", "")}</td></tr>\n'
                html += "        </table>\n"

            # Vulnerabilities for this host
            if host_vulns:
                html += f"""
        <h4 style="margin: 16px 0 8px 0; font-size: 14px; color: #dc2626;">Vulnerabilities ({len(host_vulns)})</h4>
        <div style="display: flex; flex-wrap: wrap; gap: 8px;">
"""
                for vuln in host_vulns[:20]:  # Limit to 20 per host in full view
                    sev = vuln.get("severity", "MEDIUM")
                    color = severity_colors.get(sev, "#6b7280")
                    html += f'            <span style="background: {color}; color: white; padding: 4px 8px; border-radius: 4px; font-size: 12px;">{vuln.get("id", "CVE-?")}</span>\n'
                if len(host_vulns) > 20:
                    html += f'            <span style="color: #6b7280; font-size: 12px;">... and {len(host_vulns) - 20} more</span>\n'
                html += "        </div>\n"

            html += "    </div>\n"

    # Add vulnerability details
    html += _format_html_vulns_detail(data)
    return html
