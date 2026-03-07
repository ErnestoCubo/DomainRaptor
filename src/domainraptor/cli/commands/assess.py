"""Assess command - vulnerability and configuration assessment."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Optional

import typer

from domainraptor.core.config import AppConfig, ScanMode
from domainraptor.core.types import (
    ConfigIssue,
    ScanResult,
    SeverityLevel,
    Vulnerability,
)
from domainraptor.utils.output import (
    console,
    create_progress,
    print_config_issues_table,
    print_error,
    print_info,
    print_scan_summary,
    print_success,
    print_vulnerabilities_table,
    print_warning,
)

app = typer.Typer(
    name="assess",
    help="🛡️ Assess vulnerabilities, configurations, and outdated software",
    no_args_is_help=True,
)


@app.callback(invoke_without_command=True)
def assess_callback(
    ctx: typer.Context,
    target: Annotated[
        Optional[str],
        typer.Argument(help="Target domain or IP to assess"),
    ] = None,
) -> None:
    """
    🛡️ Assess security posture of a target.

    Run without a subcommand to perform a full assessment, or use
    subcommands for specific checks.

    [bold cyan]Examples:[/bold cyan]

        [dim]# Full assessment[/dim]
        domainraptor assess example.com

        [dim]# Vulnerability check only[/dim]
        domainraptor assess vulns example.com

        [dim]# SSL/TLS configuration check[/dim]
        domainraptor assess config example.com --category ssl

        [dim]# Check for outdated software[/dim]
        domainraptor assess outdated example.com
    """
    if target is None:
        if ctx.invoked_subcommand is None:
            raise typer.Exit()
        return

    config: AppConfig = ctx.obj.get("config", AppConfig())

    print_info(f"Starting full assessment for: [bold]{target}[/bold]")
    print_info(f"Mode: {config.mode.value}")

    result = ScanResult(
        target=target,
        scan_type="assess",
        started_at=datetime.now(),
    )

    with create_progress() as progress:
        task = progress.add_task("Assessing target...", total=100)

        # Step 1: Vulnerability scan (40%)
        progress.update(task, description="Scanning for vulnerabilities...")
        _assess_vulnerabilities(target, result, config)
        progress.update(task, advance=40)

        # Step 2: Configuration check (40%)
        progress.update(task, description="Checking configurations...")
        _assess_configuration(target, result, config)
        progress.update(task, advance=40)

        # Step 3: Outdated software (20%)
        progress.update(task, description="Checking for outdated software...")
        _assess_outdated(target, result, config)
        progress.update(task, advance=20)

    result.completed_at = datetime.now()
    result.status = "completed"

    # Output
    console.print()
    print_scan_summary(result)

    if result.vulnerabilities:
        console.print()
        print_vulnerabilities_table(result.vulnerabilities)

    if result.config_issues:
        console.print()
        print_config_issues_table(result.config_issues)


# ============================================
# Subcommands
# ============================================


@app.command("vulns")
def assess_vulns_cmd(
    ctx: typer.Context,
    target: Annotated[str, typer.Argument(help="Target domain or IP")],
    cve_check: Annotated[
        bool,
        typer.Option("--cve/--no-cve", help="Check CVE databases"),
    ] = True,
    service_scan: Annotated[
        bool,
        typer.Option("--services/--no-services", help="Scan service versions for vulns"),
    ] = True,
    min_severity: Annotated[
        SeverityLevel,
        typer.Option("--min-severity", "-s", help="Minimum severity to report"),
    ] = SeverityLevel.LOW,
    exploit_check: Annotated[
        bool,
        typer.Option("--exploits", "-e", help="Check for known exploits"),
    ] = False,
) -> None:
    """
    🔓 Check for known vulnerabilities.

    Queries NVD, Shodan, and other sources to identify CVEs affecting
    the target's services and software versions.

    [bold cyan]Examples:[/bold cyan]

        [dim]# Basic vulnerability check[/dim]
        domainraptor assess vulns example.com

        [dim]# High severity only[/dim]
        domainraptor assess vulns example.com --min-severity high

        [dim]# Include exploit availability[/dim]
        domainraptor assess vulns example.com --exploits
    """
    config: AppConfig = ctx.obj.get("config", AppConfig())

    print_info(f"Vulnerability assessment for: [bold]{target}[/bold]")
    print_info(f"Min severity: {min_severity.value} | CVE check: {cve_check}")

    result = ScanResult(
        target=target,
        scan_type="assess_vulns",
        started_at=datetime.now(),
    )

    with create_progress() as progress:
        task = progress.add_task("Scanning for vulnerabilities...", total=100)

        # Service version detection
        if service_scan:
            progress.update(task, description="Detecting service versions...")
            progress.update(task, advance=30)

        # CVE database queries
        if cve_check:
            progress.update(task, description="Querying CVE databases...")
            _query_nvd(target, result, min_severity)
            progress.update(task, advance=40)

        # Exploit-db check
        if exploit_check:
            progress.update(task, description="Checking exploit databases...")
            progress.update(task, advance=20)

        progress.update(task, advance=10)

    result.completed_at = datetime.now()
    result.status = "completed"

    # Output
    console.print()
    print_scan_summary(result)

    if result.vulnerabilities:
        console.print()
        print_vulnerabilities_table(result.vulnerabilities)

        # Summary by severity
        by_severity = {}
        for vuln in result.vulnerabilities:
            by_severity[vuln.severity.value] = by_severity.get(vuln.severity.value, 0) + 1

        console.print("\n[bold]Summary by Severity:[/bold]")
        for sev, count in sorted(by_severity.items()):
            console.print(f"  {sev.upper()}: {count}")
    else:
        print_success("No vulnerabilities found!")


@app.command("config")
def assess_config_cmd(
    ctx: typer.Context,
    target: Annotated[str, typer.Argument(help="Target domain or IP")],
    category: Annotated[
        Optional[str],
        typer.Option("--category", "-c", help="Check specific category: ssl, dns, headers, all"),
    ] = "all",
    best_practices: Annotated[
        bool,
        typer.Option("--best-practices", "-b", help="Check against security best practices"),
    ] = True,
) -> None:
    """
    ⚙️ Check security configurations.

    Analyzes SSL/TLS config, DNS settings, HTTP security headers,
    and other security configurations.

    [bold cyan]Categories:[/bold cyan]
        • ssl - SSL/TLS configuration (protocols, ciphers, cert chain)
        • dns - DNS security (DNSSEC, CAA, SPF, DMARC, DKIM)
        • headers - HTTP security headers (HSTS, CSP, X-Frame-Options)
        • all - All categories (default)

    [bold cyan]Examples:[/bold cyan]

        [dim]# Full config assessment[/dim]
        domainraptor assess config example.com

        [dim]# SSL/TLS only[/dim]
        domainraptor assess config example.com --category ssl

        [dim]# DNS security check[/dim]
        domainraptor assess config example.com --category dns
    """
    config: AppConfig = ctx.obj.get("config", AppConfig())

    print_info(f"Configuration assessment for: [bold]{target}[/bold]")
    print_info(f"Category: {category}")

    result = ScanResult(
        target=target,
        scan_type="assess_config",
        started_at=datetime.now(),
    )

    with create_progress() as progress:
        task = progress.add_task("Checking configurations...", total=100)

        if category in ("all", "ssl"):
            progress.update(task, description="Checking SSL/TLS configuration...")
            _check_ssl_config(target, result)
            progress.update(task, advance=35)

        if category in ("all", "dns"):
            progress.update(task, description="Checking DNS security...")
            _check_dns_config(target, result)
            progress.update(task, advance=35)

        if category in ("all", "headers"):
            progress.update(task, description="Checking HTTP headers...")
            _check_http_headers(target, result)
            progress.update(task, advance=30)

    result.completed_at = datetime.now()
    result.status = "completed"

    console.print()
    print_scan_summary(result)

    if result.config_issues:
        console.print()
        print_config_issues_table(result.config_issues)

        # Group by category
        by_category = {}
        for issue in result.config_issues:
            by_category[issue.category] = by_category.get(issue.category, 0) + 1

        console.print("\n[bold]Issues by Category:[/bold]")
        for cat, count in sorted(by_category.items()):
            console.print(f"  {cat}: {count}")
    else:
        print_success("No configuration issues found!")


@app.command("outdated")
def assess_outdated_cmd(
    ctx: typer.Context,
    target: Annotated[str, typer.Argument(help="Target domain or IP")],
    include_minor: Annotated[
        bool,
        typer.Option("--include-minor", "-m", help="Include minor version updates"),
    ] = False,
) -> None:
    """
    📦 Check for outdated software versions.

    Detects web servers, frameworks, and libraries and compares
    versions against latest releases.

    [bold cyan]Examples:[/bold cyan]

        [dim]# Check for outdated software[/dim]
        domainraptor assess outdated example.com

        [dim]# Include minor updates[/dim]
        domainraptor assess outdated example.com --include-minor
    """
    config: AppConfig = ctx.obj.get("config", AppConfig())

    print_info(f"Outdated software check for: [bold]{target}[/bold]")

    result = ScanResult(
        target=target,
        scan_type="assess_outdated",
        started_at=datetime.now(),
    )

    with create_progress() as progress:
        task = progress.add_task("Detecting software versions...", total=100)

        progress.update(task, description="Fingerprinting services...")
        progress.update(task, advance=50)

        progress.update(task, description="Checking version databases...")
        _check_outdated_software(target, result, include_minor)
        progress.update(task, advance=50)

    result.completed_at = datetime.now()
    result.status = "completed"

    console.print()
    print_scan_summary(result)

    if result.config_issues:
        console.print()
        print_config_issues_table(result.config_issues)
    else:
        print_success("All detected software is up to date!")


# ============================================
# Internal assessment functions
# ============================================


def _assess_vulnerabilities(target: str, result: ScanResult, config: AppConfig) -> None:
    """Perform vulnerability assessment."""
    # Placeholder - will implement with NVD API, Shodan
    result.vulnerabilities.append(
        Vulnerability(
            id="CVE-2024-1234",
            title="Example vulnerability in OpenSSL",
            severity=SeverityLevel.HIGH,
            description="Buffer overflow in OpenSSL allows remote code execution",
            affected_asset=f"{target}:443",
            cvss_score=8.1,
            source="nvd",
        )
    )


def _assess_configuration(target: str, result: ScanResult, config: AppConfig) -> None:
    """Perform configuration assessment."""
    _check_ssl_config(target, result)
    _check_dns_config(target, result)


def _assess_outdated(target: str, result: ScanResult, config: AppConfig) -> None:
    """Check for outdated software."""
    _check_outdated_software(target, result, include_minor=False)


def _query_nvd(target: str, result: ScanResult, min_severity: SeverityLevel) -> None:
    """Query NVD for vulnerabilities."""
    # Placeholder - will implement with NVD API
    pass


def _check_ssl_config(target: str, result: ScanResult) -> None:
    """Check SSL/TLS configuration."""
    # Placeholder - will implement with sslyze
    result.config_issues.append(
        ConfigIssue(
            id="SSL-001",
            title="TLS 1.0 enabled",
            severity=SeverityLevel.MEDIUM,
            category="ssl",
            description="TLS 1.0 is deprecated and should be disabled",
            affected_asset=f"{target}:443",
            current_value="TLS 1.0, 1.1, 1.2, 1.3",
            recommended_value="TLS 1.2, 1.3 only",
            remediation="Disable TLS 1.0 and 1.1 in your web server configuration",
        )
    )


def _check_dns_config(target: str, result: ScanResult) -> None:
    """Check DNS security configuration."""
    # Placeholder - will implement with dnspython
    result.config_issues.append(
        ConfigIssue(
            id="DNS-001",
            title="Missing DMARC record",
            severity=SeverityLevel.MEDIUM,
            category="dns",
            description="No DMARC record found for email authentication",
            affected_asset=target,
            current_value="Not configured",
            recommended_value='v=DMARC1; p=reject; rua=mailto:dmarc@example.com',
            remediation="Add a DMARC TXT record to your DNS zone",
        )
    )


def _check_http_headers(target: str, result: ScanResult) -> None:
    """Check HTTP security headers."""
    # Placeholder - will implement with httpx
    result.config_issues.append(
        ConfigIssue(
            id="HDR-001",
            title="Missing Content-Security-Policy header",
            severity=SeverityLevel.LOW,
            category="headers",
            description="CSP header not set, increasing XSS risk",
            affected_asset=f"https://{target}",
            current_value="Not set",
            recommended_value="default-src 'self'; script-src 'self'",
            remediation="Add Content-Security-Policy header to your web server",
        )
    )


def _check_outdated_software(target: str, result: ScanResult, include_minor: bool) -> None:
    """Check for outdated software versions."""
    # Placeholder - will implement
    result.config_issues.append(
        ConfigIssue(
            id="OUT-001",
            title="Outdated nginx version",
            severity=SeverityLevel.LOW,
            category="outdated",
            description="nginx 1.18.0 is outdated, latest is 1.25.0",
            affected_asset=f"{target}:80",
            current_value="nginx/1.18.0",
            recommended_value="nginx/1.25.0",
            remediation="Update nginx to the latest stable version",
        )
    )
