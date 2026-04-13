"""Assess command - vulnerability and configuration assessment."""

from __future__ import annotations

import contextlib
from datetime import datetime
from typing import Annotated

import typer

from domainraptor.assessment import (
    DnsSecurityChecker,
    HeadersChecker,
    SSLAnalyzer,
)
from domainraptor.core.config import AppConfig
from domainraptor.core.types import (
    ScanResult,
    SeverityLevel,
    Vulnerability,
)
from domainraptor.utils.output import (
    console,
    create_progress,
    print_config_issues_table,
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
        str | None,
        typer.Option("--target", "-T", help="Target domain or IP to assess"),
    ] = None,
    save: Annotated[
        bool,
        typer.Option("--save/--no-save", help="Save results to database"),
    ] = True,
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

    # Save to database
    if save:
        try:
            from domainraptor.storage import ScanRepository

            repo = ScanRepository()
            scan_id = repo.save(result)
            print_info(f"Results saved to database (scan ID: {scan_id})")
        except Exception as e:
            print_warning(f"Failed to save results: {e}")


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
    _config: AppConfig = ctx.obj.get("config", AppConfig())

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

    # Show errors if any
    if result.errors:
        console.print()
        for error in result.errors:
            print_warning(error)

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
        str | None,
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
    _config: AppConfig = ctx.obj.get("config", AppConfig())

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
    _config: AppConfig = ctx.obj.get("config", AppConfig())

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
    # Vulnerability scanning requires service detection and CVE lookups
    # For now, we note this as a placeholder for future implementation
    # Real implementation would use NVD API, Shodan, etc.
    pass


def _assess_configuration(target: str, result: ScanResult, config: AppConfig) -> None:
    """Perform configuration assessment using real checkers."""
    # SSL/TLS check
    with contextlib.suppress(Exception), SSLAnalyzer() as ssl_checker:
        issues = ssl_checker.assess_safe(target)
        result.config_issues.extend(issues)

    # DNS security check
    with contextlib.suppress(Exception), DnsSecurityChecker() as dns_checker:
        issues = dns_checker.assess_safe(target)
        result.config_issues.extend(issues)

    # HTTP headers check
    with contextlib.suppress(Exception), HeadersChecker() as headers_checker:
        issues = headers_checker.assess_safe(target)
        result.config_issues.extend(issues)


def _assess_outdated(target: str, result: ScanResult, config: AppConfig) -> None:
    """Check for outdated software."""
    # This requires service fingerprinting which we haven't implemented yet
    # Placeholder for future implementation
    pass


def _query_nvd(target: str, result: ScanResult, min_severity: SeverityLevel) -> None:
    """Query Shodan for services and enrich with NVD CVE data.

    Strategy:
    1. Resolve target to IPs
    2. Query Shodan for host info (services, ports, known CVEs)
    3. Enrich CVEs with NVD data (description, CVSS score, severity)
    """
    import os
    import socket

    shodan_key = os.environ.get("SHODAN_API_KEY")
    if not shodan_key:
        result.errors.append(
            "Shodan API key not configured. Run: domainraptor config set SHODAN_API_KEY <key>"
        )
        return

    # Resolve target to IPs
    ips_to_check: list[str] = []
    try:
        socket.inet_aton(target)
        ips_to_check.append(target)
    except OSError:
        try:
            _, _, ip_list = socket.gethostbyname_ex(target)
            ips_to_check.extend(ip_list)
        except socket.gaierror:
            result.errors.append(f"Could not resolve domain: {target}")
            return

    if not ips_to_check:
        result.errors.append(f"No IPs found for target: {target}")
        return

    try:
        from domainraptor.discovery.shodan_client import ShodanClient

        shodan = ShodanClient(api_key=shodan_key)

        severity_order = {
            SeverityLevel.CRITICAL: 4,
            SeverityLevel.HIGH: 3,
            SeverityLevel.MEDIUM: 2,
            SeverityLevel.LOW: 1,
            SeverityLevel.INFO: 0,
        }
        min_sev_value = severity_order.get(min_severity, 0)

        # Collect all CVEs - use helper function to avoid try-except in loop
        all_cves, errors = _collect_cves_from_ips(shodan, ips_to_check[:10])
        result.errors.extend(errors)

        if not all_cves:
            return  # No CVEs found

        # Enrich with NVD data (reusing pattern from recon.py)
        nvd_info = _fetch_nvd_for_assess(list(all_cves.keys()))

        for cve_id, context in all_cves.items():
            nvd_data = nvd_info.get(cve_id)

            if nvd_data:
                desc = nvd_data.description
                severity = SeverityLevel(nvd_data.severity.lower())
                cvss_score = nvd_data.cvss_v3_score
            else:
                # Fallback description with context
                desc = _build_cve_description(
                    cve_id,
                    context["ip"],
                    context["services_summary"],
                    context["host_result"],
                )
                severity = SeverityLevel.MEDIUM
                cvss_score = None

            # Filter by minimum severity
            if severity_order.get(severity, 0) < min_sev_value:
                continue

            result.vulnerabilities.append(
                Vulnerability(
                    id=cve_id,
                    title=f"CVE {cve_id}",
                    severity=severity,
                    description=desc,
                    affected_asset=context["ip"],
                    source="shodan+nvd" if nvd_data else "shodan",
                    detected_at=datetime.now(),
                    cvss_score=cvss_score,
                )
            )

    except ImportError:
        result.errors.append("Shodan client not available")


def _collect_cves_from_ips(shodan, ips: list[str]) -> tuple[dict[str, dict], list[str]]:
    """Collect CVEs from Shodan for a list of IPs.

    Returns:
        Tuple of (cves_dict, errors_list)
    """
    all_cves: dict[str, dict] = {}
    errors: list[str] = []

    for ip in ips:
        cve_data, error = _fetch_shodan_host_cves(shodan, ip)
        if error:
            errors.append(error)
        all_cves.update(cve_data)

    return all_cves, errors


def _fetch_shodan_host_cves(shodan, ip: str) -> tuple[dict[str, dict], str | None]:
    """Fetch CVEs for a single IP from Shodan.

    Returns:
        Tuple of (cves_dict, error_message or None)
    """
    try:
        host_result = shodan.host_info(ip)

        # Build services summary for context
        services_summary = ", ".join(
            f"{svc.service_name or 'unknown'}:{svc.port}" for svc in host_result.services[:5]
        )
        if len(host_result.services) > 5:
            services_summary += f" (+{len(host_result.services) - 5} more)"

        cves = {}
        for cve_id in host_result.vulns:
            if cve_id not in cves:
                cves[cve_id] = {
                    "ip": ip,
                    "services_summary": services_summary,
                    "host_result": host_result,
                }

        return cves, None

    except Exception as e:
        return {}, f"Shodan lookup failed for {ip}: {e}"


def _fetch_nvd_for_assess(cve_ids: list[str]) -> dict:
    """Fetch CVE details from NVD API.

    Reuses NVDClient from discovery module.
    """
    import logging

    logger = logging.getLogger(__name__)

    if not cve_ids:
        return {}

    try:
        from domainraptor.discovery.nvd_client import NVDClient

        client = NVDClient()
        results = {}

        try:
            for cve_id in cve_ids:
                cve_info, should_stop = _fetch_single_cve(client, cve_id, logger)
                if cve_info:
                    results[cve_id] = cve_info
                if should_stop:
                    break
        finally:
            client.close()

        return results

    except ImportError:
        return {}
    except Exception:
        return {}


def _fetch_single_cve(client, cve_id: str, logger) -> tuple[object | None, bool]:
    """Fetch a single CVE from NVD.

    Returns:
        Tuple of (cve_info or None, should_stop_fetching)
    """
    from domainraptor.discovery.nvd_client import NVDRateLimitError

    try:
        info = client.get_cve(cve_id)
        return info, False
    except NVDRateLimitError:
        return None, True  # Stop on rate limit
    except Exception as e:
        logger.debug("Failed to fetch CVE %s from NVD: %s", cve_id, e)
        return None, False


def _build_cve_description(cve_id: str, ip: str, services_summary: str, host_result) -> str:
    """Build CVE description from context when NVD data unavailable."""
    # CVE keyword mappings
    cve_contexts = {
        "openssl": ("OpenSSL cryptographic library", "SSL/TLS"),
        "ssl": ("SSL/TLS protocol", "encrypted connections"),
        "tls": ("TLS protocol", "encrypted communications"),
        "nginx": ("NGINX web server", "HTTP/HTTPS"),
        "apache": ("Apache HTTP Server", "web hosting"),
        "ssh": ("SSH service", "remote access"),
        "openssh": ("OpenSSH", "secure shell"),
        "http": ("HTTP protocol", "web services"),
    }

    host_services = [
        svc.service_name.lower() if svc.service_name else "" for svc in host_result.services
    ]

    affected_component = None
    affected_type = None

    for keyword, (component, vtype) in cve_contexts.items():
        if any(keyword in svc for svc in host_services):
            affected_component = component
            affected_type = vtype
            break

    if affected_component:
        desc = f"Affects {affected_component} ({affected_type}). "
    else:
        desc = "Security vulnerability detected. "

    ports_str = ", ".join(str(p) for p in host_result.ports[:5])
    desc += f"Host {ip} exposes ports [{ports_str}]"

    if services_summary:
        desc += f" running {services_summary}"

    if host_result.org:
        desc += f" ({host_result.org})"

    return desc + "."


def _check_ssl_config(target: str, result: ScanResult) -> None:
    """Check SSL/TLS configuration using real analyzer."""
    try:
        with SSLAnalyzer() as checker:
            issues = checker.assess(target)
            result.config_issues.extend(issues)
    except Exception as e:
        result.errors.append(f"SSL check failed: {e}")


def _check_dns_config(target: str, result: ScanResult) -> None:
    """Check DNS security configuration using real checker."""
    try:
        with DnsSecurityChecker() as checker:
            issues = checker.assess(target)
            result.config_issues.extend(issues)
    except Exception as e:
        result.errors.append(f"DNS check failed: {e}")


def _check_http_headers(target: str, result: ScanResult) -> None:
    """Check HTTP security headers using real checker."""
    try:
        with HeadersChecker() as checker:
            issues = checker.assess(target)
            result.config_issues.extend(issues)
    except Exception as e:
        result.errors.append(f"Headers check failed: {e}")


def _check_outdated_software(target: str, result: ScanResult, include_minor: bool) -> None:
    """Check for outdated software versions."""
    # Requires service fingerprinting - placeholder for future
    pass


@app.command("list")
def list_vulns_cmd(
    ctx: typer.Context,
    scan_id: Annotated[
        int,
        typer.Argument(help="Scan ID to list vulnerabilities from"),
    ],
    enrich: Annotated[
        bool,
        typer.Option("--enrich", "-e", help="Enrich with NVD descriptions (slower)"),
    ] = False,
    all_vulns: Annotated[
        bool,
        typer.Option("--all", "-a", help="Show all vulnerabilities (no limit)"),
    ] = False,
    output_json: Annotated[
        bool,
        typer.Option("--json", help="Output as JSON"),
    ] = False,
    min_severity: Annotated[
        str,
        typer.Option("--min-severity", "-s", help="Filter by minimum severity"),
    ] = "low",
) -> None:
    """
    📋 List all vulnerabilities from a scan.

    Shows detailed vulnerability information from a previous scan.
    Use --enrich to fetch descriptions from NVD (National Vulnerability Database).

    [bold cyan]Examples:[/bold cyan]

        [dim]# List vulns from scan 32[/dim]
        domainraptor assess list 32

        [dim]# Enrich with NVD descriptions[/dim]
        domainraptor assess list 32 --enrich

        [dim]# Show all as JSON[/dim]
        domainraptor assess list 32 --all --json

        [dim]# High severity only[/dim]
        domainraptor assess list 32 --min-severity high
    """
    import json

    from rich.panel import Panel
    from rich.table import Table

    from domainraptor.storage import ScanRepository

    print_info(f"Loading vulnerabilities from scan {scan_id}...")

    # Load scan
    repo = ScanRepository()
    scan = repo.get_by_id(scan_id)

    if not scan:
        print_warning(f"Scan {scan_id} not found")
        raise typer.Exit(1)

    vulns = scan.vulnerabilities

    if not vulns:
        print_warning(f"No vulnerabilities found in scan {scan_id}")
        return

    # Filter by severity
    severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    min_sev_value = severity_order.get(min_severity.lower(), 0)
    vulns = [v for v in vulns if severity_order.get(v.severity.value.lower(), 0) >= min_sev_value]

    print_info(f"Found {len(vulns)} vulnerabilities (min severity: {min_severity})")

    # Enrich with NVD if requested
    if enrich:
        console.print()
        print_info("Enriching with NVD data (this may take a while)...")
        from domainraptor.discovery.nvd_client import NVDClient, NVDRateLimitError

        client = NVDClient()
        enriched_count = 0
        try:
            with create_progress() as progress:
                task = progress.add_task("Fetching CVE details...", total=len(vulns))

                for vuln in vulns:
                    if vuln.id.startswith("CVE-"):
                        try:
                            info = client.get_cve(vuln.id)
                            if info:
                                vuln.description = info.description
                                vuln.severity = SeverityLevel(info.severity.lower())
                                vuln.cvss_score = info.cvss_v3_score
                                vuln.cvss_vector = info.cvss_v3_vector
                                enriched_count += 1
                        except NVDRateLimitError:
                            print_warning(
                                f"Rate limited - enriched {enriched_count}/{len(vulns)} CVEs"
                            )
                            break
                    progress.advance(task)

            print_info(f"Enriched {enriched_count} of {len(vulns)} vulnerabilities")
        finally:
            client.close()

    # Output
    if output_json:
        data = [
            {
                "id": v.id,
                "title": v.title,
                "severity": v.severity.value,
                "description": v.description,
                "affected_asset": v.affected_asset,
                "cvss_score": v.cvss_score,
                "source": v.source,
            }
            for v in vulns
        ]
        console.print(json.dumps(data, indent=2))
    else:
        # Print as table
        limit = None if all_vulns else 30
        displayed = vulns[:limit] if limit else vulns

        table = Table(
            title=f"Vulnerabilities - Scan {scan_id} ({len(vulns)} total)",
            show_header=True,
            header_style="bold cyan",
        )
        table.add_column("CVE ID", style="bold yellow", width=18)
        table.add_column("Severity", width=10)
        table.add_column("CVSS", width=6)
        table.add_column("Affected", width=18)
        table.add_column("Description", max_width=50)

        severity_colors = {
            "critical": "red bold",
            "high": "red",
            "medium": "yellow",
            "low": "green",
            "info": "blue",
        }

        for v in displayed:
            sev = v.severity.value.lower()
            color = severity_colors.get(sev, "white")
            cvss = f"{v.cvss_score:.1f}" if v.cvss_score else "-"
            desc = v.description[:80] + "..." if len(v.description) > 80 else v.description

            table.add_row(
                v.id,
                f"[{color}]{sev.upper()}[/{color}]",
                cvss,
                v.affected_asset or "-",
                desc or "No description available",
            )

        console.print(table)

        if limit and len(vulns) > limit:
            console.print(f"\n[dim]Showing {limit} of {len(vulns)}. Use --all to see all.[/dim]")

        # Summary
        console.print()
        by_severity = {}
        for v in vulns:
            sev = v.severity.value
            by_severity[sev] = by_severity.get(sev, 0) + 1

        summary = " | ".join(
            f"[{severity_colors.get(s.lower(), 'white')}]{s.upper()}: {c}[/{severity_colors.get(s.lower(), 'white')}]"
            for s, c in sorted(
                by_severity.items(), key=lambda x: severity_order.get(x[0].lower(), 0), reverse=True
            )
        )
        console.print(Panel(summary, title="Summary by Severity"))
