"""Recon command - full reconnaissance workflow."""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Annotated, Any

import typer
from rich.panel import Panel
from rich.table import Table

from domainraptor.core.config import AppConfig
from domainraptor.core.types import AssetType, ScanResult
from domainraptor.utils.output import (
    console,
    create_progress,
    print_error,
    print_info,
    print_scan_summary,
    print_success,
    print_warning,
)

app = typer.Typer(
    name="recon",
    help="🎯 Full reconnaissance workflow: subdomains → IPs → services",
    no_args_is_help=True,
)


class ReconDepth(str, Enum):
    """Reconnaissance depth level."""

    SHALLOW = "shallow"
    STANDARD = "standard"
    DEEP = "deep"


@app.callback(invoke_without_command=True)
def recon_callback(
    ctx: typer.Context,
    target: Annotated[
        str | None,
        typer.Option("--target", "-T", help="Target domain to recon"),
    ] = None,
    depth: Annotated[
        ReconDepth,
        typer.Option("--depth", "-d", help="Recon depth: shallow, standard, deep"),
    ] = ReconDepth.STANDARD,
    max_ips: Annotated[
        int,
        typer.Option("--max-ips", help="Maximum IPs to enrich via Shodan"),
    ] = 10,
    resolve_all: Annotated[
        bool,
        typer.Option("--resolve-all", help="Resolve all subdomain IPs (ignores max-ips for DNS)"),
    ] = False,
    output_json: Annotated[
        bool,
        typer.Option("--json", help="Output as JSON"),
    ] = False,
    output_csv: Annotated[
        bool,
        typer.Option("--csv", help="Output as CSV"),
    ] = False,
    output_file: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Output file path"),
    ] = None,
    from_scan: Annotated[
        int | None,
        typer.Option("--from-scan", help="Enrich existing scan by ID"),
    ] = None,
    save: Annotated[
        bool,
        typer.Option("--save/--no-save", help="Save results to database"),
    ] = True,
) -> None:
    """
    🎯 Full reconnaissance workflow.

    Performs a complete reconnaissance:
    1. Discover subdomains (crt.sh, HackerTarget, Shodan DNS)
    2. Resolve IPs for each subdomain
    3. Query Shodan for port/service/vulnerability info per IP
    4. Generate consolidated report

    [bold cyan]Depth levels:[/bold cyan]

        • shallow  - crt.sh only, top 5 IPs, basic ports
        • standard - crt.sh + HackerTarget, top 10 IPs, full Shodan
        • deep     - All sources + VT + SecurityTrails, all IPs

    [bold cyan]Examples:[/bold cyan]

        [dim]# Standard recon[/dim]
        domainraptor recon -T example.com

        [dim]# Deep recon with more IPs[/dim]
        domainraptor recon -T example.com --depth deep --max-ips 50

        [dim]# Export as JSON[/dim]
        domainraptor recon -T example.com --json -o recon.json

        [dim]# Enrich existing scan[/dim]
        domainraptor recon -T example.com --from-scan 26
    """
    # If a subcommand is being invoked, skip the callback logic
    if ctx.invoked_subcommand is not None:
        return

    # Require --target when running as main command
    if not target:
        print_error(
            "Missing option '--target' / '-T'. Use 'domainraptor recon fullscan' for multi-source scan."
        )
        raise typer.Exit(1)

    config: AppConfig = ctx.obj.get("config", AppConfig())

    print_info(f"Starting full recon for: [bold]{target}[/bold]")
    print_info(f"Depth: {depth.value} | Max IPs: {max_ips}")

    # Create or load scan result
    if from_scan:
        result = _load_existing_scan(from_scan)
        if not result:
            print_error(f"Scan {from_scan} not found")
            raise typer.Exit(1)
        print_info(f"Loaded scan {from_scan} with {len(result.assets)} assets")
    else:
        result = ScanResult(
            target=target,
            scan_type="recon",
            started_at=datetime.now(),
            metadata={
                "depth": depth.value,
                "max_ips": max_ips,
            },
        )

    # Collect recon data
    recon_data: dict[str, Any] = {
        "target": target,
        "depth": depth.value,
        "max_ips": max_ips,
        "subdomains": [],
        "infrastructure": [],
    }

    with create_progress() as progress:
        task = progress.add_task("Reconnaissance...", total=100)

        # Step 1: Subdomain discovery (40%)
        if not from_scan:
            progress.update(task, description="Discovering subdomains...")
            _discover_subdomains_for_recon(target, result, depth, config)
            progress.update(task, advance=40)
        else:
            progress.update(task, advance=40)

        # Step 2: Resolve IPs (20%)
        progress.update(task, description="Resolving IP addresses...")
        ip_limit = None if resolve_all else (5 if depth == ReconDepth.SHALLOW else 50)
        _resolve_ips_for_recon(result, ip_limit)
        progress.update(task, advance=20)

        # Step 3: Shodan enrichment (40%)
        progress.update(task, description="Querying Shodan for services...")
        enriched_ips = _enrich_with_shodan(result, max_ips, config, progress, task)
        recon_data["infrastructure"] = enriched_ips
        progress.update(task, completed=100)

    # Mark complete
    result.completed_at = datetime.now()
    result.status = "completed" if not result.errors else "completed_with_errors"

    # Build subdomain data
    for asset in result.assets:
        if asset.type == AssetType.SUBDOMAIN:
            recon_data["subdomains"].append(
                {
                    "subdomain": asset.value,
                    "ip": asset.metadata.get("ip", ""),
                    "source": asset.source,
                }
            )

    # Output
    if output_json:
        output = _format_json(result, recon_data)
        if output_file:
            output_file.parent.mkdir(parents=True, exist_ok=True)
            output_file.write_text(output)
            print_success(f"JSON saved to: {output_file}")
        else:
            console.print(output)
    elif output_csv:
        output = _format_csv(recon_data)
        if output_file:
            output_file.parent.mkdir(parents=True, exist_ok=True)
            output_file.write_text(output)
            print_success(f"CSV saved to: {output_file}")
        else:
            console.print(output)
    else:
        # Rich table output
        console.print()
        print_scan_summary(result)
        console.print()
        _print_recon_table(recon_data)

    # Save to database
    if save:
        try:
            from domainraptor.storage import ScanRepository

            repo = ScanRepository()
            scan_id = repo.save(result)
            print_info(f"Results saved to database (scan ID: {scan_id})")
        except Exception as e:
            print_warning(f"Failed to save results: {e}")


def _load_existing_scan(scan_id: int) -> ScanResult | None:
    """Load an existing scan from database."""
    try:
        from domainraptor.storage import ScanRepository

        repo = ScanRepository()
        return repo.get_by_id(scan_id)
    except Exception:
        return None


def _discover_subdomains_for_recon(
    target: str,
    result: ScanResult,
    depth: ReconDepth,
    config: AppConfig,
) -> None:
    """Discover subdomains based on depth level."""
    try:
        from domainraptor.discovery.crtsh import CrtShClient
        from domainraptor.discovery.hackertarget import HackerTargetClient

        clients: list[Any] = [CrtShClient()]

        if depth in (ReconDepth.STANDARD, ReconDepth.DEEP):
            clients.append(HackerTargetClient())

        for client in clients:
            try:
                assets = client.query(target)
                for asset in assets:
                    if asset not in result.assets:
                        result.assets.append(asset)
            except Exception as e:  # noqa: PERF203
                result.errors.append(f"{client.name}: {e}")

        # Try Shodan DNS if available and deep mode
        shodan_key = os.environ.get("SHODAN_API_KEY")
        if depth == ReconDepth.DEEP and shodan_key:
            try:
                from domainraptor.discovery.shodan_client import ShodanClient

                shodan = ShodanClient(api_key=shodan_key)
                assets = shodan.dns_domain(target)
                for asset in assets:
                    if asset not in result.assets:
                        result.assets.append(asset)
            except Exception as e:
                result.errors.append(f"Shodan DNS: {e}")

    except Exception as e:
        result.errors.append(f"Subdomain discovery failed: {e}")


def _resolve_ips_for_recon(result: ScanResult, limit: int | None) -> None:
    """Resolve IPs for discovered subdomains."""
    try:
        from domainraptor.discovery.dns import DnsClient

        dns_client = DnsClient()

        subdomains = [a for a in result.assets if a.type == AssetType.SUBDOMAIN]
        to_resolve = subdomains[:limit] if limit else subdomains

        for subdomain_asset in to_resolve:
            try:
                ip_assets = dns_client.resolve_ip(subdomain_asset.value)
                if ip_assets:
                    # Store IP in subdomain metadata
                    subdomain_asset.metadata["ip"] = ip_assets[0].value
                    if len(ip_assets) > 1:
                        subdomain_asset.metadata["all_ips"] = [a.value for a in ip_assets]

                    # Add IP assets
                    for ip_asset in ip_assets:
                        ip_asset.parent = subdomain_asset.value
                        if ip_asset not in result.assets:
                            result.assets.append(ip_asset)
            except Exception:  # noqa: PERF203, S112
                continue  # Skip failed resolutions

    except Exception as e:
        result.errors.append(f"IP resolution failed: {e}")


def _fetch_nvd_descriptions(cve_ids: list[str], progress: Any, task: Any) -> dict[str, Any]:
    """Fetch CVE descriptions from NVD API.

    Args:
        cve_ids: List of CVE identifiers
        progress: Rich progress bar
        task: Progress task for updates

    Returns:
        Dict mapping CVE ID to CVEInfo objects
    """
    if not cve_ids:
        return {}

    try:
        from domainraptor.discovery.nvd_client import NVDClient, NVDRateLimitError

        progress.update(task, description=f"Fetching NVD data for {len(cve_ids)} CVEs...")

        client = NVDClient()
        results = {}

        try:
            for cve_id in cve_ids:
                try:
                    info = client.get_cve(cve_id)
                    if info:
                        results[cve_id] = info
                except NVDRateLimitError:  # noqa: PERF203
                    # Stop fetching on rate limit, use what we have
                    break
                except Exception:  # noqa: S112
                    continue  # Skip individual failures
        finally:
            client.close()

        return results

    except ImportError:
        # NVD client not available
        return {}
    except Exception:
        return {}


def _get_cve_context_description(
    cve_id: str, ip: str, services_summary: str, host_result: Any
) -> str:
    """Generate a descriptive CVE description based on context."""
    # CVE keyword mappings for common vulnerability types
    cve_contexts = {
        # OpenSSL vulnerabilities
        "openssl": ("OpenSSL cryptographic library", "SSL/TLS encrypted services"),
        "ssl": ("SSL/TLS protocol", "HTTPS, secure connections"),
        "tls": ("TLS protocol", "encrypted communications"),
        # Web vulnerabilities
        "jquery": ("jQuery JavaScript library", "web applications, frontend"),
        "nginx": ("NGINX web server", "HTTP/HTTPS services"),
        "apache": ("Apache HTTP Server", "web hosting"),
        "http": ("HTTP protocol", "web services"),
        # Database vulnerabilities
        "mongodb": ("MongoDB database", "data storage, NoSQL"),
        "mysql": ("MySQL database", "data storage, SQL"),
        "postgres": ("PostgreSQL database", "data storage, SQL"),
        "redis": ("Redis in-memory store", "caching, sessions"),
        # SSH/Remote
        "ssh": ("SSH service", "remote access"),
        "openssh": ("OpenSSH", "secure shell access"),
        # DNS
        "dns": ("DNS service", "domain resolution"),
        "bind": ("BIND DNS server", "DNS hosting"),
    }

    # Check if CVE matches known patterns from services
    host_services = [
        svc.service_name.lower() if svc.service_name else "" for svc in host_result.services
    ]

    # Try to identify what the CVE affects based on services running
    affected_component = None
    affected_type = None

    for keyword, (component, vtype) in cve_contexts.items():
        # Check if keyword is in running services
        if any(keyword in svc for svc in host_services):
            affected_component = component
            affected_type = vtype
            break
        # Check if keyword is in CVE ID patterns (some CVEs have hints)
        if keyword in cve_id.lower():
            affected_component = component
            affected_type = vtype
            break

    # Build description
    if affected_component:
        desc = f"Affects {affected_component} ({affected_type}). "
    else:
        desc = "Security vulnerability detected. "

    # Add host context
    ports_str = ", ".join(str(p) for p in host_result.ports[:5])
    if len(host_result.ports) > 5:
        ports_str += f" +{len(host_result.ports) - 5} more"

    desc += f"Host {ip} exposes ports [{ports_str}]"

    if services_summary:
        desc += f" running {services_summary}"

    org = host_result.org or "unknown organization"
    desc += f" ({org})."

    return desc


def _enrich_with_shodan(
    result: ScanResult,
    max_ips: int,
    config: AppConfig,
    progress: Any,
    task: Any,
) -> list[dict[str, Any]]:
    """Enrich IPs with Shodan data."""
    infrastructure: list[dict[str, Any]] = []

    shodan_key = os.environ.get("SHODAN_API_KEY")
    if not shodan_key:
        result.errors.append(
            "Shodan API key not configured. Run: domainraptor config set SHODAN_API_KEY <KEY>"
        )
        return infrastructure

    try:
        from domainraptor.discovery.shodan_client import ShodanClient

        shodan = ShodanClient(api_key=shodan_key)

        # Get unique IPs
        ip_assets = [a for a in result.assets if a.type == AssetType.IP]
        unique_ips = list({a.value for a in ip_assets})[:max_ips]

        progress.update(task, description=f"Querying Shodan for {len(unique_ips)} IPs...")

        for i, ip in enumerate(unique_ips):
            try:
                host_result = shodan.host_info(ip)

                # Build infrastructure entry
                infra_entry = {
                    "ip": ip,
                    "hostnames": host_result.hostnames,
                    "country": host_result.country,
                    "city": host_result.city,
                    "org": host_result.org,
                    "asn": host_result.asn,
                    "isp": host_result.isp,
                    "os": host_result.os,
                    "ports": host_result.ports,
                    "vulns": host_result.vulns,
                    "services": [],
                }

                # Add services
                for svc in host_result.services:
                    svc.metadata["ip"] = ip
                    svc.metadata["source"] = "shodan"
                    result.services.append(svc)

                    infra_entry["services"].append(
                        {
                            "port": svc.port,
                            "protocol": svc.protocol,
                            "service": svc.service_name,
                            "version": svc.version,
                            "banner": svc.banner[:100] if svc.banner else "",
                        }
                    )

                # Add vulnerabilities to result for DB persistence
                from domainraptor.core.types import SeverityLevel, Vulnerability

                # Enrich CVEs with NVD data for real descriptions
                cve_infos = _fetch_nvd_descriptions(host_result.vulns, progress, task)

                for cve_id in host_result.vulns:
                    nvd_info = cve_infos.get(cve_id)

                    if nvd_info:
                        # Use real NVD description
                        desc = nvd_info.description
                        severity = SeverityLevel(nvd_info.severity.lower())
                        cvss_score = nvd_info.cvss_v3_score
                    else:
                        # Fallback to context-based description
                        services_summary = ", ".join(
                            f"{svc.service_name or 'unknown'}:{svc.port}"
                            for svc in host_result.services[:5]
                        )
                        if len(host_result.services) > 5:
                            services_summary += f" (+{len(host_result.services) - 5} more)"
                        desc = _get_cve_context_description(
                            cve_id, ip, services_summary, host_result
                        )
                        severity = SeverityLevel.MEDIUM
                        cvss_score = None

                    result.vulnerabilities.append(
                        Vulnerability(
                            id=cve_id,
                            title=f"CVE {cve_id}",
                            severity=severity,
                            description=desc,
                            affected_asset=ip,
                            source="shodan",
                            detected_at=datetime.now(),
                            cvss_score=cvss_score,
                        )
                    )

                infrastructure.append(infra_entry)

                # Update progress
                pct = 40 + (i + 1) / len(unique_ips) * 40
                progress.update(task, completed=pct)

            except Exception as e:  # noqa: PERF203
                result.errors.append(f"Shodan lookup for {ip}: {e}")

    except ImportError:
        result.errors.append("Shodan client not available")
    except Exception as e:
        result.errors.append(f"Shodan enrichment failed: {e}")

    return infrastructure


def _print_recon_table(recon_data: dict[str, Any]) -> None:
    """Print reconnaissance results as a rich table."""
    # Infrastructure table
    infra = recon_data.get("infrastructure", [])

    if not infra:
        print_warning("No infrastructure data from Shodan")

        # At least show subdomains with IPs
        subdomains = recon_data.get("subdomains", [])
        if subdomains:
            table = Table(
                title="Discovered Subdomains",
                show_header=True,
                header_style="bold cyan",
            )
            table.add_column("Subdomain", style="bold")
            table.add_column("IP", style="cyan")
            table.add_column("Source")

            for sub in subdomains:
                table.add_row(
                    sub["subdomain"],
                    sub.get("ip", "-"),
                    sub["source"],
                )
            console.print(table)
        return

    # Main infrastructure table
    table = Table(
        title="Infrastructure Map",
        show_header=True,
        header_style="bold cyan",
    )
    table.add_column("IP", style="bold")
    table.add_column("Location")
    table.add_column("Org/ISP")
    table.add_column("Open Ports", style="cyan")
    table.add_column("Vulns", style="red")
    table.add_column("Services")

    for host in infra:
        ports_str = ", ".join(str(p) for p in host.get("ports", [])[:8])
        if len(host.get("ports", [])) > 8:
            ports_str += "..."

        vulns = host.get("vulns", [])
        vulns_str = f"[red]{len(vulns)}[/red]" if vulns else "0"

        services = host.get("services", [])
        svc_names = list({s["service"] for s in services if s.get("service")})[:3]
        svc_str = ", ".join(svc_names) or "-"

        location = f"{host.get('city', '')}, {host.get('country', '')}".strip(", ")

        table.add_row(
            host["ip"],
            location or "-",
            host.get("org") or host.get("isp") or "-",
            ports_str or "-",
            vulns_str,
            svc_str,
        )

    console.print(table)

    # Vulnerabilities summary
    all_vulns: list[str] = []
    for host in infra:
        all_vulns.extend(host.get("vulns", []))

    if all_vulns:
        console.print()
        unique_vulns = sorted(set(all_vulns))
        vuln_panel = Panel(
            "\n".join(f"[red]•[/red] {v}" for v in unique_vulns[:10]),
            title=f"[bold red]Vulnerabilities ({len(unique_vulns)} unique)[/bold red]",
            border_style="red",
        )
        console.print(vuln_panel)


def _format_json(result: ScanResult, recon_data: dict[str, Any]) -> str:
    """Format recon data as JSON."""
    output = {
        "target": result.target,
        "scan_type": "recon",
        "started_at": result.started_at.isoformat(),
        "completed_at": result.completed_at.isoformat() if result.completed_at else None,
        "status": result.status,
        "depth": recon_data.get("depth"),
        "summary": {
            "total_subdomains": len(recon_data.get("subdomains", [])),
            "total_ips": len(recon_data.get("infrastructure", [])),
            "total_services": len(result.services),
            "total_vulns": sum(
                len(h.get("vulns", [])) for h in recon_data.get("infrastructure", [])
            ),
        },
        "subdomains": recon_data.get("subdomains", []),
        "infrastructure": recon_data.get("infrastructure", []),
        "errors": result.errors,
    }
    return json.dumps(output, indent=2, default=str)


def _format_csv(recon_data: dict[str, Any]) -> str:
    """Format recon data as CSV."""
    lines = ["subdomain,ip,ports,vulns,services,location,org"]

    infra_map = {h["ip"]: h for h in recon_data.get("infrastructure", [])}

    for sub in recon_data.get("subdomains", []):
        ip = sub.get("ip", "")
        host = infra_map.get(ip, {})

        ports = ";".join(str(p) for p in host.get("ports", []))
        vulns = ";".join(host.get("vulns", []))
        services = ";".join(s.get("service", "") for s in host.get("services", []))
        location = f"{host.get('city', '')} {host.get('country', '')}".strip()
        org = host.get("org", "")

        # Escape CSV fields
        for field in [sub["subdomain"], ip, ports, vulns, services, location, org]:
            field = str(field).replace('"', '""')

        lines.append(
            f'"{sub["subdomain"]}","{ip}","{ports}","{vulns}","{services}","{location}","{org}"'
        )

    return "\n".join(lines)


# =============================================================================
# FULLSCAN Command - Centralized ASM Reconnaissance
# =============================================================================


@app.command("fullscan")
def fullscan_cmd(
    ctx: typer.Context,
    target: Annotated[
        str,
        typer.Argument(help="Target domain to perform full reconnaissance on"),
    ],
    output_file: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Output file path (JSON)"),
    ] = None,
    max_results: Annotated[
        int,
        typer.Option("--max-results", "-m", help="Max results per source"),
    ] = 50,
    shodan: Annotated[
        bool,
        typer.Option("--shodan/--no-shodan", help="Use Shodan"),
    ] = True,
    zoomeye: Annotated[
        bool,
        typer.Option("--zoomeye/--no-zoomeye", help="Use ZoomEye"),
    ] = True,
    censys: Annotated[
        bool,
        typer.Option("--censys/--no-censys", help="Use Censys"),
    ] = True,
    crtsh: Annotated[
        bool,
        typer.Option("--crtsh/--no-crtsh", help="Use crt.sh"),
    ] = True,
    hackertarget: Annotated[
        bool,
        typer.Option("--hackertarget/--no-hackertarget", help="Use HackerTarget"),
    ] = True,
    resolve_ips: Annotated[
        bool,
        typer.Option("--resolve-ips/--no-resolve-ips", help="Resolve subdomain IPs"),
    ] = True,
    save: Annotated[
        bool,
        typer.Option("--save/--no-save", help="Save results to database"),
    ] = True,
) -> None:
    """
    🎯 FULL ASM RECONNAISSANCE - Centralized multi-source attack surface discovery.

    Combines ALL reconnaissance sources into a single comprehensive scan:

    [bold cyan]Data Sources:[/bold cyan]
        • crt.sh         - Certificate Transparency subdomain discovery
        • HackerTarget   - Free subdomain enumeration
        • Shodan         - Host/port/service/vulnerability data
        • ZoomEye        - Chinese cyberspace search engine
        • Censys         - Internet-wide scanning data

    [bold cyan]Output Includes:[/bold cyan]
        • Subdomains with resolved IPs
        • Open ports and services per IP
        • Banners and version info
        • CVE vulnerabilities (with CVSS scores)
        • Organization and ASN info
        • Geographic location
        • SSL certificate data

    [bold cyan]Examples:[/bold cyan]

        [dim]# Full reconnaissance[/dim]
        domainraptor recon fullscan example.com

        [dim]# Save comprehensive JSON report[/dim]
        domainraptor recon fullscan example.com -o fullscan.json

        [dim]# Only Shodan and Censys[/dim]
        domainraptor recon fullscan example.com --no-zoomeye --no-crtsh

        [dim]# Larger result set[/dim]
        domainraptor recon fullscan example.com --max-results 200
    """
    from rich.table import Table

    print_info(f"Starting FULL ASM reconnaissance for: [bold]{target}[/bold]")

    # Track enabled sources
    sources_enabled = []
    if crtsh:
        sources_enabled.append("crt.sh")
    if hackertarget:
        sources_enabled.append("HackerTarget")
    if shodan and os.environ.get("SHODAN_API_KEY"):
        sources_enabled.append("Shodan")
    if zoomeye and os.environ.get("ZOOMEYE_API_KEY"):
        sources_enabled.append("ZoomEye")

    # Censys: support PAT token (v3 API) or legacy API ID/Secret
    censys_has_token = os.environ.get("CENSYS_API_TOKEN") or os.environ.get(
        "CENSYS_API_KEY", ""
    ).startswith("censys_")
    censys_has_legacy = os.environ.get("CENSYS_API_ID") and os.environ.get("CENSYS_API_SECRET")
    censys_configured = censys_has_token or censys_has_legacy

    if censys and censys_configured:
        sources_enabled.append("Censys")

    if not sources_enabled:
        print_error(
            "No data sources available. Configure at least one API key or enable free sources."
        )
        raise typer.Exit(1)

    print_info(f"Sources: [cyan]{', '.join(sources_enabled)}[/cyan]")
    console.print()

    # Initialize result containers
    all_subdomains: dict[str, dict[str, Any]] = {}  # subdomain -> {source, ip, ...}
    all_hosts: dict[str, dict[str, Any]] = {}  # ip -> host data
    all_vulns: list[dict[str, Any]] = []
    all_certs: list[dict[str, Any]] = []
    errors: list[str] = []

    result = ScanResult(
        target=target,
        scan_type="fullscan",
        started_at=datetime.now(),
        metadata={
            "sources": sources_enabled,
            "max_results": max_results,
        },
    )

    # ==========================================================================
    # PHASE 1: Subdomain Discovery
    # ==========================================================================
    console.print(Panel.fit("[bold cyan]PHASE 1: Subdomain Discovery[/bold cyan]"))

    with create_progress() as progress:
        task = progress.add_task("Discovering subdomains...", total=100)

        # crt.sh
        if crtsh:
            progress.update(task, description="[crt.sh] Discovering subdomains...")
            try:
                from domainraptor.discovery.crtsh import CrtShClient

                client = CrtShClient()
                assets = client.query(target)
                for asset in assets:
                    if asset.value not in all_subdomains:
                        all_subdomains[asset.value] = {"source": "crt.sh"}
                print_success(f"[crt.sh] Found {len(assets)} certificates")
            except Exception as e:
                errors.append(f"crt.sh: {e}")
                print_warning(f"[crt.sh] Failed: {e}")
            progress.update(task, advance=20)

        # HackerTarget
        if hackertarget:
            progress.update(task, description="[HackerTarget] Discovering subdomains...")
            try:
                from domainraptor.discovery.hackertarget import HackerTargetClient

                client = HackerTargetClient()
                assets = client.query(target)
                for asset in assets:
                    if asset.value not in all_subdomains:
                        all_subdomains[asset.value] = {"source": "hackertarget"}
                print_success(f"[HackerTarget] Found {len(assets)} subdomains")
            except Exception as e:
                errors.append(f"HackerTarget: {e}")
                print_warning(f"[HackerTarget] Failed: {e}")
            progress.update(task, advance=20)

        # Shodan DNS
        if shodan and os.environ.get("SHODAN_API_KEY"):
            progress.update(task, description="[Shodan] Discovering subdomains...")
            try:
                from domainraptor.discovery.shodan_client import ShodanClient

                client = ShodanClient()
                assets = client.dns_domain(target)
                for asset in assets:
                    if asset.value not in all_subdomains:
                        all_subdomains[asset.value] = {"source": "shodan"}
                print_success(f"[Shodan DNS] Found {len(assets)} subdomains")
            except Exception as e:
                errors.append(f"Shodan DNS: {e}")
            progress.update(task, advance=20)

        # Censys Certificates (requires paid subscription)
        if censys and censys_configured:
            progress.update(task, description="[Censys] Searching certificates...")
            try:
                from domainraptor.discovery.censys_client import CensysAPIKeyError, CensysClient

                client = CensysClient()
                try:
                    certs, _ = client.search_certificates(f'names: "*.{target}"', per_page=50)
                except CensysAPIKeyError:
                    # Search requires paid subscription, skip cert discovery
                    certs = []
                    print_warning(
                        "[Censys] Certificate search requires paid subscription, skipping..."
                    )
                for cert in certs:
                    all_certs.append(
                        {
                            "names": cert.names,
                            "issuer": cert.issuer,
                            "valid_to": cert.validity_end.isoformat()
                            if cert.validity_end
                            else None,
                        }
                    )
                    for name in cert.names:
                        if (
                            name.endswith(target)
                            and not name.startswith("*")
                            and name not in all_subdomains
                        ):
                            all_subdomains[name] = {"source": "censys-certs"}
                print_success(f"[Censys] Found {len(certs)} certificates")
            except CensysAPIKeyError:
                print_warning("[Censys] Skipping cert search (requires paid subscription)")
            except Exception as e:
                errors.append(f"Censys certs: {e}")
            progress.update(task, advance=20)

        # ZoomEye domain search (uses free endpoint)
        if zoomeye and os.environ.get("ZOOMEYE_API_KEY"):
            progress.update(task, description="[ZoomEye] Searching subdomains...")
            try:
                from domainraptor.discovery.zoomeye_client import ZoomEyeClient

                client = ZoomEyeClient()
                # Use domain_search which is free (doesn't require paid credits)
                results = client.domain_search(target, limit=max_results)
                zoomeye_count = 0
                for r in results:
                    name = r.get("name", "")
                    if name and name.endswith(target) and name not in all_subdomains:
                        all_subdomains[name] = {
                            "source": "zoomeye",
                            "ips": r.get("ip", []),
                        }
                        zoomeye_count += 1
                print_success(f"[ZoomEye] Found {zoomeye_count} subdomains")
            except Exception as e:
                errors.append(f"ZoomEye: {e}")
            progress.update(task, advance=20)

        progress.update(task, completed=100)

    print_info(f"Total unique subdomains: [bold]{len(all_subdomains)}[/bold]")
    console.print()

    # ==========================================================================
    # PHASE 2: IP Resolution
    # ==========================================================================
    if resolve_ips and all_subdomains:
        console.print(Panel.fit("[bold cyan]PHASE 2: IP Resolution[/bold cyan]"))

        with create_progress() as progress:
            task = progress.add_task("Resolving IPs...", total=len(all_subdomains))

            from domainraptor.discovery.dns import DnsClient

            dns_client = DnsClient()
            resolved_count = 0

            for subdomain in list(all_subdomains.keys()):
                try:
                    ip_assets = dns_client.resolve_ip(subdomain)
                    if ip_assets:
                        ip = ip_assets[0].value
                        all_subdomains[subdomain]["ip"] = ip
                        all_subdomains[subdomain]["all_ips"] = [a.value for a in ip_assets]
                        resolved_count += 1
                except Exception:
                    logging.debug("DNS resolution failed for %s", subdomain)
                progress.update(task, advance=1)

        print_info(f"Resolved {resolved_count}/{len(all_subdomains)} subdomains")
        console.print()

    # ==========================================================================
    # PHASE 3: Host Enrichment (Shodan, ZoomEye, Censys)
    # ==========================================================================
    console.print(Panel.fit("[bold cyan]PHASE 3: Host Enrichment[/bold cyan]"))

    # Collect unique IPs
    unique_ips = list({data.get("ip") for data in all_subdomains.values() if data.get("ip")})[
        :max_results
    ]

    print_info(f"Enriching {len(unique_ips)} unique IPs...")

    with create_progress() as progress:
        task = progress.add_task("Querying intelligence sources...", total=len(unique_ips) * 3)

        # Shodan enrichment
        if shodan and os.environ.get("SHODAN_API_KEY"):
            progress.update(task, description="[Shodan] Enriching hosts...")
            try:
                from domainraptor.discovery.shodan_client import ShodanClient

                client = ShodanClient()
                for ip in unique_ips:
                    try:
                        host = client.host_info(ip)
                        if ip not in all_hosts:
                            all_hosts[ip] = {
                                "ip": ip,
                                "hostnames": [],
                                "ports": [],
                                "services": [],
                                "vulns": [],
                                "sources": [],
                            }
                        all_hosts[ip]["hostnames"].extend(host.hostnames)
                        all_hosts[ip]["ports"].extend(host.ports)
                        all_hosts[ip]["org"] = host.org
                        all_hosts[ip]["asn"] = host.asn
                        all_hosts[ip]["country"] = host.country
                        all_hosts[ip]["city"] = host.city
                        all_hosts[ip]["os"] = host.os
                        all_hosts[ip]["sources"].append("shodan")

                        for svc in host.services:
                            all_hosts[ip]["services"].append(
                                {
                                    "port": svc.port,
                                    "protocol": svc.protocol,
                                    "service": svc.service_name,
                                    "version": svc.version,
                                    "banner": svc.banner[:200] if svc.banner else "",
                                    "source": "shodan",
                                }
                            )

                        for cve in host.vulns:
                            all_hosts[ip]["vulns"].append(cve)
                            all_vulns.append(
                                {
                                    "cve": cve,
                                    "ip": ip,
                                    "source": "shodan",
                                }
                            )
                    except Exception:
                        logging.debug("Shodan lookup failed for host")
                    progress.update(task, advance=1)
                print_success(
                    f"[Shodan] Enriched {len([h for h in all_hosts.values() if 'shodan' in h.get('sources', [])])} hosts"
                )
            except Exception as e:
                errors.append(f"Shodan enrichment: {e}")

        # Censys enrichment (IP lookup works with free accounts)
        if censys and censys_configured:
            progress.update(task, description="[Censys] Enriching hosts...")
            try:
                from domainraptor.discovery.censys_client import CensysClient

                client = CensysClient()
                censys_enriched = 0
                for ip in unique_ips[:25]:  # Censys rate limit is stricter
                    try:
                        host = client.get_host(ip)
                        if host:
                            if ip not in all_hosts:
                                all_hosts[ip] = {
                                    "ip": ip,
                                    "hostnames": [],
                                    "ports": [],
                                    "services": [],
                                    "vulns": [],
                                    "sources": [],
                                }
                            all_hosts[ip]["hostnames"].extend(host.hostnames)
                            all_hosts[ip]["ports"].extend(host.ports)
                            all_hosts[ip]["autonomous_system"] = host.autonomous_system
                            all_hosts[ip]["labels"] = host.labels
                            all_hosts[ip]["sources"].append("censys")

                            for svc in host.services:
                                all_hosts[ip]["services"].append(
                                    {
                                        "port": svc.port,
                                        "protocol": svc.protocol,
                                        "service": svc.service_name,
                                        "version": svc.version,
                                        "source": "censys",
                                    }
                                )
                            censys_enriched += 1
                    except Exception:
                        logging.debug("Censys lookup failed for host")
                    progress.update(task, advance=1)
                print_success(f"[Censys] Enriched {censys_enriched} hosts")
            except Exception as e:
                errors.append(f"Censys enrichment: {e}")

        # ZoomEye enrichment (requires paid credits for IP lookup)
        if zoomeye and os.environ.get("ZOOMEYE_API_KEY"):
            progress.update(task, description="[ZoomEye] Enriching hosts...")
            try:
                from domainraptor.discovery.zoomeye_client import ZoomEyeClient, ZoomEyeError

                client = ZoomEyeClient()
                zoomeye_enriched = 0
                zoomeye_skipped = False
                for ip in unique_ips[:20]:  # ZoomEye has credit limits
                    try:
                        host = client.search_by_ip(ip)
                        if host:
                            if ip not in all_hosts:
                                all_hosts[ip] = {
                                    "ip": ip,
                                    "hostnames": [],
                                    "ports": [],
                                    "services": [],
                                    "vulns": [],
                                    "sources": [],
                                }
                            all_hosts[ip]["device_type"] = host.device_type
                            all_hosts[ip]["sources"].append("zoomeye")

                            for svc in host.services:
                                all_hosts[ip]["services"].append(
                                    {
                                        "port": svc.port,
                                        "protocol": svc.protocol,
                                        "service": svc.service_name,
                                        "version": svc.version,
                                        "source": "zoomeye",
                                    }
                                )
                            zoomeye_enriched += 1
                    except ZoomEyeError as e:
                        if "Insufficient credits" in str(e) or "402" in str(e):
                            if not zoomeye_skipped:
                                print_warning(
                                    "[ZoomEye] Host enrichment requires paid credits, skipping..."
                                )
                                zoomeye_skipped = True
                            break
                    except Exception:
                        logging.debug("ZoomEye lookup failed for host")
                    progress.update(task, advance=1)
                if zoomeye_enriched > 0:
                    print_success(f"[ZoomEye] Enriched {zoomeye_enriched} hosts")
                elif not zoomeye_skipped:
                    print_info("[ZoomEye] No hosts enriched")
            except Exception as e:
                errors.append(f"ZoomEye enrichment: {e}")

        progress.update(task, completed=len(unique_ips) * 3)

    # Deduplicate data
    for data in all_hosts.values():
        data["hostnames"] = list(set(data.get("hostnames", [])))
        data["ports"] = sorted(set(data.get("ports", [])))
        data["vulns"] = list(set(data.get("vulns", [])))
        data["sources"] = list(set(data.get("sources", [])))

    # ==========================================================================
    # PHASE 4: Results Output - DETAILED VIEW
    # ==========================================================================
    console.print()
    console.print(
        Panel.fit(
            "[bold cyan]═══════════════ FULLSCAN COMPLETE RESULTS ═══════════════[/bold cyan]"
        )
    )

    # Summary stats
    total_vulns = len({v["cve"] for v in all_vulns})
    total_services = sum(len(h.get("services", [])) for h in all_hosts.values())

    summary_table = Table(show_header=False, box=None, padding=(0, 2))
    summary_table.add_column("Metric", style="bold white")
    summary_table.add_column("Value", style="bold cyan")

    summary_table.add_row("🎯 Target", target)
    summary_table.add_row("🌐 Subdomains", str(len(all_subdomains)))
    summary_table.add_row("🖥️  Unique IPs", str(len(all_hosts)))
    summary_table.add_row(
        "🔓 Open Ports", str(sum(len(h.get("ports", [])) for h in all_hosts.values()))
    )
    summary_table.add_row("⚙️  Services", str(total_services))
    summary_table.add_row("🔴 Vulnerabilities", f"[red]{total_vulns}[/red]" if total_vulns else "0")
    summary_table.add_row("📜 Certificates", str(len(all_certs)))
    summary_table.add_row("📡 Sources", ", ".join(sources_enabled))

    console.print(summary_table)
    console.print()

    # =========================================================================
    # TABLE 1: All Subdomains with IPs
    # =========================================================================
    console.print(Panel.fit("[bold green]📋 SUBDOMAINS DISCOVERED[/bold green]"))

    # Group subdomains by IP for better visualization
    subdomains_with_ip = [(sub, data) for sub, data in all_subdomains.items() if data.get("ip")]
    subdomains_without_ip = [
        (sub, data) for sub, data in all_subdomains.items() if not data.get("ip")
    ]

    if subdomains_with_ip:
        sub_table = Table(
            title=f"Subdomains with Resolved IPs ({len(subdomains_with_ip)})",
            show_header=True,
            header_style="bold green",
            show_lines=False,
        )
        sub_table.add_column("#", style="dim", width=4)
        sub_table.add_column("Subdomain", style="cyan", min_width=30)
        sub_table.add_column("IP Address", style="yellow")
        sub_table.add_column("Source", style="dim")
        sub_table.add_column("Enriched", style="green")

        for idx, (sub, data) in enumerate(sorted(subdomains_with_ip, key=lambda x: x[0]), 1):
            ip = data.get("ip", "")
            is_enriched = "✓" if ip in all_hosts else "-"
            sub_table.add_row(
                str(idx),
                sub,
                ip,
                data.get("source", "unknown"),
                is_enriched,
            )

        console.print(sub_table)
        console.print()

    if subdomains_without_ip:
        unresolved_table = Table(
            title=f"Subdomains Without IP (unresolved) ({len(subdomains_without_ip)})",
            show_header=True,
            header_style="bold yellow",
        )
        unresolved_table.add_column("#", style="dim", width=4)
        unresolved_table.add_column("Subdomain", style="cyan")
        unresolved_table.add_column("Source", style="dim")

        for idx, (sub, data) in enumerate(
            sorted(subdomains_without_ip, key=lambda x: x[0])[:50], 1
        ):
            unresolved_table.add_row(str(idx), sub, data.get("source", "unknown"))

        if len(subdomains_without_ip) > 50:
            unresolved_table.add_row(
                "...", f"[dim]+{len(subdomains_without_ip) - 50} more[/dim]", ""
            )

        console.print(unresolved_table)
        console.print()

    # =========================================================================
    # TABLE 2: All Hosts with Complete Details
    # =========================================================================
    if all_hosts:
        console.print(Panel.fit("[bold yellow]🖥️  HOSTS & INFRASTRUCTURE[/bold yellow]"))

        # Sort by vulnerability count, then ports
        hosts_sorted = sorted(
            all_hosts.values(),
            key=lambda h: (len(h.get("vulns", [])), len(h.get("ports", []))),
            reverse=True,
        )

        for host in hosts_sorted:
            ip = host.get("ip", "")
            vulns = host.get("vulns", [])
            services = host.get("services", [])

            # Host header with key info
            vuln_badge = (
                f"[bold red]🔴 {len(vulns)} VULNS[/bold red]"
                if vulns
                else "[green]✓ No vulns[/green]"
            )
            org = host.get("org") or host.get("autonomous_system", "") or "Unknown"
            location = f"{host.get('city', '')} {host.get('country', '')}".strip() or "Unknown"

            host_panel_title = (
                f"[bold yellow]{ip}[/bold yellow] | {org[:30]} | {location} | {vuln_badge}"
            )
            console.print(f"\n┌─ {host_panel_title}")

            # Hostnames
            hostnames = host.get("hostnames", [])
            if hostnames:
                console.print(f"│  [dim]Hostnames:[/dim] {', '.join(hostnames[:5])}")
                if len(hostnames) > 5:
                    console.print(f"│             [dim]+{len(hostnames) - 5} more[/dim]")

            # Ports summary
            ports = host.get("ports", [])
            if ports:
                console.print(
                    f"│  [dim]Ports:[/dim] [green]{', '.join(str(p) for p in ports)}[/green]"
                )

            # OS info if available
            if host.get("os"):
                console.print(f"│  [dim]OS:[/dim] {host.get('os')}")

            # ASN info
            if host.get("asn"):
                console.print(f"│  [dim]ASN:[/dim] {host.get('asn')}")

            # Services table
            if services:
                console.print("│")
                console.print("│  [bold]Services:[/bold]")
                console.print(
                    "│    [dim]Port   Proto  Service       Version              Banner[/dim]"
                )
                console.print(
                    "│    [dim]─────  ─────  ────────────  ──────────────────── ──────────────────────────[/dim]"
                )

                # Deduplicate services by port
                seen_ports: set[int] = set()
                for svc in services:
                    port = svc.get("port", 0)
                    if port in seen_ports:
                        continue
                    seen_ports.add(port)

                    banner = svc.get("banner", "")[:30] or "-"
                    if len(svc.get("banner", "")) > 30:
                        banner += "..."

                    port_str = str(port).ljust(5)
                    proto_str = svc.get("protocol", "tcp")[:5].ljust(5)
                    service_str = (svc.get("service") or "-")[:12].ljust(12)
                    version_str = (svc.get("version") or "-")[:20].ljust(20)

                    console.print(
                        f"│    [green]{port_str}[/green]  {proto_str}  [cyan]{service_str}[/cyan]  [yellow]{version_str}[/yellow] {banner}"
                    )

            # Vulnerabilities for this host
            if vulns:
                console.print("│")
                console.print(f"│  [bold red]Vulnerabilities ({len(vulns)}):[/bold red]")
                for cve in vulns[:10]:
                    console.print(f"│    [red]• {cve}[/red]")
                if len(vulns) > 10:
                    console.print(f"│    [dim]+{len(vulns) - 10} more CVEs[/dim]")

            # Sources
            console.print(f"│  [dim]Sources: {', '.join(host.get('sources', []))}[/dim]")
            console.print("└" + "─" * 70)

        console.print()

    # =========================================================================
    # TABLE 3: All Services Summary
    # =========================================================================
    if any(h.get("services") for h in all_hosts.values()):
        console.print(Panel.fit("[bold magenta]⚙️  SERVICES SUMMARY[/bold magenta]"))

        # Aggregate all services by port/service
        service_summary: dict[str, dict] = {}
        for host in all_hosts.values():
            ip = host.get("ip", "")
            for svc in host.get("services", []):
                key = f"{svc.get('port')}:{svc.get('service', 'unknown')}"
                if key not in service_summary:
                    service_summary[key] = {
                        "port": svc.get("port"),
                        "service": svc.get("service", "unknown"),
                        "versions": set(),
                        "hosts": [],
                    }
                if svc.get("version"):
                    service_summary[key]["versions"].add(svc.get("version"))
                if ip not in service_summary[key]["hosts"]:
                    service_summary[key]["hosts"].append(ip)

        svc_sum_table = Table(
            title=f"Service Distribution ({len(service_summary)} unique)",
            show_header=True,
            header_style="bold magenta",
        )
        svc_sum_table.add_column("Port", style="green")
        svc_sum_table.add_column("Service", style="cyan")
        svc_sum_table.add_column("Hosts", style="yellow")
        svc_sum_table.add_column("Versions", style="dim")

        for key in sorted(service_summary.keys(), key=lambda k: service_summary[k]["port"]):
            data = service_summary[key]
            hosts_str = ", ".join(data["hosts"][:3])
            if len(data["hosts"]) > 3:
                hosts_str += f" +{len(data['hosts']) - 3}"
            versions_str = ", ".join(list(data["versions"])[:2]) or "-"

            svc_sum_table.add_row(
                str(data["port"]),
                data["service"],
                hosts_str,
                versions_str[:40],
            )

        console.print(svc_sum_table)
        console.print()

    # =========================================================================
    # TABLE 4: Vulnerabilities Detail
    # =========================================================================
    if all_vulns:
        console.print(Panel.fit("[bold red]🔴 VULNERABILITIES[/bold red]"))

        # Group by CVE with affected hosts
        vuln_details: dict[str, dict] = {}
        for v in all_vulns:
            cve = v["cve"]
            if cve not in vuln_details:
                vuln_details[cve] = {
                    "cve": cve,
                    "hosts": [],
                    "source": v.get("source", "unknown"),
                }
            if v["ip"] not in vuln_details[cve]["hosts"]:
                vuln_details[cve]["hosts"].append(v["ip"])

        vuln_table = Table(
            title=f"All Vulnerabilities ({len(vuln_details)} unique CVEs)",
            show_header=True,
            header_style="bold red",
        )
        vuln_table.add_column("CVE ID", style="bold red")
        vuln_table.add_column("Affected Hosts", style="yellow")
        vuln_table.add_column("Count", style="cyan", justify="center")
        vuln_table.add_column("Source", style="dim")

        for cve in sorted(vuln_details.keys()):
            data = vuln_details[cve]
            hosts_str = ", ".join(data["hosts"][:5])
            if len(data["hosts"]) > 5:
                hosts_str += f" +{len(data['hosts']) - 5}"

            vuln_table.add_row(
                cve,
                hosts_str,
                str(len(data["hosts"])),
                data["source"],
            )

        console.print(vuln_table)
        console.print()

    # =========================================================================
    # TABLE 5: Certificates (if any)
    # =========================================================================
    if all_certs:
        console.print(Panel.fit("[bold blue]📜 SSL CERTIFICATES[/bold blue]"))

        cert_table = Table(
            title=f"Certificates Found ({len(all_certs)})",
            show_header=True,
            header_style="bold blue",
        )
        cert_table.add_column("#", style="dim", width=4)
        cert_table.add_column("Common Names", style="cyan", max_width=50)
        cert_table.add_column("Issuer", style="yellow", max_width=30)
        cert_table.add_column("Valid To", style="green")

        for idx, cert in enumerate(all_certs[:50], 1):
            names = ", ".join(cert.get("names", [])[:3])
            if len(cert.get("names", [])) > 3:
                names += f" +{len(cert.get('names', [])) - 3}"

            cert_table.add_row(
                str(idx),
                names,
                (cert.get("issuer") or "-")[:30],
                cert.get("valid_to", "-")[:10] if cert.get("valid_to") else "-",
            )

        if len(all_certs) > 50:
            cert_table.add_row("...", f"[dim]+{len(all_certs) - 50} more[/dim]", "", "")

        console.print(cert_table)
        console.print()

    # =========================================================================
    # Errors (if any)
    # =========================================================================
    if errors:
        console.print(Panel.fit("[bold yellow]⚠️  ERRORS & WARNINGS[/bold yellow]"))
        for err in errors:
            console.print(f"  [yellow]• {err}[/yellow]")
        console.print()

    # Build full report
    full_report = {
        "target": target,
        "timestamp": datetime.now().isoformat(),
        "sources": sources_enabled,
        "summary": {
            "subdomains": len(all_subdomains),
            "unique_ips": len(all_hosts),
            "total_ports": sum(len(h.get("ports", [])) for h in all_hosts.values()),
            "total_services": total_services,
            "total_vulnerabilities": total_vulns,
            "certificates": len(all_certs),
        },
        "subdomains": [{"subdomain": sub, **data} for sub, data in all_subdomains.items()],
        "hosts": list(all_hosts.values()),
        "vulnerabilities": all_vulns,
        "certificates": all_certs,
        "errors": errors,
    }

    # Save to file if requested
    if output_file:
        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_file.write_text(json.dumps(full_report, indent=2, default=str))
        print_success(f"Full report saved to: {output_file}")

    # Save to database
    if save:
        try:
            from domainraptor.core.types import Asset, AssetType, Service, Vulnerability
            from domainraptor.storage import ScanRepository

            # Add subdomains
            for sub, data in all_subdomains.items():
                result.assets.append(
                    Asset(
                        type=AssetType.SUBDOMAIN,
                        value=sub,
                        parent=target,
                        source=data.get("source", "unknown"),
                        metadata={"ip": data.get("ip")},
                    )
                )

            # Add IPs and services
            for ip, host in all_hosts.items():
                result.assets.append(
                    Asset(
                        type=AssetType.IP,
                        value=ip,
                        source=",".join(host.get("sources", [])),
                        metadata={
                            "org": host.get("org"),
                            "asn": host.get("asn"),
                            "country": host.get("country"),
                        },
                    )
                )

                for svc_data in host.get("services", []):
                    svc = Service(
                        port=svc_data.get("port", 0),
                        protocol=svc_data.get("protocol", "tcp"),
                        service_name=svc_data.get("service", ""),
                        version=svc_data.get("version", ""),
                        banner=svc_data.get("banner", ""),
                    )
                    svc.metadata["ip"] = ip
                    result.services.append(svc)

            # Add vulnerabilities
            from domainraptor.core.types import SeverityLevel

            for vuln_data in all_vulns:
                result.vulnerabilities.append(
                    Vulnerability(
                        id=vuln_data["cve"],
                        title=vuln_data["cve"],
                        severity=SeverityLevel.MEDIUM,
                        affected_asset=vuln_data["ip"],
                        source=vuln_data.get("source", "unknown"),
                    )
                )

            result.completed_at = datetime.now()
            result.status = "completed" if not errors else "completed_with_errors"
            result.errors = errors

            repo = ScanRepository()
            scan_id = repo.save(result)
            print_info(f"Results saved to database (scan ID: {scan_id})")
        except Exception as e:
            print_warning(f"Failed to save results: {e}")

    # Final summary
    print_success(
        f"Fullscan complete! Found {len(all_subdomains)} subdomains, {len(all_hosts)} hosts, {total_vulns} vulnerabilities"
    )
