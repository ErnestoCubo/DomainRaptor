"""Recon command - full reconnaissance workflow."""

from __future__ import annotations

import json
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
        str,
        typer.Option("--target", "-T", help="Target domain to recon"),
    ],
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
