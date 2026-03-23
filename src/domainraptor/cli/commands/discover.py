"""Discover command - domain, subdomain, and asset discovery."""

from __future__ import annotations

import os
from datetime import datetime
from typing import Annotated

import typer

from domainraptor.core.config import AppConfig, ScanMode
from domainraptor.core.types import ScanResult
from domainraptor.utils.output import (
    console,
    create_progress,
    print_assets_table,
    print_certificates_table,
    print_error,
    print_info,
    print_scan_summary,
    print_services_table,
    print_success,
    print_warning,
)

app = typer.Typer(
    name="discover",
    help="🔍 Discover domains, subdomains, IPs, and services",
    no_args_is_help=True,
)


@app.callback(invoke_without_command=True)
def discover_callback(
    ctx: typer.Context,
    target: Annotated[
        str | None,
        typer.Option("--target", "-T", help="Target domain or IP to discover"),
    ] = None,
    subdomains: Annotated[
        bool,
        typer.Option("--subdomains", "-s", help="Discover subdomains (default)"),
    ] = True,
    dns: Annotated[
        bool,
        typer.Option("--dns", "-d", help="Enumerate DNS records"),
    ] = True,
    certificates: Annotated[
        bool,
        typer.Option("--certs", help="Discover SSL/TLS certificates"),
    ] = True,
    ports: Annotated[
        bool,
        typer.Option("--ports", "-p", help="Discover open ports and services"),
    ] = False,
    whois: Annotated[
        bool,
        typer.Option("--whois", "-w", help="Include WHOIS information"),
    ] = True,
    recursive: Annotated[
        bool,
        typer.Option("--recursive", "-r", help="Recursively discover assets"),
    ] = False,
    sources: Annotated[
        str | None,
        typer.Option("--sources", help="Comma-separated list of sources to use"),
    ] = None,
    exclude_sources: Annotated[
        str | None,
        typer.Option("--exclude", help="Comma-separated list of sources to exclude"),
    ] = None,
    save: Annotated[
        bool,
        typer.Option("--save/--no-save", help="Save results to database"),
    ] = True,
) -> None:
    """
    🔍 Discover domains, subdomains, IPs, and services.

    [bold cyan]Examples:[/bold cyan]

        [dim]# Full discovery workflow[/dim]
        domainraptor discover -T example.com

        [dim]# Deep discovery with port scanning[/dim]
        domainraptor discover -T example.com --ports

        [dim]# Use specific sources only[/dim]
        domainraptor discover -T example.com --sources crt_sh,hackertarget

        [dim]# Individual commands (see subcommands)[/dim]
        domainraptor discover dns example.com
        domainraptor discover whois example.com
        domainraptor discover certs example.com
    """
    if target is None:
        # If no target and no subcommand, show help
        if ctx.invoked_subcommand is None:
            raise typer.Exit()
        return

    config: AppConfig = ctx.obj.get("config", AppConfig())

    # Parse sources
    source_list = sources.split(",") if sources else None
    exclude_list = exclude_sources.split(",") if exclude_sources else None

    print_info(f"Starting discovery for: [bold]{target}[/bold]")
    print_info(f"Mode: {config.mode.value} | Free only: {config.free_only}")

    # Create scan result
    result = ScanResult(
        target=target,
        scan_type="discover",
        started_at=datetime.now(),
        metadata={
            "mode": config.mode.value,
            "sources_requested": source_list,
            "sources_excluded": exclude_list,
        },
    )

    with create_progress() as progress:
        task = progress.add_task("Discovering assets...", total=100)

        # Step 1: DNS enumeration (20%)
        if dns:
            progress.update(task, description="Resolving DNS records...")
            # TODO: Implement DNS resolution using dnspython
            _discover_dns(target, result)
            progress.update(task, advance=20)

        # Step 2: Subdomain discovery (40%)
        if subdomains:
            progress.update(task, description="Discovering subdomains...")
            # TODO: Implement subdomain discovery via crt.sh, hackertarget
            _discover_subdomains(target, result, config, source_list, exclude_list)
            progress.update(task, advance=40)

        # Step 3: Certificate transparency (20%)
        if certificates:
            progress.update(task, description="Querying certificate transparency...")
            # TODO: Implement CT log querying
            _discover_certificates(target, result)
            progress.update(task, advance=20)

        # Step 4: Port scanning (10%)
        if ports and config.mode in (ScanMode.DEEP, ScanMode.STANDARD):
            progress.update(task, description="Scanning ports...")
            # TODO: Implement port scanning (via Shodan or local scan)
            _discover_ports(target, result, config)
            progress.update(task, advance=10)
        else:
            progress.update(task, advance=10)

        # Step 5: WHOIS (10%)
        if whois:
            progress.update(task, description="Querying WHOIS...")
            # TODO: Implement WHOIS lookup
            _discover_whois(target, result)
            progress.update(task, advance=10)

    # Mark complete
    result.completed_at = datetime.now()
    result.status = "completed" if not result.errors else "completed_with_errors"

    # Output results
    console.print()
    print_scan_summary(result)

    if result.assets:
        console.print()
        print_assets_table(result.assets)

    if result.services:
        console.print()
        print_services_table(result.services)

    if result.certificates:
        console.print()
        print_certificates_table(result.certificates)

    if result.errors:
        console.print()
        print_warning(f"Encountered {len(result.errors)} errors:")
        for err in result.errors[:5]:  # Show first 5
            print_error(f"  {err}")

    # Save to database
    if save:
        try:
            from domainraptor.storage import ScanRepository

            repo = ScanRepository()
            scan_id = repo.save(result)
            print_info(f"Results saved to database (scan ID: {scan_id})")
        except Exception as e:
            print_warning(f"Failed to save results: {e}")


def _discover_dns(target: str, result: ScanResult) -> None:
    """Discover DNS records for target."""
    try:
        from domainraptor.discovery.dns import DnsClient

        client = DnsClient()
        records = client.query(target)
        result.dns_records.extend(records)

        # Also resolve IPs
        ip_assets = client.resolve_ip(target)
        result.assets.extend(ip_assets)
    except ImportError:
        result.errors.append("DNS client not available (missing dnspython)")
    except Exception as e:
        result.errors.append(f"DNS discovery failed: {e}")


def _query_discovery_client(name: str, client: object, target: str) -> tuple[list, str | None]:
    """Query a discovery client and return assets or error."""
    try:
        assets = client.query(target)  # type: ignore[attr-defined]
        return assets, None
    except Exception as e:
        return [], f"Source {name} failed: {e}"


def _discover_subdomains(
    target: str,
    result: ScanResult,
    config: AppConfig,
    sources: list[str] | None,
    exclude: list[str] | None,
) -> None:
    """Discover subdomains using configured sources."""
    try:
        from domainraptor.discovery.crtsh import CrtShClient
        from domainraptor.discovery.hackertarget import HackerTargetClient

        # Build list of clients to use
        available_clients = {
            "crt_sh": CrtShClient,
            "hackertarget": HackerTargetClient,
        }

        clients_to_use = []
        for name, client_cls in available_clients.items():
            # Skip if explicitly excluded
            if exclude and name in exclude:
                continue
            # Skip if sources specified and not in list
            if sources and name not in sources:
                continue
            clients_to_use.append((name, client_cls()))

        # Query each client using helper function to avoid try-except in loop
        for name, client in clients_to_use:
            assets, error = _query_discovery_client(name, client, target)
            result.assets.extend(assets)
            if error:
                result.errors.append(error)

        # Add external API sources if not excluded and not in free-only mode
        _discover_subdomains_external(target, result, config, sources, exclude)

    except ImportError as e:
        result.errors.append(f"Subdomain discovery not available: {e}")
    except Exception as e:
        result.errors.append(f"Subdomain discovery failed: {e}")


def _discover_subdomains_external(
    target: str,
    result: ScanResult,
    config: AppConfig,
    sources: list[str] | None,
    exclude: list[str] | None,
) -> None:
    """Discover subdomains using external API sources (Shodan, VT, SecurityTrails)."""
    import os

    # Shodan DNS subdomain enumeration
    if (
        (not sources or "shodan" in sources)
        and (not exclude or "shodan" not in exclude)
        and os.environ.get("SHODAN_API_KEY")
    ):
        try:
            from domainraptor.discovery.shodan_client import ShodanClient

            client = ShodanClient()
            assets, services, vulns, errors = client.query_safe(target)
            result.assets.extend(assets)
            result.services.extend(services)
            result.vulnerabilities.extend(vulns)
            result.errors.extend(errors)
        except Exception as e:
            result.errors.append(f"Shodan failed: {e}")

    # VirusTotal subdomains
    if (
        (not sources or "virustotal" in sources)
        and (not exclude or "virustotal" not in exclude)
        and os.environ.get("VIRUSTOTAL_API_KEY")
    ):
        try:
            from domainraptor.enrichment.virustotal import VirusTotalClient

            client = VirusTotalClient()
            reputation, subdomains, errors = client.query_safe(target)
            result.assets.extend(subdomains)
            if reputation:
                result.metadata["virustotal"] = {
                    "malicious": reputation.malicious,
                    "suspicious": reputation.suspicious,
                    "harmless": reputation.harmless,
                    "reputation_score": reputation.reputation_score,
                    "detection_ratio": reputation.detection_ratio,
                }
            result.errors.extend(errors)
        except Exception as e:
            result.errors.append(f"VirusTotal failed: {e}")

    # SecurityTrails subdomains
    if (
        (not sources or "securitytrails" in sources)
        and (not exclude or "securitytrails" not in exclude)
        and os.environ.get("SECURITYTRAILS_API_KEY")
    ):
        try:
            from domainraptor.enrichment.securitytrails import SecurityTrailsClient

            client = SecurityTrailsClient()
            domain_info, subdomains, errors = client.query_safe(target)
            result.assets.extend(subdomains)
            if domain_info:
                result.metadata["securitytrails"] = {
                    "subdomain_count": domain_info.subdomain_count,
                    "current_dns": domain_info.current_dns,
                }
            result.errors.extend(errors)
        except Exception as e:
            result.errors.append(f"SecurityTrails failed: {e}")


def _discover_certificates(target: str, result: ScanResult) -> None:
    """Discover SSL/TLS certificates."""
    try:
        from domainraptor.discovery.crtsh import CrtShClient

        client = CrtShClient()
        certs = client.query_certificates(target)
        result.certificates.extend(certs)
    except ImportError:
        result.errors.append("Certificate discovery not available (missing httpx)")
    except Exception as e:
        result.errors.append(f"Certificate discovery failed: {e}")


def _discover_ports(target: str, result: ScanResult, config: AppConfig) -> None:
    """Discover open ports and services using Shodan."""
    import os
    import re

    # Check if target is an IP
    ipv4_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    is_ip = bool(re.match(ipv4_pattern, target))

    if not is_ip:
        # Need to resolve domain to IP first
        try:
            import socket

            ip = socket.gethostbyname(target)
        except Exception:
            result.errors.append(f"Could not resolve {target} for port scanning")
            return
    else:
        ip = target

    # Use Shodan if API key available
    if os.environ.get("SHODAN_API_KEY"):
        try:
            from domainraptor.discovery.shodan_client import ShodanClient

            client = ShodanClient()
            host_info = client.host_info(ip)

            result.services.extend(host_info.services)

            # Add vulnerability data
            for cve_id in host_info.vulns:
                from domainraptor.core.types import SeverityLevel, Vulnerability

                result.vulnerabilities.append(
                    Vulnerability(
                        id=cve_id,
                        title=f"CVE {cve_id}",
                        severity=SeverityLevel.MEDIUM,
                        description=f"Vulnerability detected on {ip}",
                        affected_asset=ip,
                        source="shodan",
                    )
                )

            # Add host metadata
            result.metadata["shodan_host"] = {
                "ip": host_info.ip,
                "hostnames": host_info.hostnames,
                "country": host_info.country,
                "org": host_info.org,
                "asn": host_info.asn,
                "ports": host_info.ports,
                "os": host_info.os,
            }

        except Exception as e:
            # Don't fail entirely - just log the error
            result.errors.append(f"Shodan port scan failed: {e}")
    else:
        # No Shodan key - add placeholder info
        from domainraptor.core.types import Service

        result.metadata["port_scan_note"] = "Set SHODAN_API_KEY for detailed port/service info"
        # Add basic HTTPS/HTTP assuming standard web service
        result.services.append(
            Service(
                port=443,
                protocol="tcp",
                service_name="https",
                version="",
            )
        )
        result.services.append(
            Service(
                port=80,
                protocol="tcp",
                service_name="http",
                version="",
            )
        )


def _discover_whois(target: str, result: ScanResult) -> None:
    """Perform WHOIS lookup."""
    try:
        from domainraptor.discovery.whois_client import WhoisClient

        client = WhoisClient()
        info = client.query(target)
        if info:
            creation = info.creation_date.isoformat() if info.creation_date else None
            expiration = info.expiration_date.isoformat() if info.expiration_date else None
            result.metadata["whois"] = {
                "registrar": info.registrar,
                "creation_date": creation,
                "expiration_date": expiration,
                "nameservers": info.nameservers,
                "dnssec": info.dnssec,
                "days_until_expiry": info.days_until_expiry,
            }
    except ImportError:
        result.errors.append("WHOIS client not available (missing python-whois)")
    except Exception as e:
        result.errors.append(f"WHOIS lookup failed: {e}")


# ============================================
# Subcommands for specific discovery tasks
# ============================================


@app.command("subdomains")
def discover_subdomains_cmd(
    ctx: typer.Context,
    target: Annotated[str, typer.Argument(help="Target domain")],
    recursive: Annotated[
        bool,
        typer.Option("--recursive", "-r", help="Recursively discover nested subdomains"),
    ] = False,
    wordlist: Annotated[
        str | None,
        typer.Option("--wordlist", "-w", help="Custom wordlist for bruteforce"),
    ] = None,
    bruteforce: Annotated[
        bool,
        typer.Option("--bruteforce", "-b", help="Enable DNS bruteforce"),
    ] = False,
) -> None:
    """Discover subdomains only."""
    from domainraptor.discovery import create_default_orchestrator

    print_info(f"Subdomain discovery for: {target}")

    orchestrator = create_default_orchestrator()
    result = orchestrator.discover(target, resolve_ips=recursive)

    print_success(f"Found {len(result.unique_subdomains)} unique subdomains")
    if result.subdomains:
        print_assets_table(result.subdomains)


@app.command("dns")
def discover_dns_cmd(
    ctx: typer.Context,
    target: Annotated[str, typer.Argument(help="Target domain")],
    record_types: Annotated[
        str,
        typer.Option("--types", "-t", help="Record types to query (comma-separated)"),
    ] = "A,AAAA,MX,NS,TXT,CNAME,SOA",
) -> None:
    """Enumerate DNS records."""
    from rich.table import Table

    from domainraptor.discovery.dns import DnsClient

    print_info(f"DNS enumeration for: {target}")

    client = DnsClient()
    types = [t.strip().upper() for t in record_types.split(",")]
    records = client.query(target, record_types=types)

    if records:
        table = Table(title=f"DNS Records for {target}")
        table.add_column("Type", style="cyan")
        table.add_column("Value", style="green")
        table.add_column("TTL", style="dim")
        table.add_column("Priority", style="yellow")

        for rec in records:
            table.add_row(
                rec.record_type,
                rec.value,
                str(rec.ttl) if rec.ttl else "-",
                str(rec.priority) if rec.priority else "-",
            )
        console.print(table)
    else:
        print_warning("No DNS records found")


@app.command("certs")
def discover_certs_cmd(
    ctx: typer.Context,
    target: Annotated[str, typer.Argument(help="Target domain")],
    include_expired: Annotated[
        bool,
        typer.Option("--include-expired", help="Include expired certificates"),
    ] = False,
) -> None:
    """Discover SSL/TLS certificates from CT logs."""
    from domainraptor.discovery.crtsh import CrtShClient

    print_info(f"Certificate discovery for: {target}")

    client = CrtShClient()
    certs = client.query_certificates(target)

    if not include_expired:
        certs = [c for c in certs if not c.is_expired]

    if certs:
        print_certificates_table(certs)
        print_success(f"Found {len(certs)} certificates")
    else:
        print_warning("No certificates found")


@app.command("ports")
def discover_ports_cmd(
    ctx: typer.Context,
    target: Annotated[str, typer.Argument(help="Target IP or domain")],
    port_range: Annotated[
        str,
        typer.Option("--range", "-r", help="Port range to scan"),
    ] = "1-1000",
    top_ports: Annotated[
        int | None,
        typer.Option("--top", "-t", help="Scan top N common ports"),
    ] = None,
) -> None:
    """Discover open ports and services."""
    import re

    from rich.panel import Panel
    from rich.table import Table

    print_info(f"Port discovery for: {target}")

    # Check if target is an IP
    ipv4_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    is_ip = bool(re.match(ipv4_pattern, target))

    if not is_ip:
        # Resolve domain to IP
        try:
            import socket

            ip = socket.gethostbyname(target)
            print_info(f"Resolved to: {ip}")
        except Exception:
            print_error(f"Could not resolve {target}")
            raise typer.Exit(1) from None
    else:
        ip = target

    # Use Shodan if API key available
    if os.environ.get("SHODAN_API_KEY"):
        try:
            from domainraptor.discovery.shodan_client import ShodanClient

            client = ShodanClient()
            host_info = client.host_info(ip)

            # Host info panel
            info_table = Table(show_header=False, box=None)
            info_table.add_column("Field", style="cyan")
            info_table.add_column("Value", style="green")

            info_table.add_row("IP", host_info.ip)
            if host_info.hostnames:
                info_table.add_row("Hostnames", ", ".join(host_info.hostnames[:3]))
            info_table.add_row(
                "Location",
                f"{host_info.city}, {host_info.country}" if host_info.city else host_info.country,
            )
            info_table.add_row("Organization", host_info.org)
            info_table.add_row("ASN", host_info.asn)
            if host_info.os:
                info_table.add_row("OS", host_info.os)

            console.print(Panel(info_table, title="Host Information"))

            # Services table
            if host_info.services:
                svc_table = Table(
                    title=f"Open Ports ({len(host_info.ports)} found)",
                    show_header=True,
                    header_style="bold cyan",
                )
                svc_table.add_column("Port", style="bold yellow")
                svc_table.add_column("Protocol")
                svc_table.add_column("Service", style="green")
                svc_table.add_column("Version")
                svc_table.add_column("Banner", max_width=50)

                for svc in host_info.services:
                    svc_table.add_row(
                        str(svc.port),
                        svc.protocol,
                        svc.service_name or "-",
                        svc.version or "-",
                        (svc.banner[:50] + "...")
                        if svc.banner and len(svc.banner) > 50
                        else (svc.banner or "-"),
                    )

                console.print(svc_table)
            else:
                print_warning("No open ports found in Shodan database")

            # Vulnerabilities
            if host_info.vulns:
                console.print(
                    Panel(
                        "\n".join(f"• {cve}" for cve in host_info.vulns[:15])
                        + (
                            f"\n... and {len(host_info.vulns) - 15} more"
                            if len(host_info.vulns) > 15
                            else ""
                        ),
                        title=f"Vulnerabilities ({len(host_info.vulns)} CVEs)",
                        border_style="red",
                    )
                )

            print_success(f"Found {len(host_info.ports)} open ports, {len(host_info.vulns)} CVEs")

        except Exception as e:
            print_error(f"Shodan lookup failed: {e}")
            raise typer.Exit(1) from None
    else:
        print_warning("SHODAN_API_KEY not configured")
        print_info("Run: domainraptor config set SHODAN_API_KEY <your-key>")
        print_info("Get a free key at: https://account.shodan.io/")


@app.command("whois")
def discover_whois_cmd(
    ctx: typer.Context,
    target: Annotated[str, typer.Argument(help="Target domain or IP")],
) -> None:
    """Perform WHOIS lookup."""
    from rich.panel import Panel
    from rich.table import Table

    from domainraptor.discovery.whois_client import WhoisClient

    print_info(f"WHOIS lookup for: {target}")

    client = WhoisClient()
    info = client.query(target)

    if info:
        table = Table(show_header=False, box=None)
        table.add_column("Field", style="cyan")
        table.add_column("Value", style="green")

        created = info.creation_date.strftime("%Y-%m-%d") if info.creation_date else "N/A"
        expires = info.expiration_date.strftime("%Y-%m-%d") if info.expiration_date else "N/A"
        expiry_days = str(info.days_until_expiry) if info.days_until_expiry else "N/A"

        table.add_row("Domain", info.domain)
        table.add_row("Registrar", info.registrar or "N/A")
        table.add_row("Created", created)
        table.add_row("Expires", expires)
        table.add_row("Days until expiry", expiry_days)
        table.add_row("DNSSEC", "Yes" if info.dnssec else "No")
        if info.nameservers:
            table.add_row("Nameservers", ", ".join(info.nameservers[:4]))
        if info.registrant_org:
            table.add_row("Organization", info.registrant_org)

        console.print(Panel(table, title=f"WHOIS: {target}"))
    else:
        print_error(f"WHOIS lookup failed for {target}")
