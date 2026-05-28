"""Configuration management commands."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Annotated

import typer
from rich.table import Table

from domainraptor.utils.output import (
    console,
    print_info,
    print_success,
    print_warning,
)

app = typer.Typer(
    name="config",
    help="⚙️  Configuration management commands",
    no_args_is_help=True,
)


# Supported API keys with their environment variable names and descriptions
API_KEYS = {
    "SHODAN_API_KEY": {
        "service": "Shodan",
        "description": "Port scanning and service detection",
        "url": "https://account.shodan.io/",
        "free_tier": "100 queries/month",
    },
    "VIRUSTOTAL_API_KEY": {
        "service": "VirusTotal",
        "description": "Reputation and threat intelligence",
        "url": "https://www.virustotal.com/gui/my-apikey",
        "free_tier": "4 req/min, 500/day",
    },
    "CENSYS_API_KEY": {
        "service": "Censys (Legacy)",
        "description": "Internet-wide scanning data (API ID/Secret)",
        "url": "https://search.censys.io/account/api",
        "free_tier": "250 queries/month",
    },
    "CENSYS_API_TOKEN": {
        "service": "Censys (PAT)",
        "description": "Censys Platform API v3 Personal Access Token",
        "url": "https://platform.censys.io/settings/api",
        "free_tier": "IP lookup free, search requires subscription",
    },
    "ZOOMEYE_API_KEY": {
        "service": "ZoomEye",
        "description": "Chinese cyberspace search engine",
        "url": "https://www.zoomeye.ai/profile",
        "free_tier": "Subdomain discovery free, host search paid",
    },
}


def _get_config_dir() -> Path:
    """Get the domainraptor config directory."""
    return Path.home() / ".domainraptor"


def _get_env_file() -> Path:
    """Get the path to the .env file."""
    return _get_config_dir() / ".env"


def _load_env_file() -> dict[str, str]:
    """Load existing environment variables from .env file."""
    env_file = _get_env_file()
    env_vars: dict[str, str] = {}

    if env_file.exists():
        with env_file.open() as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, _, value = line.partition("=")
                    key = key.strip()
                    value = value.strip().strip('"').strip("'")
                    env_vars[key] = value

    return env_vars


def _save_env_file(env_vars: dict[str, str]) -> None:
    """Save environment variables to .env file."""
    env_file = _get_env_file()
    env_file.parent.mkdir(parents=True, exist_ok=True)

    lines = ["# DomainRaptor API Keys", "# Do not share this file!\n"]

    for key, value in sorted(env_vars.items()):
        lines.append(f'{key}="{value}"')

    env_file.write_text("\n".join(lines) + "\n")
    # Make file readable only by owner
    env_file.chmod(0o600)


@app.command("set")
def set_key(
    key: Annotated[
        str,
        typer.Argument(help="API key name (e.g., SHODAN_API_KEY)"),
    ],
    value: Annotated[
        str,
        typer.Argument(help="API key value"),
    ],
) -> None:
    """
    🔑 Set an API key.

    API keys are stored in ~/.domainraptor/.env and loaded automatically.

    [bold cyan]Supported keys:[/bold cyan]
        • SHODAN_API_KEY
        • VIRUSTOTAL_API_KEY
        • CENSYS_API_KEY (legacy API ID)
        • CENSYS_API_TOKEN (PAT for v3 API)
        • ZOOMEYE_API_KEY

    [bold cyan]Examples:[/bold cyan]

        [dim]# Set Shodan API key[/dim]
        domainraptor config set SHODAN_API_KEY abc123...

        [dim]# Set ZoomEye API key[/dim]
        domainraptor config set ZOOMEYE_API_KEY xyz789...

        [dim]# Set Censys PAT token[/dim]
        domainraptor config set CENSYS_API_TOKEN censys_xxx_yyy
    """
    key = key.upper()

    if key not in API_KEYS:
        print_warning(f"Unknown key: {key}")
        print_info(f"Supported keys: {', '.join(API_KEYS.keys())}")
        # Still allow setting custom keys
        if not typer.confirm("Set this key anyway?"):
            raise typer.Abort()

    env_vars = _load_env_file()
    env_vars[key] = value
    _save_env_file(env_vars)

    # Also set in current environment
    os.environ[key] = value

    service = API_KEYS.get(key, {}).get("service", key)
    print_success(f"✓ {service} API key saved")
    print_info(f"Stored in: {_get_env_file()}")


@app.command("get")
def get_key(
    key: Annotated[
        str,
        typer.Argument(help="API key name to retrieve"),
    ],
    show: Annotated[
        bool,
        typer.Option("--show", "-s", help="Show the full key value (hidden by default)"),
    ] = False,
) -> None:
    """
    🔍 Get an API key value.

    By default, only shows if the key is set. Use --show to reveal the value.

    [bold cyan]Examples:[/bold cyan]

        [dim]# Check if key is set[/dim]
        domainraptor config get SHODAN_API_KEY

        [dim]# Show the actual value[/dim]
        domainraptor config get SHODAN_API_KEY --show
    """
    key = key.upper()

    # Check environment first, then .env file
    value = os.environ.get(key)
    if not value:
        env_vars = _load_env_file()
        value = env_vars.get(key)

    if not value:
        print_warning(f"{key} is not set")
        if key in API_KEYS:
            info = API_KEYS[key]
            print_info(f"Get your key at: {info['url']}")
        return

    service = API_KEYS.get(key, {}).get("service", key)
    if show:
        console.print(f"[green]{service}:[/green] {value}")
    else:
        masked = value[:4] + "*" * (len(value) - 8) + value[-4:] if len(value) > 12 else "***"
        console.print(f"[green]{service}:[/green] {masked} [dim](use --show to reveal)[/dim]")


@app.command("list")
def list_keys(
    show_values: Annotated[
        bool,
        typer.Option("--show", "-s", help="Show actual key values"),
    ] = False,
) -> None:
    """
    📋 List all configured API keys.

    Shows which API keys are configured and their status.

    [bold cyan]Examples:[/bold cyan]

        [dim]# List all keys[/dim]
        domainraptor config list

        [dim]# List with values shown[/dim]
        domainraptor config list --show
    """
    env_vars = _load_env_file()

    table = Table(title="API Keys Configuration")
    table.add_column("Service", style="cyan")
    table.add_column("Key Name", style="dim")
    table.add_column("Status", style="green")
    table.add_column("Free Tier", style="yellow")
    if show_values:
        table.add_column("Value", style="dim")

    for key_name, info in API_KEYS.items():
        # Check env var first, then file
        value = os.environ.get(key_name) or env_vars.get(key_name)

        status = "[green]✓ Configured[/green]" if value else "[red]✗ Not set[/red]"

        row = [
            info["service"],
            key_name,
            status,
            info["free_tier"],
        ]

        if show_values:
            if value:
                masked = value[:4] + "***" + value[-4:] if len(value) > 12 else "***"
                row.append(masked)
            else:
                row.append("-")

        table.add_row(*row)

    console.print(table)
    print_info(f"\nConfig file: {_get_env_file()}")


@app.command("test")
def test_keys(
    key: Annotated[
        str | None,
        typer.Argument(help="Specific key to test (tests all if not specified)"),
    ] = None,
) -> None:
    """
    🧪 Test API key validity.

    Makes a simple API call to verify each configured key works.

    [bold cyan]Examples:[/bold cyan]

        [dim]# Test all configured keys[/dim]
        domainraptor config test

        [dim]# Test specific key[/dim]
        domainraptor config test SHODAN_API_KEY
    """
    env_vars = _load_env_file()
    keys_to_test = [key.upper()] if key else list(API_KEYS.keys())

    results: list[tuple[str, bool, str]] = []

    for key_name in keys_to_test:
        if key_name not in API_KEYS:
            print_warning(f"Unknown key: {key_name}")
            continue

        value = os.environ.get(key_name) or env_vars.get(key_name)
        if not value:
            results.append((key_name, False, "Not configured"))
            continue

        # Set in environment for client to use
        os.environ[key_name] = value

        service = API_KEYS[key_name]["service"]
        print_info(f"Testing {service}...")

        try:
            success, message = _test_api_key(key_name, value)
            results.append((key_name, success, message))
        except Exception as e:
            results.append((key_name, False, str(e)))

    # Print results
    console.print()
    table = Table(title="API Key Test Results")
    table.add_column("Service", style="cyan")
    table.add_column("Status")
    table.add_column("Details", style="dim")

    for key_name, success, message in results:
        service = API_KEYS.get(key_name, {}).get("service", key_name)
        status = "[green]✓ Valid[/green]" if success else "[red]✗ Failed[/red]"
        table.add_row(service, status, message)

    console.print(table)


def _test_api_key(key_name: str, value: str) -> tuple[bool, str]:
    """Test a specific API key."""
    if key_name == "SHODAN_API_KEY":
        return _test_shodan(value)
    if key_name == "VIRUSTOTAL_API_KEY":
        return _test_virustotal(value)
    if key_name == "CENSYS_API_KEY":
        return _test_censys(value)
    if key_name == "CENSYS_API_TOKEN":
        return _test_censys_pat(value)
    if key_name == "ZOOMEYE_API_KEY":
        return _test_zoomeye(value)
    return False, "No test available"


def _test_shodan(api_key: str) -> tuple[bool, str]:
    """Test Shodan API key."""
    try:
        from domainraptor.discovery.shodan_client import ShodanClient

        client = ShodanClient(api_key=api_key)
        # Try to resolve a known domain (simple test)
        result = client.dns_resolve(["google.com"])
        if result:
            return True, "Connected successfully"
        return True, "Key accepted"
    except Exception as e:
        return False, str(e)


def _test_virustotal(api_key: str) -> tuple[bool, str]:
    """Test VirusTotal API key."""
    try:
        from domainraptor.enrichment.virustotal import VirusTotalClient

        client = VirusTotalClient(api_key=api_key)
        # Try to get a well-known domain
        report = client.get_domain_report("google.com")
        return True, f"Connected ({report.total_engines} engines)"
    except Exception as e:
        return False, str(e)


def _test_censys(api_key: str) -> tuple[bool, str]:
    """Test Censys API key."""
    # Censys client not yet implemented
    return False, "Censys client not yet implemented"


def _test_censys_pat(api_token: str) -> tuple[bool, str]:
    """Test Censys PAT (Personal Access Token) for v3 API."""
    try:
        from domainraptor.discovery.censys_client import CensysClient

        client = CensysClient(api_token=api_token)
        # Use free endpoint: get host info for Google DNS
        result = client.get_host("8.8.8.8")
        if result:
            name = result.get("name", result.get("ip", "unknown"))
            return True, f"Connected (tested: {name})"
        return True, "Key accepted"
    except Exception as e:
        return False, str(e)


def _test_zoomeye(api_key: str) -> tuple[bool, str]:
    """Test ZoomEye API key."""
    try:
        from domainraptor.discovery.zoomeye_client import ZoomEyeClient

        client = ZoomEyeClient(api_key=api_key)
        # Use resources-info endpoint to check account (always free)
        result = client.get_resources_info()
        if result:
            plan = result.get("plan", "unknown")
            credits = result.get("resources", {}).get("search", 0)
            return True, f"Connected ({plan} plan, {credits} credits)"
        return True, "Key accepted"
    except Exception as e:
        return False, str(e)


@app.command("path")
def show_path() -> None:
    """
    📂 Show configuration file paths.

    Displays the location of all configuration files.
    """
    config_dir = _get_config_dir()
    env_file = _get_env_file()

    console.print("[bold]Configuration Paths:[/bold]\n")
    console.print(f"  Config directory: [cyan]{config_dir}[/cyan]")
    console.print(f"  API keys file:    [cyan]{env_file}[/cyan]")

    # Show yaml config locations
    yaml_locations = [
        Path.cwd() / "domainraptor.yaml",
        Path.cwd() / ".domainraptor.yaml",
        Path.home() / ".config" / "domainraptor" / "config.yaml",
        Path.home() / ".domainraptor" / "config.yaml",
    ]

    console.print("\n[bold]YAML config search order:[/bold]")
    for loc in yaml_locations:
        exists = "[green]✓[/green]" if loc.exists() else "[dim]✗[/dim]"
        console.print(f"  {exists} {loc}")

    # Check env file status
    console.print()
    if env_file.exists():
        print_success(f"API keys file exists ({env_file.stat().st_size} bytes)")
    else:
        print_warning("API keys file does not exist yet")
        print_info("Use 'domainraptor config set <KEY> <value>' to create it")


@app.command("init")
def init_config() -> None:
    """
    🚀 Initialize configuration with interactive setup.

    Guides you through setting up API keys for all supported services.
    """
    console.print("[bold cyan]DomainRaptor Configuration Setup[/bold cyan]\n")
    console.print("This will help you configure API keys for external services.\n")

    for key_name, info in API_KEYS.items():
        console.print(f"\n[bold]{info['service']}[/bold]")
        console.print(f"  {info['description']}")
        console.print(f"  Free tier: {info['free_tier']}")
        console.print(f"  Get key: [link={info['url']}]{info['url']}[/link]")

        # Check if already configured
        existing = os.environ.get(key_name) or _load_env_file().get(key_name)
        if existing:
            console.print("  [green]✓ Already configured[/green]")
            if not typer.confirm("  Update this key?", default=False):
                continue

        value = typer.prompt(f"  Enter {key_name}", default="", show_default=False)
        if value:
            env_vars = _load_env_file()
            env_vars[key_name] = value
            _save_env_file(env_vars)
            os.environ[key_name] = value
            print_success(f"  ✓ {info['service']} key saved")
        else:
            print_info("  Skipped")

    console.print("\n[bold green]Configuration complete![/bold green]")
    console.print("Run [cyan]domainraptor config test[/cyan] to verify your keys.")
