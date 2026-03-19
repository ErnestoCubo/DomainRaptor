"""Tests for discover CLI command."""

from __future__ import annotations

from datetime import datetime
from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

from domainraptor.cli.main import app
from domainraptor.core.types import (
    Asset,
    AssetType,
    Certificate,
    DnsRecord,
    ScanResult,
    Service,
)
from domainraptor.discovery.shodan_client import ShodanHostResult
from domainraptor.discovery.whois_client import WhoisInfo

runner = CliRunner()


# ============================================================================
# Helper Function Tests
# ============================================================================


class TestDiscoverDnsHelper:
    """Tests for _discover_dns helper function."""

    def test_discover_dns_success(self) -> None:
        """Test DNS discovery with successful query."""
        from domainraptor.cli.commands.discover import _discover_dns

        result = ScanResult(
            target="example.com",
            scan_type="discover",
            started_at=datetime.now(),
        )

        with patch("domainraptor.discovery.dns.DnsClient") as mock_cls:
            mock_client = MagicMock()
            mock_cls.return_value = mock_client
            mock_client.query.return_value = [
                DnsRecord(record_type="A", value="93.184.216.34", ttl=300),
            ]
            mock_client.resolve_ip.return_value = [
                Asset(type=AssetType.IP, value="93.184.216.34"),
            ]

            _discover_dns("example.com", result)

            assert len(result.dns_records) == 1
            assert len(result.assets) == 1

    def test_discover_dns_import_error(self) -> None:
        """Test DNS discovery handles ImportError."""
        from domainraptor.cli.commands.discover import _discover_dns

        result = ScanResult(
            target="example.com",
            scan_type="discover",
            started_at=datetime.now(),
        )

        with patch.dict("sys.modules", {"domainraptor.discovery.dns": None}):
            _discover_dns("example.com", result)

            assert len(result.errors) == 1
            assert "not available" in result.errors[0]

    def test_discover_dns_exception(self) -> None:
        """Test DNS discovery handles generic exception."""
        from domainraptor.cli.commands.discover import _discover_dns

        result = ScanResult(
            target="example.com",
            scan_type="discover",
            started_at=datetime.now(),
        )

        with patch("domainraptor.discovery.dns.DnsClient") as mock_cls:
            mock_cls.side_effect = Exception("Connection failed")

            _discover_dns("example.com", result)

            assert len(result.errors) == 1
            assert "DNS discovery failed" in result.errors[0]


class TestDiscoverSubdomainsHelper:
    """Tests for _discover_subdomains helper function."""

    def test_discover_subdomains_success(self) -> None:
        """Test subdomain discovery with success."""
        from domainraptor.cli.commands.discover import _discover_subdomains
        from domainraptor.core.config import AppConfig

        result = ScanResult(
            target="example.com",
            scan_type="discover",
            started_at=datetime.now(),
        )
        config = AppConfig()

        with (
            patch("domainraptor.discovery.crtsh.CrtShClient") as mock_crtsh,
            patch("domainraptor.discovery.hackertarget.HackerTargetClient") as mock_ht,
        ):
            mock_crtsh_inst = MagicMock()
            mock_crtsh.return_value = mock_crtsh_inst
            mock_crtsh_inst.query.return_value = [
                Asset(type=AssetType.SUBDOMAIN, value="www.example.com"),
            ]

            mock_ht_inst = MagicMock()
            mock_ht.return_value = mock_ht_inst
            mock_ht_inst.query.return_value = []

            _discover_subdomains("example.com", result, config, None, None)

            assert len(result.assets) >= 1

    def test_discover_subdomains_with_sources(self) -> None:
        """Test subdomain discovery with source filter."""
        from domainraptor.cli.commands.discover import _discover_subdomains
        from domainraptor.core.config import AppConfig

        result = ScanResult(
            target="example.com",
            scan_type="discover",
            started_at=datetime.now(),
        )
        config = AppConfig()

        with (
            patch("domainraptor.discovery.crtsh.CrtShClient") as mock_crtsh,
            patch("domainraptor.discovery.hackertarget.HackerTargetClient") as mock_ht,
        ):
            mock_crtsh_inst = MagicMock()
            mock_crtsh.return_value = mock_crtsh_inst
            mock_crtsh_inst.query.return_value = []

            mock_ht_inst = MagicMock()
            mock_ht.return_value = mock_ht_inst

            # Only use crt_sh
            _discover_subdomains("example.com", result, config, ["crt_sh"], None)

            mock_crtsh_inst.query.assert_called_once()
            mock_ht_inst.query.assert_not_called()

    def test_discover_subdomains_with_exclude(self) -> None:
        """Test subdomain discovery with exclusion."""
        from domainraptor.cli.commands.discover import _discover_subdomains
        from domainraptor.core.config import AppConfig

        result = ScanResult(
            target="example.com",
            scan_type="discover",
            started_at=datetime.now(),
        )
        config = AppConfig()

        with (
            patch("domainraptor.discovery.crtsh.CrtShClient") as mock_crtsh,
            patch("domainraptor.discovery.hackertarget.HackerTargetClient") as mock_ht,
        ):
            mock_crtsh_inst = MagicMock()
            mock_crtsh.return_value = mock_crtsh_inst
            mock_crtsh_inst.query.return_value = []

            mock_ht_inst = MagicMock()
            mock_ht.return_value = mock_ht_inst

            _discover_subdomains("example.com", result, config, None, ["hackertarget"])

            mock_crtsh_inst.query.assert_called()
            mock_ht_inst.query.assert_not_called()

    def test_discover_subdomains_import_error(self) -> None:
        """Test subdomain discovery handles ImportError."""
        from domainraptor.cli.commands.discover import _discover_subdomains
        from domainraptor.core.config import AppConfig

        result = ScanResult(
            target="example.com",
            scan_type="discover",
            started_at=datetime.now(),
        )
        config = AppConfig()

        with patch.dict(
            "sys.modules",
            {"domainraptor.discovery.crtsh": None, "domainraptor.discovery.hackertarget": None},
        ):
            _discover_subdomains("example.com", result, config, None, None)
            # Should not raise


class TestDiscoverCertificatesHelper:
    """Tests for _discover_certificates helper function."""

    def test_discover_certificates_success(self) -> None:
        """Test certificate discovery with success."""
        from domainraptor.cli.commands.discover import _discover_certificates

        result = ScanResult(
            target="example.com",
            scan_type="discover",
            started_at=datetime.now(),
        )

        with patch("domainraptor.discovery.crtsh.CrtShClient") as mock_cls:
            mock_client = MagicMock()
            mock_cls.return_value = mock_client
            mock_client.query_certificates.return_value = [
                Certificate(
                    serial_number="123456",
                    subject="example.com",
                    issuer="Let's Encrypt",
                    not_before=datetime.now(),
                    not_after=datetime.now(),
                    is_expired=False,
                ),
            ]

            _discover_certificates("example.com", result)

            assert len(result.certificates) == 1

    def test_discover_certificates_import_error(self) -> None:
        """Test certificate discovery handles ImportError."""
        from domainraptor.cli.commands.discover import _discover_certificates

        result = ScanResult(
            target="example.com",
            scan_type="discover",
            started_at=datetime.now(),
        )

        with patch.dict("sys.modules", {"domainraptor.discovery.crtsh": None}):
            _discover_certificates("example.com", result)

            assert len(result.errors) >= 1


class TestDiscoverWhoisHelper:
    """Tests for _discover_whois helper function."""

    def test_discover_whois_success(self) -> None:
        """Test WHOIS discovery with success."""
        from domainraptor.cli.commands.discover import _discover_whois

        result = ScanResult(
            target="example.com",
            scan_type="discover",
            started_at=datetime.now(),
        )

        with patch("domainraptor.discovery.whois_client.WhoisClient") as mock_cls:
            mock_client = MagicMock()
            mock_cls.return_value = mock_client
            mock_client.query.return_value = WhoisInfo(
                domain="example.com",
                registrar="Example Registrar",
                creation_date=datetime(2000, 1, 1),
                expiration_date=datetime(2025, 1, 1),
                nameservers=["ns1.example.com"],
                dnssec=True,
            )

            _discover_whois("example.com", result)

            assert "whois" in result.metadata

    def test_discover_whois_import_error(self) -> None:
        """Test WHOIS discovery handles ImportError."""
        from domainraptor.cli.commands.discover import _discover_whois

        result = ScanResult(
            target="example.com",
            scan_type="discover",
            started_at=datetime.now(),
        )

        with patch.dict("sys.modules", {"domainraptor.discovery.whois_client": None}):
            _discover_whois("example.com", result)

            assert len(result.errors) >= 1

    def test_discover_whois_exception(self) -> None:
        """Test WHOIS discovery handles exception."""
        from domainraptor.cli.commands.discover import _discover_whois

        result = ScanResult(
            target="example.com",
            scan_type="discover",
            started_at=datetime.now(),
        )

        with patch("domainraptor.discovery.whois_client.WhoisClient") as mock_cls:
            mock_cls.side_effect = Exception("WHOIS failed")

            _discover_whois("example.com", result)

            assert len(result.errors) >= 1


class TestDiscoverPortsHelper:
    """Tests for _discover_ports helper function."""

    def test_discover_ports_without_shodan_key(self) -> None:
        """Test port discovery without Shodan API key."""
        from domainraptor.cli.commands.discover import _discover_ports
        from domainraptor.core.config import AppConfig

        result = ScanResult(
            target="93.184.216.34",
            scan_type="discover",
            started_at=datetime.now(),
        )
        config = AppConfig()

        with patch.dict("os.environ", {}, clear=True):
            _discover_ports("93.184.216.34", result, config)

            # Should add placeholder services
            assert len(result.services) == 2
            assert any(s.port == 80 for s in result.services)
            assert any(s.port == 443 for s in result.services)
            assert "port_scan_note" in result.metadata

    def test_discover_ports_with_shodan_key(self) -> None:
        """Test port discovery with Shodan API key."""
        from domainraptor.cli.commands.discover import _discover_ports
        from domainraptor.core.config import AppConfig

        result = ScanResult(
            target="93.184.216.34",
            scan_type="discover",
            started_at=datetime.now(),
        )
        config = AppConfig()

        mock_host_result = ShodanHostResult(
            ip="93.184.216.34",
            hostnames=["example.com"],
            ports=[80, 443],
            services=[
                Service(port=80, protocol="tcp", service_name="http"),
                Service(port=443, protocol="tcp", service_name="https"),
            ],
            vulns=["CVE-2021-12345"],
            country="US",
            org="Example Inc",
            asn="AS12345",
            os=None,
        )

        with (
            patch.dict("os.environ", {"SHODAN_API_KEY": "test-key"}),  # pragma: allowlist secret
            patch("domainraptor.discovery.shodan_client.ShodanClient") as mock_cls,
        ):
            mock_client = MagicMock()
            mock_cls.return_value = mock_client
            mock_client.host_info.return_value = mock_host_result

            _discover_ports("93.184.216.34", result, config)

            assert len(result.services) == 2
            assert "shodan_host" in result.metadata

    def test_discover_ports_domain_needs_resolution(self) -> None:
        """Test port discovery resolves domain to IP."""
        from domainraptor.cli.commands.discover import _discover_ports
        from domainraptor.core.config import AppConfig

        result = ScanResult(
            target="example.com",
            scan_type="discover",
            started_at=datetime.now(),
        )
        config = AppConfig()

        with (
            patch.dict("os.environ", {}, clear=True),
            patch("socket.gethostbyname", return_value="93.184.216.34"),
        ):
            _discover_ports("example.com", result, config)

            assert len(result.services) == 2

    def test_discover_ports_resolution_failure(self) -> None:
        """Test port discovery handles resolution failure."""
        from domainraptor.cli.commands.discover import _discover_ports
        from domainraptor.core.config import AppConfig

        result = ScanResult(
            target="nonexistent.invalid",
            scan_type="discover",
            started_at=datetime.now(),
        )
        config = AppConfig()

        with (
            patch.dict("os.environ", {"SHODAN_API_KEY": "test"}),  # pragma: allowlist secret
            patch("socket.gethostbyname", side_effect=Exception("DNS failed")),
        ):
            _discover_ports("nonexistent.invalid", result, config)

            assert len(result.errors) >= 1


# ============================================================================
# CLI Command Tests
# ============================================================================


class TestDiscoverDnsCommand:
    """Tests for discover dns command."""

    def test_discover_dns_success(self) -> None:
        """Test discover dns command."""
        with patch("domainraptor.discovery.dns.DnsClient") as mock_cls:
            mock_client = MagicMock()
            mock_cls.return_value = mock_client
            mock_client.query.return_value = [
                DnsRecord(record_type="A", value="93.184.216.34", ttl=300),
            ]

            result = runner.invoke(app, ["--no-banner", "discover", "dns", "example.com"])

            assert result.exit_code == 0

    def test_discover_dns_with_types(self) -> None:
        """Test discover dns command with custom types."""
        with patch("domainraptor.discovery.dns.DnsClient") as mock_cls:
            mock_client = MagicMock()
            mock_cls.return_value = mock_client
            mock_client.query.return_value = []

            result = runner.invoke(
                app, ["--no-banner", "discover", "dns", "example.com", "--types", "A,MX"]
            )

            assert result.exit_code == 0

    def test_discover_dns_no_records(self) -> None:
        """Test discover dns command with no records."""
        with patch("domainraptor.discovery.dns.DnsClient") as mock_cls:
            mock_client = MagicMock()
            mock_cls.return_value = mock_client
            mock_client.query.return_value = []

            result = runner.invoke(app, ["--no-banner", "discover", "dns", "example.com"])

            assert result.exit_code == 0
            assert "No DNS records found" in result.output


class TestDiscoverCertsCommand:
    """Tests for discover certs command."""

    def test_discover_certs_success(self) -> None:
        """Test discover certs command."""
        with patch("domainraptor.discovery.crtsh.CrtShClient") as mock_cls:
            mock_client = MagicMock()
            mock_cls.return_value = mock_client
            mock_client.query_certificates.return_value = [
                Certificate(
                    serial_number="123456",
                    subject="example.com",
                    issuer="Let's Encrypt",
                    not_before=datetime.now(),
                    not_after=datetime.now(),
                    is_expired=False,
                ),
            ]

            result = runner.invoke(app, ["--no-banner", "discover", "certs", "example.com"])

            assert result.exit_code == 0
            assert "Found 1 certificate" in result.output

    def test_discover_certs_no_certs(self) -> None:
        """Test discover certs command with no certificates."""
        with patch("domainraptor.discovery.crtsh.CrtShClient") as mock_cls:
            mock_client = MagicMock()
            mock_cls.return_value = mock_client
            mock_client.query_certificates.return_value = []

            result = runner.invoke(app, ["--no-banner", "discover", "certs", "example.com"])

            assert result.exit_code == 0
            assert "No certificates found" in result.output


class TestDiscoverWhoisCommand:
    """Tests for discover whois command."""

    def test_discover_whois_success(self) -> None:
        """Test discover whois command."""
        with patch("domainraptor.discovery.whois_client.WhoisClient") as mock_cls:
            mock_client = MagicMock()
            mock_cls.return_value = mock_client
            mock_client.query.return_value = WhoisInfo(
                domain="example.com",
                registrar="Example Registrar",
                creation_date=datetime(2000, 1, 1),
                expiration_date=datetime(2025, 1, 1),
                nameservers=["ns1.example.com"],
                dnssec=True,
            )

            result = runner.invoke(app, ["--no-banner", "discover", "whois", "example.com"])

            assert result.exit_code == 0
            assert "example.com" in result.output

    def test_discover_whois_not_found(self) -> None:
        """Test discover whois command with lookup failure."""
        with patch("domainraptor.discovery.whois_client.WhoisClient") as mock_cls:
            mock_client = MagicMock()
            mock_cls.return_value = mock_client
            mock_client.query.return_value = None

            result = runner.invoke(app, ["--no-banner", "discover", "whois", "unknown.example"])

            assert result.exit_code == 0
            assert "WHOIS lookup failed" in result.output


class TestDiscoverPortsCommand:
    """Tests for discover ports command."""

    def test_discover_ports_shows_info(self) -> None:
        """Test discover ports command shows info."""
        result = runner.invoke(app, ["--no-banner", "discover", "ports", "example.com"])

        assert result.exit_code == 0
        assert "Port discovery for: example.com" in result.output


class TestDiscoverSubdomainsCommand:
    """Tests for discover subdomains command."""

    def test_discover_subdomains_success(self) -> None:
        """Test discover subdomains command."""
        with patch(
            "domainraptor.discovery.orchestrator.create_default_orchestrator"
        ) as mock_orch_fn:
            mock_orch = MagicMock()
            mock_orch_fn.return_value = mock_orch
            mock_result = MagicMock()
            mock_result.unique_subdomains = ["www.example.com", "api.example.com"]
            mock_result.subdomains = [
                Asset(type=AssetType.SUBDOMAIN, value="www.example.com"),
                Asset(type=AssetType.SUBDOMAIN, value="api.example.com"),
            ]
            mock_orch.discover.return_value = mock_result

            result = runner.invoke(app, ["--no-banner", "discover", "subdomains", "example.com"])

            assert result.exit_code == 0


class TestDiscoverCallback:
    """Tests for the main discover callback."""

    def test_discover_no_args_shows_help(self) -> None:
        """Test discover without arguments shows help."""
        result = runner.invoke(app, ["--no-banner", "discover"])

        # With no_args_is_help=True
        assert result.exit_code == 2 or result.exit_code == 0

    def test_discover_with_target_runs(self) -> None:
        """Test discover with target option."""
        with (
            patch("domainraptor.discovery.dns.DnsClient") as mock_dns,
            patch("domainraptor.discovery.crtsh.CrtShClient") as mock_crtsh,
            patch("domainraptor.discovery.hackertarget.HackerTargetClient") as mock_ht,
            patch("domainraptor.discovery.whois_client.WhoisClient") as mock_whois,
        ):
            mock_dns_inst = MagicMock()
            mock_dns.return_value = mock_dns_inst
            mock_dns_inst.query.return_value = []
            mock_dns_inst.resolve_ip.return_value = []

            mock_crtsh_inst = MagicMock()
            mock_crtsh.return_value = mock_crtsh_inst
            mock_crtsh_inst.query.return_value = []
            mock_crtsh_inst.query_certificates.return_value = []

            mock_ht_inst = MagicMock()
            mock_ht.return_value = mock_ht_inst
            mock_ht_inst.query.return_value = []

            mock_whois_inst = MagicMock()
            mock_whois.return_value = mock_whois_inst
            mock_whois_inst.query.return_value = None

            result = runner.invoke(app, ["--no-banner", "discover", "--target", "example.com"])

            assert result.exit_code == 0

    def test_discover_with_save_option(self) -> None:
        """Test discover with --save option."""
        with (
            patch("domainraptor.discovery.dns.DnsClient") as mock_dns,
            patch("domainraptor.discovery.crtsh.CrtShClient") as mock_crtsh,
            patch("domainraptor.discovery.hackertarget.HackerTargetClient") as mock_ht,
            patch("domainraptor.discovery.whois_client.WhoisClient") as mock_whois,
            patch("domainraptor.storage.database.DatabaseManager") as mock_db,
        ):
            # Set up mocks
            mock_dns.return_value.query.return_value = []
            mock_dns.return_value.resolve_ip.return_value = []
            mock_crtsh.return_value.query.return_value = []
            mock_crtsh.return_value.query_certificates.return_value = []
            mock_ht.return_value.query.return_value = []
            mock_whois.return_value.query.return_value = None

            mock_db_inst = MagicMock()
            mock_db.return_value = mock_db_inst

            result = runner.invoke(
                app,
                ["--no-banner", "discover", "--target", "example.com", "--save"],
            )

            assert result.exit_code == 0


# ============================================================================
# Discovery External Tests
# ============================================================================


class TestDiscoverSubdomainsExternal:
    """Tests for external API subdomain discovery."""

    def test_discover_subdomains_external_shodan(self) -> None:
        """Test subdomain discovery with Shodan."""
        from domainraptor.cli.commands.discover import _discover_subdomains_external
        from domainraptor.core.config import AppConfig

        result = ScanResult(
            target="example.com",
            scan_type="discover",
            started_at=datetime.now(),
        )
        config = AppConfig()

        with (
            patch.dict("os.environ", {"SHODAN_API_KEY": "test-key"}),  # pragma: allowlist secret
            patch("domainraptor.discovery.shodan_client.ShodanClient") as mock_shodan,
        ):
            mock_shodan_inst = MagicMock()
            mock_shodan.return_value = mock_shodan_inst
            mock_shodan_inst.query_safe.return_value = ([], [], [], [])

            _discover_subdomains_external("example.com", result, config, ["shodan"], None)

            # Should complete without error
            assert result.target == "example.com"

    def test_discover_subdomains_external_no_api_key(self) -> None:
        """Test external discovery without API key."""
        from domainraptor.cli.commands.discover import _discover_subdomains_external
        from domainraptor.core.config import AppConfig

        result = ScanResult(
            target="example.com",
            scan_type="discover",
            started_at=datetime.now(),
        )
        config = AppConfig()

        with patch.dict("os.environ", {}, clear=True):
            _discover_subdomains_external("example.com", result, config, ["shodan"], None)

            # Should complete without crashing
            assert result.target == "example.com"

    def test_discover_subdomains_external_with_exclude(self) -> None:
        """Test external discovery with exclude parameter."""
        from domainraptor.cli.commands.discover import _discover_subdomains_external
        from domainraptor.core.config import AppConfig

        result = ScanResult(
            target="example.com",
            scan_type="discover",
            started_at=datetime.now(),
        )
        config = AppConfig()

        with (
            patch.dict("os.environ", {"SHODAN_API_KEY": "test-key"}),  # pragma: allowlist secret
            patch("domainraptor.discovery.shodan_client.ShodanClient") as mock_shodan,
        ):
            mock_shodan_inst = MagicMock()
            mock_shodan.return_value = mock_shodan_inst

            # Exclude shodan - it should not be called
            _discover_subdomains_external("example.com", result, config, None, ["shodan"])

            mock_shodan_inst.query_safe.assert_not_called()

    def test_discover_subdomains_external_exception_handling(self) -> None:
        """Test external discovery handles exceptions."""
        from domainraptor.cli.commands.discover import _discover_subdomains_external
        from domainraptor.core.config import AppConfig

        result = ScanResult(
            target="example.com",
            scan_type="discover",
            started_at=datetime.now(),
        )
        config = AppConfig()

        with (
            patch.dict("os.environ", {"SHODAN_API_KEY": "test-key"}),  # pragma: allowlist secret
            patch("domainraptor.discovery.shodan_client.ShodanClient") as mock_shodan,
        ):
            mock_shodan.side_effect = Exception("API error")

            _discover_subdomains_external("example.com", result, config, ["shodan"], None)

            # Should add error and continue
            assert len(result.errors) >= 1
            assert "Shodan failed" in result.errors[0]
