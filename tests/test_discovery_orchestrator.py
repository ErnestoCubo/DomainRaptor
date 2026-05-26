"""Tests for the discovery orchestrator module."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING
from unittest.mock import MagicMock

from domainraptor.core.types import Asset, AssetType
from domainraptor.discovery.orchestrator import DiscoveryOrchestrator, DiscoveryResult

if TYPE_CHECKING:
    pass


class TestDiscoveryResult:
    """Tests for DiscoveryResult dataclass."""

    def test_discovery_result_creation(self) -> None:
        """Test DiscoveryResult initialization."""
        result = DiscoveryResult(target="example.com")
        assert result.target == "example.com"
        assert result.subdomains == []
        assert result.ips == []
        assert result.domains == []
        assert result.certificates == []
        assert result.dns_records == []
        assert result.sources_used == []
        assert result.errors == {}
        assert result.completed_at is None
        assert isinstance(result.started_at, datetime)

    def test_all_assets_property(self) -> None:
        """Test all_assets property combines all asset types."""
        result = DiscoveryResult(target="example.com")
        sub1 = Asset(type=AssetType.SUBDOMAIN, value="api.example.com", source="test")
        sub2 = Asset(type=AssetType.SUBDOMAIN, value="www.example.com", source="test")
        ip1 = Asset(type=AssetType.IP, value="1.2.3.4", source="test")
        dom1 = Asset(type=AssetType.DOMAIN, value="related.com", source="test")

        result.subdomains = [sub1, sub2]
        result.ips = [ip1]
        result.domains = [dom1]

        all_assets = result.all_assets
        assert len(all_assets) == 4
        assert sub1 in all_assets
        assert sub2 in all_assets
        assert ip1 in all_assets
        assert dom1 in all_assets

    def test_unique_subdomains_property(self) -> None:
        """Test unique_subdomains returns set of subdomain values."""
        result = DiscoveryResult(target="example.com")
        result.subdomains = [
            Asset(type=AssetType.SUBDOMAIN, value="api.example.com", source="test"),
            Asset(type=AssetType.SUBDOMAIN, value="www.example.com", source="test"),
            Asset(type=AssetType.SUBDOMAIN, value="api.example.com", source="other"),  # Duplicate
        ]

        unique = result.unique_subdomains
        assert isinstance(unique, set)
        assert len(unique) == 2
        assert "api.example.com" in unique
        assert "www.example.com" in unique

    def test_unique_ips_property(self) -> None:
        """Test unique_ips returns set of IP values."""
        result = DiscoveryResult(target="example.com")
        result.ips = [
            Asset(type=AssetType.IP, value="1.2.3.4", source="test"),
            Asset(type=AssetType.IP, value="5.6.7.8", source="test"),
            Asset(type=AssetType.IP, value="1.2.3.4", source="other"),  # Duplicate
        ]

        unique = result.unique_ips
        assert isinstance(unique, set)
        assert len(unique) == 2
        assert "1.2.3.4" in unique
        assert "5.6.7.8" in unique

    def test_to_dict(self) -> None:
        """Test to_dict serialization."""
        result = DiscoveryResult(target="example.com")
        result.subdomains = [
            Asset(type=AssetType.SUBDOMAIN, value="api.example.com", source="test"),
        ]
        result.ips = [
            Asset(type=AssetType.IP, value="1.2.3.4", source="test"),
        ]
        result.sources_used = ["crtsh", "dns"]
        result.errors = {"shodan": "API key required"}
        result.completed_at = datetime.now()

        d = result.to_dict()

        assert d["target"] == "example.com"
        assert "started_at" in d
        assert "completed_at" in d
        assert d["sources_used"] == ["crtsh", "dns"]
        assert d["errors"] == {"shodan": "API key required"}
        assert d["summary"]["total_subdomains"] == 1
        assert d["summary"]["total_ips"] == 1
        assert "api.example.com" in d["subdomains"]
        assert "1.2.3.4" in d["ips"]

    def test_to_dict_without_complete_time(self) -> None:
        """Test to_dict when completed_at is None."""
        result = DiscoveryResult(target="example.com")
        d = result.to_dict()
        assert d["completed_at"] is None


class TestDiscoveryOrchestrator:
    """Tests for DiscoveryOrchestrator class."""

    def test_orchestrator_init_defaults(self) -> None:
        """Test DiscoveryOrchestrator initialization with defaults."""
        orch = DiscoveryOrchestrator()
        assert orch.max_workers == 4
        assert orch.include_dns is True
        assert orch.include_whois is True
        assert orch._clients == []

    def test_orchestrator_init_custom(self) -> None:
        """Test DiscoveryOrchestrator with custom settings."""
        orch = DiscoveryOrchestrator(
            max_workers=8,
            include_dns=False,
            include_whois=False,
        )
        assert orch.max_workers == 8
        assert orch.include_dns is False
        assert orch.include_whois is False

    def test_add_client(self) -> None:
        """Test adding a client to the orchestrator."""
        orch = DiscoveryOrchestrator()

        mock_client = MagicMock()
        mock_client.name = "test_client"

        orch.add_client(mock_client)

        assert len(orch._clients) == 1
        assert orch._clients[0] == mock_client

    def test_add_multiple_clients(self) -> None:
        """Test adding multiple clients."""
        orch = DiscoveryOrchestrator()

        client1 = MagicMock()
        client1.name = "client1"
        client2 = MagicMock()
        client2.name = "client2"

        orch.add_client(client1)
        orch.add_client(client2)

        assert len(orch._clients) == 2

    def test_dns_client_disabled(self) -> None:
        """Test dns_client returns None when disabled."""
        orch = DiscoveryOrchestrator(include_dns=False)
        assert orch.dns_client is None

    def test_whois_client_disabled(self) -> None:
        """Test whois_client returns None when disabled."""
        orch = DiscoveryOrchestrator(include_whois=False)
        assert orch.whois_client is None

    def test_discover_no_clients(self) -> None:
        """Test discover with no clients configured."""
        orch = DiscoveryOrchestrator(include_dns=False, include_whois=False)

        result = orch.discover("example.com")

        assert result.target == "example.com"
        assert result.subdomains == []
        assert result.completed_at is not None

    def test_discover_sequential(self) -> None:
        """Test sequential discovery mode."""
        orch = DiscoveryOrchestrator(include_dns=False, include_whois=False)

        mock_client = MagicMock()
        mock_client.name = "test_client"
        mock_client.query.return_value = [
            Asset(type=AssetType.SUBDOMAIN, value="api.example.com", source="test_client"),
        ]

        orch.add_client(mock_client)

        result = orch.discover("example.com", parallel=False)

        mock_client.query.assert_called_once_with("example.com")
        assert "test_client" in result.sources_used
        assert len(result.subdomains) >= 1

    def test_discover_parallel(self) -> None:
        """Test parallel discovery mode."""
        orch = DiscoveryOrchestrator(include_dns=False, include_whois=False)

        mock_client = MagicMock()
        mock_client.name = "test_client"
        mock_client.query.return_value = [
            Asset(type=AssetType.SUBDOMAIN, value="api.example.com", source="test_client"),
        ]

        orch.add_client(mock_client)

        result = orch.discover("example.com", parallel=True)

        mock_client.query.assert_called_once_with("example.com")
        assert "test_client" in result.sources_used

    def test_discover_client_error(self) -> None:
        """Test handling of client errors during discovery."""
        orch = DiscoveryOrchestrator(include_dns=False, include_whois=False)

        mock_client = MagicMock()
        mock_client.name = "failing_client"
        mock_client.query.side_effect = Exception("API error")

        orch.add_client(mock_client)

        result = orch.discover("example.com", parallel=False)

        assert "failing_client" in result.errors
        assert "API error" in result.errors["failing_client"]

    def test_discover_multiple_clients(self) -> None:
        """Test discovery with multiple clients."""
        orch = DiscoveryOrchestrator(include_dns=False, include_whois=False)

        client1 = MagicMock()
        client1.name = "client1"
        client1.query.return_value = [
            Asset(type=AssetType.SUBDOMAIN, value="api.example.com", source="client1"),
        ]

        client2 = MagicMock()
        client2.name = "client2"
        client2.query.return_value = [
            Asset(type=AssetType.SUBDOMAIN, value="www.example.com", source="client2"),
        ]

        orch.add_client(client1)
        orch.add_client(client2)

        result = orch.discover("example.com", parallel=False)

        assert "client1" in result.sources_used
        assert "client2" in result.sources_used
        # Should have subdomains from both clients
        subdomain_values = [a.value for a in result.subdomains]
        assert "api.example.com" in subdomain_values
        assert "www.example.com" in subdomain_values

    def test_discover_mixed_asset_types(self) -> None:
        """Test discovery returning mixed asset types."""
        orch = DiscoveryOrchestrator(include_dns=False, include_whois=False)

        mock_client = MagicMock()
        mock_client.name = "test"
        mock_client.query.return_value = [
            Asset(type=AssetType.SUBDOMAIN, value="api.example.com", source="test"),
            Asset(type=AssetType.IP, value="1.2.3.4", source="test"),
            Asset(type=AssetType.DOMAIN, value="related.com", source="test"),
        ]

        orch.add_client(mock_client)

        result = orch.discover("example.com", parallel=False)

        assert len(result.subdomains) >= 1
        assert any(a.type == AssetType.IP for a in result.all_assets)

    def test_discover_completes_with_timestamp(self) -> None:
        """Test that discovery sets completed_at timestamp."""
        orch = DiscoveryOrchestrator(include_dns=False, include_whois=False)

        result = orch.discover("example.com")

        assert result.completed_at is not None
        assert result.completed_at >= result.started_at


class TestDiscoveryOrchestratorPrivateMethods:
    """Tests for DiscoveryOrchestrator private methods."""

    def test_process_client_results_subdomains(self) -> None:
        """Test _process_client_results with subdomain assets."""
        orch = DiscoveryOrchestrator(include_dns=False, include_whois=False)
        result = DiscoveryResult(target="example.com")

        assets = [
            Asset(type=AssetType.SUBDOMAIN, value="api.example.com", source="test"),
            Asset(type=AssetType.SUBDOMAIN, value="www.example.com", source="test"),
        ]

        orch._process_client_results("test", assets, result)

        assert len(result.subdomains) == 2

    def test_process_client_results_ips(self) -> None:
        """Test _process_client_results with IP assets."""
        orch = DiscoveryOrchestrator(include_dns=False, include_whois=False)
        result = DiscoveryResult(target="example.com")

        assets = [
            Asset(type=AssetType.IP, value="1.2.3.4", source="test"),
        ]

        orch._process_client_results("test", assets, result)

        assert len(result.ips) == 1

    def test_merge_assets(self) -> None:
        """Test _merge_assets adds new assets."""
        orch = DiscoveryOrchestrator(include_dns=False, include_whois=False)

        existing = [
            Asset(type=AssetType.IP, value="1.2.3.4", source="test"),
        ]

        new_assets = [
            Asset(type=AssetType.IP, value="5.6.7.8", source="test"),
            Asset(type=AssetType.IP, value="1.2.3.4", source="other"),  # Duplicate value
        ]

        orch._merge_assets(existing, new_assets)

        # Should have 2 unique values (1.2.3.4 and 5.6.7.8)
        values = [a.value for a in existing]
        assert "1.2.3.4" in values
        assert "5.6.7.8" in values

    def test_deduplicate(self) -> None:
        """Test _deduplicate removes duplicate assets."""
        orch = DiscoveryOrchestrator(include_dns=False, include_whois=False)
        result = DiscoveryResult(target="example.com")

        # Add duplicates
        result.subdomains = [
            Asset(type=AssetType.SUBDOMAIN, value="api.example.com", source="client1"),
            Asset(type=AssetType.SUBDOMAIN, value="api.example.com", source="client2"),
            Asset(type=AssetType.SUBDOMAIN, value="www.example.com", source="client1"),
        ]

        orch._deduplicate(result)

        # Should have 2 unique subdomains
        values = [a.value for a in result.subdomains]
        assert len(set(values)) == 2
