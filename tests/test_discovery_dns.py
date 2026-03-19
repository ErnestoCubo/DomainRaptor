"""Tests for DNS discovery module."""

from __future__ import annotations

from unittest.mock import MagicMock, PropertyMock, patch

import dns.exception
import dns.resolver

from domainraptor.core.types import AssetType
from domainraptor.discovery.dns import DnsClient, DnsConfig


class TestDnsConfig:
    """Tests for DnsConfig dataclass."""

    def test_dns_config_defaults(self) -> None:
        """Test DNS config default values."""
        config = DnsConfig()
        assert config.nameservers is None
        assert config.timeout == 5.0
        assert config.lifetime == 10.0
        assert config.retry_servfail is True

    def test_dns_config_custom(self) -> None:
        """Test DNS config with custom values."""
        config = DnsConfig(
            nameservers=["8.8.8.8", "8.8.4.4"],
            timeout=10.0,
            lifetime=20.0,
        )
        assert config.nameservers == ["8.8.8.8", "8.8.4.4"]
        assert config.timeout == 10.0


class TestDnsClient:
    """Tests for DnsClient class."""

    def test_dns_client_creation(self) -> None:
        """Test DNS client creation."""
        client = DnsClient()
        assert client.name == "dns"
        assert client.is_free is True
        assert client.requires_api_key is False

    def test_dns_client_with_config(self) -> None:
        """Test DNS client with custom config."""
        config = DnsConfig(timeout=15.0)
        client = DnsClient(config)
        assert client.config.timeout == 15.0

    def test_dns_client_lazy_resolver(self) -> None:
        """Test lazy initialization of resolver."""
        client = DnsClient()
        assert client._resolver is None

        # Access resolver property
        resolver = client.resolver
        assert resolver is not None
        assert client._resolver is not None

    def test_dns_client_resolver_config(self) -> None:
        """Test resolver is configured correctly."""
        config = DnsConfig(
            nameservers=["1.1.1.1"],
            timeout=15.0,
            lifetime=30.0,
        )
        client = DnsClient(config)
        resolver = client.resolver

        assert resolver.nameservers == ["1.1.1.1"]
        assert resolver.timeout == 15.0
        assert resolver.lifetime == 30.0

    def test_default_record_types(self) -> None:
        """Test default record types are defined."""
        assert "A" in DnsClient.DEFAULT_RECORD_TYPES
        assert "AAAA" in DnsClient.DEFAULT_RECORD_TYPES
        assert "MX" in DnsClient.DEFAULT_RECORD_TYPES
        assert "NS" in DnsClient.DEFAULT_RECORD_TYPES
        assert "TXT" in DnsClient.DEFAULT_RECORD_TYPES

    def test_extended_record_types(self) -> None:
        """Test extended record types are defined."""
        assert "SRV" in DnsClient.EXTENDED_RECORD_TYPES
        assert "CAA" in DnsClient.EXTENDED_RECORD_TYPES
        assert "DNSKEY" in DnsClient.EXTENDED_RECORD_TYPES

    @patch.object(DnsClient, "resolver", new_callable=PropertyMock)
    def test_query_returns_records(self, mock_resolver_prop: MagicMock) -> None:
        """Test query returns DNS records."""
        mock_resolver = MagicMock()
        mock_resolver_prop.return_value = mock_resolver

        # Mock A record response
        mock_answer = MagicMock()
        mock_answer.rrset.ttl = 3600
        mock_rdata = MagicMock()
        mock_rdata.__str__ = lambda self: "93.184.216.34"
        mock_answer.__iter__ = lambda self: iter([mock_rdata])

        def resolve_side_effect(target: str, rtype: str) -> MagicMock:
            if rtype == "A":
                return mock_answer
            raise dns.resolver.NoAnswer()

        mock_resolver.resolve.side_effect = resolve_side_effect

        client = DnsClient()
        records = client.query("example.com", record_types=["A", "AAAA"])

        assert len(records) >= 1
        assert any(r.record_type == "A" for r in records)

    @patch.object(DnsClient, "resolver", new_callable=PropertyMock)
    def test_query_handles_nxdomain(self, mock_resolver_prop: MagicMock) -> None:
        """Test query handles NXDOMAIN gracefully."""
        mock_resolver = MagicMock()
        mock_resolver_prop.return_value = mock_resolver
        mock_resolver.resolve.side_effect = dns.resolver.NXDOMAIN()

        client = DnsClient()
        records = client.query("nonexistent.invalid")

        assert records == []

    @patch.object(DnsClient, "resolver", new_callable=PropertyMock)
    def test_query_handles_no_answer(self, mock_resolver_prop: MagicMock) -> None:
        """Test query handles NoAnswer gracefully."""
        mock_resolver = MagicMock()
        mock_resolver_prop.return_value = mock_resolver
        mock_resolver.resolve.side_effect = dns.resolver.NoAnswer()

        client = DnsClient()
        records = client.query("example.com", record_types=["SRV"])

        assert records == []

    @patch.object(DnsClient, "resolver", new_callable=PropertyMock)
    def test_query_handles_timeout(self, mock_resolver_prop: MagicMock) -> None:
        """Test query handles timeout gracefully."""
        mock_resolver = MagicMock()
        mock_resolver_prop.return_value = mock_resolver
        mock_resolver.resolve.side_effect = dns.exception.Timeout()

        client = DnsClient()
        records = client.query("example.com")

        assert records == []

    @patch.object(DnsClient, "resolver", new_callable=PropertyMock)
    def test_resolve_ip_returns_assets(self, mock_resolver_prop: MagicMock) -> None:
        """Test resolve_ip returns IP assets."""
        mock_resolver = MagicMock()
        mock_resolver_prop.return_value = mock_resolver

        # Mock A record response
        mock_a_answer = MagicMock()
        mock_a_rdata = MagicMock()
        mock_a_rdata.__str__ = lambda self: "93.184.216.34"
        mock_a_answer.__iter__ = lambda self: iter([mock_a_rdata])

        # Mock AAAA record response
        mock_aaaa_answer = MagicMock()
        mock_aaaa_rdata = MagicMock()
        mock_aaaa_rdata.__str__ = lambda self: "2606:2800:220:1:248:1893:25c8:1946"
        mock_aaaa_answer.__iter__ = lambda self: iter([mock_aaaa_rdata])

        def resolve_side_effect(target: str, rtype: str) -> MagicMock:
            if rtype == "A":
                return mock_a_answer
            if rtype == "AAAA":
                return mock_aaaa_answer
            raise dns.resolver.NoAnswer()

        mock_resolver.resolve.side_effect = resolve_side_effect

        client = DnsClient()
        assets = client.resolve_ip("example.com")

        assert len(assets) == 2
        assert all(a.type == AssetType.IP for a in assets)
        assert any(a.value == "93.184.216.34" for a in assets)
        assert any(a.metadata.get("ip_version") == 4 for a in assets)
        assert any(a.metadata.get("ip_version") == 6 for a in assets)

    @patch.object(DnsClient, "resolver", new_callable=PropertyMock)
    def test_resolve_ip_handles_errors(self, mock_resolver_prop: MagicMock) -> None:
        """Test resolve_ip handles errors gracefully."""
        mock_resolver = MagicMock()
        mock_resolver_prop.return_value = mock_resolver
        mock_resolver.resolve.side_effect = Exception("DNS error")

        client = DnsClient()
        assets = client.resolve_ip("example.com")

        assert assets == []

    @patch.object(DnsClient, "resolver", new_callable=PropertyMock)
    def test_reverse_lookup(self, mock_resolver_prop: MagicMock) -> None:
        """Test reverse DNS lookup."""
        mock_resolver = MagicMock()
        mock_resolver_prop.return_value = mock_resolver

        mock_answer = MagicMock()
        mock_answer.__iter__ = lambda self: iter(["example.com."])
        mock_answer.__getitem__ = lambda self, i: "example.com."
        mock_resolver.resolve.return_value = mock_answer

        client = DnsClient()
        hostname = client.reverse_lookup("93.184.216.34")

        # Should strip trailing dot
        assert hostname is not None
        assert not hostname.endswith(".")

    @patch.object(DnsClient, "resolver", new_callable=PropertyMock)
    def test_reverse_lookup_not_found(self, mock_resolver_prop: MagicMock) -> None:
        """Test reverse lookup when no PTR record exists."""
        mock_resolver = MagicMock()
        mock_resolver_prop.return_value = mock_resolver
        mock_resolver.resolve.side_effect = dns.resolver.NXDOMAIN()

        client = DnsClient()
        hostname = client.reverse_lookup("192.0.2.1")

        assert hostname is None

    @patch.object(DnsClient, "resolver", new_callable=PropertyMock)
    def test_check_dnssec(self, mock_resolver_prop: MagicMock) -> None:
        """Test DNSSEC checking."""
        mock_resolver = MagicMock()
        mock_resolver_prop.return_value = mock_resolver

        # Mock DNSKEY response
        mock_dnskey = MagicMock()
        mock_dnskey.__iter__ = lambda self: iter([MagicMock()])
        mock_dnskey.__bool__ = lambda self: True

        def resolve_side_effect(target: str, rtype: str) -> MagicMock:
            if rtype == "DNSKEY":
                return mock_dnskey
            raise dns.resolver.NoAnswer()

        mock_resolver.resolve.side_effect = resolve_side_effect

        client = DnsClient()
        result = client.check_dnssec("example.com")

        assert "enabled" in result or "dnskey" in result

    def test_query_includes_extended_types(self) -> None:
        """Test query with extended record types."""
        client = DnsClient()

        # Just verify the method accepts the parameter
        with patch.object(client, "_resolver") as mock_resolver:
            mock_resolver.resolve.side_effect = dns.resolver.NoAnswer()
            records = client.query("example.com", include_extended=True)
            assert records == []
