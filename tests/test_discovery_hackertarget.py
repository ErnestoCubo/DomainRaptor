"""Tests for HackerTarget discovery module."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from domainraptor.core.types import AssetType
from domainraptor.discovery.base import ClientConfig
from domainraptor.discovery.hackertarget import HackerTargetClient


class TestHackerTargetClient:
    """Tests for HackerTargetClient class."""

    def test_client_creation(self) -> None:
        """Test client creation with defaults."""
        client = HackerTargetClient()
        assert client.name == "hackertarget"
        assert client.is_free is True
        assert client.requires_api_key is False
        assert client.config.rate_limit == 0.5
        assert client.config.timeout == 30

    def test_client_with_custom_config(self) -> None:
        """Test client with custom config."""
        config = ClientConfig(rate_limit=1.0, timeout=60)
        client = HackerTargetClient(config)
        assert client.config.rate_limit == 1.0
        assert client.config.timeout == 60

    def test_base_url(self) -> None:
        """Test base URL is correct."""
        assert HackerTargetClient.BASE_URL == "https://api.hackertarget.com"

    @patch("domainraptor.discovery.hackertarget.HackerTargetClient.get")
    def test_query_returns_subdomains(self, mock_get: MagicMock) -> None:
        """Test query returns subdomain assets."""
        mock_response = MagicMock()
        mock_response.text = """www.example.com,93.184.216.34
api.example.com,93.184.216.35
mail.example.com,93.184.216.36"""
        mock_get.return_value = mock_response

        client = HackerTargetClient()
        assets = client.query("example.com")

        assert len(assets) == 3
        assert all(a.type == AssetType.SUBDOMAIN for a in assets)
        assert all(a.source == "hackertarget" for a in assets)
        assert all(a.parent == "example.com" for a in assets)

    @patch("domainraptor.discovery.hackertarget.HackerTargetClient.get")
    def test_query_deduplicates(self, mock_get: MagicMock) -> None:
        """Test query deduplicates subdomains."""
        mock_response = MagicMock()
        mock_response.text = """www.example.com,93.184.216.34
www.example.com,93.184.216.34
www.example.com,93.184.216.35"""
        mock_get.return_value = mock_response

        client = HackerTargetClient()
        assets = client.query("example.com")

        # Should only have one www.example.com
        assert len(assets) == 1

    @patch("domainraptor.discovery.hackertarget.HackerTargetClient.get")
    def test_query_handles_error_response(self, mock_get: MagicMock) -> None:
        """Test query handles error responses."""
        mock_response = MagicMock()
        mock_response.text = "error invalid input"
        mock_get.return_value = mock_response

        client = HackerTargetClient()
        assets = client.query("example.com")

        assert assets == []

    @patch("domainraptor.discovery.hackertarget.HackerTargetClient.get")
    def test_query_handles_api_limit(self, mock_get: MagicMock) -> None:
        """Test query handles API limit exceeded."""
        mock_response = MagicMock()
        mock_response.text = "API count exceeded - Bandwidth limit reached"
        mock_get.return_value = mock_response

        client = HackerTargetClient()
        assets = client.query("example.com")

        assert assets == []

    @patch("domainraptor.discovery.hackertarget.HackerTargetClient.get")
    def test_query_handles_empty_response(self, mock_get: MagicMock) -> None:
        """Test query handles empty response."""
        mock_response = MagicMock()
        mock_response.text = ""
        mock_get.return_value = mock_response

        client = HackerTargetClient()
        assets = client.query("example.com")

        assert assets == []

    @patch("domainraptor.discovery.hackertarget.HackerTargetClient.get")
    def test_query_filters_wrong_domain(self, mock_get: MagicMock) -> None:
        """Test query filters out wrong domain entries."""
        mock_response = MagicMock()
        mock_response.text = """www.example.com,93.184.216.34
api.otherdomain.com,10.0.0.1"""
        mock_get.return_value = mock_response

        client = HackerTargetClient()
        assets = client.query("example.com")

        # Should only include example.com subdomains
        assert len(assets) == 1
        assert assets[0].value == "www.example.com"

    @patch("domainraptor.discovery.hackertarget.HackerTargetClient.get")
    def test_query_handles_malformed_lines(self, mock_get: MagicMock) -> None:
        """Test query handles malformed lines."""
        mock_response = MagicMock()
        mock_response.text = """www.example.com,93.184.216.34
badline
another,bad,line,too,many,commas
api.example.com,10.0.0.1"""
        mock_get.return_value = mock_response

        client = HackerTargetClient()
        assets = client.query("example.com")

        # Should handle gracefully
        assert len(assets) == 2

    @patch("domainraptor.discovery.hackertarget.HackerTargetClient.get")
    def test_query_handles_exception(self, mock_get: MagicMock) -> None:
        """Test query handles exceptions gracefully."""
        mock_get.side_effect = Exception("Connection failed")

        client = HackerTargetClient()
        assets = client.query("example.com")

        assert assets == []

    @patch("domainraptor.discovery.hackertarget.HackerTargetClient.get")
    def test_query_lowercases_domains(self, mock_get: MagicMock) -> None:
        """Test query lowercases domain names."""
        mock_response = MagicMock()
        mock_response.text = """WWW.EXAMPLE.COM,93.184.216.34
API.Example.Com,93.184.216.35"""
        mock_get.return_value = mock_response

        client = HackerTargetClient()
        assets = client.query("example.com")

        # All domains should be lowercase
        for asset in assets:
            assert asset.value == asset.value.lower()


class TestHackerTargetClientReverseLookup:
    """Tests for reverse IP lookup functionality."""

    @patch("domainraptor.discovery.hackertarget.HackerTargetClient.get")
    def test_reverse_ip_lookup_returns_domains(self, mock_get: MagicMock) -> None:
        """Test reverse IP lookup returns domain assets."""
        mock_response = MagicMock()
        mock_response.text = """example.com
www.example.com
api.example.com"""
        mock_get.return_value = mock_response

        client = HackerTargetClient()
        assets = client.reverse_ip_lookup("93.184.216.34")

        assert len(assets) == 3
        assert all(a.type == AssetType.DOMAIN for a in assets)
        assert all(a.source == "hackertarget" for a in assets)
        assert all(a.parent == "93.184.216.34" for a in assets)

    @patch("domainraptor.discovery.hackertarget.HackerTargetClient.get")
    def test_reverse_ip_lookup_handles_error(self, mock_get: MagicMock) -> None:
        """Test reverse IP lookup handles error response."""
        mock_response = MagicMock()
        mock_response.text = "error invalid IP"
        mock_get.return_value = mock_response

        client = HackerTargetClient()
        assets = client.reverse_ip_lookup("invalid")

        assert assets == []

    @patch("domainraptor.discovery.hackertarget.HackerTargetClient.get")
    def test_reverse_ip_lookup_handles_api_limit(self, mock_get: MagicMock) -> None:
        """Test reverse IP lookup handles API limit."""
        mock_response = MagicMock()
        mock_response.text = "API count exceeded"
        mock_get.return_value = mock_response

        client = HackerTargetClient()
        assets = client.reverse_ip_lookup("93.184.216.34")

        assert assets == []

    @patch("domainraptor.discovery.hackertarget.HackerTargetClient.get")
    def test_reverse_ip_lookup_handles_exception(self, mock_get: MagicMock) -> None:
        """Test reverse IP lookup handles exceptions."""
        mock_get.side_effect = Exception("Connection failed")

        client = HackerTargetClient()
        assets = client.reverse_ip_lookup("93.184.216.34")

        assert assets == []

    @patch("domainraptor.discovery.hackertarget.HackerTargetClient.get")
    def test_reverse_ip_lookup_deduplicates(self, mock_get: MagicMock) -> None:
        """Test reverse IP lookup deduplicates."""
        mock_response = MagicMock()
        mock_response.text = """example.com
example.com
example.com"""
        mock_get.return_value = mock_response

        client = HackerTargetClient()
        assets = client.reverse_ip_lookup("93.184.216.34")

        assert len(assets) == 1

    @patch("domainraptor.discovery.hackertarget.HackerTargetClient.get")
    def test_reverse_ip_lookup_lowercases(self, mock_get: MagicMock) -> None:
        """Test reverse IP lookup lowercases domains."""
        mock_response = MagicMock()
        mock_response.text = """EXAMPLE.COM
WWW.Example.Com"""
        mock_get.return_value = mock_response

        client = HackerTargetClient()
        assets = client.reverse_ip_lookup("93.184.216.34")

        for asset in assets:
            assert asset.value == asset.value.lower()


class TestHackerTargetClientDnsLookup:
    """Tests for DNS lookup functionality."""

    @patch("domainraptor.discovery.hackertarget.HackerTargetClient.get")
    def test_dns_lookup_returns_records(self, mock_get: MagicMock) -> None:
        """Test DNS lookup returns records."""
        mock_response = MagicMock()
        mock_response.text = """A: 93.184.216.34
MX: mail.example.com
NS: ns1.example.com
TXT: "v=spf1 include:_spf.example.com ~all" """
        mock_get.return_value = mock_response

        client = HackerTargetClient()
        records = client.dns_lookup("example.com")

        assert "A" in records
        assert "MX" in records
        assert "NS" in records
        assert "TXT" in records

    @patch("domainraptor.discovery.hackertarget.HackerTargetClient.get")
    def test_dns_lookup_handles_error(self, mock_get: MagicMock) -> None:
        """Test DNS lookup handles error response."""
        mock_response = MagicMock()
        mock_response.text = "error invalid domain"
        mock_get.return_value = mock_response

        client = HackerTargetClient()
        records = client.dns_lookup("invalid")

        assert records == {}

    @patch("domainraptor.discovery.hackertarget.HackerTargetClient.get")
    def test_dns_lookup_handles_api_limit(self, mock_get: MagicMock) -> None:
        """Test DNS lookup handles API limit."""
        mock_response = MagicMock()
        mock_response.text = "API count exceeded"
        mock_get.return_value = mock_response

        client = HackerTargetClient()
        records = client.dns_lookup("example.com")

        assert records == {}

    @patch("domainraptor.discovery.hackertarget.HackerTargetClient.get")
    def test_dns_lookup_handles_exception(self, mock_get: MagicMock) -> None:
        """Test DNS lookup handles exceptions."""
        mock_get.side_effect = Exception("Connection failed")

        client = HackerTargetClient()
        records = client.dns_lookup("example.com")

        assert records == {}

    @patch("domainraptor.discovery.hackertarget.HackerTargetClient.get")
    def test_dns_lookup_handles_malformed_lines(self, mock_get: MagicMock) -> None:
        """Test DNS lookup handles malformed lines."""
        mock_response = MagicMock()
        mock_response.text = """A: 93.184.216.34
badline
: nokey
keyonly:
MX: mail.example.com"""
        mock_get.return_value = mock_response

        client = HackerTargetClient()
        records = client.dns_lookup("example.com")

        assert "A" in records
        assert "MX" in records


class TestHackerTargetClientIntegration:
    """Integration tests for HackerTargetClient (marked as slow)."""

    @pytest.mark.slow
    @pytest.mark.integration
    def test_real_query(self) -> None:
        """Test real query against HackerTarget API."""
        client = HackerTargetClient()
        assets = client.query("example.com")

        # example.com should return some results
        assert isinstance(assets, list)
        for asset in assets:
            assert asset.type == AssetType.SUBDOMAIN
            assert asset.value.endswith("example.com")
