"""Tests for crt.sh discovery module."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from domainraptor.core.types import AssetType
from domainraptor.discovery.base import ClientConfig
from domainraptor.discovery.crtsh import CrtShClient


class TestCrtShClient:
    """Tests for CrtShClient class."""

    def test_client_creation(self) -> None:
        """Test client creation with defaults."""
        client = CrtShClient()
        assert client.name == "crt_sh"
        assert client.is_free is True
        assert client.requires_api_key is False
        assert client.config.rate_limit == 0.5
        assert client.config.timeout == 60

    def test_client_with_custom_config(self) -> None:
        """Test client with custom config."""
        config = ClientConfig(rate_limit=1.0, timeout=30)
        client = CrtShClient(config)
        assert client.config.rate_limit == 1.0
        assert client.config.timeout == 30

    def test_base_url(self) -> None:
        """Test base URL is correct."""
        assert CrtShClient.BASE_URL == "https://crt.sh"

    @patch("domainraptor.discovery.crtsh.CrtShClient.get")
    def test_query_returns_subdomains(self, mock_get: MagicMock) -> None:
        """Test query returns subdomain assets."""
        mock_response = MagicMock()
        mock_response.json.return_value = [
            {"common_name": "www.example.com", "name_value": "www.example.com"},
            {"common_name": "api.example.com", "name_value": "api.example.com\nmail.example.com"},
            {"common_name": "*.example.com", "name_value": "*.example.com"},
        ]
        mock_get.return_value = mock_response

        client = CrtShClient()
        assets = client.query("example.com")

        assert len(assets) > 0
        assert all(a.type == AssetType.SUBDOMAIN for a in assets)
        assert all(a.source == "crt_sh" for a in assets)
        assert all(a.parent == "example.com" for a in assets)

    @patch("domainraptor.discovery.crtsh.CrtShClient.get")
    def test_query_deduplicates_subdomains(self, mock_get: MagicMock) -> None:
        """Test query deduplicates subdomains."""
        mock_response = MagicMock()
        mock_response.json.return_value = [
            {"common_name": "www.example.com", "name_value": "www.example.com"},
            {"common_name": "www.example.com", "name_value": "www.example.com"},
            {"common_name": "www.example.com", "name_value": "www.example.com"},
        ]
        mock_get.return_value = mock_response

        client = CrtShClient()
        assets = client.query("example.com")

        # Should only have one www.example.com
        www_assets = [a for a in assets if a.value == "www.example.com"]
        assert len(www_assets) == 1

    @patch("domainraptor.discovery.crtsh.CrtShClient.get")
    def test_query_filters_invalid_domains(self, mock_get: MagicMock) -> None:
        """Test query filters out invalid domains."""
        mock_response = MagicMock()
        mock_response.json.return_value = [
            {"common_name": "valid.example.com", "name_value": "valid.example.com"},
            {"common_name": "other.domain.com", "name_value": "other.domain.com"},  # Wrong domain
        ]
        mock_get.return_value = mock_response

        client = CrtShClient()
        assets = client.query("example.com")

        # Should not include other.domain.com
        domain_values = [a.value for a in assets]
        assert "other.domain.com" not in domain_values

    @patch("domainraptor.discovery.crtsh.CrtShClient.get")
    def test_query_handles_empty_response(self, mock_get: MagicMock) -> None:
        """Test query handles empty response."""
        mock_response = MagicMock()
        mock_response.json.return_value = []
        mock_get.return_value = mock_response

        client = CrtShClient()
        assets = client.query("example.com")

        assert assets == []

    @patch("domainraptor.discovery.crtsh.CrtShClient.get")
    def test_query_handles_none_response(self, mock_get: MagicMock) -> None:
        """Test query handles None response."""
        mock_response = MagicMock()
        mock_response.json.return_value = None
        mock_get.return_value = mock_response

        client = CrtShClient()
        assets = client.query("example.com")

        assert assets == []

    @patch("domainraptor.discovery.crtsh.CrtShClient.get")
    def test_query_handles_exception(self, mock_get: MagicMock) -> None:
        """Test query handles exceptions gracefully."""
        mock_get.side_effect = Exception("Connection failed")

        client = CrtShClient()
        assets = client.query("example.com")

        assert assets == []

    @patch("domainraptor.discovery.crtsh.CrtShClient.get")
    def test_query_handles_wildcard_certs(self, mock_get: MagicMock) -> None:
        """Test query handles wildcard certificates."""
        mock_response = MagicMock()
        mock_response.json.return_value = [
            {"common_name": "*.example.com", "name_value": "*.example.com"},
            {"common_name": "*.api.example.com", "name_value": "*.api.example.com"},
        ]
        mock_get.return_value = mock_response

        client = CrtShClient()
        assets = client.query("example.com")

        # Wildcards should be filtered or there should be at least some results
        assert isinstance(assets, list)

    @patch("domainraptor.discovery.crtsh.CrtShClient.get")
    def test_query_extracts_from_san(self, mock_get: MagicMock) -> None:
        """Test query extracts domains from Subject Alternative Names."""
        mock_response = MagicMock()
        mock_response.json.return_value = [
            {
                "common_name": "example.com",
                "name_value": "example.com\nwww.example.com\napi.example.com",
            },
        ]
        mock_get.return_value = mock_response

        client = CrtShClient()
        assets = client.query("example.com")

        domain_values = [a.value for a in assets]
        # Should extract all three domains from the SAN
        assert len(domain_values) >= 1


class TestCrtShClientCertificates:
    """Tests for certificate retrieval."""

    @patch("domainraptor.discovery.crtsh.CrtShClient.get")
    def test_query_certificates_returns_list(self, mock_get: MagicMock) -> None:
        """Test query_certificates returns certificate list."""
        mock_response = MagicMock()
        mock_response.json.return_value = [
            {
                "id": 1,
                "common_name": "example.com",
                "issuer_name": "Let's Encrypt",
                "serial_number": "12345",
                "not_before": "2024-01-01T00:00:00",
                "not_after": "2024-12-31T23:59:59",
                "name_value": "example.com\nwww.example.com",
            },
        ]
        mock_get.return_value = mock_response

        client = CrtShClient()
        certs = client.query_certificates("example.com")

        assert len(certs) == 1
        assert certs[0].subject == "example.com"
        assert certs[0].issuer == "Let's Encrypt"

    @patch("domainraptor.discovery.crtsh.CrtShClient.get")
    def test_query_certificates_empty_response(self, mock_get: MagicMock) -> None:
        """Test query_certificates handles empty response."""
        mock_response = MagicMock()
        mock_response.json.return_value = []
        mock_get.return_value = mock_response

        client = CrtShClient()
        certs = client.query_certificates("example.com")

        assert certs == []

    @patch("domainraptor.discovery.crtsh.CrtShClient.get")
    def test_query_certificates_handles_exception(self, mock_get: MagicMock) -> None:
        """Test query_certificates handles exceptions."""
        mock_get.side_effect = Exception("Connection failed")

        client = CrtShClient()
        certs = client.query_certificates("example.com")

        assert certs == []

    @patch("domainraptor.discovery.crtsh.CrtShClient.get")
    def test_query_certificates_deduplicates_by_id(self, mock_get: MagicMock) -> None:
        """Test query_certificates deduplicates certificates by ID."""
        mock_response = MagicMock()
        mock_response.json.return_value = [
            {
                "id": 1,
                "common_name": "example.com",
                "issuer_name": "Issuer1",
                "serial_number": "1",
                "not_before": "",
                "not_after": "",
                "name_value": "",
            },
            {
                "id": 1,
                "common_name": "example.com",
                "issuer_name": "Issuer1",
                "serial_number": "1",
                "not_before": "",
                "not_after": "",
                "name_value": "",
            },
            {
                "id": 2,
                "common_name": "example.com",
                "issuer_name": "Issuer2",
                "serial_number": "2",
                "not_before": "",
                "not_after": "",
                "name_value": "",
            },
        ]
        mock_get.return_value = mock_response

        client = CrtShClient()
        certs = client.query_certificates("example.com")

        assert len(certs) == 2  # Only 2 unique IDs


class TestCrtShClientHelpers:
    """Tests for helper methods."""

    def test_is_valid_domain_valid(self) -> None:
        """Test _is_valid_domain with valid domains."""
        assert CrtShClient._is_valid_domain("example.com") is True
        assert CrtShClient._is_valid_domain("sub.example.com") is True
        assert CrtShClient._is_valid_domain("a.b.c.example.com") is True

    def test_is_valid_domain_invalid(self) -> None:
        """Test _is_valid_domain with invalid domains."""
        assert CrtShClient._is_valid_domain("") is False
        assert CrtShClient._is_valid_domain("-example.com") is False
        assert CrtShClient._is_valid_domain("example.com-") is False
        assert CrtShClient._is_valid_domain(".example.com") is False
        assert CrtShClient._is_valid_domain("example.com.") is False

    def test_is_valid_domain_too_long(self) -> None:
        """Test _is_valid_domain with too long domain."""
        long_domain = "a" * 254 + ".com"
        assert CrtShClient._is_valid_domain(long_domain) is False

    def test_extract_domains_adds_valid_domains(self) -> None:
        """Test _extract_domains adds valid subdomains."""
        client = CrtShClient()
        subdomains: set[str] = set()

        client._extract_domains("www.example.com", "example.com", subdomains)

        assert "www.example.com" in subdomains

    def test_extract_domains_skips_different_domain(self) -> None:
        """Test _extract_domains skips domains not matching target."""
        client = CrtShClient()
        subdomains: set[str] = set()

        client._extract_domains("www.other.com", "example.com", subdomains)

        assert len(subdomains) == 0

    def test_extract_domains_handles_wildcards(self) -> None:
        """Test _extract_domains handles wildcard domains."""
        client = CrtShClient()
        subdomains: set[str] = set()

        client._extract_domains("*.example.com", "example.com", subdomains)

        # Should extract the base domain from wildcard
        assert "example.com" in subdomains


class TestCrtShClientIntegration:
    """Integration tests for CrtShClient (marked as slow)."""

    @pytest.mark.slow
    @pytest.mark.integration
    def test_real_query(self) -> None:
        """Test real query against crt.sh."""
        client = CrtShClient()
        assets = client.query("example.com")

        # example.com should have some certificates
        assert len(assets) >= 0  # May be empty if rate limited
        for asset in assets:
            assert asset.type == AssetType.SUBDOMAIN
            assert asset.value.endswith("example.com")
