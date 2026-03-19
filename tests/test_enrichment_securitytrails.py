"""Tests for SecurityTrails enrichment client."""

from __future__ import annotations

from datetime import datetime
from unittest.mock import MagicMock, create_autospec, patch

import httpx
import pytest

from domainraptor.discovery.base import ClientConfig
from domainraptor.enrichment.securitytrails import (
    DomainInfo,
    HistoricalDnsRecord,
    SecurityTrailsAPIKeyError,
    SecurityTrailsClient,
    SecurityTrailsError,
    SecurityTrailsNotFoundError,
    SecurityTrailsQuotaExceededError,
    SecurityTrailsRateLimitError,
)


class TestSecurityTrailsErrors:
    """Tests for SecurityTrails error classes."""

    def test_base_error(self) -> None:
        """Test base SecurityTrails error."""
        error = SecurityTrailsError("test error")
        assert str(error) == "test error"
        assert isinstance(error, Exception)

    def test_api_key_error(self) -> None:
        """Test API key error."""
        error = SecurityTrailsAPIKeyError("missing key")
        assert isinstance(error, SecurityTrailsError)

    def test_rate_limit_error(self) -> None:
        """Test rate limit error."""
        error = SecurityTrailsRateLimitError("rate limited")
        assert isinstance(error, SecurityTrailsError)

    def test_quota_exceeded_error(self) -> None:
        """Test quota exceeded error."""
        error = SecurityTrailsQuotaExceededError("quota exceeded")
        assert isinstance(error, SecurityTrailsError)

    def test_not_found_error(self) -> None:
        """Test not found error."""
        error = SecurityTrailsNotFoundError("not found")
        assert isinstance(error, SecurityTrailsError)


class TestHistoricalDnsRecord:
    """Tests for HistoricalDnsRecord dataclass."""

    def test_historical_record_creation(self) -> None:
        """Test historical DNS record creation."""
        record = HistoricalDnsRecord(record_type="A")
        assert record.record_type == "A"
        assert record.values == []
        assert record.first_seen is None
        assert record.last_seen is None
        assert record.organizations == []

    def test_historical_record_with_data(self) -> None:
        """Test historical DNS record with full data."""
        record = HistoricalDnsRecord(
            record_type="A",
            values=["93.184.216.34", "93.184.216.35"],
            first_seen=datetime(2020, 1, 1),
            last_seen=datetime(2024, 1, 15),
            organizations=["Example Inc."],
        )
        assert len(record.values) == 2
        assert record.first_seen.year == 2020
        assert record.last_seen.year == 2024
        assert "Example Inc." in record.organizations


class TestDomainInfo:
    """Tests for DomainInfo dataclass."""

    def test_domain_info_creation(self) -> None:
        """Test domain info creation."""
        info = DomainInfo(domain="example.com")
        assert info.domain == "example.com"
        assert info.alexa_rank is None
        assert info.apex_domain == ""
        assert info.current_dns == {}
        assert info.subdomains == []
        assert info.subdomain_count == 0
        assert info.historical_dns == {}

    def test_domain_info_with_data(self) -> None:
        """Test domain info with full data."""
        info = DomainInfo(
            domain="example.com",
            alexa_rank=1000,
            apex_domain="example.com",
            current_dns={
                "A": ["93.184.216.34"],
                "MX": ["mail.example.com"],
            },
            subdomains=["www", "mail", "api"],
            subdomain_count=3,
        )
        assert info.alexa_rank == 1000
        assert len(info.current_dns) == 2
        assert len(info.subdomains) == 3
        assert info.subdomain_count == 3


class TestSecurityTrailsClientAttributes:
    """Tests for SecurityTrailsClient class attributes."""

    def test_client_name(self) -> None:
        """Test client name attribute."""
        from domainraptor.enrichment.securitytrails import SecurityTrailsClient

        assert SecurityTrailsClient.name == "securitytrails"

    def test_client_requires_api_key(self) -> None:
        """Test client attributes."""
        from domainraptor.enrichment.securitytrails import SecurityTrailsClient

        assert SecurityTrailsClient.requires_api_key is True
        assert SecurityTrailsClient.is_free is True

    def test_client_base_url(self) -> None:
        """Test client base URL."""
        from domainraptor.enrichment.securitytrails import SecurityTrailsClient

        assert "securitytrails.com" in SecurityTrailsClient.BASE_URL
        assert "v1" in SecurityTrailsClient.BASE_URL


class TestSecurityTrailsClientInit:
    """Tests for SecurityTrailsClient initialization."""

    def test_client_init_with_api_key(self) -> None:
        """Test client initialization with API key."""
        client = SecurityTrailsClient(api_key="test-key")
        assert client.api_key == "test-key"  # pragma: allowlist secret

    def test_client_init_with_config_api_key(self) -> None:
        """Test client initialization with config API key."""
        config = ClientConfig(api_key="config-key")
        client = SecurityTrailsClient(config=config)
        assert client.api_key == "config-key"  # pragma: allowlist secret

    @patch.dict("os.environ", {"SECURITYTRAILS_API_KEY": "env-key"})  # pragma: allowlist secret
    def test_client_init_from_env(self) -> None:
        """Test client initialization from environment variable."""
        client = SecurityTrailsClient()
        assert client.api_key == "env-key"  # pragma: allowlist secret

    @patch.dict("os.environ", {}, clear=True)
    def test_client_init_no_api_key(self) -> None:
        """Test client initialization without API key."""
        # Clear any existing env var
        import os

        if "SECURITYTRAILS_API_KEY" in os.environ:
            del os.environ["SECURITYTRAILS_API_KEY"]
        client = SecurityTrailsClient()
        assert client.api_key is None


class TestSecurityTrailsClientHelpers:
    """Tests for SecurityTrails client helper methods."""

    def test_check_api_key_raises_without_key(self) -> None:
        """Test _check_api_key raises without key."""
        client = SecurityTrailsClient()
        client.api_key = None
        with pytest.raises(SecurityTrailsAPIKeyError):
            client._check_api_key()

    def test_check_api_key_passes_with_key(self) -> None:
        """Test _check_api_key passes with key."""
        client = SecurityTrailsClient(api_key="test-key")
        # Should not raise
        client._check_api_key()

    def test_get_headers(self) -> None:
        """Test _get_headers returns proper headers."""
        client = SecurityTrailsClient(api_key="test-key")
        headers = client._get_headers()
        assert headers["APIKEY"] == "test-key"  # pragma: allowlist secret
        assert headers["Accept"] == "application/json"

    def test_is_ip_with_ipv4(self) -> None:
        """Test _is_ip with IPv4 address."""
        assert SecurityTrailsClient._is_ip("192.168.1.1") is True
        assert SecurityTrailsClient._is_ip("8.8.8.8") is True

    def test_is_ip_with_domain(self) -> None:
        """Test _is_ip with domain name."""
        assert SecurityTrailsClient._is_ip("example.com") is False
        assert SecurityTrailsClient._is_ip("www.example.com") is False

    def test_is_ip_with_invalid(self) -> None:
        """Test _is_ip with invalid input."""
        assert SecurityTrailsClient._is_ip("not-an-ip") is False
        assert SecurityTrailsClient._is_ip("") is False


class TestSecurityTrailsClientResponseErrors:
    """Tests for response error handling."""

    def test_handle_401_response(self) -> None:
        """Test handling 401 unauthorized response."""
        client = SecurityTrailsClient(api_key="invalid-key")
        mock_response = create_autospec(httpx.Response, instance=True)
        mock_response.status_code = 401

        with pytest.raises(SecurityTrailsAPIKeyError):
            client._handle_response_errors(mock_response)

    def test_handle_403_quota_response(self) -> None:
        """Test handling 403 with quota exceeded."""
        client = SecurityTrailsClient(api_key="test-key")
        mock_response = create_autospec(httpx.Response, instance=True)
        mock_response.status_code = 403
        mock_response.json.return_value = {"message": "Monthly quota exceeded"}

        with pytest.raises(SecurityTrailsQuotaExceededError):
            client._handle_response_errors(mock_response)

    def test_handle_403_access_denied(self) -> None:
        """Test handling 403 access denied."""
        client = SecurityTrailsClient(api_key="test-key")
        mock_response = create_autospec(httpx.Response, instance=True)
        mock_response.status_code = 403
        mock_response.json.return_value = {"message": "Access denied"}

        with pytest.raises(SecurityTrailsAPIKeyError):
            client._handle_response_errors(mock_response)

    def test_handle_429_response(self) -> None:
        """Test handling 429 rate limit response."""
        client = SecurityTrailsClient(api_key="test-key")
        mock_response = create_autospec(httpx.Response, instance=True)
        mock_response.status_code = 429

        with pytest.raises(SecurityTrailsRateLimitError):
            client._handle_response_errors(mock_response)

    def test_handle_404_response(self) -> None:
        """Test handling 404 not found response."""
        client = SecurityTrailsClient(api_key="test-key")
        mock_response = create_autospec(httpx.Response, instance=True)
        mock_response.status_code = 404

        with pytest.raises(SecurityTrailsNotFoundError):
            client._handle_response_errors(mock_response, "example.com")


class TestSecurityTrailsClientGetDomain:
    """Tests for get_domain method."""

    @patch.object(SecurityTrailsClient, "get")
    def test_get_domain_success(self, mock_get: MagicMock) -> None:
        """Test successful domain lookup."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "alexa_rank": 1000,
            "apex_domain": "example.com",
            "subdomain_count": 5,
            "current_dns": {
                "a": {"values": [{"ip": "93.184.216.34"}]},
                "mx": {"values": [{"value": "mail.example.com"}]},
            },
        }
        mock_get.return_value = mock_response

        client = SecurityTrailsClient(api_key="test-key")
        result = client.get_domain("example.com")

        assert result.domain == "example.com"
        assert result.alexa_rank == 1000
        assert result.subdomain_count == 5
        assert "A" in result.current_dns

    @patch.object(SecurityTrailsClient, "get")
    def test_get_domain_not_found(self, mock_get: MagicMock) -> None:
        """Test domain not found."""
        mock_response = create_autospec(httpx.Response, instance=True)
        mock_response.status_code = 404
        mock_get.return_value = mock_response

        client = SecurityTrailsClient(api_key="test-key")
        with pytest.raises(SecurityTrailsNotFoundError):
            client.get_domain("nonexistent.example")

    @patch.object(SecurityTrailsClient, "get")
    def test_get_domain_no_api_key(self, mock_get: MagicMock) -> None:
        """Test domain lookup without API key."""
        client = SecurityTrailsClient()
        client.api_key = None
        with pytest.raises(SecurityTrailsAPIKeyError):
            client.get_domain("example.com")

    @patch.object(SecurityTrailsClient, "get")
    def test_get_domain_exception(self, mock_get: MagicMock) -> None:
        """Test domain lookup with exception."""
        mock_get.side_effect = Exception("Connection error")

        client = SecurityTrailsClient(api_key="test-key")
        with pytest.raises(SecurityTrailsError):
            client.get_domain("example.com")


class TestSecurityTrailsClientGetSubdomains:
    """Tests for get_subdomains method."""

    @patch.object(SecurityTrailsClient, "get")
    def test_get_subdomains_success(self, mock_get: MagicMock) -> None:
        """Test successful subdomain enumeration."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "subdomains": ["www", "mail", "api", "cdn"],
        }
        mock_get.return_value = mock_response

        client = SecurityTrailsClient(api_key="test-key")
        result = client.get_subdomains("example.com")

        assert len(result) == 4
        assert result[0].value == "www.example.com"
        assert result[0].source == "securitytrails"

    @patch.object(SecurityTrailsClient, "get")
    def test_get_subdomains_not_found(self, mock_get: MagicMock) -> None:
        """Test subdomains not found returns empty list."""
        mock_response = create_autospec(httpx.Response, instance=True)
        mock_response.status_code = 404
        mock_get.return_value = mock_response

        client = SecurityTrailsClient(api_key="test-key")
        result = client.get_subdomains("nonexistent.example")

        assert result == []

    @patch.object(SecurityTrailsClient, "get")
    def test_get_subdomains_no_api_key(self, mock_get: MagicMock) -> None:
        """Test subdomain enumeration without API key."""
        client = SecurityTrailsClient()
        client.api_key = None
        with pytest.raises(SecurityTrailsAPIKeyError):
            client.get_subdomains("example.com")


class TestSecurityTrailsClientGetDnsHistory:
    """Tests for get_dns_history method."""

    @patch.object(SecurityTrailsClient, "get")
    def test_get_dns_history_success(self, mock_get: MagicMock) -> None:
        """Test successful DNS history lookup."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "records": [
                {
                    "values": [{"ip": "93.184.216.34", "ip_organization": "Example Inc"}],
                    "first_seen": "2020-01-01",
                    "last_seen": "2024-01-15",
                },
                {
                    "values": [{"ip": "93.184.216.35"}],
                    "first_seen": "2019-01-01",
                    "last_seen": "2019-12-31",
                },
            ],
        }
        mock_get.return_value = mock_response

        client = SecurityTrailsClient(api_key="test-key")
        result = client.get_dns_history("example.com", "a")

        assert len(result) == 2
        assert result[0].record_type == "A"
        assert "93.184.216.34" in result[0].values
        assert "Example Inc" in result[0].organizations

    @patch.object(SecurityTrailsClient, "get")
    def test_get_dns_history_not_found(self, mock_get: MagicMock) -> None:
        """Test DNS history not found."""
        mock_response = create_autospec(httpx.Response, instance=True)
        mock_response.status_code = 404
        mock_get.return_value = mock_response

        client = SecurityTrailsClient(api_key="test-key")
        result = client.get_dns_history("nonexistent.example", "a")

        assert result == []

    @patch.object(SecurityTrailsClient, "get")
    def test_get_dns_history_no_api_key(self, mock_get: MagicMock) -> None:
        """Test DNS history without API key."""
        client = SecurityTrailsClient()
        client.api_key = None
        with pytest.raises(SecurityTrailsAPIKeyError):
            client.get_dns_history("example.com", "a")


class TestSecurityTrailsClientGetAssociatedDomains:
    """Tests for get_associated_domains method."""

    @patch.object(SecurityTrailsClient, "get")
    def test_get_associated_domains_success(self, mock_get: MagicMock) -> None:
        """Test successful associated domains lookup."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "records": [
                {"hostname": "related1.com"},
                {"hostname": "related2.com"},
            ],
        }
        mock_get.return_value = mock_response

        client = SecurityTrailsClient(api_key="test-key")
        result = client.get_associated_domains("example.com")

        assert len(result) == 2
        assert "related1.com" in result
        assert "related2.com" in result

    @patch.object(SecurityTrailsClient, "get")
    def test_get_associated_domains_not_found(self, mock_get: MagicMock) -> None:
        """Test associated domains not found."""
        mock_response = create_autospec(httpx.Response, instance=True)
        mock_response.status_code = 404
        mock_get.return_value = mock_response

        client = SecurityTrailsClient(api_key="test-key")
        result = client.get_associated_domains("nonexistent.example")

        assert result == []

    @patch.object(SecurityTrailsClient, "get")
    def test_get_associated_domains_exception(self, mock_get: MagicMock) -> None:
        """Test associated domains with exception."""
        mock_get.side_effect = Exception("Connection error")

        client = SecurityTrailsClient(api_key="test-key")
        result = client.get_associated_domains("example.com")

        assert result == []


class TestSecurityTrailsClientGetIpNeighbors:
    """Tests for get_ip_neighbors method."""

    @patch.object(SecurityTrailsClient, "get")
    def test_get_ip_neighbors_success(self, mock_get: MagicMock) -> None:
        """Test successful IP neighbors lookup."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "blocks": [
                {"sites": ["site1.com", "site2.com"]},
                {"sites": ["site3.com"]},
            ],
        }
        mock_get.return_value = mock_response

        client = SecurityTrailsClient(api_key="test-key")
        result = client.get_ip_neighbors("93.184.216.34")

        assert len(result) == 3
        assert "site1.com" in result
        assert "site3.com" in result

    @patch.object(SecurityTrailsClient, "get")
    def test_get_ip_neighbors_not_found(self, mock_get: MagicMock) -> None:
        """Test IP neighbors not found."""
        mock_response = create_autospec(httpx.Response, instance=True)
        mock_response.status_code = 404
        mock_get.return_value = mock_response

        client = SecurityTrailsClient(api_key="test-key")
        result = client.get_ip_neighbors("192.168.1.1")

        assert result == []

    @patch.object(SecurityTrailsClient, "get")
    def test_get_ip_neighbors_exception(self, mock_get: MagicMock) -> None:
        """Test IP neighbors with exception."""
        mock_get.side_effect = Exception("Connection error")

        client = SecurityTrailsClient(api_key="test-key")
        result = client.get_ip_neighbors("192.168.1.1")

        assert result == []


class TestSecurityTrailsClientQuerySafe:
    """Tests for query_safe method."""

    @patch.object(SecurityTrailsClient, "get_domain")
    @patch.object(SecurityTrailsClient, "get_subdomains")
    def test_query_safe_success(self, mock_subdomains: MagicMock, mock_domain: MagicMock) -> None:
        """Test successful query_safe."""
        mock_domain.return_value = DomainInfo(
            domain="example.com",
            subdomain_count=3,
        )
        mock_subdomains.return_value = []

        client = SecurityTrailsClient(api_key="test-key")
        info, _subdomains, errors = client.query_safe("example.com")

        assert info is not None
        assert info.domain == "example.com"
        assert errors == []

    def test_query_safe_ip_skipped(self) -> None:
        """Test query_safe skips IPs."""
        client = SecurityTrailsClient(api_key="test-key")
        info, subdomains, errors = client.query_safe("192.168.1.1")

        assert info is None
        assert subdomains == []
        assert errors == []

    @patch.object(SecurityTrailsClient, "get_domain")
    def test_query_safe_api_key_error(self, mock_domain: MagicMock) -> None:
        """Test query_safe with API key error."""
        mock_domain.side_effect = SecurityTrailsAPIKeyError("Invalid key")

        client = SecurityTrailsClient(api_key="test-key")
        info, _subdomains, errors = client.query_safe("example.com")

        assert info is None
        assert len(errors) == 1
        assert "SecurityTrails" in errors[0]

    @patch.object(SecurityTrailsClient, "get_domain")
    def test_query_safe_quota_exceeded(self, mock_domain: MagicMock) -> None:
        """Test query_safe with quota exceeded."""
        mock_domain.side_effect = SecurityTrailsQuotaExceededError("Quota exceeded")

        client = SecurityTrailsClient(api_key="test-key")
        info, _subdomains, errors = client.query_safe("example.com")

        assert info is None
        assert len(errors) == 1

    @patch.object(SecurityTrailsClient, "get_domain")
    @patch.object(SecurityTrailsClient, "get_subdomains")
    def test_query_safe_not_found(
        self,
        mock_subdomains: MagicMock,
        mock_domain: MagicMock,
    ) -> None:
        """Test query_safe with domain not found."""
        mock_domain.side_effect = SecurityTrailsNotFoundError("Not found")
        mock_subdomains.return_value = []

        client = SecurityTrailsClient(api_key="test-key")
        info, _subdomains, errors = client.query_safe("example.com")

        assert info is None
        assert errors == []

    @patch.object(SecurityTrailsClient, "get_domain")
    @patch.object(SecurityTrailsClient, "get_subdomains")
    @patch.object(SecurityTrailsClient, "get_dns_history")
    def test_query_safe_with_history(
        self,
        mock_history: MagicMock,
        mock_subdomains: MagicMock,
        mock_domain: MagicMock,
    ) -> None:
        """Test query_safe with history."""
        mock_domain.return_value = DomainInfo(domain="example.com")
        mock_subdomains.return_value = []
        mock_history.return_value = [HistoricalDnsRecord(record_type="A", values=["1.2.3.4"])]

        client = SecurityTrailsClient(api_key="test-key")
        info, _subdomains, _errors = client.query_safe("example.com", include_history=True)

        assert info is not None
        # History is called multiple times for different record types
        assert mock_history.call_count >= 1
