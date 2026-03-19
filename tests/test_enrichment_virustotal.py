"""Tests for VirusTotal enrichment client."""

from __future__ import annotations

import time
from datetime import datetime
from unittest.mock import MagicMock, create_autospec, patch

import httpx
import pytest

from domainraptor.discovery.base import ClientConfig
from domainraptor.enrichment.virustotal import (
    ReputationResult,
    VirusTotalAPIKeyError,
    VirusTotalClient,
    VirusTotalError,
    VirusTotalNotFoundError,
    VirusTotalQuotaExceededError,
    VirusTotalRateLimitError,
)


class TestVirusTotalErrors:
    """Tests for VirusTotal error classes."""

    def test_base_error(self) -> None:
        """Test base VirusTotal error."""
        error = VirusTotalError("test error")
        assert str(error) == "test error"
        assert isinstance(error, Exception)

    def test_api_key_error(self) -> None:
        """Test API key error."""
        error = VirusTotalAPIKeyError("missing key")
        assert isinstance(error, VirusTotalError)

    def test_rate_limit_error(self) -> None:
        """Test rate limit error."""
        error = VirusTotalRateLimitError("rate limited")
        assert isinstance(error, VirusTotalError)

    def test_quota_exceeded_error(self) -> None:
        """Test quota exceeded error."""
        error = VirusTotalQuotaExceededError("quota exceeded")
        assert isinstance(error, VirusTotalError)

    def test_not_found_error(self) -> None:
        """Test not found error."""
        error = VirusTotalNotFoundError("not found")
        assert isinstance(error, VirusTotalError)


class TestReputationResult:
    """Tests for ReputationResult dataclass."""

    def test_reputation_result_creation(self) -> None:
        """Test reputation result creation."""
        result = ReputationResult(
            resource="example.com",
            resource_type="domain",
        )
        assert result.resource == "example.com"
        assert result.resource_type == "domain"
        assert result.malicious == 0
        assert result.suspicious == 0

    def test_is_malicious_false(self) -> None:
        """Test is_malicious returns False for clean domain."""
        result = ReputationResult(
            resource="example.com",
            resource_type="domain",
            malicious=0,
        )
        assert result.is_malicious is False

    def test_is_malicious_true(self) -> None:
        """Test is_malicious returns True for bad domain."""
        result = ReputationResult(
            resource="badsite.com",
            resource_type="domain",
            malicious=5,
        )
        assert result.is_malicious is True

    def test_is_suspicious_with_malicious(self) -> None:
        """Test is_suspicious with 1 malicious detection."""
        result = ReputationResult(
            resource="example.com",
            resource_type="domain",
            malicious=1,
            suspicious=0,
        )
        assert result.is_suspicious is True

    def test_is_suspicious_with_suspicious(self) -> None:
        """Test is_suspicious with 3+ suspicious detections."""
        result = ReputationResult(
            resource="example.com",
            resource_type="domain",
            malicious=0,
            suspicious=3,
        )
        assert result.is_suspicious is True

    def test_detection_ratio(self) -> None:
        """Test detection ratio string."""
        result = ReputationResult(
            resource="example.com",
            resource_type="domain",
            malicious=3,
            total_engines=70,
        )
        assert result.detection_ratio == "3/70"

    def test_detection_ratio_zero_engines(self) -> None:
        """Test detection ratio with zero engines."""
        result = ReputationResult(
            resource="example.com",
            resource_type="domain",
            total_engines=0,
        )
        assert result.detection_ratio == "0/0"

    def test_reputation_result_with_full_data(self) -> None:
        """Test reputation result with all fields populated."""
        result = ReputationResult(
            resource="example.com",
            resource_type="domain",
            malicious=2,
            suspicious=1,
            harmless=60,
            undetected=7,
            total_engines=70,
            reputation_score=5,
            last_analysis_date=datetime(2024, 1, 15),
            categories={"BitDefender": "business"},
            tags=["top-1m"],
            whois="Domain Name: example.com",
            registrar="Example Registrar",
            as_owner="AS15133 Example Inc.",
            country="US",
            last_dns_records=[{"type": "A", "value": "93.184.216.34"}],
            subdomains=["www", "mail"],
        )
        assert result.is_malicious is True
        assert result.registrar == "Example Registrar"
        assert len(result.subdomains) == 2


class TestVirusTotalClientAttributes:
    """Tests for VirusTotalClient class attributes."""

    def test_client_name(self) -> None:
        """Test client name attribute."""
        from domainraptor.enrichment.virustotal import VirusTotalClient

        assert VirusTotalClient.name == "virustotal"

    def test_client_requires_api_key(self) -> None:
        """Test client requires API key attribute."""
        from domainraptor.enrichment.virustotal import VirusTotalClient

        assert VirusTotalClient.requires_api_key is True
        assert VirusTotalClient.is_free is True

    def test_client_base_url(self) -> None:
        """Test client base URL."""
        from domainraptor.enrichment.virustotal import VirusTotalClient

        assert "virustotal.com" in VirusTotalClient.BASE_URL
        assert "v3" in VirusTotalClient.BASE_URL

    def test_min_request_interval(self) -> None:
        """Test minimum request interval is set."""
        from domainraptor.enrichment.virustotal import VirusTotalClient

        assert VirusTotalClient.MIN_REQUEST_INTERVAL > 0
        # Free tier is 4 req/min, so at least 15 seconds between requests
        assert VirusTotalClient.MIN_REQUEST_INTERVAL >= 15.0


class TestVirusTotalClientInit:
    """Tests for VirusTotalClient initialization."""

    def test_client_init_with_api_key(self) -> None:
        """Test client initialization with API key."""
        client = VirusTotalClient(api_key="test-key")
        assert client.api_key == "test-key"  # pragma: allowlist secret

    def test_client_init_with_config_api_key(self) -> None:
        """Test client initialization with config API key."""
        config = ClientConfig(api_key="config-key")  # pragma: allowlist secret
        client = VirusTotalClient(config=config)
        assert client.api_key == "config-key"  # pragma: allowlist secret

    @patch.dict("os.environ", {"VIRUSTOTAL_API_KEY": "env-key"})  # pragma: allowlist secret
    def test_client_init_from_env(self) -> None:
        """Test client initialization from environment variable."""
        client = VirusTotalClient()
        assert client.api_key == "env-key"  # pragma: allowlist secret

    @patch.dict("os.environ", {}, clear=True)
    def test_client_init_no_api_key(self) -> None:
        """Test client initialization without API key."""
        # Remove env var if exists
        import os

        os.environ.pop("VIRUSTOTAL_API_KEY", None)
        client = VirusTotalClient()
        assert client.api_key is None


class TestVirusTotalClientHelpers:
    """Tests for VirusTotalClient helper methods."""

    def test_check_api_key_raises_without_key(self) -> None:
        """Test _check_api_key raises error without key."""
        client = VirusTotalClient(api_key=None)
        client.api_key = None
        with pytest.raises(VirusTotalAPIKeyError):
            client._check_api_key()

    def test_check_api_key_passes_with_key(self) -> None:
        """Test _check_api_key passes with key."""
        client = VirusTotalClient(api_key="test-key")
        # Should not raise
        client._check_api_key()

    def test_get_headers(self) -> None:
        """Test _get_headers returns correct headers."""
        client = VirusTotalClient(api_key="test-key")
        headers = client._get_headers()
        assert headers["x-apikey"] == "test-key"  # pragma: allowlist secret
        assert headers["Accept"] == "application/json"

    def test_is_ip_with_ipv4(self) -> None:
        """Test _is_ip returns True for IPv4."""
        assert VirusTotalClient._is_ip("192.168.1.1") is True
        assert VirusTotalClient._is_ip("8.8.8.8") is True
        assert VirusTotalClient._is_ip("10.0.0.1") is True

    def test_is_ip_with_domain(self) -> None:
        """Test _is_ip returns False for domains."""
        assert VirusTotalClient._is_ip("example.com") is False
        assert VirusTotalClient._is_ip("www.example.com") is False

    def test_is_ip_with_invalid(self) -> None:
        """Test _is_ip with invalid inputs."""
        assert VirusTotalClient._is_ip("not-an-ip") is False
        assert VirusTotalClient._is_ip("192.168.1") is False


class TestVirusTotalClientRateLimit:
    """Tests for rate limiting."""

    def test_rate_limit_first_request(self) -> None:
        """Test rate limit on first request."""
        client = VirusTotalClient(api_key="test-key")
        client._last_request_time = 0
        # Should not sleep for first request if time is 0
        start = time.time()
        client._rate_limit()
        time.time() - start
        # First request after init should be quick
        assert client._last_request_time > 0


class TestVirusTotalClientResponseErrors:
    """Tests for response error handling."""

    def test_handle_401_response(self) -> None:
        """Test handling 401 unauthorized response."""
        client = VirusTotalClient(api_key="invalid-key")
        mock_response = create_autospec(httpx.Response, instance=True)
        mock_response.status_code = 401

        with pytest.raises(VirusTotalAPIKeyError):
            client._handle_response_errors(mock_response)

    def test_handle_429_rate_limit_response(self) -> None:
        """Test handling 429 rate limit response."""
        client = VirusTotalClient(api_key="test-key")
        mock_response = create_autospec(httpx.Response, instance=True)
        mock_response.status_code = 429
        mock_response.json.return_value = {"error": {"code": "RateLimitError"}}

        with pytest.raises(VirusTotalRateLimitError):
            client._handle_response_errors(mock_response)

    def test_handle_429_quota_exceeded_response(self) -> None:
        """Test handling 429 quota exceeded response."""
        client = VirusTotalClient(api_key="test-key")
        mock_response = create_autospec(httpx.Response, instance=True)
        mock_response.status_code = 429
        mock_response.json.return_value = {"error": {"code": "QuotaExceededError"}}

        with pytest.raises(VirusTotalQuotaExceededError):
            client._handle_response_errors(mock_response)

    def test_handle_404_response(self) -> None:
        """Test handling 404 not found response."""
        client = VirusTotalClient(api_key="test-key")
        mock_response = create_autospec(httpx.Response, instance=True)
        mock_response.status_code = 404

        with pytest.raises(VirusTotalNotFoundError):
            client._handle_response_errors(mock_response, "example.com")


class TestVirusTotalClientGetDomainReport:
    """Tests for get_domain_report method."""

    @patch.object(VirusTotalClient, "get")
    @patch.object(VirusTotalClient, "_rate_limit")
    def test_get_domain_report_success(self, mock_rate: MagicMock, mock_get: MagicMock) -> None:
        """Test successful domain report."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 0,
                        "suspicious": 0,
                        "harmless": 60,
                        "undetected": 10,
                    },
                    "reputation": 5,
                    "categories": {"BitDefender": "business"},
                }
            }
        }
        mock_get.return_value = mock_response

        client = VirusTotalClient(api_key="test-key")
        result = client.get_domain_report("example.com")

        assert result.resource == "example.com"
        assert result.resource_type == "domain"
        assert result.malicious == 0
        assert result.harmless == 60

    @patch.object(VirusTotalClient, "get")
    @patch.object(VirusTotalClient, "_rate_limit")
    def test_get_domain_report_with_analysis_date(
        self, mock_rate: MagicMock, mock_get: MagicMock
    ) -> None:
        """Test domain report with analysis date."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {},
                    "last_analysis_date": 1705320000,  # Some timestamp
                }
            }
        }
        mock_get.return_value = mock_response

        client = VirusTotalClient(api_key="test-key")
        result = client.get_domain_report("example.com")

        assert result.last_analysis_date is not None

    def test_get_domain_report_no_api_key(self) -> None:
        """Test get_domain_report without API key."""
        client = VirusTotalClient(api_key=None)
        client.api_key = None
        with pytest.raises(VirusTotalAPIKeyError):
            client.get_domain_report("example.com")

    @patch.object(VirusTotalClient, "get")
    @patch.object(VirusTotalClient, "_rate_limit")
    def test_get_domain_report_exception(self, mock_rate: MagicMock, mock_get: MagicMock) -> None:
        """Test get_domain_report handles exceptions."""
        mock_get.side_effect = Exception("Network error")

        client = VirusTotalClient(api_key="test-key")
        with pytest.raises(VirusTotalError, match="Failed to lookup"):
            client.get_domain_report("example.com")


class TestVirusTotalClientGetIpReport:
    """Tests for get_ip_report method."""

    @patch.object(VirusTotalClient, "get")
    @patch.object(VirusTotalClient, "_rate_limit")
    def test_get_ip_report_success(self, mock_rate: MagicMock, mock_get: MagicMock) -> None:
        """Test successful IP report."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 2,
                        "suspicious": 1,
                        "harmless": 50,
                        "undetected": 17,
                    },
                    "as_owner": "AS15133 Example Inc.",
                    "country": "US",
                }
            }
        }
        mock_get.return_value = mock_response

        client = VirusTotalClient(api_key="test-key")
        result = client.get_ip_report("8.8.8.8")

        assert result.resource == "8.8.8.8"
        assert result.resource_type == "ip"
        assert result.malicious == 2
        assert result.as_owner == "AS15133 Example Inc."

    def test_get_ip_report_no_api_key(self) -> None:
        """Test get_ip_report without API key."""
        client = VirusTotalClient(api_key=None)
        client.api_key = None
        with pytest.raises(VirusTotalAPIKeyError):
            client.get_ip_report("8.8.8.8")

    @patch.object(VirusTotalClient, "get")
    @patch.object(VirusTotalClient, "_rate_limit")
    def test_get_ip_report_exception(self, mock_rate: MagicMock, mock_get: MagicMock) -> None:
        """Test get_ip_report handles exceptions."""
        mock_get.side_effect = Exception("Network error")

        client = VirusTotalClient(api_key="test-key")
        with pytest.raises(VirusTotalError, match="Failed to lookup"):
            client.get_ip_report("8.8.8.8")


class TestVirusTotalClientGetSubdomains:
    """Tests for get_subdomains method."""

    @patch.object(VirusTotalClient, "get")
    @patch.object(VirusTotalClient, "_rate_limit")
    def test_get_subdomains_success(self, mock_rate: MagicMock, mock_get: MagicMock) -> None:
        """Test successful subdomain enumeration."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": [
                {"id": "www.example.com"},
                {"id": "mail.example.com"},
                {"id": "api.example.com"},
            ]
        }
        mock_get.return_value = mock_response

        client = VirusTotalClient(api_key="test-key")
        assets = client.get_subdomains("example.com")

        assert len(assets) == 3
        assert assets[0].value == "www.example.com"
        assert assets[0].parent == "example.com"

    @patch.object(VirusTotalClient, "get")
    @patch.object(VirusTotalClient, "_rate_limit")
    def test_get_subdomains_not_found(self, mock_rate: MagicMock, mock_get: MagicMock) -> None:
        """Test subdomain enumeration with not found."""
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_get.return_value = mock_response

        client = VirusTotalClient(api_key="test-key")
        # Patching _handle_response_errors to raise NotFoundError
        with patch.object(client, "_handle_response_errors", side_effect=VirusTotalNotFoundError):
            assets = client.get_subdomains("unknown-domain.com")

        assert assets == []

    def test_get_subdomains_no_api_key(self) -> None:
        """Test get_subdomains without API key."""
        client = VirusTotalClient(api_key=None)
        client.api_key = None
        with pytest.raises(VirusTotalAPIKeyError):
            client.get_subdomains("example.com")


class TestVirusTotalClientGetDnsRecords:
    """Tests for get_dns_records method."""

    @patch.object(VirusTotalClient, "get_domain_report")
    def test_get_dns_records_success(self, mock_report: MagicMock) -> None:
        """Test successful DNS records retrieval."""
        mock_report.return_value = ReputationResult(
            resource="example.com",
            resource_type="domain",
            last_dns_records=[
                {"type": "A", "value": "93.184.216.34"},
                {"type": "MX", "value": "mail.example.com"},
            ],
        )

        client = VirusTotalClient(api_key="test-key")
        records = client.get_dns_records("example.com")

        assert len(records) == 2
        assert records[0]["type"] == "A"

    @patch.object(VirusTotalClient, "get_domain_report")
    def test_get_dns_records_error(self, mock_report: MagicMock) -> None:
        """Test DNS records with error returns empty list."""
        mock_report.side_effect = VirusTotalError("Error")

        client = VirusTotalClient(api_key="test-key")
        records = client.get_dns_records("example.com")

        assert records == []


class TestVirusTotalClientQuerySafe:
    """Tests for query_safe method."""

    @patch.object(VirusTotalClient, "get_domain_report")
    @patch.object(VirusTotalClient, "get_subdomains")
    def test_query_safe_domain_success(self, mock_subs: MagicMock, mock_report: MagicMock) -> None:
        """Test query_safe with successful domain query."""
        mock_report.return_value = ReputationResult(
            resource="example.com",
            resource_type="domain",
        )
        mock_subs.return_value = []

        client = VirusTotalClient(api_key="test-key")
        rep, _subs, errors = client.query_safe("example.com")

        assert rep is not None
        assert rep.resource == "example.com"
        assert errors == []

    @patch.object(VirusTotalClient, "get_ip_report")
    def test_query_safe_ip_success(self, mock_report: MagicMock) -> None:
        """Test query_safe with successful IP query."""
        mock_report.return_value = ReputationResult(
            resource="8.8.8.8",
            resource_type="ip",
        )

        client = VirusTotalClient(api_key="test-key")
        rep, subs, _errors = client.query_safe("8.8.8.8")

        assert rep is not None
        assert rep.resource == "8.8.8.8"
        assert subs == []  # IPs don't have subdomains

    @patch.object(VirusTotalClient, "get_domain_report")
    @patch.object(VirusTotalClient, "get_subdomains")
    def test_query_safe_api_key_error(self, mock_subs: MagicMock, mock_report: MagicMock) -> None:
        """Test query_safe handles API key error."""
        mock_report.side_effect = VirusTotalAPIKeyError("No key")

        client = VirusTotalClient(api_key="test-key")
        rep, _subs, errors = client.query_safe("example.com")

        assert rep is None
        assert len(errors) == 1

    @patch.object(VirusTotalClient, "get_domain_report")
    @patch.object(VirusTotalClient, "get_subdomains")
    def test_query_safe_not_found(self, mock_subs: MagicMock, mock_report: MagicMock) -> None:
        """Test query_safe handles not found gracefully."""
        mock_report.side_effect = VirusTotalNotFoundError("Not found")
        mock_subs.return_value = []

        client = VirusTotalClient(api_key="test-key")
        rep, _subs, errors = client.query_safe("unknown.com")

        assert rep is None
        assert errors == []  # Not found is not an error

    @patch.object(VirusTotalClient, "get_domain_report")
    @patch.object(VirusTotalClient, "get_subdomains")
    def test_query_safe_rate_limit(self, mock_subs: MagicMock, mock_report: MagicMock) -> None:
        """Test query_safe handles rate limit."""
        mock_report.side_effect = VirusTotalRateLimitError("Rate limited")
        mock_subs.return_value = []

        client = VirusTotalClient(api_key="test-key")
        rep, _subs, errors = client.query_safe("example.com")

        assert rep is None
        assert len(errors) == 1
