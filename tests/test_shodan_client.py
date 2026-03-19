"""Tests for Shodan client."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from domainraptor.core.types import AssetType, Service, SeverityLevel
from domainraptor.discovery.base import ClientConfig
from domainraptor.discovery.shodan_client import (
    ShodanAPIKeyError,
    ShodanClient,
    ShodanError,
    ShodanHostResult,
    ShodanNotFoundError,
    ShodanRateLimitError,
)


# Concrete implementation of ShodanClient for testing
# ShodanClient is abstract because it inherits from BaseClient which has abstract method 'query'
class ConcreteShodanClient(ShodanClient):
    """Concrete implementation of ShodanClient for testing."""

    def query(self, target: str) -> list[Any]:
        """Implement abstract method."""
        return []


# ============================================================================
# Initialization Tests
# ============================================================================


class TestShodanClientInit:
    """Tests for ShodanClient initialization."""

    def test_init_without_api_key(self) -> None:
        """Test initialization without API key."""
        with patch.dict("os.environ", {}, clear=True):
            client = ConcreteShodanClient()
            assert client.api_key is None

    def test_init_with_api_key_param(self) -> None:
        """Test initialization with API key parameter."""
        client = ConcreteShodanClient(api_key="test-key")
        assert client.api_key == "test-key"  # pragma: allowlist secret

    def test_init_with_env_var(self) -> None:
        """Test initialization from environment variable."""
        with patch.dict("os.environ", {"SHODAN_API_KEY": "env-key"}):  # pragma: allowlist secret
            client = ConcreteShodanClient()
            assert client.api_key == "env-key"  # pragma: allowlist secret

    def test_init_with_config_api_key(self) -> None:
        """Test initialization with API key in config."""
        config = ClientConfig(api_key="config-key")
        client = ConcreteShodanClient(config=config)
        assert client.api_key == "config-key"  # pragma: allowlist secret

    def test_api_key_precedence(self) -> None:
        """Test API key parameter takes precedence."""
        with patch.dict("os.environ", {"SHODAN_API_KEY": "env-key"}):  # pragma: allowlist secret
            client = ConcreteShodanClient(api_key="param-key")
            assert client.api_key == "param-key"  # pragma: allowlist secret

    def test_init_with_custom_config(self) -> None:
        """Test initialization with custom config."""
        config = ClientConfig(rate_limit=2.0, timeout=60)
        client = ConcreteShodanClient(api_key="key", config=config)
        assert client.config.rate_limit == 2.0
        assert client.config.timeout == 60


# ============================================================================
# API Key Check Tests
# ============================================================================


class TestShodanCheckApiKey:
    """Tests for _check_api_key method."""

    def test_check_api_key_raises_without_key(self) -> None:
        """Test _check_api_key raises when no key set."""
        with patch.dict("os.environ", {}, clear=True):
            client = ConcreteShodanClient()
            with pytest.raises(ShodanAPIKeyError, match="API key required"):
                client._check_api_key()

    def test_check_api_key_passes_with_key(self) -> None:
        """Test _check_api_key passes when key is set."""
        client = ConcreteShodanClient(api_key="test-key")
        client._check_api_key()  # Should not raise


# ============================================================================
# Response Error Handling Tests
# ============================================================================


class TestShodanHandleResponseErrors:
    """Tests for _handle_response_errors method."""

    def test_handle_401_unauthorized(self) -> None:
        """Test handling 401 unauthorized."""
        import httpx

        client = ConcreteShodanClient(api_key="test")
        mock_response = MagicMock(spec=httpx.Response)
        mock_response.status_code = 401

        with pytest.raises(ShodanAPIKeyError, match="Invalid"):
            client._handle_response_errors(mock_response)

    def test_handle_429_rate_limit(self) -> None:
        """Test handling 429 rate limit."""
        import httpx

        client = ConcreteShodanClient(api_key="test")
        mock_response = MagicMock(spec=httpx.Response)
        mock_response.status_code = 429

        with pytest.raises(ShodanRateLimitError, match="rate limit"):
            client._handle_response_errors(mock_response)

    def test_handle_404_not_found(self) -> None:
        """Test handling 404 not found."""
        import httpx

        client = ConcreteShodanClient(api_key="test")
        mock_response = MagicMock(spec=httpx.Response)
        mock_response.status_code = 404

        with pytest.raises(ShodanNotFoundError, match="Not found"):
            client._handle_response_errors(mock_response, "8.8.8.8")

    def test_handle_200_ok(self) -> None:
        """Test handling 200 OK doesn't raise."""
        import httpx

        client = ConcreteShodanClient(api_key="test")
        mock_response = MagicMock(spec=httpx.Response)
        mock_response.status_code = 200

        # Should not raise
        client._handle_response_errors(mock_response)


# ============================================================================
# Host Info Tests
# ============================================================================


class TestShodanHostInfo:
    """Tests for host_info method."""

    def test_host_info_success(self) -> None:
        """Test successful host info lookup."""
        client = ConcreteShodanClient(api_key="test-key")

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "ip_str": "8.8.8.8",
            "hostnames": ["dns.google"],
            "country_name": "United States",
            "city": "Mountain View",
            "org": "Google LLC",
            "asn": "AS15169",
            "ports": [53, 443],
            "data": [
                {
                    "port": 53,
                    "transport": "udp",
                    "product": "Google DNS",
                    "version": "1.0",
                    "data": "banner data",
                    "_shodan": {"module": "dns"},
                }
            ],
            "vulns": {"CVE-2021-12345": {}},
            "tags": ["cloud"],
        }

        with patch.object(client, "get", return_value=mock_response):
            result = client.host_info("8.8.8.8")

        assert result.ip == "8.8.8.8"
        assert "dns.google" in result.hostnames
        assert result.country == "United States"
        assert len(result.services) == 1
        assert result.services[0].port == 53
        assert "CVE-2021-12345" in result.vulns

    def test_host_info_with_history(self) -> None:
        """Test host info with history flag."""
        client = ConcreteShodanClient(api_key="test-key")

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "ip_str": "8.8.8.8",
            "data": [],
        }

        with patch.object(client, "get", return_value=mock_response) as mock_get:
            client.host_info("8.8.8.8", history=True)
            call_args = mock_get.call_args
            assert "history" in call_args[1]["params"]

    def test_host_info_no_api_key(self) -> None:
        """Test host info without API key raises."""
        with patch.dict("os.environ", {}, clear=True):
            client = ConcreteShodanClient()
            with pytest.raises(ShodanAPIKeyError):
                client.host_info("8.8.8.8")

    def test_host_info_api_error(self) -> None:
        """Test host info handles API errors."""
        import httpx

        client = ConcreteShodanClient(api_key="test-key")

        mock_response = MagicMock(spec=httpx.Response)
        mock_response.status_code = 401

        with (
            patch.object(client, "get", return_value=mock_response),
            pytest.raises(ShodanAPIKeyError),
        ):
            client.host_info("8.8.8.8")

    def test_host_info_exception(self) -> None:
        """Test host info handles generic exceptions."""
        client = ConcreteShodanClient(api_key="test-key")

        with (
            patch.object(client, "get", side_effect=Exception("Connection error")),
            pytest.raises(ShodanError, match="Failed to lookup"),
        ):
            client.host_info("8.8.8.8")


# ============================================================================
# Parse Host Result Tests
# ============================================================================


class TestShodanParseHostResult:
    """Tests for _parse_host_result method."""

    def test_parse_minimal_data(self) -> None:
        """Test parsing minimal host data."""
        client = ConcreteShodanClient(api_key="test")

        data = {"ip_str": "1.2.3.4"}
        result = client._parse_host_result(data)

        assert result.ip == "1.2.3.4"
        assert result.hostnames == []
        assert result.services == []

    def test_parse_full_data(self) -> None:
        """Test parsing complete host data."""
        client = ConcreteShodanClient(api_key="test")

        data = {
            "ip_str": "1.2.3.4",
            "hostnames": ["example.com"],
            "country_name": "US",
            "city": "NYC",
            "org": "Example Inc",
            "asn": "AS12345",
            "isp": "Example ISP",
            "os": "Linux",
            "ports": [80, 443],
            "tags": ["cdn"],
            "last_update": "2024-01-01T00:00:00Z",
            "vulns": {"CVE-2024-0001": {}, "CVE-2024-0002": {}},
            "data": [
                {
                    "port": 80,
                    "transport": "tcp",
                    "product": "nginx",
                    "version": "1.20",
                    "data": "HTTP/1.1 200 OK",
                    "cpe": ["cpe:/a:nginx:nginx"],
                    "ssl": {},
                    "http": {"status": 200},
                    "_shodan": {"module": "http"},
                }
            ],
        }

        result = client._parse_host_result(data)

        assert result.ip == "1.2.3.4"
        assert result.hostnames == ["example.com"]
        assert result.country == "US"
        assert result.city == "NYC"
        assert result.org == "Example Inc"
        assert result.asn == "AS12345"
        assert result.isp == "Example ISP"
        assert result.os == "Linux"
        assert result.ports == [80, 443]
        assert result.tags == ["cdn"]
        assert len(result.vulns) == 2
        assert len(result.services) == 1
        assert result.services[0].port == 80
        assert result.services[0].service_name == "nginx"

    def test_parse_with_invalid_date(self) -> None:
        """Test parsing handles invalid date."""
        client = ConcreteShodanClient(api_key="test")

        data = {
            "ip_str": "1.2.3.4",
            "last_update": "invalid-date",
        }
        result = client._parse_host_result(data)

        assert result.last_update is None


# ============================================================================
# DNS Domain Tests
# ============================================================================


class TestShodanDnsDomain:
    """Tests for dns_domain method."""

    def test_dns_domain_success(self) -> None:
        """Test successful subdomain enumeration."""
        client = ConcreteShodanClient(api_key="test-key")

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "subdomains": ["www", "api", "mail"],
        }

        with patch.object(client, "get", return_value=mock_response):
            assets = client.dns_domain("example.com")

        assert len(assets) == 3
        assert all(a.type == AssetType.SUBDOMAIN for a in assets)
        assert "www.example.com" in [a.value for a in assets]

    def test_dns_domain_no_subdomains(self) -> None:
        """Test dns_domain with no results."""
        client = ConcreteShodanClient(api_key="test-key")

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"subdomains": []}

        with patch.object(client, "get", return_value=mock_response):
            assets = client.dns_domain("example.com")

        assert len(assets) == 0

    def test_dns_domain_not_found(self) -> None:
        """Test dns_domain returns empty on 404."""
        client = ConcreteShodanClient(api_key="test-key")

        mock_response = MagicMock()
        mock_response.status_code = 404

        with patch.object(client, "get", return_value=mock_response):
            assets = client.dns_domain("unknown.com")

        assert len(assets) == 0

    def test_dns_domain_no_api_key(self) -> None:
        """Test dns_domain raises without API key."""
        with patch.dict("os.environ", {}, clear=True):
            client = ConcreteShodanClient()
            with pytest.raises(ShodanAPIKeyError):
                client.dns_domain("example.com")


# ============================================================================
# DNS Resolve Tests
# ============================================================================


class TestShodanDnsResolve:
    """Tests for dns_resolve method."""

    def test_dns_resolve_success(self) -> None:
        """Test successful DNS resolution."""
        client = ConcreteShodanClient(api_key="test-key")

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "example.com": "93.184.216.34",
            "google.com": "142.250.80.14",
        }

        with patch.object(client, "get", return_value=mock_response):
            result = client.dns_resolve(["example.com", "google.com"])

        assert result["example.com"] == "93.184.216.34"
        assert result["google.com"] == "142.250.80.14"

    def test_dns_resolve_empty_list(self) -> None:
        """Test dns_resolve with empty list."""
        client = ConcreteShodanClient(api_key="test-key")
        result = client.dns_resolve([])
        assert result == {}

    def test_dns_resolve_no_api_key(self) -> None:
        """Test dns_resolve raises without API key."""
        with patch.dict("os.environ", {}, clear=True):
            client = ConcreteShodanClient()
            with pytest.raises(ShodanAPIKeyError):
                client.dns_resolve(["example.com"])

    def test_dns_resolve_error_returns_empty(self) -> None:
        """Test dns_resolve returns empty dict on error."""
        client = ConcreteShodanClient(api_key="test-key")

        with patch.object(client, "get", side_effect=Exception("error")):
            result = client.dns_resolve(["example.com"])

        assert result == {}


# ============================================================================
# Reverse DNS Tests
# ============================================================================


class TestShodanReverseDns:
    """Tests for reverse_dns method."""

    def test_reverse_dns_success(self) -> None:
        """Test successful reverse DNS lookup."""
        client = ConcreteShodanClient(api_key="test-key")

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "8.8.8.8": ["dns.google"],
            "1.1.1.1": ["one.one.one.one"],
        }

        with patch.object(client, "get", return_value=mock_response):
            result = client.reverse_dns(["8.8.8.8", "1.1.1.1"])

        assert result["8.8.8.8"] == ["dns.google"]

    def test_reverse_dns_empty_list(self) -> None:
        """Test reverse_dns with empty list."""
        client = ConcreteShodanClient(api_key="test-key")
        result = client.reverse_dns([])
        assert result == {}

    def test_reverse_dns_no_api_key(self) -> None:
        """Test reverse_dns raises without API key."""
        with patch.dict("os.environ", {}, clear=True):
            client = ConcreteShodanClient()
            with pytest.raises(ShodanAPIKeyError):
                client.reverse_dns(["8.8.8.8"])

    def test_reverse_dns_error_returns_empty(self) -> None:
        """Test reverse_dns returns empty dict on error."""
        client = ConcreteShodanClient(api_key="test-key")

        with patch.object(client, "get", side_effect=Exception("error")):
            result = client.reverse_dns(["8.8.8.8"])

        assert result == {}


# ============================================================================
# Vulnerability Tests
# ============================================================================


class TestShodanGetVulns:
    """Tests for get_vulns_for_host method."""

    def test_get_vulns_success(self) -> None:
        """Test successful vulnerability lookup."""
        client = ConcreteShodanClient(api_key="test-key")

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "ip_str": "1.2.3.4",
            "vulns": {"CVE-2021-12345": {}, "CVE-2022-67890": {}},
            "data": [],
        }

        with patch.object(client, "get", return_value=mock_response):
            vulns = client.get_vulns_for_host("1.2.3.4")

        assert len(vulns) == 2
        assert any(v.id == "CVE-2021-12345" for v in vulns)

    def test_get_vulns_not_found(self) -> None:
        """Test get_vulns returns empty on not found."""
        import httpx

        client = ConcreteShodanClient(api_key="test-key")

        mock_response = MagicMock(spec=httpx.Response)
        mock_response.status_code = 404

        with patch.object(client, "get", return_value=mock_response):
            vulns = client.get_vulns_for_host("1.2.3.4")

        assert len(vulns) == 0


# ============================================================================
# Estimate CVE Severity Tests
# ============================================================================


class TestShodanEstimateCveSeverity:
    """Tests for _estimate_cve_severity method."""

    def test_estimate_returns_medium(self) -> None:
        """Test severity estimation returns MEDIUM."""
        client = ConcreteShodanClient(api_key="test")
        severity = client._estimate_cve_severity("CVE-2024-12345")
        assert severity == SeverityLevel.MEDIUM


# ============================================================================
# Query Safe Tests
# ============================================================================


class TestShodanQuerySafe:
    """Tests for query_safe method."""

    def test_query_safe_domain_success(self) -> None:
        """Test query_safe with domain returns subdomains."""
        client = ConcreteShodanClient(api_key="test-key")

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"subdomains": ["www", "api"]}

        with patch.object(client, "get", return_value=mock_response):
            assets, _services, _vulns, errors = client.query_safe("example.com")

        assert len(assets) == 2
        assert len(errors) == 0

    def test_query_safe_ip_success(self) -> None:
        """Test query_safe with IP returns host info."""
        client = ConcreteShodanClient(api_key="test-key")

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "ip_str": "8.8.8.8",
            "vulns": {"CVE-2021-1234": {}},
            "data": [{"port": 53, "transport": "udp", "_shodan": {"module": "dns"}}],
        }

        with patch.object(client, "get", return_value=mock_response):
            _assets, services, vulns, errors = client.query_safe("8.8.8.8")

        assert len(services) == 1
        assert len(vulns) == 1
        assert len(errors) == 0

    def test_query_safe_api_key_error(self) -> None:
        """Test query_safe handles API key error."""
        with patch.dict("os.environ", {}, clear=True):
            client = ConcreteShodanClient()
            _assets, _services, _vulns, errors = client.query_safe("example.com")

        assert len(errors) == 1
        assert "API key" in errors[0]

    def test_query_safe_rate_limit_error(self) -> None:
        """Test query_safe handles rate limit error."""
        import httpx

        client = ConcreteShodanClient(api_key="test-key")

        mock_response = MagicMock(spec=httpx.Response)
        mock_response.status_code = 429

        with patch.object(client, "get", return_value=mock_response):
            _assets, _services, _vulns, errors = client.query_safe("example.com")

        assert len(errors) == 1
        assert "rate limit" in errors[0].lower()

    def test_query_safe_not_found(self) -> None:
        """Test query_safe handles not found."""
        import httpx

        client = ConcreteShodanClient(api_key="test-key")

        mock_response = MagicMock(spec=httpx.Response)
        mock_response.status_code = 404

        with patch.object(client, "get", return_value=mock_response):
            # IP lookup returns empty, not error
            _assets, services, _vulns, _errors = client.query_safe("192.168.1.1")

        # Not found is not an error for query_safe
        assert len(services) == 0

    def test_query_safe_generic_error(self) -> None:
        """Test query_safe handles generic error."""
        client = ConcreteShodanClient(api_key="test-key")

        with patch.object(client, "get", side_effect=Exception("Network error")):
            _assets, _services, _vulns, errors = client.query_safe("example.com")

        assert len(errors) >= 1

    def test_query_safe_without_vulns(self) -> None:
        """Test query_safe with include_vulns=False."""
        client = ConcreteShodanClient(api_key="test-key")

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "ip_str": "8.8.8.8",
            "vulns": {"CVE-2021-1234": {}},
            "data": [],
        }

        with patch.object(client, "get", return_value=mock_response):
            _assets, _services, vulns, _errors = client.query_safe("8.8.8.8", include_vulns=False)

        assert len(vulns) == 0


# ============================================================================
# Is IP Tests
# ============================================================================


class TestShodanIsIp:
    """Tests for _is_ip static method."""

    def test_ipv4_address(self) -> None:
        """Test IPv4 detection."""
        assert ShodanClient._is_ip("8.8.8.8") is True
        assert ShodanClient._is_ip("192.168.1.1") is True
        assert ShodanClient._is_ip("10.0.0.1") is True

    def test_ipv6_address(self) -> None:
        """Test IPv6 detection."""
        assert ShodanClient._is_ip("2001:4860:4860:0000:0000:0000:0000:8888") is True

    def test_domain_not_ip(self) -> None:
        """Test domain is not detected as IP."""
        assert ShodanClient._is_ip("example.com") is False
        assert ShodanClient._is_ip("www.google.com") is False
        assert ShodanClient._is_ip("subdomain.domain.tld") is False

    def test_invalid_ip(self) -> None:
        """Test invalid IPs are not detected."""
        # Note: _is_ip uses simple regex and doesn't validate octet ranges
        # 999.999.999.999 matches the pattern even though it's not a valid IP
        assert ShodanClient._is_ip("999.999.999.999") is True  # Matches pattern
        assert ShodanClient._is_ip("1.2.3") is False  # Incomplete


# ============================================================================
# ShodanHostResult Tests
# ============================================================================


class TestShodanHostResult:
    """Tests for ShodanHostResult dataclass."""

    def test_create_minimal(self) -> None:
        """Test creating minimal result."""
        result = ShodanHostResult(ip="1.2.3.4")
        assert result.ip == "1.2.3.4"
        assert result.hostnames == []
        assert result.services == []

    def test_create_full(self) -> None:
        """Test creating full result."""
        result = ShodanHostResult(
            ip="1.2.3.4",
            hostnames=["example.com"],
            country="US",
            city="NYC",
            org="Org",
            asn="AS123",
            isp="ISP",
            os="Linux",
            ports=[80, 443],
            services=[Service(port=80, protocol="tcp")],
            vulns=["CVE-123"],
            last_update=datetime.now(),
            tags=["cloud"],
        )
        assert result.ip == "1.2.3.4"
        assert len(result.hostnames) == 1
        assert len(result.services) == 1
