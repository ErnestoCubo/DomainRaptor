"""Tests for Shodan discovery module."""

from __future__ import annotations

from domainraptor.discovery.shodan_client import (
    ShodanAPIKeyError,
    ShodanError,
    ShodanHostResult,
    ShodanNotFoundError,
    ShodanRateLimitError,
)


class TestShodanErrors:
    """Tests for Shodan exception classes."""

    def test_shodan_error(self) -> None:
        """Test base ShodanError."""
        error = ShodanError("Test error")
        assert str(error) == "Test error"

    def test_api_key_error(self) -> None:
        """Test ShodanAPIKeyError."""
        error = ShodanAPIKeyError("Invalid key")
        assert isinstance(error, ShodanError)

    def test_rate_limit_error(self) -> None:
        """Test ShodanRateLimitError."""
        error = ShodanRateLimitError("Rate limit")
        assert isinstance(error, ShodanError)

    def test_not_found_error(self) -> None:
        """Test ShodanNotFoundError."""
        error = ShodanNotFoundError("Not found")
        assert isinstance(error, ShodanError)


class TestShodanHostResult:
    """Tests for ShodanHostResult dataclass."""

    def test_host_result_creation(self) -> None:
        """Test host result creation."""
        result = ShodanHostResult(ip="8.8.8.8")
        assert result.ip == "8.8.8.8"
        assert result.hostnames == []
        assert result.ports == []
        assert result.services == []

    def test_host_result_full(self) -> None:
        """Test host result with all fields."""
        result = ShodanHostResult(
            ip="8.8.8.8",
            hostnames=["dns.google"],
            country="United States",
            city="Mountain View",
            org="Google",
            asn="AS15169",
            ports=[53, 443],
            vulns=["CVE-2021-12345"],
        )
        assert len(result.hostnames) == 1
        assert len(result.ports) == 2


class TestShodanClientAttributes:
    """Tests for ShodanClient class attributes."""

    def test_client_name(self) -> None:
        """Test client name."""
        from domainraptor.discovery.shodan_client import ShodanClient

        assert ShodanClient.name == "shodan"

    def test_client_requires_api_key(self) -> None:
        """Test client requires API key."""
        from domainraptor.discovery.shodan_client import ShodanClient

        assert ShodanClient.requires_api_key is True
        assert ShodanClient.is_free is False

    def test_client_base_url(self) -> None:
        """Test client base URL."""
        from domainraptor.discovery.shodan_client import ShodanClient

        assert ShodanClient.BASE_URL == "https://api.shodan.io"
