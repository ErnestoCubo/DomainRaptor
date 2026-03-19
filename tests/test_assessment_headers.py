"""Tests for headers checker module."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import httpx

from domainraptor.assessment.headers_checker import (
    LEAKY_HEADERS,
    SECURITY_HEADERS_CONFIG,
    HeadersChecker,
    SecurityHeaders,
)
from domainraptor.core.types import SeverityLevel


class TestSecurityHeaders:
    """Tests for SecurityHeaders dataclass."""

    def test_security_headers_creation(self) -> None:
        """Test security headers creation."""
        headers = SecurityHeaders(url="https://example.com", status_code=200)
        assert headers.url == "https://example.com"
        assert headers.status_code == 200
        assert headers.strict_transport_security is None

    def test_security_headers_with_values(self) -> None:
        """Test security headers with actual values."""
        headers = SecurityHeaders(
            url="https://example.com",
            status_code=200,
            strict_transport_security="max-age=31536000",
            content_security_policy="default-src 'self'",
            x_frame_options="DENY",
        )
        assert headers.strict_transport_security == "max-age=31536000"
        assert headers.x_frame_options == "DENY"


class TestSecurityHeadersConfig:
    """Tests for SECURITY_HEADERS_CONFIG constant."""

    def test_config_has_required_headers(self) -> None:
        """Test config has all important security headers."""
        assert "strict-transport-security" in SECURITY_HEADERS_CONFIG
        assert "content-security-policy" in SECURITY_HEADERS_CONFIG
        assert "x-frame-options" in SECURITY_HEADERS_CONFIG
        assert "x-content-type-options" in SECURITY_HEADERS_CONFIG

    def test_config_has_severity(self) -> None:
        """Test each header config has severity."""
        for config in SECURITY_HEADERS_CONFIG.values():
            assert "severity" in config
            assert isinstance(config["severity"], SeverityLevel)

    def test_config_has_recommendations(self) -> None:
        """Test each header config has recommendations."""
        for config in SECURITY_HEADERS_CONFIG.values():
            assert "recommended" in config
            assert "title" in config


class TestLeakyHeaders:
    """Tests for LEAKY_HEADERS constant."""

    def test_leaky_headers_defined(self) -> None:
        """Test leaky headers are defined."""
        assert "server" in LEAKY_HEADERS
        assert "x-powered-by" in LEAKY_HEADERS


class TestHeadersChecker:
    """Tests for HeadersChecker class."""

    def test_checker_creation(self) -> None:
        """Test headers checker creation."""
        checker = HeadersChecker()
        assert checker.name == "headers_checker"
        assert checker.category == "headers"

    @patch("domainraptor.assessment.headers_checker.HeadersChecker.http_client")
    def test_assess_missing_headers(self, mock_client: MagicMock) -> None:
        """Test assess reports missing security headers."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {}  # No headers
        mock_client.get.return_value = mock_response

        checker = HeadersChecker()
        issues = checker.assess("https://example.com")

        # Should report missing HSTS, CSP, etc.
        issue_ids = [i.id for i in issues]
        assert any("HDR-001" in id_ for id_ in issue_ids)  # Missing HSTS

    @patch("domainraptor.assessment.headers_checker.HeadersChecker.http_client")
    def test_assess_with_good_headers(self, mock_client: MagicMock) -> None:
        """Test assess with proper security headers."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {
            "strict-transport-security": "max-age=31536000; includeSubDomains",
            "content-security-policy": "default-src 'self'",
            "x-frame-options": "DENY",
            "x-content-type-options": "nosniff",
            "referrer-policy": "strict-origin-when-cross-origin",
            "permissions-policy": "geolocation=()",
        }
        mock_client.get.return_value = mock_response

        checker = HeadersChecker()
        issues = checker.assess("https://example.com")

        # Should have fewer issues since headers are present
        missing_header_issues = [i for i in issues if "Missing" in i.title]
        # With good headers, some issues should not appear
        assert len(missing_header_issues) < len(SECURITY_HEADERS_CONFIG)

    @patch("domainraptor.assessment.headers_checker.HeadersChecker.http_client")
    def test_assess_leaky_headers(self, mock_client: MagicMock) -> None:
        """Test assess detects leaky server headers."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {
            "server": "Apache/2.4.41 (Ubuntu)",
            "x-powered-by": "PHP/7.4.3",
        }
        mock_client.get.return_value = mock_response

        checker = HeadersChecker()
        issues = checker.assess("https://example.com")

        # Should report server version disclosure
        issue_ids = [i.id for i in issues]
        assert any("HDR-01" in id_ for id_ in issue_ids)  # Server/X-Powered-By

    @patch("domainraptor.assessment.headers_checker.HeadersChecker.http_client")
    def test_assess_adds_https_scheme(self, mock_client: MagicMock) -> None:
        """Test assess adds https:// if no scheme provided."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {}
        mock_client.get.return_value = mock_response

        checker = HeadersChecker()
        checker.assess("example.com")  # No scheme

        # Should still work (adds https://)
        mock_client.get.assert_called()
        call_url = mock_client.get.call_args[0][0]
        assert call_url.startswith("https://")

    @patch("domainraptor.assessment.headers_checker.HeadersChecker.http_client")
    def test_assess_handles_connection_error(self, mock_client: MagicMock) -> None:
        """Test assess handles connection errors gracefully."""
        mock_client.get.side_effect = httpx.ConnectError("Connection refused")

        checker = HeadersChecker()
        issues = checker.assess("https://example.com")

        # Should return empty or error issue
        assert isinstance(issues, list)

    def test_assess_safe(self) -> None:
        """Test assess_safe catches exceptions."""
        checker = HeadersChecker()

        with patch.object(checker, "assess", side_effect=ValueError("Test error")):
            issues = checker.assess_safe("https://example.com")
            assert issues == []

    def test_context_manager(self) -> None:
        """Test checker as context manager."""
        with HeadersChecker() as checker:
            assert checker.category == "headers"
