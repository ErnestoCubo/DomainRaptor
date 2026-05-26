"""Tests for DNS security checker module."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import dns.exception
import dns.resolver
import pytest

from domainraptor.assessment.dns_security import (
    COMMON_DKIM_SELECTORS,
    DnsSecurityChecker,
    DnsSecurityInfo,
)


class TestDnsSecurityInfo:
    """Tests for DnsSecurityInfo dataclass."""

    def test_dns_security_info_creation(self) -> None:
        """Test DNS security info creation."""
        info = DnsSecurityInfo(domain="example.com")
        assert info.domain == "example.com"
        assert info.has_dnssec is False
        assert info.spf_record is None
        assert info.dmarc_record is None

    def test_dns_security_info_with_values(self) -> None:
        """Test DNS security info with values."""
        info = DnsSecurityInfo(
            domain="example.com",
            has_dnssec=True,
            dnssec_valid=True,
            spf_record="v=spf1 include:_spf.example.com ~all",
            dmarc_record="v=DMARC1; p=reject",
            dmarc_policy="reject",
        )
        assert info.has_dnssec is True
        assert info.spf_record is not None
        assert info.dmarc_policy == "reject"


class TestCommonDkimSelectors:
    """Tests for COMMON_DKIM_SELECTORS constant."""

    def test_common_selectors_defined(self) -> None:
        """Test common DKIM selectors are defined."""
        assert "google" in COMMON_DKIM_SELECTORS
        assert "selector1" in COMMON_DKIM_SELECTORS  # Microsoft
        assert "default" in COMMON_DKIM_SELECTORS

    def test_reasonable_selector_count(self) -> None:
        """Test reasonable number of selectors to check."""
        assert 5 <= len(COMMON_DKIM_SELECTORS) <= 20


class TestDnsSecurityChecker:
    """Tests for DnsSecurityChecker class."""

    def test_checker_creation(self) -> None:
        """Test DNS security checker creation."""
        checker = DnsSecurityChecker()
        assert checker.name == "dns_security"
        assert checker.category == "dns"
        assert checker.resolver is not None

    def test_checker_resolver_timeout(self) -> None:
        """Test checker resolver has proper timeout."""
        checker = DnsSecurityChecker()
        assert checker.resolver.timeout == 5.0
        assert checker.resolver.lifetime == 10.0

    @patch.object(DnsSecurityChecker, "_get_dns_security_info")
    def test_assess_returns_issues(self, mock_get_info: MagicMock) -> None:
        """Test assess returns configuration issues."""
        mock_get_info.return_value = DnsSecurityInfo(
            domain="example.com",
            has_dnssec=False,
            has_mx=True,
            spf_record=None,  # Missing SPF
            dmarc_record=None,  # Missing DMARC
        )

        checker = DnsSecurityChecker()

        # Mock the check methods
        with (
            patch.object(checker, "_check_dnssec", return_value=[]),
            patch.object(checker, "_check_spf", return_value=[]),
            patch.object(checker, "_check_dmarc", return_value=[]),
            patch.object(checker, "_check_dkim", return_value=[]),
            patch.object(checker, "_check_caa", return_value=[]),
            patch.object(checker, "_check_ns", return_value=[]),
        ):
            issues = checker.assess("example.com")

        assert isinstance(issues, list)

    def test_assess_cleans_domain(self) -> None:
        """Test assess cleans URL to domain."""
        checker = DnsSecurityChecker()

        with patch.object(checker, "_get_dns_security_info") as mock_get:
            mock_get.return_value = DnsSecurityInfo(domain="example.com")

            # Mock check methods to avoid errors
            with (
                patch.object(checker, "_check_dnssec", return_value=[]),
                patch.object(checker, "_check_caa", return_value=[]),
                patch.object(checker, "_check_ns", return_value=[]),
            ):
                checker.assess("https://example.com/path")

            # Should have cleaned the URL
            call_args = mock_get.call_args[0][0]
            assert "https://" not in call_args
            assert "/path" not in call_args

    def test_assess_handles_exceptions(self) -> None:
        """Test assess handles DNS exceptions."""
        checker = DnsSecurityChecker()

        with patch.object(
            checker, "_get_dns_security_info", side_effect=dns.exception.DNSException()
        ):
            issues = checker.assess_safe("example.com")
            assert issues == []

    def test_context_manager(self) -> None:
        """Test checker as context manager."""
        with DnsSecurityChecker() as checker:
            assert checker.category == "dns"

    @patch("dns.resolver.Resolver")
    def test_get_dns_security_info_structure(self, mock_resolver_class: MagicMock) -> None:
        """Test _get_dns_security_info returns proper structure."""
        mock_resolver = MagicMock()
        mock_resolver.resolve.side_effect = dns.resolver.NoAnswer()
        mock_resolver_class.return_value = mock_resolver

        checker = DnsSecurityChecker()
        checker.resolver = mock_resolver

        info = checker._get_dns_security_info("example.com")

        assert isinstance(info, DnsSecurityInfo)
        assert info.domain == "example.com"

    def test_check_methods_return_lists(self) -> None:
        """Test that check methods return lists."""
        checker = DnsSecurityChecker()
        info = DnsSecurityInfo(domain="example.com")

        # These should all return lists
        assert isinstance(checker._check_dnssec(info), list)
        assert isinstance(checker._check_caa(info), list)
        assert isinstance(checker._check_ns(info), list)


class TestDnsSecurityCheckerIntegration:
    """Integration tests for DnsSecurityChecker (marked as slow)."""

    @pytest.mark.slow
    @pytest.mark.integration
    def test_real_assessment(self) -> None:
        """Test real DNS security assessment."""
        checker = DnsSecurityChecker()
        issues = checker.assess("example.com")

        # Should return some issues (example.com likely has some misconfigs)
        assert isinstance(issues, list)
        for issue in issues:
            assert issue.category == "dns"
