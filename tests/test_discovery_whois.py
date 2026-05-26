"""Tests for WHOIS client module."""

from __future__ import annotations

from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest

from domainraptor.discovery.whois_client import (
    WhoisClient,
    WhoisInfo,
)


class TestWhoisInfo:
    """Tests for WhoisInfo dataclass."""

    def test_whois_info_creation(self) -> None:
        """Test WhoisInfo creation."""
        info = WhoisInfo(domain="example.com")
        assert info.domain == "example.com"
        assert info.registrar is None
        assert info.nameservers is None
        assert info.dnssec is False

    def test_whois_info_with_data(self) -> None:
        """Test WhoisInfo with full data."""
        info = WhoisInfo(
            domain="example.com",
            registrar="Example Registrar",
            registrar_url="https://registrar.example.com",
            creation_date=datetime(2010, 1, 1),
            expiration_date=datetime(2025, 1, 1),
            updated_date=datetime(2024, 1, 1),
            status=["clientTransferProhibited"],
            nameservers=["ns1.example.com", "ns2.example.com"],
            dnssec=True,
            registrant_name="John Doe",
            registrant_org="Example Inc",
            registrant_country="US",
        )
        assert info.registrar == "Example Registrar"
        assert len(info.nameservers) == 2
        assert info.dnssec is True

    def test_days_until_expiry(self) -> None:
        """Test days_until_expiry calculation."""
        future_date = datetime.now() + timedelta(days=30)
        info = WhoisInfo(
            domain="example.com",
            expiration_date=future_date,
        )
        days = info.days_until_expiry
        assert days is not None
        assert 29 <= days <= 31  # Allow some tolerance

    def test_days_until_expiry_none(self) -> None:
        """Test days_until_expiry with no expiration."""
        info = WhoisInfo(domain="example.com")
        assert info.days_until_expiry is None

    def test_is_expired_false(self) -> None:
        """Test is_expired returns False for valid domain."""
        future_date = datetime.now() + timedelta(days=30)
        info = WhoisInfo(
            domain="example.com",
            expiration_date=future_date,
        )
        assert info.is_expired is False

    def test_is_expired_true(self) -> None:
        """Test is_expired returns True for expired domain."""
        past_date = datetime.now() - timedelta(days=30)
        info = WhoisInfo(
            domain="expired.example.com",
            expiration_date=past_date,
        )
        assert info.is_expired is True

    def test_is_expired_no_date(self) -> None:
        """Test is_expired returns False when no date."""
        info = WhoisInfo(domain="example.com")
        assert info.is_expired is False

    def test_age_days(self) -> None:
        """Test age_days calculation."""
        old_date = datetime.now() - timedelta(days=365)
        info = WhoisInfo(
            domain="example.com",
            creation_date=old_date,
        )
        age = info.age_days
        assert age is not None
        assert 364 <= age <= 366

    def test_age_days_none(self) -> None:
        """Test age_days with no creation date."""
        info = WhoisInfo(domain="example.com")
        assert info.age_days is None

    def test_normalize_date_with_timezone(self) -> None:
        """Test _normalize_date removes timezone."""
        from datetime import timezone

        info = WhoisInfo(domain="example.com")
        dt_with_tz = datetime(2024, 1, 15, tzinfo=timezone.utc)
        normalized = info._normalize_date(dt_with_tz)

        assert normalized is not None
        assert normalized.tzinfo is None

    def test_normalize_date_without_timezone(self) -> None:
        """Test _normalize_date keeps naive datetime."""
        info = WhoisInfo(domain="example.com")
        dt = datetime(2024, 1, 15)
        normalized = info._normalize_date(dt)

        assert normalized == dt

    def test_normalize_date_none(self) -> None:
        """Test _normalize_date handles None."""
        info = WhoisInfo(domain="example.com")
        assert info._normalize_date(None) is None


class TestWhoisClient:
    """Tests for WhoisClient class."""

    def test_client_creation(self) -> None:
        """Test client creation."""
        client = WhoisClient()
        assert client.name == "whois"
        assert client.is_free is True
        assert client.requires_api_key is False
        assert client.timeout == 10

    def test_client_custom_timeout(self) -> None:
        """Test client with custom timeout."""
        client = WhoisClient(timeout=30)
        assert client.timeout == 30

    def test_client_class_attributes(self) -> None:
        """Test client class attributes."""
        assert WhoisClient.name == "whois"
        assert WhoisClient.is_free is True
        assert WhoisClient.requires_api_key is False

    @patch("domainraptor.discovery.whois_client.whois.whois")
    def test_query_success(self, mock_whois: MagicMock) -> None:
        """Test successful WHOIS query."""
        mock_response = MagicMock()
        mock_response.domain_name = "example.com"
        mock_response.registrar = "Example Registrar"
        mock_response.registrar_url = "https://registrar.example.com"
        mock_response.name_servers = ["ns1.example.com", "ns2.example.com"]
        mock_response.creation_date = datetime(2010, 1, 1)
        mock_response.expiration_date = datetime(2025, 1, 1)
        mock_response.updated_date = datetime(2024, 1, 1)
        mock_response.status = ["active"]
        mock_response.dnssec = False
        mock_response.emails = None
        mock_whois.return_value = mock_response

        client = WhoisClient()
        result = client.query("example.com")

        assert result is not None
        assert result.domain == "example.com"
        assert result.registrar == "Example Registrar"
        assert result.nameservers is not None

    @patch("domainraptor.discovery.whois_client.whois.whois")
    def test_query_returns_none_on_exception(self, mock_whois: MagicMock) -> None:
        """Test WHOIS query returns None on exception."""
        mock_whois.side_effect = Exception("Domain not found")

        client = WhoisClient()
        result = client.query("nonexistent.example.com")

        assert result is None

    @patch("domainraptor.discovery.whois_client.whois.whois")
    def test_query_returns_none_on_empty(self, mock_whois: MagicMock) -> None:
        """Test WHOIS query returns None for empty response."""
        mock_whois.return_value = None

        client = WhoisClient()
        result = client.query("empty.example.com")

        assert result is None

    @patch("domainraptor.discovery.whois_client.whois.whois")
    def test_query_returns_none_on_no_domain(self, mock_whois: MagicMock) -> None:
        """Test WHOIS query returns None when domain_name is None."""
        mock_response = MagicMock()
        mock_response.domain_name = None
        mock_whois.return_value = mock_response

        client = WhoisClient()
        result = client.query("invalid.example.com")

        assert result is None

    @patch("domainraptor.discovery.whois_client.whois.whois")
    def test_query_handles_list_domain_name(self, mock_whois: MagicMock) -> None:
        """Test WHOIS query handles domain_name as list."""
        mock_response = MagicMock()
        mock_response.domain_name = ["EXAMPLE.COM", "example.com"]
        mock_response.registrar = "Test Registrar"
        mock_response.name_servers = []
        mock_response.creation_date = None
        mock_response.expiration_date = None
        mock_response.updated_date = None
        mock_response.status = None
        mock_response.dnssec = None
        mock_response.emails = None
        mock_response.registrar_url = None
        mock_whois.return_value = mock_response

        client = WhoisClient()
        result = client.query("example.com")

        assert result is not None
        assert result.domain == "example.com"

    @patch("domainraptor.discovery.whois_client.whois.whois")
    def test_query_handles_list_dates(self, mock_whois: MagicMock) -> None:
        """Test WHOIS query handles dates as lists."""
        mock_response = MagicMock()
        mock_response.domain_name = "example.com"
        mock_response.registrar = "Test"
        mock_response.name_servers = None
        # Some registries return dates as lists
        mock_response.creation_date = [datetime(2010, 1, 1), datetime(2010, 1, 2)]
        mock_response.expiration_date = [datetime(2025, 1, 1)]
        mock_response.updated_date = datetime(2024, 1, 1)
        mock_response.status = None
        mock_response.dnssec = None
        mock_response.emails = None
        mock_response.registrar_url = None
        mock_whois.return_value = mock_response

        client = WhoisClient()
        result = client.query("example.com")

        assert result is not None
        assert result.creation_date == datetime(2010, 1, 1)

    @patch("domainraptor.discovery.whois_client.whois.whois")
    def test_query_timeout(self, mock_whois: MagicMock) -> None:
        """Test WHOIS query timeout handling."""
        mock_whois.side_effect = TimeoutError("Connection timed out")

        client = WhoisClient()
        result = client.query("timeout.example.com")

        assert result is None


class TestWhoisClientHelpers:
    """Tests for WhoisClient helper methods."""

    def test_get_first_with_string(self) -> None:
        """Test _get_first with string input."""
        client = WhoisClient()
        assert client._get_first("example.com") == "example.com"

    def test_get_first_with_list(self) -> None:
        """Test _get_first with list input."""
        client = WhoisClient()
        assert client._get_first(["first", "second"]) == "first"

    def test_get_first_with_empty_list(self) -> None:
        """Test _get_first with empty list."""
        client = WhoisClient()
        assert client._get_first([]) is None

    def test_get_first_with_none(self) -> None:
        """Test _get_first with None."""
        client = WhoisClient()
        assert client._get_first(None) is None

    def test_normalize_list_with_list(self) -> None:
        """Test _normalize_list with list input."""
        client = WhoisClient()
        result = client._normalize_list(["NS1.EXAMPLE.COM", "ns2.example.com"])
        assert result == ["NS1.EXAMPLE.COM", "ns2.example.com"]

    def test_normalize_list_with_string(self) -> None:
        """Test _normalize_list with string input."""
        client = WhoisClient()
        result = client._normalize_list("NS.EXAMPLE.COM")
        assert result == ["NS.EXAMPLE.COM"]

    def test_normalize_list_with_none(self) -> None:
        """Test _normalize_list with None."""
        client = WhoisClient()
        assert client._normalize_list(None) is None

    def test_parse_date_with_datetime(self) -> None:
        """Test _parse_date with datetime."""
        client = WhoisClient()
        dt = datetime(2024, 1, 15)
        assert client._parse_date(dt) == dt

    def test_parse_date_with_list(self) -> None:
        """Test _parse_date with list of datetimes."""
        client = WhoisClient()
        dates = [datetime(2024, 1, 15), datetime(2024, 1, 16)]
        assert client._parse_date(dates) == datetime(2024, 1, 15)

    def test_parse_date_with_none(self) -> None:
        """Test _parse_date with None."""
        client = WhoisClient()
        assert client._parse_date(None) is None


class TestWhoisClientIntegration:
    """Integration tests for WhoisClient (marked as slow)."""

    @pytest.mark.slow
    @pytest.mark.integration
    def test_real_whois_lookup(self) -> None:
        """Test real WHOIS lookup."""
        client = WhoisClient()
        result = client.query("example.com")

        # example.com is a reserved domain and should have WHOIS info
        if result:
            assert result.domain  # May be normalized
