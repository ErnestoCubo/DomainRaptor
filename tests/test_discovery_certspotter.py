"""Tests for the CertSpotter discovery client."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from domainraptor.core.types import AssetType
from domainraptor.discovery.base import ClientConfig
from domainraptor.discovery.certspotter import CertSpotterClient


class TestCertSpotterClient:
    """Unit tests for ``CertSpotterClient``."""

    def test_client_defaults(self) -> None:
        client = CertSpotterClient()
        assert client.name == "certspotter"
        assert client.is_free is True
        assert client.requires_api_key is False
        assert client.config.rate_limit == 1.0
        assert client.config.timeout == 30
        assert client.BASE_URL == "https://api.certspotter.com/v1"

    def test_client_with_custom_config(self) -> None:
        client = CertSpotterClient(ClientConfig(rate_limit=0.25, timeout=15))
        assert client.config.rate_limit == 0.25
        assert client.config.timeout == 15

    @patch("domainraptor.discovery.certspotter.CertSpotterClient.get")
    def test_query_extracts_and_dedups_subdomains(self, mock_get: MagicMock) -> None:
        mock_response = MagicMock()
        mock_response.json.return_value = [
            {"dns_names": ["www.example.com", "api.example.com"]},
            {"dns_names": ["www.example.com", "*.example.com"]},
            {"dns_names": ["example.com"]},
        ]
        mock_get.return_value = mock_response

        assets = CertSpotterClient().query("example.com")
        values = sorted(a.value for a in assets)

        assert values == ["api.example.com", "example.com", "www.example.com"]
        assert all(a.type == AssetType.SUBDOMAIN for a in assets)
        assert all(a.source == "certspotter" for a in assets)
        assert all(a.parent == "example.com" for a in assets)

    @patch("domainraptor.discovery.certspotter.CertSpotterClient.get")
    def test_query_filters_unrelated_domains(self, mock_get: MagicMock) -> None:
        mock_response = MagicMock()
        mock_response.json.return_value = [
            {"dns_names": ["other.com", "evil-example.com", "x.example.com"]},
        ]
        mock_get.return_value = mock_response

        assets = CertSpotterClient().query("example.com")
        assert [a.value for a in assets] == ["x.example.com"]

    @patch("domainraptor.discovery.certspotter.CertSpotterClient.get")
    def test_query_returns_empty_on_no_data(self, mock_get: MagicMock) -> None:
        mock_response = MagicMock()
        mock_response.json.return_value = []
        mock_get.return_value = mock_response

        assert CertSpotterClient().query("example.com") == []

    @patch("domainraptor.discovery.certspotter.CertSpotterClient.get")
    def test_query_swallows_request_errors(self, mock_get: MagicMock) -> None:
        mock_get.side_effect = RuntimeError("upstream 503")
        # Must not raise — discovery clients return [] on failure so other
        # sources still contribute results.
        assert CertSpotterClient().query("example.com") == []
