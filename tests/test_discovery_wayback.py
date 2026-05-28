"""Tests for the Wayback Machine CDX subdomain client."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from domainraptor.core.types import AssetType
from domainraptor.discovery.wayback_client import WaybackClient


def _mock_response(payload: list) -> MagicMock:
    r = MagicMock()
    r.json.return_value = payload
    return r


def test_query_extracts_subdomains() -> None:
    cdx_rows = [
        ["original"],
        ["http://www.example.com/index.html"],
        ["https://api.example.com/v1"],
        ["http://www.example.com/about"],  # duplicate host
        ["http://example.com/root"],  # parent, must be filtered
        ["http://other.org/foo"],  # different domain, must be filtered
        ["https://admin.example.com:8443/secret"],  # port stripped
    ]
    with patch("domainraptor.discovery.wayback_client.WaybackClient.get") as mock_get:
        mock_get.return_value = _mock_response(cdx_rows)

        client = WaybackClient()
        assets = client.query("example.com")

    values = {a.value for a in assets}
    assert values == {"www.example.com", "api.example.com", "admin.example.com"}
    for a in assets:
        assert a.type == AssetType.SUBDOMAIN
        assert a.source == "wayback"
        assert a.parent == "example.com"


def test_query_empty_payload_returns_empty() -> None:
    with patch("domainraptor.discovery.wayback_client.WaybackClient.get") as mock_get:
        mock_get.return_value = _mock_response([["original"]])  # only header

        client = WaybackClient()
        assert client.query("example.com") == []


def test_query_handles_http_failure() -> None:
    with patch("domainraptor.discovery.wayback_client.WaybackClient.get") as mock_get:
        mock_get.side_effect = RuntimeError("boom")

        client = WaybackClient()
        assert client.query("example.com") == []


def test_extract_host_handles_bare_hosts() -> None:
    client = WaybackClient()
    assert client._extract_host("www.example.com/foo") == "www.example.com"
    assert client._extract_host("https://user@www.example.com:80/x") == "www.example.com"
    assert client._extract_host("") is None
