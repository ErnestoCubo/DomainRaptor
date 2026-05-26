"""Tests for the URLScan.io enrichment client."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from domainraptor.enrichment.urlscan_client import UrlscanClient


def _response(payload: dict) -> MagicMock:
    r = MagicMock()
    r.json.return_value = payload
    return r


SAMPLE_SEARCH = {
    "results": [
        {
            "_id": "scan-1",
            "task": {"url": "https://example.com/"},
            "page": {
                "domain": "example.com",
                "ip": "93.184.216.34",
                "country": "US",
                "server": "ECS",
                "asn": "AS15133",
                "asnname": "EDGECAST",
                "url": "https://example.com/",
            },
            "screenshot": "https://urlscan.io/s/1.png",
            "result": "https://urlscan.io/result/scan-1",
            "indexedAt": "2025-01-01T00:00:00Z",
        },
        {
            "_id": "scan-2",
            "task": {"url": "https://www.example.com/"},
            "page": {
                "domain": "www.example.com",
                "ip": "93.184.216.34",  # duplicate ip
                "country": "US",
                "server": "ECS",
                "asn": "AS15133",
                "asnname": "EDGECAST",
            },
        },
        # Non-dict result must be skipped
        "garbage",
    ]
}


def test_query_parses_hits() -> None:
    with patch("domainraptor.enrichment.urlscan_client.UrlscanClient.get") as mock_get:
        mock_get.return_value = _response(SAMPLE_SEARCH)

        client = UrlscanClient()
        results = client.query("example.com")

    assert len(results) == 2
    assert results[0].scan_id == "scan-1"
    assert results[0].ip == "93.184.216.34"
    assert results[0].asn == "AS15133"
    assert results[0].asn_name == "EDGECAST"


def test_enrich_dedupes_and_aggregates() -> None:
    with patch("domainraptor.enrichment.urlscan_client.UrlscanClient.get") as mock_get:
        mock_get.return_value = _response(SAMPLE_SEARCH)

        client = UrlscanClient()
        enrichment = client.enrich("example.com")

    assert enrichment.total_scans == 2
    assert enrichment.unique_ips == ["93.184.216.34"]
    assert enrichment.unique_asns == ["AS15133 (EDGECAST)"]
    assert enrichment.unique_servers == ["ECS"]
    assert enrichment.countries == ["US"]


def test_query_handles_http_failure() -> None:
    with patch("domainraptor.enrichment.urlscan_client.UrlscanClient.get") as mock_get:
        mock_get.side_effect = RuntimeError("boom")

        client = UrlscanClient()
        assert client.query("example.com") == []


def test_api_key_added_to_headers(monkeypatch) -> None:
    monkeypatch.delenv("URLSCAN_API_KEY", raising=False)
    client = UrlscanClient(api_key="secret-test-key")  # pragma: allowlist secret
    assert client.config.headers.get("API-Key") == "secret-test-key"  # pragma: allowlist secret


def test_no_api_key_means_no_header(monkeypatch) -> None:
    monkeypatch.delenv("URLSCAN_API_KEY", raising=False)
    client = UrlscanClient()
    assert "API-Key" not in client.config.headers
