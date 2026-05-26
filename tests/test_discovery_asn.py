"""Tests for the ASN / BGP discovery client."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from domainraptor.core.types import AssetType
from domainraptor.discovery.asn_client import AsnClient


def _response(payload: dict) -> MagicMock:
    r = MagicMock()
    r.json.return_value = payload
    return r


def test_parse_asn() -> None:
    assert AsnClient._parse_asn("AS15169") == 15169
    assert AsnClient._parse_asn("as15169") == 15169
    assert AsnClient._parse_asn("15169") == 15169
    assert AsnClient._parse_asn(" 15169 ") == 15169
    assert AsnClient._parse_asn("google") is None


def test_lookup_asn_uses_bgpview() -> None:
    details = {"data": {"name": "GOOGLE", "description_short": "Google LLC", "country_code": "US"}}
    prefixes = {
        "data": {
            "ipv4_prefixes": [{"prefix": "8.8.8.0/24"}, {"prefix": "8.8.4.0/24"}],
            "ipv6_prefixes": [{"prefix": "2001:4860::/32"}],
        }
    }

    with patch("domainraptor.discovery.asn_client.AsnClient.get") as mock_get:
        mock_get.side_effect = [_response(details), _response(prefixes)]

        client = AsnClient()
        info = client.lookup_asn(15169)

    assert info is not None
    assert info.name == "GOOGLE"
    assert info.country == "US"
    assert info.prefixes_v4 == ["8.8.8.0/24", "8.8.4.0/24"]
    assert info.prefixes_v6 == ["2001:4860::/32"]
    assert len(info.all_prefixes) == 3


def test_lookup_asn_falls_back_to_ripestat() -> None:
    """When BGPView fails, RIPEstat is used."""
    ripe_payload = {
        "data": {
            "prefixes": [
                {"prefix": "8.8.8.0/24"},
                {"prefix": "2001:4860::/32"},
            ]
        }
    }

    with patch("domainraptor.discovery.asn_client.AsnClient.get") as mock_get:
        # BGPView details + prefixes both raise; RIPEstat succeeds
        mock_get.side_effect = [
            RuntimeError("bgpview down"),
            _response(ripe_payload),
        ]

        client = AsnClient()
        info = client.lookup_asn(15169)

    assert info is not None
    assert info.prefixes_v4 == ["8.8.8.0/24"]
    assert info.prefixes_v6 == ["2001:4860::/32"]


def test_query_returns_asset_objects() -> None:
    details = {"data": {"name": "GOOGLE", "description_short": "Google LLC", "country_code": "US"}}
    prefixes = {
        "data": {
            "ipv4_prefixes": [{"prefix": "8.8.8.0/24"}],
            "ipv6_prefixes": [],
        }
    }
    with patch("domainraptor.discovery.asn_client.AsnClient.get") as mock_get:
        mock_get.side_effect = [_response(details), _response(prefixes)]

        client = AsnClient()
        assets = client.query("AS15169")

    assert len(assets) == 1
    asset = assets[0]
    assert asset.type == AssetType.IP
    assert asset.value == "8.8.8.0/24"
    assert asset.metadata["asn"] == 15169
    assert asset.metadata["asn_name"] == "GOOGLE"
    assert asset.metadata["is_cidr"] is True


def test_search_by_name_returns_asns() -> None:
    payload = {
        "data": {
            "asns": [
                {"asn": 15169, "name": "GOOGLE"},
                {"asn": "32934", "name": "FACEBOOK"},
                {"asn": "garbage", "name": "BAD"},
                {"name": "no asn key"},
            ]
        }
    }
    with patch("domainraptor.discovery.asn_client.AsnClient.get") as mock_get:
        mock_get.return_value = _response(payload)

        client = AsnClient()
        asns = client._search_asn_by_name("google")

    assert asns == [15169, 32934]


def test_lookup_returns_empty_on_unresolvable() -> None:
    with patch("domainraptor.discovery.asn_client.AsnClient.get") as mock_get:
        mock_get.side_effect = RuntimeError("down")

        client = AsnClient()
        # Free-form name; search fails → no results
        assert client.lookup("some company") == []
