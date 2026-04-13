"""Tests for discovery base module."""

from __future__ import annotations

import time
from unittest.mock import MagicMock, patch

import httpx

from domainraptor.core.types import Asset
from domainraptor.discovery.base import (
    BaseClient,
    ClientConfig,
    RateLimiter,
    SubdomainClient,
)


class TestRateLimiter:
    """Tests for RateLimiter class."""

    def test_rate_limiter_creation(self) -> None:
        """Test rate limiter creation."""
        limiter = RateLimiter(requests_per_second=2.0)
        assert limiter.requests_per_second == 2.0

    def test_rate_limiter_wait_first_request(self) -> None:
        """Test that first request doesn't wait."""
        limiter = RateLimiter(requests_per_second=1.0)
        start = time.time()
        limiter.wait()
        elapsed = time.time() - start
        assert elapsed < 0.1  # Should be near-instant

    def test_rate_limiter_wait_respects_limit(self) -> None:
        """Test that rate limiter enforces wait time."""
        limiter = RateLimiter(requests_per_second=10.0)  # 10 req/s = 0.1s interval

        # First request
        limiter.wait()

        # Second request should wait
        start = time.time()
        limiter.wait()
        elapsed = time.time() - start

        # Should wait approximately 0.1 seconds (allowing some variance)
        assert 0.05 <= elapsed <= 0.2

    def test_rate_limiter_disabled(self) -> None:
        """Test rate limiter with 0 requests per second (disabled)."""
        limiter = RateLimiter(requests_per_second=0.0)
        start = time.time()
        limiter.wait()
        limiter.wait()
        elapsed = time.time() - start
        assert elapsed < 0.05  # Should be instant


class TestClientConfig:
    """Tests for ClientConfig dataclass."""

    def test_client_config_defaults(self) -> None:
        """Test client config defaults."""
        config = ClientConfig()
        assert config.timeout == 30
        assert config.retries == 3
        assert config.rate_limit == 1.0
        assert config.api_key is None
        assert config.base_url == ""
        assert config.headers == {}

    def test_client_config_custom(self) -> None:
        """Test client config with custom values."""
        config = ClientConfig(
            timeout=60,
            retries=5,
            rate_limit=0.5,
            api_key="test_key",  # pragma: allowlist secret
            base_url="https://api.example.com",
            headers={"Authorization": "Bearer token"},
        )
        assert config.timeout == 60
        assert config.retries == 5
        assert config.api_key == "test_key"  # pragma: allowlist secret


class ConcreteClient(BaseClient[Asset]):
    """Concrete implementation for testing."""

    name = "test_client"

    def query(self, target: str) -> list[Asset]:
        return []


class TestBaseClient:
    """Tests for BaseClient abstract class."""

    def test_client_initialization(self) -> None:
        """Test client initialization."""
        client = ConcreteClient()
        assert client.config.timeout == 30
        assert client.config.retries == 3

    def test_client_with_config(self) -> None:
        """Test client with custom config."""
        config = ClientConfig(timeout=60, rate_limit=2.0)
        client = ConcreteClient(config)
        assert client.config.timeout == 60

    def test_client_context_manager(self) -> None:
        """Test client as context manager."""
        with ConcreteClient() as client:
            assert client is not None
        # Client should be closed after context exit

    def test_client_lazy_http_client(self) -> None:
        """Test lazy initialization of HTTP client."""
        client = ConcreteClient()
        assert client._client is None  # Not initialized yet

        # Access the client property
        http_client = client.client
        assert http_client is not None
        assert client._client is not None

    def test_client_close(self) -> None:
        """Test closing the client."""
        client = ConcreteClient()
        _ = client.client  # Initialize
        assert client._client is not None

        client.close()
        assert client._client is None

    @patch("httpx.Client")
    def test_request_with_retries(self, mock_client_class: MagicMock) -> None:
        """Test HTTP request with retries on failure."""
        mock_client = MagicMock()
        mock_client_class.return_value = mock_client

        # First two calls fail, third succeeds
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_client.request.side_effect = [
            httpx.RequestError("Connection failed"),
            httpx.RequestError("Connection failed"),
            mock_response,
        ]

        client = ConcreteClient()
        response = client.get("https://example.com")

        assert response == mock_response
        assert mock_client.request.call_count == 3

    @patch("httpx.Client")
    def test_request_rate_limiting_response(self, mock_client_class: MagicMock) -> None:
        """Test handling of rate limit response (429)."""
        mock_client = MagicMock()
        mock_client_class.return_value = mock_client

        rate_limit_response = MagicMock()
        rate_limit_response.status_code = 429
        rate_limit_response.raise_for_status.side_effect = httpx.HTTPStatusError(
            "Rate limited", request=MagicMock(), response=rate_limit_response
        )

        success_response = MagicMock()
        success_response.status_code = 200

        mock_client.request.side_effect = [
            rate_limit_response,
            success_response,
        ]

        # Set low retries for faster test
        config = ClientConfig(retries=2)
        client = ConcreteClient(config)

        response = client.get("https://example.com")
        assert response == success_response

    def test_query_safe_catches_exceptions(self) -> None:
        """Test query_safe returns empty list on error."""

        class FailingClient(BaseClient[Asset]):
            name = "failing"

            def query(self, target: str) -> list[Asset]:
                raise ValueError("Test error")

        client = FailingClient()
        result = client.query_safe("example.com")
        assert result == []


class ConcreteSubdomainClient(SubdomainClient):
    """Concrete implementation for testing."""

    name = "test_subdomain"

    def query(self, target: str) -> list[Asset]:
        return []


class TestSubdomainClient:
    """Tests for SubdomainClient base class."""

    def test_subdomain_client_inheritance(self) -> None:
        """Test that SubdomainClient inherits from BaseClient."""
        client = ConcreteSubdomainClient()
        assert isinstance(client, BaseClient)

    def test_subdomain_client_query(self) -> None:
        """Test subdomain client query method."""
        client = ConcreteSubdomainClient()
        result = client.query("example.com")
        assert result == []
