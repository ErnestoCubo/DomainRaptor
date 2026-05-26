"""Base client class for all data source clients."""

from __future__ import annotations

import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Generic, TypeVar

import httpx

from domainraptor.core.types import Asset

logger = logging.getLogger(__name__)

T = TypeVar("T")


@dataclass
class RateLimiter:
    """Simple rate limiter for API calls."""

    requests_per_second: float = 1.0
    _last_request: float = field(default=0.0, repr=False)

    def wait(self) -> None:
        """Wait if necessary to respect rate limit."""
        if self.requests_per_second <= 0:
            return

        min_interval = 1.0 / self.requests_per_second
        elapsed = time.time() - self._last_request

        if elapsed < min_interval:
            sleep_time = min_interval - elapsed
            logger.debug(f"Rate limiting: sleeping {sleep_time:.2f}s")
            time.sleep(sleep_time)

        self._last_request = time.time()


@dataclass
class ClientConfig:
    """Configuration for a data source client."""

    timeout: int = 30
    retries: int = 3
    rate_limit: float = 1.0  # requests per second
    api_key: str | None = None
    base_url: str = ""
    headers: dict[str, str] = field(default_factory=dict)


class BaseClient(ABC, Generic[T]):
    """Abstract base class for all data source clients."""

    name: str = "base"
    is_free: bool = True
    requires_api_key: bool = False

    def __init__(self, config: ClientConfig | None = None) -> None:
        self.config = config or ClientConfig()
        self.rate_limiter = RateLimiter(self.config.rate_limit)
        self._client: httpx.Client | None = None

    @property
    def client(self) -> httpx.Client:
        """Lazy-initialized HTTP client."""
        if self._client is None:
            self._client = httpx.Client(
                timeout=self.config.timeout,
                headers=self.config.headers,
                follow_redirects=True,
            )
        return self._client

    def close(self) -> None:
        """Close the HTTP client."""
        if self._client is not None:
            self._client.close()
            self._client = None

    def __enter__(self) -> BaseClient[T]:
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

    def _single_request_attempt(
        self, method: str, url: str, **kwargs: Any
    ) -> tuple[httpx.Response | None, Exception | None, bool]:
        """Make a single HTTP request attempt.

        Returns:
            Tuple of (response, error, should_retry).
        """
        try:
            response = self.client.request(method, url, **kwargs)
            response.raise_for_status()
            return response, None, False
        except httpx.HTTPStatusError as e:
            if e.response.status_code in (429, 503) or e.response.status_code >= 500:
                return None, e, True
            return None, e, False
        except httpx.RequestError as e:
            return None, e, True

    def _request(
        self,
        method: str,
        url: str,
        **kwargs: Any,
    ) -> httpx.Response:
        """Make an HTTP request with rate limiting and retries."""
        self.rate_limiter.wait()

        last_error: Exception | None = None
        for attempt in range(self.config.retries):
            response, error, should_retry = self._single_request_attempt(method, url, **kwargs)

            if response is not None:
                return response

            last_error = error
            if not should_retry:
                if error is not None:
                    raise error
                break

            # Log and wait before retry
            if isinstance(error, httpx.HTTPStatusError):
                if error.response.status_code in (429, 503):
                    wait_time = 2**attempt
                    logger.warning(f"{self.name}: Rate limited, waiting {wait_time}s")
                    time.sleep(wait_time)
                else:
                    logger.warning(
                        f"{self.name}: Server error {error.response.status_code}, retrying"
                    )
                    time.sleep(1)
            else:
                logger.warning(f"{self.name}: Request error on attempt {attempt + 1}: {error}")
                time.sleep(1)

        msg = f"{self.name}: Request failed after {self.config.retries} attempts"
        raise last_error or Exception(msg)

    def get(self, url: str, **kwargs: Any) -> httpx.Response:
        """Make a GET request."""
        return self._request("GET", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> httpx.Response:
        """Make a POST request."""
        return self._request("POST", url, **kwargs)

    @abstractmethod
    def query(self, target: str) -> list[T]:
        """Query the data source for information about the target."""
        ...

    def query_safe(self, target: str) -> list[T]:
        """Query with error handling, returns empty list on failure."""
        try:
            return self.query(target)
        except Exception as e:
            logger.error(f"{self.name}: Query failed for {target}: {e}")
            return []


class SubdomainClient(BaseClient[Asset]):
    """Base class for subdomain discovery clients."""

    @abstractmethod
    def query(self, target: str) -> list[Asset]:
        """Query for subdomains of the target domain."""
        ...
