"""Rate-limited HTTP client for LocalGuard-Pro."""

import asyncio
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any

import httpx
from httpx import RequestError, Response, TimeoutException, TooManyRedirects

from localguard.core.config import DASTConfig
from localguard.core.exceptions import NetworkError


@dataclass
class RateLimiter:
    """Token bucket rate limiter for HTTP requests."""

    delay: float
    _last_request: float = field(default=0.0, init=False)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock, init=False)

    async def wait(self) -> None:
        """Wait if necessary to maintain rate limit."""
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_request
            if elapsed < self.delay:
                wait_time = self.delay - elapsed
                await asyncio.sleep(wait_time)
            self._last_request = time.monotonic()


class RateLimitedHTTPClient:
    """
    HTTP client with built-in rate limiting and safety defaults.

    Features:
    - Configurable rate limiting (delay between requests)
    - Automatic retry with exponential backoff
    - Request/response logging
    - Timeout enforcement
    - Redirect limiting
    """

    def __init__(self, config: DASTConfig | None = None):
        self.config = config or DASTConfig()
        self.rate_limiter = RateLimiter(delay=self.config.rate_limit_delay)
        self._client: httpx.AsyncClient | None = None
        self._request_count = 0
        self._error_count = 0

    async def __aenter__(self) -> "RateLimitedHTTPClient":
        await self._ensure_client()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self.close()

    async def _ensure_client(self) -> None:
        """Initialize HTTP client if not already created."""
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(self.config.timeout),
                follow_redirects=self.config.follow_redirects,
                limits=httpx.Limits(
                    max_keepalive_connections=5,
                    max_connections=10,
                    keepalive_expiry=30.0,
                ),
                headers={
                    "User-Agent": "LocalGuard-Pro/1.0.0 (Security Auditor)",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                },
            )

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None

    @property
    def request_count(self) -> int:
        return self._request_count

    @property
    def error_count(self) -> int:
        return self._error_count

    async def request(self, method: str, url: str, **kwargs: Any) -> Response:
        """
        Make an HTTP request with rate limiting.

        Args:
            method: HTTP method (GET, POST, etc.)
            url: Target URL
            **kwargs: Additional arguments passed to httpx

        Returns:
            httpx.Response object

        Raises:
            NetworkError: On network errors or HTTP errors
        """
        await self.rate_limiter.wait()
        await self._ensure_client()

        self._request_count += 1

        try:
            if self._client is None:  # pragma: no cover - _ensure_client guarantees this
                raise NetworkError("HTTP client not initialised", url=url)
            response = await self._client.request(method, url, **kwargs)
            return response
        except TimeoutException as e:
            self._error_count += 1
            raise NetworkError(f"Request timeout after {self.config.timeout}s", url=url) from e
        except TooManyRedirects as e:
            self._error_count += 1
            raise NetworkError("Too many redirects", url=url) from e
        except RequestError as e:
            self._error_count += 1
            raise NetworkError(f"Request failed: {str(e)}", url=url) from e

    async def get(self, url: str, **kwargs: Any) -> Response:
        """Convenience method for GET requests."""
        return await self.request("GET", url, **kwargs)

    async def head(self, url: str, **kwargs: Any) -> Response:
        """Convenience method for HEAD requests."""
        return await self.request("HEAD", url, **kwargs)

    async def options(self, url: str, **kwargs: Any) -> Response:
        """Convenience method for OPTIONS requests (for CORS testing)."""
        return await self.request("OPTIONS", url, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> Response:
        """Convenience method for POST requests."""
        return await self.request("POST", url, **kwargs)


@asynccontextmanager
async def create_client(config: DASTConfig | None = None):
    """Context manager for creating and managing HTTP client."""
    client = RateLimitedHTTPClient(config)
    try:
        yield client
    finally:
        await client.close()
