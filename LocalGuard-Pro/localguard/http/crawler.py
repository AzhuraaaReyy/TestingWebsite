"""Simple BFS crawler for LocalGuard-Pro."""

import logging
from collections import deque
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from urllib.parse import urldefrag, urljoin, urlparse

from bs4 import BeautifulSoup

from localguard.core.config import DASTConfig
from localguard.core.exceptions import NetworkError
from localguard.http.client import RateLimitedHTTPClient

logger = logging.getLogger(__name__)


@dataclass
class CrawlResult:
    """Result of a crawl operation."""

    urls: list[str] = field(default_factory=list)
    forms: list[dict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    visited_count: int = 0


class BFSCrawler:
    """
    Breadth-First Search crawler for discovering endpoints and forms.

    Features:
    - Same-origin only (configurable)
    - Configurable max depth
    - Form extraction
    - Respects rate limiting via RateLimitedHTTPClient
    """

    def __init__(
        self,
        client: RateLimitedHTTPClient,
        config: DASTConfig | None = None,
        same_origin_only: bool = True,
    ):
        self.client = client
        self.config = config or DASTConfig()
        self.same_origin_only = same_origin_only
        self._visited: set[str] = set()
        self._queue: deque = deque()
        self._base_url: str = ""
        self._base_domain: str = ""

    def _normalize_url(self, url: str) -> str:
        """Normalize URL by removing fragment and trailing slash."""
        url, _ = urldefrag(url)
        if url.endswith("/") and url != self._base_url:
            url = url.rstrip("/")
        return url

    def _is_same_origin(self, url: str) -> bool:
        """Check if URL is same origin as base."""
        try:
            parsed = urlparse(url)
            base_parsed = urlparse(self._base_url)
            return parsed.netloc == base_parsed.netloc
        except Exception:
            return False

    def _extract_links(self, html: str, base_url: str) -> list[str]:
        """Extract all links from HTML."""
        links = []
        try:
            soup = BeautifulSoup(html, "lxml")
            for a_tag in soup.find_all("a", href=True):
                href = str(a_tag.get("href", ""))
                absolute_url = urljoin(base_url, href)
                normalized = self._normalize_url(absolute_url)
                links.append(normalized)
        except Exception as e:
            logger.debug("Failed to extract links from %s: %s", base_url, e)
        return links

    def _extract_forms(self, html: str, base_url: str) -> list[dict]:
        """Extract all forms from HTML with their details."""
        forms = []
        try:
            soup = BeautifulSoup(html, "lxml")
            for form in soup.find_all("form"):
                action = str(form.get("action", ""))
                method = str(form.get("method", "GET")).upper()
                form_url = urljoin(base_url, action) if action else base_url

                inputs: list[dict] = []
                for input_tag in form.find_all(["input", "textarea", "select"]):
                    input_info = {
                        "name": str(input_tag.get("name", "")),
                        "type": str(input_tag.get("type", "text")),
                        "value": str(input_tag.get("value", "")),
                        "required": input_tag.has_attr("required"),
                    }
                    inputs.append(input_info)

                # Check for CSRF tokens
                has_csrf = any(
                    "csrf" in inp["name"].lower() or "token" in inp["name"].lower()
                    for inp in inputs
                )

                forms.append(
                    {
                        "url": self._normalize_url(form_url),
                        "method": method,
                        "inputs": inputs,
                        "has_csrf_token": has_csrf,
                        "action": action,
                    }
                )
        except Exception as e:
            logger.debug("Failed to extract forms from %s: %s", base_url, e)
        return forms

    async def crawl(
        self, start_url: str, progress_callback: Callable[[str], Awaitable[None]] | None = None
    ) -> CrawlResult:
        """
        Start crawling from the given URL.

        Args:
            start_url: Starting URL
            progress_callback: Optional async callback for progress updates

        Returns:
            CrawlResult with discovered URLs and forms
        """
        self._visited.clear()
        self._queue.clear()

        parsed = urlparse(start_url)
        self._base_url = f"{parsed.scheme}://{parsed.netloc}"
        self._base_domain = parsed.netloc

        self._queue.append((start_url, 0))
        result = CrawlResult()

        while self._queue:
            current_url, depth = self._queue.popleft()
            normalized = self._normalize_url(current_url)

            if normalized in self._visited:
                continue

            if depth > self.config.max_depth:
                continue

            if self.same_origin_only and not self._is_same_origin(normalized):
                continue

            self._visited.add(normalized)
            result.visited_count += 1
            result.urls.append(normalized)

            if progress_callback:
                await progress_callback(normalized)

            try:
                response = await self.client.get(normalized)
                if response.status_code == 200:
                    html = response.text
                    # Extract links for further crawling
                    if depth < self.config.max_depth:
                        links = self._extract_links(html, normalized)
                        for link in links:
                            if link not in self._visited:
                                self._queue.append((link, depth + 1))

                    # Extract forms
                    forms = self._extract_forms(html, normalized)
                    result.forms.extend(forms)

            except NetworkError as e:
                result.errors.append(f"{normalized}: {str(e)}")
            except Exception as e:
                result.errors.append(f"{normalized}: {type(e).__name__}: {str(e)}")

        return result

    def get_visited_urls(self) -> list[str]:
        """Get list of visited URLs."""
        return list(self._visited)
