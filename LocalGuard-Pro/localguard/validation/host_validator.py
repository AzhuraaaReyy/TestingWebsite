"""Host Validation Engine - Strict Local-Only Execution Guard."""

import contextlib
import ipaddress
import re
from urllib.parse import urlparse

from localguard.core.config import TargetConfig
from localguard.core.exceptions import ValidationError


class HostValidationEngine:
    """
    Strict host validation engine to prevent abuse.

    Only allows:
    - localhost, 127.0.0.1, 0.0.0.0
    - Private IP ranges (RFC 1918): 10.x.x.x, 172.16-31.x.x, 192.168.x.x
    - Custom private ranges from config
    - TLDs: .local, .test
    """

    # Default private ranges (RFC 1918)
    DEFAULT_PRIVATE_NETWORKS: list[ipaddress.IPv4Network] = [
        ipaddress.IPv4Network("10.0.0.0/8"),
        ipaddress.IPv4Network("172.16.0.0/12"),
        ipaddress.IPv4Network("192.168.0.0/16"),
    ]

    def __init__(self, config: TargetConfig):
        self.config = config
        self._allowed_patterns = self._compile_patterns(config.allowed_hosts)
        # Always include RFC 1918 defaults, plus any valid custom ranges
        self._private_networks = list(self.DEFAULT_PRIVATE_NETWORKS) + self._parse_cidr_ranges(
            config.custom_private_ranges
        )

    @staticmethod
    def _compile_patterns(patterns: list[str]) -> list[re.Pattern]:
        """Compile wildcard patterns to regex."""
        compiled = []
        for pattern in patterns:
            # Escape special chars except *
            regex_pattern = re.escape(pattern).replace(r"\*", ".*")
            # Anchor to full match
            regex_pattern = f"^{regex_pattern}$"
            compiled.append(re.compile(regex_pattern, re.IGNORECASE))
        return compiled

    @staticmethod
    def _parse_cidr_ranges(cidr_strings: list[str]) -> list[ipaddress.IPv4Network]:
        """Parse CIDR strings to network objects."""
        networks: list[ipaddress.IPv4Network] = []
        for cidr in cidr_strings:
            with contextlib.suppress(ValueError, ipaddress.AddressValueError):
                networks.append(ipaddress.IPv4Network(cidr, strict=False))
        return networks

    def validate(self, url: str) -> None:
        """
        Validate target URL against allowlist.

        Raises:
            ValidationError: If target is not allowed (blocked)
        """
        parsed = urlparse(url)
        host = parsed.hostname or ""

        if not host:
            raise ValidationError("Invalid URL: no hostname found", target=url)

        # Check exact hostname matches
        if self._is_host_allowed(host):
            return

        # Check if host is an IP address in private ranges
        if self._is_private_ip(host):
            return

        # If we reach here, target is blocked
        raise ValidationError(
            f"Target '{host}' is not in allowed hosts list. "
            f"Only localhost, private IPs, and .local/.test domains are permitted.",
            target=url,
        )

    def _is_host_allowed(self, host: str) -> bool:
        """Check if host matches any allowed pattern."""
        # Remove port if present
        host_only = host.split(":")[0]
        return any(pattern.match(host_only) for pattern in self._allowed_patterns)

    def _is_private_ip(self, host: str) -> bool:
        """Check if host is a private IP address."""
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            return False

        # Check against private networks
        if any(ip in network for network in self._private_networks):
            return True

        # Also check standard private ranges
        return ip.is_private or ip.is_loopback or ip.is_unspecified

    def get_allowed_hosts_display(self) -> list[str]:
        """Get human-readable list of allowed hosts for display."""
        return self.config.allowed_hosts + self.config.custom_private_ranges


def validate_target_url(url: str, config: TargetConfig | None = None) -> None:
    """
    Convenience function to validate a target URL.

    Args:
        url: Target URL to validate
        config: Optional target configuration (uses defaults if not provided)

    Raises:
        ValidationError: If target is not allowed
    """
    if config is None:
        config = TargetConfig()
    engine = HostValidationEngine(config)
    engine.validate(url)
