"""Unit tests for HostValidationEngine."""

import pytest

from localguard.core.config import TargetConfig
from localguard.core.exceptions import ValidationError
from localguard.validation.host_validator import HostValidationEngine


class TestHostValidationEngine:
    """Tests for HostValidationEngine."""

    def setup_method(self):
        """Set up test configuration."""
        self.config = TargetConfig()
        self.engine = HostValidationEngine(self.config)

    # Allowed hosts tests
    def test_localhost_allowed(self):
        """Test localhost is allowed."""
        self.engine.validate("http://localhost:8000")
        self.engine.validate("https://localhost:8000")

    def test_127_0_0_1_allowed(self):
        """Test 127.0.0.1 is allowed."""
        self.engine.validate("http://127.0.0.1:8000")

    def test_0_0_0_0_allowed(self):
        """Test 0.0.0.0 is allowed."""
        self.engine.validate("http://0.0.0.0:8000")

    def test_local_tld_allowed(self):
        """Test .local TLD is allowed."""
        self.engine.validate("http://myapp.local:8000")
        self.engine.validate("http://sub.domain.local:8000")

    def test_test_tld_allowed(self):
        """Test .test TLD is allowed."""
        self.engine.validate("http://myapp.test:8000")

    # Private IP ranges tests
    def test_10_x_x_x_allowed(self):
        """Test 10.x.x.x range is allowed."""
        self.engine.validate("http://10.0.0.1:8000")
        self.engine.validate("http://10.255.255.255:8000")

    def test_172_16_31_x_x_allowed(self):
        """Test 172.16-31.x.x range is allowed."""
        self.engine.validate("http://172.16.0.1:8000")
        self.engine.validate("http://172.31.255.255:8000")

    def test_192_168_x_x_allowed(self):
        """Test 192.168.x.x range is allowed."""
        self.engine.validate("http://192.168.0.1:8000")
        self.engine.validate("http://192.168.255.255:8000")

    # Blocked hosts tests
    def test_public_ip_blocked(self):
        """Test public IP is blocked."""
        with pytest.raises(ValidationError):
            self.engine.validate("http://8.8.8.8:8000")

    def test_public_domain_blocked(self):
        """Test public domain is blocked."""
        with pytest.raises(ValidationError):
            self.engine.validate("http://google.com:8000")

    def test_github_com_blocked(self):
        """Test github.com is blocked."""
        with pytest.raises(ValidationError):
            self.engine.validate("https://github.com")

    def test_example_com_blocked(self):
        """Test example.com is blocked."""
        with pytest.raises(ValidationError):
            self.engine.validate("http://example.com")

    # Edge cases
    def test_invalid_url(self):
        """Test invalid URL raises error."""
        with pytest.raises(ValidationError):
            self.engine.validate("not-a-url")

    def test_empty_host(self):
        """Test URL with empty host."""
        with pytest.raises(ValidationError):
            self.engine.validate("http://:8000")

    def test_custom_private_ranges(self):
        """Test custom private ranges work."""
        config = TargetConfig(custom_private_ranges=["100.64.0.0/10"])
        engine = HostValidationEngine(config)
        engine.validate("http://100.64.0.1:8000")

    def test_custom_private_ranges_invalid_cidr(self):
        """Test invalid CIDR is ignored."""
        config = TargetConfig(custom_private_ranges=["invalid"])
        engine = HostValidationEngine(config)
        # Should not crash, just ignore invalid CIDR
        assert len(engine._private_networks) == 3  # Default RFC 1918 ranges

    def test_port_stripping(self):
        """Test port is stripped from host validation."""
        # These should all be allowed (port doesn't matter)
        self.engine.validate("http://localhost:80")
        self.engine.validate("http://localhost:8000")
        self.engine.validate("http://localhost:443")
        self.engine.validate("http://localhost:8080")


class TestValidateTargetUrl:
    """Tests for validate_target_url convenience function."""

    def test_validate_target_url_allowed(self):
        """Test validate_target_url with allowed host."""
        from localguard.validation.host_validator import validate_target_url

        validate_target_url("http://localhost:8000")

    def test_validate_target_url_blocked(self):
        """Test validate_target_url with blocked host."""
        from localguard.validation.host_validator import validate_target_url

        with pytest.raises(ValidationError):
            validate_target_url("http://google.com")
