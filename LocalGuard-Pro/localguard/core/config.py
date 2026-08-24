"""Configuration management for LocalGuard-Pro using Pydantic Settings."""

from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
    YamlConfigSettingsSource,
)

from localguard.core.constants import (
    ALLOWED_HOST_PATTERNS,
    DEFAULT_CACHE_TTL_HOURS,
    DEFAULT_ENTROPY_THRESHOLD,
    DEFAULT_MAX_DEPTH,
    DEFAULT_RATE_LIMIT_DELAY,
    DEFAULT_SAST_EXCLUDE_PATTERNS,
    DEFAULT_SCA_ECOSYSTEMS,
    DEFAULT_TIMEOUT,
    HTML_THEMES,
    PRIVATE_IP_RANGES,
    REPORT_FORMATS,
)


class TargetConfig(BaseSettings):
    """Target validation configuration."""

    model_config = SettingsConfigDict(extra="ignore")

    allowed_hosts: list[str] = Field(
        default_factory=lambda: ALLOWED_HOST_PATTERNS.copy(),
        description="List of allowed host patterns (supports wildcards)",
    )
    custom_private_ranges: list[str] = Field(
        default_factory=lambda: PRIVATE_IP_RANGES.copy(),
        description="Additional private CIDR ranges to allow",
    )


class DASTConfig(BaseSettings):
    """DAST scan configuration."""

    model_config = SettingsConfigDict(extra="ignore")

    max_depth: int = Field(
        default=DEFAULT_MAX_DEPTH, ge=1, le=10, description="Maximum crawl depth"
    )
    rate_limit_delay: float = Field(
        default=DEFAULT_RATE_LIMIT_DELAY,
        ge=0.1,
        le=5.0,
        description="Delay between requests in seconds",
    )
    timeout: int = Field(
        default=DEFAULT_TIMEOUT, ge=5, le=60, description="Request timeout in seconds"
    )
    follow_redirects: bool = Field(default=True, description="Follow HTTP redirects")
    custom_wordlist: str | None = Field(
        default=None, description="Path to custom wordlist file (merged with built-in)"
    )


class SASTConfig(BaseSettings):
    """SAST scan configuration."""

    model_config = SettingsConfigDict(extra="ignore")

    exclude_patterns: list[str] = Field(
        default_factory=lambda: DEFAULT_SAST_EXCLUDE_PATTERNS.copy(),
        description="Glob patterns to exclude from scanning",
    )
    entropy_threshold: float = Field(
        default=DEFAULT_ENTROPY_THRESHOLD,
        ge=3.0,
        le=8.0,
        description="Shannon entropy threshold for secret detection",
    )
    custom_patterns: list[str] = Field(
        default_factory=list, description="Additional regex patterns for secret detection"
    )


class SCAConfig(BaseSettings):
    """SCA scan configuration."""

    model_config = SettingsConfigDict(extra="ignore")

    online_cve: bool = Field(
        default=False, description="Enable online CVE lookup (requires internet)"
    )
    cache_ttl_hours: int = Field(
        default=DEFAULT_CACHE_TTL_HOURS, ge=1, le=168, description="CVE cache TTL in hours"
    )
    ecosystems: list[str] = Field(
        default_factory=lambda: DEFAULT_SCA_ECOSYSTEMS.copy(),
        description="Package ecosystems to scan",
    )


class ReportConfig(BaseSettings):
    """Report generation configuration."""

    model_config = SettingsConfigDict(extra="ignore")

    output_dir: str = Field(
        default="./security-reports", description="Output directory for reports"
    )
    formats: list[str] = Field(
        default_factory=lambda: REPORT_FORMATS.copy(), description="Report formats to generate"
    )
    html_theme: str = Field(default="auto", description="HTML report theme")
    title: str = Field(
        default="LocalGuard-Pro Security Audit Report", description="Custom report title"
    )
    company_name: str = Field(default="", description="Company name for branding")

    @field_validator("formats")
    @classmethod
    def validate_formats(cls, v: list[str]) -> list[str]:
        for fmt in v:
            if fmt not in REPORT_FORMATS:
                raise ValueError(f"Invalid format: {fmt}. Allowed: {REPORT_FORMATS}")
        return v

    @field_validator("html_theme")
    @classmethod
    def validate_theme(cls, v: str) -> str:
        if v not in HTML_THEMES:
            raise ValueError(f"Invalid theme: {v}. Allowed: {HTML_THEMES}")
        return v


class IgnoreConfig(BaseSettings):
    """Ignore/suppression configuration."""

    model_config = SettingsConfigDict(extra="ignore")

    paths: list[str] = Field(
        default_factory=list, description="File paths to ignore (glob patterns)"
    )
    patterns: list[str] = Field(
        default_factory=list, description="Finding patterns to ignore (regex)"
    )
    findings: list[str] = Field(
        default_factory=list, description="Specific finding IDs to suppress"
    )


class ScanConfig(BaseSettings):
    """Main scan configuration."""

    model_config = SettingsConfigDict(extra="ignore")

    target: TargetConfig = Field(default_factory=TargetConfig)
    dast: DASTConfig = Field(default_factory=DASTConfig)
    sast: SASTConfig = Field(default_factory=SASTConfig)
    sca: SCAConfig = Field(default_factory=SCAConfig)
    report: ReportConfig = Field(default_factory=ReportConfig)
    ignore: IgnoreConfig = Field(default_factory=IgnoreConfig)


class Config(BaseSettings):
    """Root configuration with file loading support."""

    model_config = SettingsConfigDict(
        extra="ignore",
        env_prefix="LOCALGUARD_",
        env_nested_delimiter="__",
    )

    scan: ScanConfig = Field(default_factory=ScanConfig)

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        """Customize settings sources to include YAML files."""
        return (
            init_settings,
            env_settings,
            dotenv_settings,
            YamlConfigSettingsSource(settings_cls, yaml_file="localguard.yaml"),
            YamlConfigSettingsSource(settings_cls, yaml_file=".localguard.yaml"),
            YamlConfigSettingsSource(
                settings_cls, yaml_file=Path.home() / ".config" / "localguard" / "localguard.yaml"
            ),
            file_secret_settings,
        )

    @classmethod
    def load_from_file(cls, config_path: str | None = None) -> "Config":
        """Load configuration from file with precedence."""
        if config_path:
            path = Path(config_path)
            if path.exists():
                return cls(_yaml_file=path)  # type: ignore[call-arg]

        # Try default locations in order
        for default_path in [
            Path("localguard.yaml"),
            Path(".localguard.yaml"),
            Path.home() / ".config" / "localguard" / "localguard.yaml",
        ]:
            if default_path.exists():
                return cls(_yaml_file=default_path)  # type: ignore[call-arg]

        # Return defaults
        return cls()

    def get_merged_wordlist(self) -> list[str]:
        """Get merged wordlist (built-in + custom)."""
        from localguard.core.constants import ALLOWED_HOST_PATTERNS

        wordlist = ALLOWED_HOST_PATTERNS.copy()
        if self.scan.dast.custom_wordlist:
            custom_path = Path(self.scan.dast.custom_wordlist)
            if custom_path.exists():
                with open(custom_path, encoding="utf-8") as f:
                    custom_words = [
                        line.strip() for line in f if line.strip() and not line.startswith("#")
                    ]
                wordlist.extend(custom_words)
        return wordlist
