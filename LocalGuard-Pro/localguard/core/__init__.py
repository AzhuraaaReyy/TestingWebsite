"""Core module for LocalGuard-Pro."""

from localguard.core.config import (
    Config,
    DASTConfig,
    IgnoreConfig,
    ReportConfig,
    SASTConfig,
    SCAConfig,
    ScanConfig,
    TargetConfig,
)
from localguard.core.constants import (
    CONSENT_PROMPT,
    COOKIE_FLAGS,
    LEGAL_WARNING,
    SECURITY_HEADERS,
    VERSION_DISCLOSURE_HEADERS,
    Category,
    ExitCode,
    Severity,
)
from localguard.core.exceptions import (
    ConfigurationError,
    ConsentError,
    LocalGuardError,
    NetworkError,
    ReportGenerationError,
    ScanError,
    ValidationError,
)
from localguard.core.models import Finding, FindingStatus, ScanResult, Target

__all__ = [
    "Config",
    "ScanConfig",
    "TargetConfig",
    "DASTConfig",
    "SASTConfig",
    "SCAConfig",
    "ReportConfig",
    "IgnoreConfig",
    "Finding",
    "Target",
    "ScanResult",
    "FindingStatus",
    "LocalGuardError",
    "ValidationError",
    "ConfigurationError",
    "ConsentError",
    "ScanError",
    "NetworkError",
    "ReportGenerationError",
    "Severity",
    "Category",
    "ExitCode",
    "SECURITY_HEADERS",
    "COOKIE_FLAGS",
    "VERSION_DISCLOSURE_HEADERS",
    "LEGAL_WARNING",
    "CONSENT_PROMPT",
]
