"""LocalGuard-Pro - Internal Security Auditor CLI."""

__version__ = "1.0.0"
__author__ = "DevSecOps Architect"
__description__ = "Internal security auditor for local/staging web applications"

from localguard.core import (
    Category,
    Config,
    ConfigurationError,
    ConsentError,
    ExitCode,
    Finding,
    ScanResult,
    Severity,
    Target,
    ValidationError,
)

__all__ = [
    "Config",
    "Finding",
    "Target",
    "ScanResult",
    "Severity",
    "Category",
    "ExitCode",
    "ValidationError",
    "ConfigurationError",
    "ConsentError",
    "__version__",
]
