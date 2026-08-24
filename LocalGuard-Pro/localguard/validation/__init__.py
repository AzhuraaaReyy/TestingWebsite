"""Validation module for LocalGuard-Pro."""

from localguard.validation.consent import ConsentManager, get_consent
from localguard.validation.host_validator import HostValidationEngine, validate_target_url

__all__ = [
    "HostValidationEngine",
    "validate_target_url",
    "ConsentManager",
    "get_consent",
]
