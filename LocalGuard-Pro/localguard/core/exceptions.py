"""Custom exceptions for LocalGuard-Pro."""


class LocalGuardError(Exception):
    """Base exception for LocalGuard-Pro."""

    def __init__(self, message: str, exit_code: int = 2):
        super().__init__(message)
        self.message = message
        self.exit_code = exit_code


class ValidationError(LocalGuardError):
    """Raised when target validation fails."""

    def __init__(self, message: str, target: str | None = None):
        full_message = f"Validation Error: {message}"
        if target:
            full_message += f" (target: {target})"
        super().__init__(full_message, exit_code=3)


class ConfigurationError(LocalGuardError):
    """Raised when configuration is invalid."""

    def __init__(self, message: str, config_path: str | None = None):
        full_message = f"Configuration Error: {message}"
        if config_path:
            full_message += f" (config: {config_path})"
        super().__init__(full_message, exit_code=2)


class ConsentError(LocalGuardError):
    """Raised when user consent is not given."""

    def __init__(self, message: str = "User consent required but not provided"):
        super().__init__(f"Consent Error: {message}", exit_code=2)


class ScanError(LocalGuardError):
    """Raised when scan encounters an error."""

    def __init__(self, message: str, auditor: str | None = None):
        full_message = f"Scan Error: {message}"
        if auditor:
            full_message += f" (auditor: {auditor})"
        super().__init__(full_message, exit_code=2)


class NetworkError(LocalGuardError):
    """Raised when network request fails."""

    def __init__(self, message: str, url: str | None = None, status_code: int | None = None):
        full_message = f"Network Error: {message}"
        if url:
            full_message += f" (url: {url})"
        if status_code:
            full_message += f" (status: {status_code})"
        super().__init__(full_message, exit_code=2)


class ReportGenerationError(LocalGuardError):
    """Raised when report generation fails."""

    def __init__(self, message: str, format_type: str | None = None):
        full_message = f"Report Generation Error: {message}"
        if format_type:
            full_message += f" (format: {format_type})"
        super().__init__(full_message, exit_code=2)
