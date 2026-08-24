"""Core constants for LocalGuard-Pro."""

from enum import Enum
from typing import Final


# Severity Levels
class Severity(str, Enum):
    """Finding severity levels."""

    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


class Category(str, Enum):
    """Audit categories."""

    DAST = "DAST"
    SAST = "SAST"
    SCA = "SCA"


# Exit Codes
class ExitCode(int, Enum):
    """Standardized exit codes for CI/CD integration."""

    CLEAN = 0
    VULNERABILITIES_FOUND = 1
    RUNTIME_ERROR = 2
    BLOCKED = 3


# Default Configuration Values
DEFAULT_RATE_LIMIT_DELAY: Final[float] = 0.4
DEFAULT_TIMEOUT: Final[int] = 10
DEFAULT_MAX_DEPTH: Final[int] = 2
DEFAULT_MAX_REDIRECTS: Final[int] = 5
DEFAULT_ENTROPY_THRESHOLD: Final[float] = 4.5
DEFAULT_CACHE_TTL_HOURS: Final[int] = 24

# Allowed Host Patterns (Strict Local-Only)
ALLOWED_HOST_PATTERNS: Final[list[str]] = [
    "localhost",
    "127.0.0.1",
    "0.0.0.0",  # nosec: B104 - this is an allowlist entry for host validation, not a socket bind address
    "*.local",
    "*.test",
]

# Private IP Ranges (RFC 1918)
PRIVATE_IP_RANGES: Final[list[str]] = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
]

# Security Headers to Check
SECURITY_HEADERS: Final[list[str]] = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]

# Cookie Flags to Check
COOKIE_FLAGS: Final[list[str]] = [
    "HttpOnly",
    "Secure",
    "SameSite",
]

# Version Disclosure Headers
VERSION_DISCLOSURE_HEADERS: Final[list[str]] = [
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
    "X-Runtime",
    "X-Version",
]

# Default Exclude Patterns for SAST
DEFAULT_SAST_EXCLUDE_PATTERNS: Final[list[str]] = [
    "**/node_modules/**",
    "**/vendor/**",
    "**/.git/**",
    "**/dist/**",
    "**/build/**",
    "**/venv/**",
    "**/__pycache__/**",
    "**/.pytest_cache/**",
    "**/.mypy_cache/**",
    "**/.ruff_cache/**",
]

# Default Ecosystems for SCA
DEFAULT_SCA_ECOSYSTEMS: Final[list[str]] = ["composer", "npm"]

# Report Formats
REPORT_FORMATS: Final[list[str]] = ["json", "html", "terminal"]

# HTML Themes
HTML_THEMES: Final[list[str]] = ["light", "dark", "auto"]

# Legal Warning Message
LEGAL_WARNING: Final[str] = """
================================================================================
⚠️  LEGAL WARNING / PERINGATAN HUKUM ⚠️
================================================================================
LocalGuard-Pro adalah tool keamanan INTERNAL untuk mengaudit aplikasi MILIK SENDIRI.
Penggunaan tool ini terhadap target yang BUKAN milik Anda atau tanpa izin tertulis
adalah PELANGGARAN HUKUM dan melanggar etika keamanan siber.

DILARANG KERAS:
- Mengarahkan scan ke domain publik (google.com, website-orang-lain.com, dll)
- Menggunakan tool ini untuk aktivitas ilegal atau unauthorized access
- Menyebarkan hasil scan tanpa izin pemilik sistem

Dengan mengetik 'Y', Anda menyatakan:
1. Target aplikasi adalah MILIK ANDA / di bawah WEWENANG ANDA
2. Anda memiliki IZIN tertulis untuk melakukan pengujian keamanan
3. Anda bertanggung jawab penuh atas penggunaan tool ini

PELANGGARAN akan dihentikan paksa (Exit Code 3) dan dicatat.
================================================================================
"""

# Consent Prompt
CONSENT_PROMPT: Final[str] = (
    "Apakah Anda memiliki hak milik/izin penuh atas target ini? Ketik 'Y' untuk melanjutkan: "
)
