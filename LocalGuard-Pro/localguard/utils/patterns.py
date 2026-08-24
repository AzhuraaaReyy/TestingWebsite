"""Regex patterns for secret detection and vulnerability identification."""

import re
from dataclasses import dataclass
from re import Pattern


@dataclass(frozen=True)
class SecretPattern:
    """Represents a secret detection pattern."""

    name: str
    regex: Pattern
    severity: str  # Critical, High, Medium, Low
    description: str
    examples: "list[str] | None" = None


# Secret Detection Patterns
SECRET_PATTERNS: list[SecretPattern] = [
    # AWS
    SecretPattern(
        name="AWS Access Key ID",
        regex=re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        severity="Critical",
        description="AWS Access Key ID",
        examples=["AKIAIOSFODNN7EXAMPLE"],
    ),
    SecretPattern(
        name="AWS Secret Access Key",
        regex=re.compile(r"\b[0-9a-zA-Z/+]{40}\b"),
        severity="Critical",
        description="AWS Secret Access Key",
        examples=["wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"],
    ),
    # Generic API Keys
    SecretPattern(
        name="Generic API Key (32+ chars)",
        regex=re.compile(r"\b[a-zA-Z0-9_\-]{32,}\b"),
        severity="High",
        description="Generic high-entropy API key",
    ),
    SecretPattern(
        name="Generic Secret (base64-like)",
        regex=re.compile(r"\b[a-zA-Z0-9+/]{40,}={0,2}\b"),
        severity="Medium",
        description="Base64-encoded secret",
    ),
    # Private Keys
    SecretPattern(
        name="RSA Private Key",
        regex=re.compile(r"-----BEGIN RSA PRIVATE KEY-----"),
        severity="Critical",
        description="RSA Private Key",
    ),
    SecretPattern(
        name="EC Private Key",
        regex=re.compile(r"-----BEGIN EC PRIVATE KEY-----"),
        severity="Critical",
        description="EC Private Key",
    ),
    SecretPattern(
        name="OpenSSH Private Key",
        regex=re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----"),
        severity="Critical",
        description="OpenSSH Private Key",
    ),
    SecretPattern(
        name="PGP Private Key",
        regex=re.compile(r"-----BEGIN PGP PRIVATE KEY BLOCK-----"),  # nosemgrep
        severity="Critical",
        description="PGP Private Key",
    ),
    # JWT
    SecretPattern(
        name="JWT Token",
        regex=re.compile(r"\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b"),
        severity="High",
        description="JWT Token",
        examples=[
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        ],  # nosemgrep
    ),
    # Database URLs
    SecretPattern(
        name="PostgreSQL URL",
        regex=re.compile(r'postgres(?:ql)?://[^:\s]+:[^@\s]+@[^/\s]+/[^"\'\s]+'),
        severity="Critical",
        description="PostgreSQL connection string with credentials",
    ),
    SecretPattern(
        name="MySQL URL",
        regex=re.compile(r'mysql://[^:\s]+:[^@\s]+@[^/\s]+/[^"\'\s]+'),
        severity="Critical",
        description="MySQL connection string with credentials",
    ),
    SecretPattern(
        name="MongoDB URL",
        regex=re.compile(r'mongodb://[^:\s]+:[^@\s]+@[^/\s]+/[^"\'\s]+'),
        severity="Critical",
        description="MongoDB connection string with credentials",
    ),
    SecretPattern(
        name="Redis URL",
        regex=re.compile(r"redis://[^:\s]+:[^@\s]+@[^/\s]+"),
        severity="Critical",
        description="Redis connection string with credentials",
    ),
    # Laravel Specific
    SecretPattern(
        name="Laravel APP_KEY",
        regex=re.compile(r"APP_KEY\s*=\s*base64:[a-zA-Z0-9+/]+={0,2}"),
        severity="Critical",
        description="Laravel Application Key",
    ),
    SecretPattern(
        name="Laravel DB_PASSWORD",
        regex=re.compile(r"DB_PASSWORD\s*=\s*[^\s#]+"),
        severity="Critical",
        description="Laravel Database Password",
    ),
    SecretPattern(
        name="Laravel JWT_SECRET",
        regex=re.compile(r"JWT_SECRET\s*=\s*[^\s#]+"),
        severity="Critical",
        description="Laravel JWT Secret",
    ),
    SecretPattern(
        name="Laravel SANCTUM_SECRET",
        regex=re.compile(r"SANCTUM_SECRET\s*=\s*[^\s#]+"),
        severity="Critical",
        description="Laravel Sanctum Secret",
    ),
    # Supabase Specific
    SecretPattern(
        name="Supabase Service Role Key",
        regex=re.compile(
            r'(?:SUPABASE_SERVICE_ROLE_KEY|SUPABASE_SECRET_KEY)\s*=\s*["\']?eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+["\']?'
        ),
        severity="Critical",
        description="Supabase Service Role Key (Full Admin Access)",
    ),
    SecretPattern(
        name="Supabase Anon Key",
        regex=re.compile(
            r'(?:SUPABASE_ANON_KEY|NEXT_PUBLIC_SUPABASE_ANON_KEY|VITE_SUPABASE_ANON_KEY)\s*=\s*["\']?eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+["\']?'
        ),
        severity="Low",
        description="Supabase Anon Key (Public Access - Low Risk if in Frontend)",
    ),
    SecretPattern(
        name="Supabase URL",
        regex=re.compile(
            r"(?:SUPABASE_URL|NEXT_PUBLIC_SUPABASE_URL|VITE_SUPABASE_URL)\s*=\s*https://[a-z0-9-]+\.supabase\.co"
        ),
        severity="Info",
        description="Supabase Project URL",
    ),
    # Generic .env patterns
    SecretPattern(
        name="Generic Password",
        regex=re.compile(r"(?:PASSWORD|PASS|PWD|SECRET|TOKEN|KEY)\s*=\s*[^\s#]{8,}"),
        severity="High",
        description="Generic password/secret in config",
    ),
    SecretPattern(
        name="API Key Assignment",
        regex=re.compile(r"(?:API_KEY|APIKEY|API_KEY_|_API_KEY)\s*=\s*[^\s#]{16,}"),
        severity="High",
        description="API Key assignment",
    ),
    # Slack
    SecretPattern(
        name="Slack Token",
        regex=re.compile(r"xox[baprs]-[0-9a-zA-Z]{10,48}"),
        severity="High",
        description="Slack Bot/User/App Token",
    ),
    # GitHub
    SecretPattern(
        name="GitHub Token",
        regex=re.compile(r"gh[pousr]_[0-9a-zA-Z]{36,}"),
        severity="High",
        description="GitHub Personal Access Token",
    ),
    SecretPattern(
        name="GitHub OAuth Token",
        regex=re.compile(r"github_pat_[0-9a-zA-Z_]{80,}"),
        severity="High",
        description="GitHub Fine-grained PAT",
    ),
    # Stripe
    SecretPattern(
        name="Stripe Secret Key",
        regex=re.compile(r"sk_live_[0-9a-zA-Z]{24,}"),
        severity="Critical",
        description="Stripe Live Secret Key",
    ),
    SecretPattern(
        name="Stripe Test Key",
        regex=re.compile(r"sk_test_[0-9a-zA-Z]{24,}"),
        severity="Medium",
        description="Stripe Test Secret Key",
    ),
    # SendGrid
    SecretPattern(
        name="SendGrid API Key",
        regex=re.compile(r"SG\.[0-9a-zA-Z_\-]{22}\.[0-9a-zA-Z_\-]{43}"),
        severity="High",
        description="SendGrid API Key",
    ),
    # Twilio
    SecretPattern(
        name="Twilio Auth Token",
        regex=re.compile(r"SK[0-9a-f]{32}"),
        severity="High",
        description="Twilio Auth Token",
    ),
]


# Vulnerability Patterns (for passive detection)
VULN_PATTERNS = {
    "sql_error": [
        re.compile(r"SQL syntax.*MySQL", re.IGNORECASE),
        re.compile(r"Warning.*mysql_.*", re.IGNORECASE),
        re.compile(r"PostgreSQL.*ERROR", re.IGNORECASE),
        re.compile(r"ORA-\d{5}", re.IGNORECASE),
        re.compile(r"Microsoft.*ODBC.*SQL Server", re.IGNORECASE),
        re.compile(r"SQLite.*error", re.IGNORECASE),
        re.compile(r"syntax error.*near", re.IGNORECASE),
        re.compile(r"unclosed quotation mark", re.IGNORECASE),
    ],
    "xss_reflection": [
        re.compile(r"<script>.*alert\(.*\)", re.IGNORECASE),
        re.compile(r"onerror\s*=", re.IGNORECASE),
        re.compile(r"onload\s*=", re.IGNORECASE),
        re.compile(r"javascript:", re.IGNORECASE),
    ],
    "path_traversal": [
        re.compile(r"\.\./", re.IGNORECASE),
        re.compile(r"\.\.\\", re.IGNORECASE),
    ],
    "command_injection": [
        re.compile(r";\s*(?:ls|cat|id|whoami|pwd)", re.IGNORECASE),
        re.compile(r"\|\s*(?:ls|cat|id|whoami|pwd)", re.IGNORECASE),
        re.compile(r"`.*`", re.IGNORECASE),
    ],
}


# CORS Headers to check
CORS_HEADERS = [
    "Access-Control-Allow-Origin",
    "Access-Control-Allow-Methods",
    "Access-Control-Allow-Headers",
    "Access-Control-Allow-Credentials",
    "Access-Control-Expose-Headers",
    "Access-Control-Max-Age",
]


# Security Headers (from constants, duplicated here for reference)
SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]


def get_all_secret_patterns() -> list[SecretPattern]:
    """Get all secret detection patterns."""
    return SECRET_PATTERNS


def get_patterns_by_severity(severity: str) -> list[SecretPattern]:
    """Get patterns filtered by severity."""
    return [p for p in SECRET_PATTERNS if p.severity == severity]


def compile_vuln_patterns() -> dict:
    """Compile all vulnerability detection patterns."""
    return VULN_PATTERNS
