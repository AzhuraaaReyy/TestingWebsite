"""Sensitive Path Scanner for LocalGuard-Pro."""

import asyncio
import logging
import time
from pathlib import Path

from localguard.auditors.base import AuditorResult, DASTAuditor
from localguard.core.config import DASTConfig
from localguard.core.constants import Category, Severity
from localguard.core.models import Finding, Target
from localguard.http.client import RateLimitedHTTPClient
from localguard.utils.filesystem import read_file_safely

logger = logging.getLogger(__name__)


class SensitivePathScanner(DASTAuditor):
    """Scanner for sensitive files and endpoints using wordlist-based approach."""

    def __init__(self):
        super().__init__("SensitivePaths")
        self._wordlist: list[str] = []

    def _load_wordlists(self, config: DASTConfig) -> list[str]:
        """Load built-in and custom wordlists."""
        wordlist = []

        # Built-in wordlists
        base_dir = Path(__file__).parent.parent.parent.parent / "wordlists"

        for wordlist_file in ["sensitive_paths.txt", "laravel_paths.txt", "react_paths.txt"]:
            path = base_dir / wordlist_file
            if path.exists():
                content = read_file_safely(path)
                if content:
                    for line in content.splitlines():
                        line = line.strip()
                        if line and not line.startswith("#"):
                            wordlist.append(line)

        # Custom wordlist from config
        if config.custom_wordlist:
            custom_path = Path(config.custom_wordlist)
            if custom_path.exists():
                content = read_file_safely(custom_path)
                if content:
                    for line in content.splitlines():
                        line = line.strip()
                        if line and not line.startswith("#"):
                            wordlist.append(line)

        # Deduplicate while preserving order
        seen = set()
        unique = []
        for item in wordlist:
            if item not in seen:
                seen.add(item)
                unique.append(item)
        return unique

    async def audit(self, target: Target, config: DASTConfig) -> AuditorResult:
        start_time = time.time()
        findings: list[Finding] = []
        errors: list[str] = []

        # Load wordlists
        self._wordlist = self._load_wordlists(config)
        if not self._wordlist:
            errors.append("No wordlists loaded for sensitive path scanning")
            return AuditorResult(
                auditor_name=self.name,
                findings=findings,
                errors=errors,
                duration_seconds=time.time() - start_time,
            )

        async with RateLimitedHTTPClient(config) as client:
            try:
                # Test base URL first
                base_response = await client.get(target.base_url)
                if base_response.status_code == 404:
                    errors.append(f"Base URL {target.base_url} returns 404")
                    return AuditorResult(
                        auditor_name=self.name,
                        findings=findings,
                        errors=errors,
                        duration_seconds=time.time() - start_time,
                    )

                # Scan paths concurrently with semaphore
                semaphore = asyncio.Semaphore(10)  # Limit concurrent requests
                tasks = [
                    self._check_path(client, target, path, semaphore) for path in self._wordlist
                ]
                results = await asyncio.gather(*tasks, return_exceptions=True)

                for result in results:
                    if isinstance(result, Finding):
                        findings.append(result)
                    elif isinstance(result, Exception):
                        errors.append(str(result))
                    elif isinstance(result, list):
                        findings.extend(result)

            except Exception as e:
                errors.append(f"SensitivePathScanner: {str(e)}")

        return AuditorResult(
            auditor_name=self.name,
            findings=findings,
            errors=errors,
            duration_seconds=time.time() - start_time,
        )

    async def _check_path(
        self,
        client: RateLimitedHTTPClient,
        target: Target,
        path: str,
        semaphore: asyncio.Semaphore,
    ) -> Finding | None:
        """Check a single path for exposure."""
        async with semaphore:
            # Normalize path
            path = path.lstrip("/")
            url = f"{target.base_url}/{path}"

            try:
                response = await client.get(url)

                # Check if path is accessible (2xx or 3xx)
                if response.status_code < 400:
                    return self._analyze_response(target, path, response)
                if response.status_code == 403:
                    # 403 might indicate file exists but forbidden
                    return self._create_finding(
                        finding_id="LG-DAST-PATH-003",
                        severity=Severity.INFO,
                        title=f"Forbidden Access (403): /{path}",
                        endpoint=url,
                        evidence="Path returns 403 Forbidden, file may exist",
                        impact="Confirms existence of sensitive path",
                        remediation="Ensure proper access controls; consider 404 instead of 403",
                        cwe="CWE-200",
                        owasp="A05:2021 - Security Misconfiguration",
                    )
            except Exception as e:
                logger.debug("Sensitive path check failed for %s: %s", url, e)
        return None

    def _analyze_response(self, target: Target, path: str, response) -> Finding:
        """Analyze response to determine severity and type of exposure."""
        url = f"{target.base_url}/{path}"
        content_type = response.headers.get("content-type", "").lower()
        content_length = len(response.content)
        status = response.status_code

        # Determine finding type based on path patterns
        path_lower = path.lower()

        # Critical: Environment files
        if any(p in path_lower for p in [".env", ".env.", "config.json", "settings.json"]):
            return self._create_finding(
                finding_id="LG-DAST-PATH-001",
                severity=Severity.CRITICAL,
                title=f"Exposed Environment/Config File: /{path}",
                endpoint=url,
                evidence=f"Status: {status}, Content-Type: {content_type}, Size: {content_length} bytes",
                impact="Full exposure of secrets, database credentials, API keys",
                remediation=f"Remove /{path} from web root; restrict access via web server config",
                cwe="CWE-522",
                owasp="A05:2021 - Security Misconfiguration",
            )

        # Critical: Git/VCS directories
        if ".git" in path_lower or ".svn" in path_lower or ".hg" in path_lower:
            return self._create_finding(
                finding_id="LG-DAST-PATH-002",
                severity=Severity.CRITICAL,
                title=f"Exposed Version Control Directory: /{path}",
                endpoint=url,
                evidence=f"Status: {status}, Content-Type: {content_type}, Size: {content_length} bytes",
                impact="Source code disclosure, history exposure, potential secret leakage",
                remediation=f"Block access to /{path} via web server config; remove from web root",
                cwe="CWE-522",
                owasp="A05:2021 - Security Misconfiguration",
            )

        # High: Backup files
        if any(
            ext in path_lower for ext in [".bak", ".backup", ".old", ".orig", ".save", "~", ".swp"]
        ):
            return self._create_finding(
                finding_id="LG-DAST-PATH-004",
                severity=Severity.HIGH,
                title=f"Exposed Backup File: /{path}",
                endpoint=url,
                evidence=f"Status: {status}, Content-Type: {content_type}, Size: {content_length} bytes",
                impact="May contain source code, credentials, or sensitive data",
                remediation=f"Remove /{path} from web root",
                cwe="CWE-522",
                owasp="A05:2021 - Security Misconfiguration",
            )

        # High: Database dumps
        if any(
            ext in path_lower for ext in [".sql", ".dump", "backup.sql", "database.sql", "db.sql"]
        ):
            return self._create_finding(
                finding_id="LG-DAST-PATH-005",
                severity=Severity.HIGH,
                title=f"Exposed Database Dump: /{path}",
                endpoint=url,
                evidence=f"Status: {status}, Content-Type: {content_type}, Size: {content_length} bytes",
                impact="Full database exposure including user data",
                remediation=f"Remove /{path} from web root immediately",
                cwe="CWE-522",
                owasp="A05:2021 - Security Misconfiguration",
            )

        # High: Debug/Info endpoints
        if any(
            p in path_lower
            for p in [
                "phpinfo",
                "info.php",
                "server-status",
                "server-info",
                "status.php",
                "health.php",
                "healthz",
            ]
        ):
            return self._create_finding(
                finding_id="LG-DAST-PATH-006",
                severity=Severity.HIGH,
                title=f"Exposed Debug/Info Endpoint: /{path}",
                endpoint=url,
                evidence=f"Status: {status}, Content-Type: {content_type}, Size: {content_length} bytes",
                impact="Server configuration, PHP version, module info exposed",
                remediation=f"Remove /{path} or restrict to internal access only",
                cwe="CWE-200",
                owasp="A05:2021 - Security Misconfiguration",
            )

        # High: Laravel storage/logs
        if "storage/logs" in path_lower or "storage/framework" in path_lower:
            return self._create_finding(
                finding_id="LG-DAST-PATH-007",
                severity=Severity.HIGH,
                title=f"Exposed Laravel Storage: /{path}",
                endpoint=url,
                evidence=f"Status: {status}, Content-Type: {content_type}, Size: {content_length} bytes",
                impact="Application logs, cache, sessions exposed; may contain sensitive data",
                remediation=f"Block /{path} via web server; ensure storage/ is not in web root",
                cwe="CWE-522",
                owasp="A05:2021 - Security Misconfiguration",
            )

        # High: Docker/CI configs
        if any(
            p in path_lower
            for p in [
                "docker-compose",
                "dockerfile",
                ".github/workflows",
                ".gitlab-ci",
                "jenkinsfile",
            ]
        ):
            return self._create_finding(
                finding_id="LG-DAST-PATH-008",
                severity=Severity.HIGH,
                title=f"Exposed CI/CD or Docker Config: /{path}",
                endpoint=url,
                evidence=f"Status: {status}, Content-Type: {content_type}, Size: {content_length} bytes",
                impact="Infrastructure details, secrets, deployment config exposed",
                remediation=f"Remove /{path} from web root",
                cwe="CWE-522",
                owasp="A05:2021 - Security Misconfiguration",
            )

        # Medium: Admin panels
        if any(
            p in path_lower
            for p in ["/admin", "/administrator", "/wp-admin", "/manager", "/console", "/panel"]
        ):
            return self._create_finding(
                finding_id="LG-DAST-PATH-009",
                severity=Severity.MEDIUM,
                title=f"Exposed Admin Panel: /{path}",
                endpoint=url,
                evidence=f"Status: {status}, Content-Type: {content_type}, Size: {content_length} bytes",
                impact="Admin interface accessible; brute-force or bypass risk",
                remediation=f"Restrict /{path} to authorized IPs; add MFA",
                cwe="CWE-200",
                owasp="A01:2021 - Broken Access Control",
            )

        # Medium: API documentation
        if any(p in path_lower for p in ["swagger", "api-docs", "redoc", "openapi"]):
            return self._create_finding(
                finding_id="LG-DAST-PATH-010",
                severity=Severity.MEDIUM,
                title=f"Exposed API Documentation: /{path}",
                endpoint=url,
                evidence=f"Status: {status}, Content-Type: {content_type}, Size: {content_length} bytes",
                impact="API structure exposed; aids reconnaissance",
                remediation=f"Restrict /{path} to authenticated users or internal network",
                cwe="CWE-200",
                owasp="A05:2021 - Security Misconfiguration",
            )

        # Medium: React Source Maps
        if path_lower.endswith(".map") or ".js.map" in path_lower:
            return self._create_finding(
                finding_id="LG-DAST-PATH-011",
                severity=Severity.MEDIUM,
                title=f"Exposed React/JS Source Map: /{path}",
                endpoint=url,
                evidence=f"Status: {status}, Content-Type: {content_type}, Size: {content_length} bytes",
                impact="Original TypeScript/JS source code exposed; aids reverse engineering",
                remediation="Disable source map generation in production builds; remove .map files",
                cwe="CWE-200",
                owasp="A05:2021 - Security Misconfiguration",
            )

        # Low/Info: Generic accessible file
        severity = Severity.LOW
        if status == 200:
            severity = Severity.MEDIUM

        return self._create_finding(
            finding_id="LG-DAST-PATH-012",
            severity=severity,
            title=f"Accessible Sensitive Path: /{path}",
            endpoint=url,
            evidence=f"Status: {status}, Content-Type: {content_type}, Size: {content_length} bytes",
            impact="File accessible that should be restricted",
            remediation=f"Review /{path} and restrict access if not intended for public",
            cwe="CWE-200",
            owasp="A05:2021 - Security Misconfiguration",
        )

    def _create_finding(  # type: ignore[override]  # noqa
        self,
        finding_id: str,
        severity: Severity,
        title: str,
        endpoint: str,
        parameter: str | None = None,
        evidence: str = "",
        impact: str = "",
        remediation: str = "",
        cwe: str | None = None,
        owasp: str | None = None,
    ) -> Finding:
        return Finding(
            id=finding_id,
            severity=severity,
            category=Category.DAST,
            title=title,
            endpoint=endpoint,
            parameter=parameter,
            evidence=evidence,
            impact=impact,
            remediation=remediation,
            cwe=cwe,
            owasp=owasp,
        )
