"""CORS Security Auditor for LocalGuard-Pro."""

import logging
import time

from localguard.auditors.base import AuditorResult, DASTAuditor
from localguard.core.config import DASTConfig
from localguard.core.constants import Category, Severity
from localguard.core.models import Finding, Target
from localguard.http.client import RateLimitedHTTPClient
from localguard.utils.patterns import CORS_HEADERS

logger = logging.getLogger(__name__)


class CORSAuditor(DASTAuditor):
    """Auditor for CORS security configuration."""

    def __init__(self):
        super().__init__("CORS")

    async def audit(self, target: Target, config: DASTConfig) -> AuditorResult:
        start_time = time.time()
        findings: list[Finding] = []
        errors: list[str] = []

        async with RateLimitedHTTPClient(config) as client:
            try:
                # Test CORS with OPTIONS request
                findings.extend(await self._test_cors_preflight(client, target))

                # Test CORS with actual requests from different origins
                findings.extend(await self._test_cors_actual(client, target))

            except Exception as e:
                errors.append(f"CORSAuditor: {str(e)}")

        return AuditorResult(
            auditor_name=self.name,
            findings=findings,
            errors=errors,
            duration_seconds=time.time() - start_time,
        )

    async def _test_cors_preflight(
        self,
        client: RateLimitedHTTPClient,
        target: Target,
    ) -> list[Finding]:
        """Test CORS preflight (OPTIONS) requests."""
        findings = []

        # Test origins
        test_origins = [
            "https://evil.com",
            "https://attacker.local",
            "null",
            "https://subdomain.evil.com",
        ]

        for origin in test_origins:
            try:
                response = await client.options(
                    target.base_url,
                    headers={
                        "Origin": origin,
                        "Access-Control-Request-Method": "POST",
                        "Access-Control-Request-Headers": "Content-Type,Authorization",
                    },
                )

                cors_headers = self._extract_cors_headers(response.headers)
                findings.extend(
                    self._analyze_cors_response(
                        target.base_url, origin, cors_headers, is_preflight=True
                    )
                )

            except Exception as e:
                logger.debug("CORS preflight check failed for origin %s: %s", origin, e)

        return findings

    async def _test_cors_actual(
        self,
        client: RateLimitedHTTPClient,
        target: Target,
    ) -> list[Finding]:
        """Test CORS with actual GET requests from different origins."""
        findings = []

        test_origins = [
            "https://evil.com",
            "https://attacker.local",
            "null",
        ]

        for origin in test_origins:
            try:
                response = await client.get(target.base_url, headers={"Origin": origin})

                cors_headers = self._extract_cors_headers(response.headers)
                findings.extend(
                    self._analyze_cors_response(
                        target.base_url, origin, cors_headers, is_preflight=False
                    )
                )

            except Exception as e:
                logger.debug("CORS actual request check failed for origin %s: %s", origin, e)

        return findings

    def _extract_cors_headers(self, headers) -> dict:
        """Extract CORS-related headers from response."""
        cors = {}
        for header in CORS_HEADERS:
            header_lower = header.lower()
            if header_lower in headers:
                cors[header] = headers[header_lower]
        return cors

    def _analyze_cors_response(
        self,
        url: str,
        origin: str,
        cors_headers: dict,
        is_preflight: bool,
    ) -> list[Finding]:
        """Analyze CORS response for security issues."""
        findings = []

        acao = cors_headers.get("Access-Control-Allow-Origin", "")
        acac = cors_headers.get("Access-Control-Allow-Credentials", "").lower()
        acam = cors_headers.get("Access-Control-Allow-Methods", "")
        acah = cors_headers.get("Access-Control-Allow-Headers", "")
        acma = cors_headers.get("Access-Control-Max-Age", "")

        # 1. Critical: ACAO: * with ACAC: true
        if acao == "*" and acac == "true":
            findings.append(
                self._create_finding(
                    finding_id="LG-DAST-CORS-001",
                    severity=Severity.CRITICAL,
                    title="CORS Misconfiguration: Wildcard Origin with Credentials",
                    endpoint=url,
                    evidence=f"ACAO: {acao}, ACAC: {acac}",
                    impact="Any origin can make authenticated requests; CSRF and data theft possible",
                    remediation="Never use '*' with credentials; specify exact allowed origins",
                    cwe="CWE-942",
                    owasp="A05:2021 - Security Misconfiguration",
                )
            )

        # 2. High: Overly permissive ACAO
        if acao == "*" and acac != "true":
            findings.append(
                self._create_finding(
                    finding_id="LG-DAST-CORS-002",
                    severity=Severity.HIGH,
                    title="CORS Misconfiguration: Wildcard Origin (No Credentials)",
                    endpoint=url,
                    evidence=f"ACAO: {acao}",
                    impact="Any origin can read responses; data leakage risk",
                    remediation="Restrict ACAO to specific trusted origins",
                    cwe="CWE-942",
                    owasp="A05:2021 - Security Misconfiguration",
                )
            )

        # 3. High: Reflection of arbitrary origin
        # (server echoes an attacker-controlled test origin back in ACAO)
        if acao == origin and origin in ("https://evil.com", "https://attacker.local", "null"):
            findings.append(
                self._create_finding(
                    finding_id="LG-DAST-CORS-003",
                    severity=Severity.HIGH,
                    title="CORS Misconfiguration: Origin Reflection",
                    endpoint=url,
                    evidence=f"Server reflects Origin header: {acao}",
                    impact="Any origin can access resources; effectively same as wildcard",
                    remediation="Validate Origin against allowlist; do not reflect arbitrary origins",
                    cwe="CWE-942",
                    owasp="A05:2021 - Security Misconfiguration",
                )
            )

        # 4. Medium: Null origin allowed
        if acao == "null":
            findings.append(
                self._create_finding(
                    finding_id="LG-DAST-CORS-004",
                    severity=Severity.MEDIUM,
                    title="CORS Misconfiguration: Null Origin Allowed",
                    endpoint=url,
                    evidence=f"ACAO: {acao}",
                    impact="Sandboxed iframes or local files can access resources",
                    remediation="Do not allow 'null' origin; validate Origin header",
                    cwe="CWE-942",
                    owasp="A05:2021 - Security Misconfiguration",
                )
            )

        # 5. Medium: Overly permissive methods
        if acam:
            methods = [m.strip().upper() for m in acam.split(",")]
            dangerous_methods = ["PUT", "DELETE", "PATCH", "TRACE", "CONNECT"]
            for method in methods:
                if method in dangerous_methods:
                    findings.append(
                        self._create_finding(
                            finding_id="LG-DAST-CORS-005",
                            severity=Severity.MEDIUM,
                            title=f"CORS: Dangerous Method Allowed: {method}",
                            endpoint=url,
                            evidence=f"ACAM: {acam}",
                            impact=f"Cross-origin {method} requests allowed; potential data modification",
                            remediation="Restrict ACAM to only required methods (GET, POST)",
                            cwe="CWE-942",
                            owasp="A05:2021 - Security Misconfiguration",
                        )
                    )

        # 6. Low: Overly permissive headers
        if acah:
            headers_allowed = [h.strip() for h in acah.split(",")]
            sensitive_headers = ["authorization", "cookie", "x-csrf-token", "x-xsrf-token"]
            for header in headers_allowed:
                if header.lower() in sensitive_headers:
                    findings.append(
                        self._create_finding(
                            finding_id="LG-DAST-CORS-006",
                            severity=Severity.LOW,
                            title=f"CORS: Sensitive Header Allowed: {header}",
                            endpoint=url,
                            evidence=f"ACAH: {acah}",
                            impact="Sensitive headers exposed cross-origin",
                            remediation="Only allow necessary headers in ACAH",
                            cwe="CWE-942",
                            owasp="A05:2021 - Security Misconfiguration",
                        )
                    )

        # 7. Info: Missing CORS headers (if API endpoint)
        if not cors_headers:
            findings.append(
                self._create_finding(
                    finding_id="LG-DAST-CORS-007",
                    severity=Severity.INFO,
                    title="CORS Headers Not Present",
                    endpoint=url,
                    evidence="No CORS headers in response",
                    impact="Cross-origin requests may be blocked by browsers",
                    remediation="Add appropriate CORS headers if cross-origin access is needed",
                    cwe="CWE-942",
                    owasp="A05:2021 - Security Misconfiguration",
                )
            )

        # 8. Info: Max-Age too high
        if acma:
            try:
                max_age = int(acma)
                if max_age > 86400:  # > 24 hours
                    findings.append(
                        self._create_finding(
                            finding_id="LG-DAST-CORS-008",
                            severity=Severity.INFO,
                            title=f"CORS: Long Preflight Cache: {max_age}s",
                            endpoint=url,
                            evidence=f"ACMA: {acma}",
                            impact="Preflight results cached too long; changes take time to propagate",
                            remediation="Set ACMA to reasonable value (e.g., 86400 or less)",
                            cwe="CWE-942",
                            owasp="A05:2021 - Security Misconfiguration",
                        )
                    )
            except ValueError:
                pass

        return findings

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
