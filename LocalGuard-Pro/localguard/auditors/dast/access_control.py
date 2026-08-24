"""Access Control & Auth Bypass Auditor for LocalGuard-Pro."""

import logging
import time
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from localguard.auditors.base import AuditorResult, DASTAuditor
from localguard.core.config import DASTConfig
from localguard.core.constants import Category, Severity
from localguard.core.models import Finding, Target
from localguard.http.client import RateLimitedHTTPClient
from localguard.http.crawler import BFSCrawler

logger = logging.getLogger(__name__)


class AccessControlAuditor(DASTAuditor):
    """Auditor for access control, authentication bypass, and IDOR."""

    def __init__(self):
        super().__init__("AccessControl")
        # Common protected path patterns
        self.protected_patterns = [
            "/api/",
            "/admin",
            "/dashboard",
            "/user",
            "/account",
            "/profile",
            "/settings",
            "/private",
            "/secure",
            "/api/v1/",
            "/api/v2/",
        ]
        # IDOR parameter patterns
        self.idor_param_patterns = [
            "id",
            "user_id",
            "userid",
            "uid",
            "account_id",
            "accountid",
            "profile_id",
            "profileid",
            "item_id",
            "itemid",
            "order_id",
            "orderid",
            "document_id",
            "docid",
        ]

    async def audit(self, target: Target, config: DASTConfig) -> AuditorResult:
        start_time = time.time()
        findings: list[Finding] = []
        errors: list[str] = []

        async with RateLimitedHTTPClient(config) as client:
            try:
                # Crawl for endpoints
                crawler = BFSCrawler(client, config)
                crawl_result = await crawler.crawl(target.base_url)

                # 1. Test protected endpoints without auth
                findings.extend(await self._test_auth_bypass(client, target, crawl_result.urls))

                # 2. Test IDOR on parameterized endpoints
                findings.extend(await self._test_idor(client, target, crawl_result.urls))

                # 3. Test Laravel Sanctum specific checks
                findings.extend(await self._test_laravel_sanctum(client, target, crawl_result.urls))

            except Exception as e:
                errors.append(f"AccessControlAuditor: {str(e)}")

        return AuditorResult(
            auditor_name=self.name,
            findings=findings,
            errors=errors,
            duration_seconds=time.time() - start_time,
        )

    async def _test_auth_bypass(
        self,
        client: RateLimitedHTTPClient,
        target: Target,
        urls: list[str],
    ) -> list[Finding]:
        """Test protected endpoints without authentication."""
        findings = []
        tested = set()

        for url in urls:
            # Check if URL looks like a protected endpoint
            if not self._is_likely_protected(url):
                continue

            if url in tested:
                continue
            tested.add(url)

            try:
                # Request without any auth headers/cookies
                response = await client.get(url)

                # Check for auth bypass (200 OK without auth)
                if response.status_code == 200:
                    # Verify it's not a public page by checking content
                    if self._looks_like_protected_content(response.text):
                        findings.append(
                            self._create_finding(
                                finding_id="LG-DAST-ACCESS-001",
                                severity=Severity.HIGH,
                                title="Authentication Bypass: Protected Endpoint Accessible Without Auth",
                                endpoint=url,
                                evidence=f"Status: 200 OK, Content-Type: {response.headers.get('content-type', 'unknown')}",
                                impact="Unauthorized access to protected resources; data leakage",
                                remediation="Implement proper authentication middleware; verify session/token on all protected routes",
                                cwe="CWE-306",
                                owasp="A07:2021 - Identification and Authentication Failures",
                            )
                        )
                elif response.status_code == 302:
                    # Check if redirect is to login (good) or elsewhere (potential bypass)
                    location = response.headers.get("location", "")
                    if not self._is_login_redirect(location):
                        findings.append(
                            self._create_finding(
                                finding_id="LG-DAST-ACCESS-002",
                                severity=Severity.MEDIUM,
                                title="Suspicious Redirect on Protected Endpoint",
                                endpoint=url,
                                evidence=f"Status: 302, Location: {location}",
                                impact="Redirect may bypass auth or leak information",
                                remediation="Ensure all redirects from protected endpoints go to login page",
                                cwe="CWE-306",
                                owasp="A07:2021 - Identification and Authentication Failures",
                            )
                        )

            except Exception as e:
                logger.debug("Auth bypass check failed for %s: %s", url, e)

        return findings

    async def _test_idor(
        self,
        client: RateLimitedHTTPClient,
        target: Target,
        urls: list[str],
    ) -> list[Finding]:
        """Test for Insecure Direct Object References (IDOR)."""
        findings = []
        tested = set()

        for url in urls:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)

            for param_name, param_values in params.items():
                if not self._is_idor_param(param_name):
                    continue

                for value in param_values:
                    # Only test numeric/UUID values
                    if not self._is_testable_id(value):
                        continue

                    test_key = f"{parsed.path}?{param_name}={value}"
                    if test_key in tested:
                        continue
                    tested.add(test_key)

                    # Try to manipulate the ID
                    test_values = self._generate_idor_tests(value)

                    for test_value in test_values:
                        try:
                            new_params = params.copy()
                            new_params[param_name] = [test_value]
                            new_query = urlencode(new_params, doseq=True)
                            test_url = urlunparse(
                                (
                                    parsed.scheme,
                                    parsed.netloc,
                                    parsed.path,
                                    parsed.params,
                                    new_query,
                                    parsed.fragment,
                                )
                            )

                            response = await client.get(test_url)

                            # If we get 200 with different content, potential IDOR
                            if response.status_code == 200:
                                findings.append(
                                    self._create_finding(
                                        finding_id="LG-DAST-ACCESS-003",
                                        severity=Severity.HIGH,
                                        title=f"Potential IDOR on Parameter: {param_name}",
                                        endpoint=test_url,
                                        parameter=param_name,
                                        evidence=f"Modified {param_name} from '{value}' to '{test_value}' returned 200 OK",
                                        impact="Unauthorized access to other users' resources",
                                        remediation="Implement proper authorization checks; verify user owns requested resource",
                                        cwe="CWE-639",
                                        owasp="A01:2021 - Broken Access Control",
                                    )
                                )
                                break  # One finding per parameter is enough
                        except Exception as e:
                            logger.debug("Access control check failed for %s: %s", url, e)

        return findings

    async def _test_laravel_sanctum(
        self,
        client: RateLimitedHTTPClient,
        target: Target,
        urls: list[str],
    ) -> list[Finding]:
        """Test Laravel Sanctum specific configurations."""
        findings = []

        # Check for Sanctum API endpoints
        api_endpoints = [u for u in urls if "/api/" in u]

        for url in api_endpoints:
            try:
                # Test without token
                response = await client.get(url)

                if response.status_code == 200:
                    # Check if it's a Sanctum-protected route returning data
                    content_type = response.headers.get("content-type", "").lower()
                    if "json" in content_type:
                        findings.append(
                            self._create_finding(
                                finding_id="LG-DAST-ACCESS-004",
                                severity=Severity.HIGH,
                                title="Laravel Sanctum: API Endpoint Accessible Without Token",
                                endpoint=url,
                                evidence="Status: 200 OK, JSON response without auth token",
                                impact="API data exposed to unauthenticated users",
                                remediation="Add auth:sanctum middleware to routes/api.php; verify token validation",
                                cwe="CWE-306",
                                owasp="A07:2021 - Identification and Authentication Failures",
                            )
                        )
                elif response.status_code == 401:
                    # Good - proper 401 response
                    pass
                elif response.status_code == 302:
                    location = response.headers.get("location", "")
                    if "/login" not in location and "/sanctum" not in location:
                        findings.append(
                            self._create_finding(
                                finding_id="LG-DAST-ACCESS-005",
                                severity=Severity.MEDIUM,
                                title="Laravel Sanctum: Unexpected Redirect on API Endpoint",
                                endpoint=url,
                                evidence=f"Status: 302, Location: {location}",
                                impact="API should return 401, not redirect",
                                remediation="Configure Sanctum to return 401 for API routes; check routes/api.php middleware",
                                cwe="CWE-306",
                                owasp="A07:2021 - Identification and Authentication Failures",
                            )
                        )

            except Exception as e:
                logger.debug("Laravel Sanctum check failed for %s: %s", url, e)

        # Check for session-based auth on /api/* routes (should use token)
        for url in api_endpoints:
            try:
                response = await client.get(url)
                set_cookie = response.headers.get("set-cookie", "")
                if set_cookie and "laravel_session" in set_cookie.lower():
                    findings.append(
                        self._create_finding(
                            finding_id="LG-DAST-ACCESS-006",
                            severity=Severity.MEDIUM,
                            title="Laravel Sanctum: Session Cookie on API Endpoint",
                            endpoint=url,
                            evidence="Set-Cookie header contains laravel_session on API route",
                            impact="API using session auth instead of token; CSRF risk",
                            remediation="Use token-based auth for API routes; disable session middleware on /api/*",
                            cwe="CWE-306",
                            owasp="A07:2021 - Identification and Authentication Failures",
                        )
                    )
            except Exception as e:
                logger.debug("Laravel Sanctum session check failed for %s: %s", url, e)

        return findings

    def _is_likely_protected(self, url: str) -> bool:
        """Check if URL looks like a protected endpoint."""
        url_lower = url.lower()
        return any(pattern in url_lower for pattern in self.protected_patterns)

    def _looks_like_protected_content(self, html: str) -> bool:
        """Heuristic to detect if content looks like protected/user-specific data."""
        html_lower = html.lower()

        # Indicators of user-specific content
        indicators = [
            "logout",
            "sign out",
            "my account",
            "my profile",
            "dashboard",
            "welcome",
            "settings",
            "preferences",
            "my orders",
            "my posts",
            "my projects",
            "csrf_token",
            "_token",
        ]

        for indicator in indicators:
            if indicator in html_lower:
                return True

        # Check for JSON with user data
        return html.strip().startswith("{") and "id" in html_lower and "email" in html_lower

    def _is_login_redirect(self, location: str) -> bool:
        """Check if redirect is to a login page."""
        location_lower = location.lower()
        login_indicators = ["/login", "/signin", "/sign-in", "/auth", "/oauth", "/sso"]
        return any(ind in location_lower for ind in login_indicators)

    def _is_idor_param(self, param_name: str) -> bool:
        """Check if parameter name suggests IDOR vulnerability."""
        param_lower = param_name.lower()
        return any(pattern in param_lower for pattern in self.idor_param_patterns)

    def _is_testable_id(self, value: str) -> bool:
        """Check if value is a testable ID (numeric or UUID)."""
        # Numeric ID
        if value.isdigit():
            return True
        # UUID
        import re

        uuid_pattern = re.compile(
            r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE
        )
        return bool(uuid_pattern.match(value))

    def _generate_idor_tests(self, value: str) -> list[str]:
        """Generate test values for IDOR testing."""
        tests = []

        if value.isdigit():
            num = int(value)
            # Try adjacent IDs
            tests.append(str(num + 1))
            tests.append(str(num - 1))
            tests.append(str(num + 10))
            tests.append(str(num - 10))
            tests.append("1")
            tests.append("999999")
        else:
            # UUID - can't easily generate valid ones, skip
            pass

        return tests

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
