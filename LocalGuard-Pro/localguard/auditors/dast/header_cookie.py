"""Header & Cookie Security Auditor for LocalGuard-Pro."""

import time

from localguard.auditors.base import AuditorResult, DASTAuditor
from localguard.core.config import DASTConfig
from localguard.core.constants import VERSION_DISCLOSURE_HEADERS, Category, Severity
from localguard.core.models import Finding, Target
from localguard.http.client import RateLimitedHTTPClient


class HeaderCookieAuditor(DASTAuditor):
    """Auditor for HTTP Security Headers and Cookie configuration."""

    def __init__(self):
        super().__init__("HeaderCookie")

    async def audit(self, target: Target, config: DASTConfig) -> AuditorResult:
        start_time = time.time()
        findings: list[Finding] = []
        errors: list[str] = []

        async with RateLimitedHTTPClient(config) as client:
            try:
                response = await client.get(target.base_url)
                headers = response.headers
                cookies = response.cookies

                findings.extend(self._check_security_headers(target, headers))
                findings.extend(self._check_cookie_security(target, cookies))
                findings.extend(self._check_version_disclosure(target, headers))

            except Exception as e:
                errors.append(f"HeaderCookieAuditor: {str(e)}")

        return AuditorResult(
            auditor_name=self.name,
            findings=findings,
            errors=errors,
            duration_seconds=time.time() - start_time,
        )

    def _check_security_headers(self, target: Target, headers) -> list[Finding]:
        """Check for presence and configuration of security headers."""
        findings = []
        header_dict = {k.lower(): v for k, v in headers.items()}

        # 1. Content-Security-Policy
        csp = header_dict.get("content-security-policy")
        if not csp:
            findings.append(
                self._create_finding(
                    finding_id="LG-DAST-HEADER-001",
                    severity=Severity.HIGH,
                    title="Missing Content-Security-Policy Header",
                    endpoint=target.base_url,
                    evidence="Content-Security-Policy header not present in response",
                    impact="Increased risk of XSS, data injection, and clickjacking attacks",
                    remediation="Add CSP header: Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';",
                    cwe="CWE-693",
                    owasp="A05:2021 - Security Misconfiguration",
                )
            )
        else:
            # Check for unsafe CSP directives
            csp_issues = self._analyze_csp(csp)
            for issue in csp_issues:
                findings.append(
                    self._create_finding(
                        finding_id=f"LG-DAST-HEADER-001-{issue['code']}",
                        severity=issue["severity"],
                        title=f"Content-Security-Policy: {issue['title']}",
                        endpoint=target.base_url,
                        evidence=f"CSP value: {csp}",
                        impact=issue["impact"],
                        remediation=issue["remediation"],
                        cwe="CWE-693",
                        owasp="A05:2021 - Security Misconfiguration",
                    )
                )

        # 2. Strict-Transport-Security
        hsts = header_dict.get("strict-transport-security")
        if not hsts:
            findings.append(
                self._create_finding(
                    finding_id="LG-DAST-HEADER-002",
                    severity=Severity.MEDIUM,
                    title="Missing Strict-Transport-Security Header",
                    endpoint=target.base_url,
                    evidence="Strict-Transport-Security header not present",
                    impact="HTTPS not enforced, vulnerable to SSL stripping attacks",
                    remediation="Add HSTS header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
                    cwe="CWE-523",
                    owasp="A05:2021 - Security Misconfiguration",
                )
            )
        else:
            hsts_issues = self._analyze_hsts(hsts)
            for issue in hsts_issues:
                findings.append(
                    self._create_finding(
                        finding_id=f"LG-DAST-HEADER-002-{issue['code']}",
                        severity=issue["severity"],
                        title=f"Strict-Transport-Security: {issue['title']}",
                        endpoint=target.base_url,
                        evidence=f"HSTS value: {hsts}",
                        impact=issue["impact"],
                        remediation=issue["remediation"],
                        cwe="CWE-523",
                        owasp="A05:2021 - Security Misconfiguration",
                    )
                )

        # 3. X-Frame-Options
        xfo = header_dict.get("x-frame-options")
        if not xfo:
            findings.append(
                self._create_finding(
                    finding_id="LG-DAST-HEADER-003",
                    severity=Severity.MEDIUM,
                    title="Missing X-Frame-Options Header",
                    endpoint=target.base_url,
                    evidence="X-Frame-Options header not present",
                    impact="Vulnerable to clickjacking attacks",
                    remediation="Add X-Frame-Options: DENY or SAMEORIGIN",
                    cwe="CWE-1021",
                    owasp="A05:2021 - Security Misconfiguration",
                )
            )
        else:
            xfo_upper = xfo.upper()
            if xfo_upper not in ("DENY", "SAMEORIGIN"):
                findings.append(
                    self._create_finding(
                        finding_id="LG-DAST-HEADER-003-01",
                        severity=Severity.LOW,
                        title="Weak X-Frame-Options Value",
                        endpoint=target.base_url,
                        evidence=f"X-Frame-Options: {xfo}",
                        impact="May not adequately prevent clickjacking",
                        remediation="Use DENY or SAMEORIGIN",
                        cwe="CWE-1021",
                        owasp="A05:2021 - Security Misconfiguration",
                    )
                )

        # 4. X-Content-Type-Options
        xcto = header_dict.get("x-content-type-options")
        if not xcto:
            findings.append(
                self._create_finding(
                    finding_id="LG-DAST-HEADER-004",
                    severity=Severity.LOW,
                    title="Missing X-Content-Type-Options Header",
                    endpoint=target.base_url,
                    evidence="X-Content-Type-Options header not present",
                    impact="MIME type sniffing may lead to XSS",
                    remediation="Add X-Content-Type-Options: nosniff",
                    cwe="CWE-1021",
                    owasp="A05:2021 - Security Misconfiguration",
                )
            )
        elif xcto.lower() != "nosniff":
            findings.append(
                self._create_finding(
                    finding_id="LG-DAST-HEADER-004-01",
                    severity=Severity.INFO,
                    title="Non-standard X-Content-Type-Options Value",
                    endpoint=target.base_url,
                    evidence=f"X-Content-Type-Options: {xcto}",
                    impact="May not prevent MIME sniffing",
                    remediation="Use 'nosniff' value",
                    cwe="CWE-1021",
                    owasp="A05:2021 - Security Misconfiguration",
                )
            )

        # 5. Referrer-Policy
        rp = header_dict.get("referrer-policy")
        if not rp:
            findings.append(
                self._create_finding(
                    finding_id="LG-DAST-HEADER-005",
                    severity=Severity.LOW,
                    title="Missing Referrer-Policy Header",
                    endpoint=target.base_url,
                    evidence="Referrer-Policy header not present",
                    impact="Full referrer sent with cross-origin requests, potential information leakage",
                    remediation="Add Referrer-Policy: strict-origin-when-cross-origin",
                    cwe="CWE-200",
                    owasp="A05:2021 - Security Misconfiguration",
                )
            )
        else:
            rp_issues = self._analyze_referrer_policy(rp)
            for issue in rp_issues:
                findings.append(
                    self._create_finding(
                        finding_id=f"LG-DAST-HEADER-005-{issue['code']}",
                        severity=issue["severity"],
                        title=f"Referrer-Policy: {issue['title']}",
                        endpoint=target.base_url,
                        evidence=f"Referrer-Policy value: {rp}",
                        impact=issue["impact"],
                        remediation=issue["remediation"],
                        cwe="CWE-200",
                        owasp="A05:2021 - Security Misconfiguration",
                    )
                )

        # 6. Permissions-Policy (Feature-Policy)
        pp = header_dict.get("permissions-policy") or header_dict.get("feature-policy")
        if not pp:
            findings.append(
                self._create_finding(
                    finding_id="LG-DAST-HEADER-006",
                    severity=Severity.INFO,
                    title="Missing Permissions-Policy Header",
                    endpoint=target.base_url,
                    evidence="Permissions-Policy (Feature-Policy) header not present",
                    impact="No control over browser features/APIs available to page",
                    remediation="Add Permissions-Policy with appropriate restrictions",
                    cwe="CWE-1021",
                    owasp="A05:2021 - Security Misconfiguration",
                )
            )

        return findings

    def _analyze_csp(self, csp: str) -> list[dict]:
        """Analyze CSP for unsafe directives."""
        issues = []
        csp_lower = csp.lower()

        unsafe_patterns = [
            (
                "unsafe-inline",
                "UNSAFE_INLINE",
                Severity.MEDIUM,
                "Unsafe inline scripts/styles allowed",
                "Increases XSS risk",
                "Remove 'unsafe-inline', use nonces or hashes instead",
            ),
            (
                "unsafe-eval",
                "UNSAFE_EVAL",
                Severity.HIGH,
                "Unsafe eval() allowed",
                "Allows dynamic code execution",
                "Remove 'unsafe-eval', refactor code to avoid eval()",
            ),
            (
                "data:",
                "DATA_URI",
                Severity.LOW,
                "Data URIs allowed in CSP",
                "Can bypass CSP restrictions",
                "Avoid data: URIs where possible",
            ),
            (
                "*",
                "WILDCARD",
                Severity.HIGH,
                "Wildcard source allowed",
                "Defeats purpose of CSP",
                "Restrict to specific domains",
            ),
        ]

        for pattern, code, severity, title, impact, remediation in unsafe_patterns:
            if pattern in csp_lower:
                issues.append(
                    {
                        "code": code,
                        "severity": severity,
                        "title": title,
                        "impact": impact,
                        "remediation": remediation,
                    }
                )

        # Check for missing critical directives
        if "script-src" not in csp_lower and "default-src" not in csp_lower:
            issues.append(
                {
                    "code": "MISSING_SCRIPT_SRC",
                    "severity": Severity.MEDIUM,
                    "title": "Missing script-src directive",
                    "impact": "No control over script sources",
                    "remediation": "Add script-src directive with allowed sources",
                }
            )

        return issues

    def _analyze_hsts(self, hsts: str) -> list[dict]:
        """Analyze HSTS for weak configuration."""
        issues = []
        hsts_lower = hsts.lower()

        if "max-age=" not in hsts_lower:
            issues.append(
                {
                    "code": "MISSING_MAX_AGE",
                    "severity": Severity.MEDIUM,
                    "title": "Missing max-age directive",
                    "impact": "HSTS not properly enforced",
                    "remediation": "Add max-age=31536000 (1 year minimum)",
                }
            )
        else:
            # Extract max-age value
            import re

            match = re.search(r"max-age=(\d+)", hsts_lower)
            if match:
                max_age = int(match.group(1))
                if max_age < 31536000:  # 1 year
                    issues.append(
                        {
                            "code": "SHORT_MAX_AGE",
                            "severity": Severity.LOW,
                            "title": f"Short HSTS max-age: {max_age}s",
                            "impact": "HSTS expires too quickly",
                            "remediation": "Set max-age to at least 31536000 (1 year)",
                        }
                    )

        if "includesubdomains" not in hsts_lower:
            issues.append(
                {
                    "code": "MISSING_INCLUDE_SUBDOMAINS",
                    "severity": Severity.LOW,
                    "title": "Missing includeSubDomains directive",
                    "impact": "Subdomains not protected by HSTS",
                    "remediation": "Add includeSubDomains directive",
                }
            )

        return issues

    def _analyze_referrer_policy(self, rp: str) -> list[dict]:
        """Analyze Referrer-Policy for weak values."""
        issues = []
        rp_lower = rp.lower()

        weak_policies = [
            "unsafe-url",
            "no-referrer-when-downgrade",
            "origin",
            "origin-when-cross-origin",
        ]

        for weak in weak_policies:
            if weak in rp_lower:
                issues.append(
                    {
                        "code": "WEAK_POLICY",
                        "severity": Severity.LOW,
                        "title": f"Weak Referrer-Policy: {weak}",
                        "impact": "May leak referrer information cross-origin",
                        "remediation": "Use 'strict-origin-when-cross-origin' or 'no-referrer'",
                    }
                )

        return issues

    def _check_cookie_security(self, target: Target, cookies) -> list[Finding]:
        """Check cookie security flags."""
        findings = []

        for cookie in cookies:
            cookie_name = cookie.name
            cookie_flags = {
                "httponly": cookie.get("httponly", False),
                "secure": cookie.get("secure", False),
                "samesite": cookie.get("samesite", "").lower(),
            }

            # Check HttpOnly
            if not cookie_flags["httponly"]:
                findings.append(
                    self._create_finding(
                        finding_id="LG-DAST-COOKIE-001",
                        severity=Severity.MEDIUM,
                        title=f"Cookie Missing HttpOnly Flag: {cookie_name}",
                        endpoint=target.base_url,
                        parameter=cookie_name,
                        evidence=f"Cookie '{cookie_name}' does not have HttpOnly flag",
                        impact="JavaScript can access cookie, increasing XSS impact",
                        remediation=f"Set HttpOnly flag on cookie '{cookie_name}'",
                        cwe="CWE-1004",
                        owasp="A05:2021 - Security Misconfiguration",
                    )
                )

            # Check Secure
            if not cookie_flags["secure"]:
                findings.append(
                    self._create_finding(
                        finding_id="LG-DAST-COOKIE-002",
                        severity=Severity.MEDIUM,
                        title=f"Cookie Missing Secure Flag: {cookie_name}",
                        endpoint=target.base_url,
                        parameter=cookie_name,
                        evidence=f"Cookie '{cookie_name}' does not have Secure flag",
                        impact="Cookie sent over HTTP, vulnerable to MITM",
                        remediation=f"Set Secure flag on cookie '{cookie_name}'",
                        cwe="CWE-614",
                        owasp="A05:2021 - Security Misconfiguration",
                    )
                )

            # Check SameSite
            samesite = cookie_flags["samesite"]
            if not samesite or samesite == "none":
                findings.append(
                    self._create_finding(
                        finding_id="LG-DAST-COOKIE-003",
                        severity=Severity.HIGH if samesite == "none" else Severity.MEDIUM,
                        title=f"Cookie Missing/Weak SameSite: {cookie_name}",
                        endpoint=target.base_url,
                        parameter=cookie_name,
                        evidence=f"Cookie '{cookie_name}' SameSite: '{samesite or 'not set'}'",
                        impact="Vulnerable to CSRF and cross-site request forgery",
                        remediation=f"Set SameSite=Strict or SameSite=Lax on cookie '{cookie_name}'",
                        cwe="CWE-1275",
                        owasp="A01:2021 - Broken Access Control",
                    )
                )
            elif samesite not in ("strict", "lax"):
                findings.append(
                    self._create_finding(
                        finding_id="LG-DAST-COOKIE-003-01",
                        severity=Severity.LOW,
                        title=f"Non-standard SameSite Value: {cookie_name}",
                        endpoint=target.base_url,
                        parameter=cookie_name,
                        evidence=f"Cookie '{cookie_name}' SameSite: '{samesite}'",
                        impact="May not provide expected CSRF protection",
                        remediation="Use 'Strict' or 'Lax'",
                        cwe="CWE-1275",
                        owasp="A01:2021 - Broken Access Control",
                    )
                )

        return findings

    def _check_version_disclosure(self, target: Target, headers) -> list[Finding]:
        """Check for version disclosure in headers."""
        findings = []
        header_dict = {k.lower(): v for k, v in headers.items()}

        for header in VERSION_DISCLOSURE_HEADERS:
            header_lower = header.lower()
            if header_lower in header_dict:
                value = header_dict[header_lower]
                findings.append(
                    self._create_finding(
                        finding_id=f"LG-DAST-VERSION-001-{header_lower.replace('-', '_')}",
                        severity=Severity.LOW,
                        title=f"Version Disclosure via {header} Header",
                        endpoint=target.base_url,
                        evidence=f"{header}: {value}",
                        impact="Attacker can fingerprint server/framework versions for targeted exploits",
                        remediation=f"Remove or obfuscate {header} header",
                        cwe="CWE-200",
                        owasp="A05:2021 - Security Misconfiguration",
                    )
                )

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
