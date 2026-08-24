"""Form & Injection Auditor for LocalGuard-Pro."""

import logging
import time
from urllib.parse import parse_qs, urlparse

from localguard.auditors.base import AuditorResult, DASTAuditor
from localguard.core.config import DASTConfig
from localguard.core.constants import Category, Severity
from localguard.core.models import Finding, Target
from localguard.http.client import RateLimitedHTTPClient
from localguard.http.crawler import BFSCrawler
from localguard.utils.patterns import VULN_PATTERNS

logger = logging.getLogger(__name__)


class FormInjectionAuditor(DASTAuditor):
    """Auditor for forms, CSRF tokens, and passive injection analysis."""

    def __init__(self):
        super().__init__("FormsInjection")
        # Passive detection patterns
        self.sql_patterns = VULN_PATTERNS.get("sql_error", [])
        self.xss_patterns = VULN_PATTERNS.get("xss_reflection", [])
        self.path_traversal_patterns = VULN_PATTERNS.get("path_traversal", [])
        self.cmd_injection_patterns = VULN_PATTERNS.get("command_injection", [])

    async def audit(self, target: Target, config: DASTConfig) -> AuditorResult:
        start_time = time.time()
        findings: list[Finding] = []
        errors: list[str] = []

        async with RateLimitedHTTPClient(config) as client:
            try:
                # Crawl for forms
                crawler = BFSCrawler(client, config)
                crawl_result = await crawler.crawl(target.base_url)

                # Analyze each form
                for form in crawl_result.forms:
                    findings.extend(await self._analyze_form(client, target, form))

                # Analyze URL parameters for injection indicators
                findings.extend(
                    await self._analyze_url_parameters(client, target, crawl_result.urls)
                )

            except Exception as e:
                errors.append(f"FormInjectionAuditor: {str(e)}")

        return AuditorResult(
            auditor_name=self.name,
            findings=findings,
            errors=errors,
            duration_seconds=time.time() - start_time,
        )

    async def _analyze_form(
        self,
        client: RateLimitedHTTPClient,
        target: Target,
        form: dict,
    ) -> list[Finding]:
        """Analyze a single form for security issues."""
        findings = []
        form_url = form["url"]
        method = form["method"]
        inputs = form["inputs"]
        has_csrf = form.get("has_csrf_token", False)

        # 1. Check CSRF protection on state-changing methods
        if method in ("POST", "PUT", "DELETE", "PATCH") and not has_csrf:
            findings.append(
                self._create_finding(
                    finding_id="LG-DAST-FORM-001",
                    severity=Severity.HIGH,
                    title=f"Missing CSRF Token on {method} Form",
                    endpoint=form_url,
                    evidence=f"Form with method={method} has no CSRF token in inputs",
                    impact="Cross-Site Request Forgery (CSRF) possible",
                    remediation="Add CSRF token to form; validate on server side",
                    cwe="CWE-352",
                    owasp="A01:2021 - Broken Access Control",
                )
            )

        # 2. Analyze each input for injection indicators
        for inp in inputs:
            name = inp.get("name", "")
            inp_type = inp.get("type", "text")

            # Skip non-user-input types
            if inp_type in ("hidden", "submit", "button", "image", "reset"):
                continue

            # Passive XSS check - test reflection
            xss_finding = await self._check_xss_reflection(
                client, target, form_url, method, name, inp
            )
            if xss_finding:
                findings.append(xss_finding)

            # Passive SQLi check - test error-based
            sqli_finding = await self._check_sqli_error(client, target, form_url, method, name, inp)
            if sqli_finding:
                findings.append(sqli_finding)

        return findings

    async def _check_xss_reflection(
        self,
        client: RateLimitedHTTPClient,
        target: Target,
        form_url: str,
        method: str,
        param_name: str,
        inp: dict,
    ) -> Finding | None:
        """Check for reflected XSS by submitting a harmless test payload."""
        # Use a unique, harmless test string
        test_payload = "lgxss" + str(hash(param_name + form_url))[:8]

        # For passive detection, we just check if input reflects in response
        # We'll do a simple GET with the param to check reflection
        try:
            test_url = f"{form_url}?{param_name}={test_payload}"
            response = await client.get(test_url)

            # Check if payload reflects in response
            if test_payload in response.text:
                # Check if it's in a dangerous context
                context = self._analyze_reflection_context(response.text, test_payload)
                if context["dangerous"]:
                    return self._create_finding(
                        finding_id="LG-DAST-FORM-002",
                        severity=Severity.HIGH,
                        title=f"Potential Reflected XSS in Parameter: {param_name}",
                        endpoint=form_url,
                        parameter=param_name,
                        evidence=f"Payload '{test_payload}' reflected in {context['context']} context",
                        impact="Attacker could inject arbitrary JavaScript",
                        remediation="Implement proper output encoding; validate and sanitize input",
                        cwe="CWE-79",
                        owasp="A03:2021 - Injection",
                    )
        except Exception as e:
            logger.debug("XSS reflection check failed for %s param %s: %s", form_url, param_name, e)
        return None

    async def _check_sqli_error(
        self,
        client: RateLimitedHTTPClient,
        target: Target,
        form_url: str,
        method: str,
        param_name: str,
        inp: dict,
    ) -> Finding | None:
        """Check for SQL injection error-based indicators."""
        # Test payloads that commonly trigger SQL errors
        test_payloads = [
            "'",
            '"',
            "' OR '1'='1",
            '" OR "1"="1',
            "';--",
            "' OR 1=1--",
        ]

        for payload in test_payloads:
            try:
                test_url = f"{form_url}?{param_name}={payload}"
                response = await client.get(test_url)

                # Check for SQL error patterns
                for pattern in self.sql_patterns:
                    if pattern.search(response.text):
                        return self._create_finding(
                            finding_id="LG-DAST-FORM-003",
                            severity=Severity.HIGH,
                            title=f"Potential SQL Injection in Parameter: {param_name}",
                            endpoint=form_url,
                            parameter=param_name,
                            evidence=f"SQL error pattern detected with payload: {payload}",
                            impact="Database data extraction, modification, or deletion possible",
                            remediation="Use parameterized queries; implement input validation",
                            cwe="CWE-89",
                            owasp="A03:2021 - Injection",
                        )
            except Exception as e:
                logger.debug(
                    "SQLi check failed for %s param %s with payload %s: %s",
                    form_url,
                    param_name,
                    payload,
                    e,
                )
        return None

    async def _analyze_url_parameters(
        self,
        client: RateLimitedHTTPClient,
        target: Target,
        urls: list[str],
    ) -> list[Finding]:
        """Analyze URL parameters for injection indicators."""
        findings = []
        tested_params: set[str] = set()

        for url in urls:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)

            for param_name, param_values in params.items():
                param_key = f"{parsed.path}?{param_name}"
                if param_key in tested_params:
                    continue
                tested_params.add(param_key)

                for value in param_values:
                    # Check for path traversal indicators
                    for pattern in self.path_traversal_patterns:
                        if pattern.search(value):
                            findings.append(
                                self._create_finding(
                                    finding_id="LG-DAST-FORM-004",
                                    severity=Severity.MEDIUM,
                                    title=f"Path Traversal Indicator in Parameter: {param_name}",
                                    endpoint=url,
                                    parameter=param_name,
                                    evidence=f"Value contains path traversal pattern: {value}",
                                    impact="Potential directory traversal to access sensitive files",
                                    remediation="Validate and sanitize file path inputs; use allowlist",
                                    cwe="CWE-22",
                                    owasp="A01:2021 - Broken Access Control",
                                )
                            )

                    # Check for command injection indicators
                    for pattern in self.cmd_injection_patterns:
                        if pattern.search(value):
                            findings.append(
                                self._create_finding(
                                    finding_id="LG-DAST-FORM-005",
                                    severity=Severity.HIGH,
                                    title=f"Command Injection Indicator in Parameter: {param_name}",
                                    endpoint=url,
                                    parameter=param_name,
                                    evidence=f"Value contains command injection pattern: {value}",
                                    impact="Remote code execution possible",
                                    remediation="Avoid shell commands; use safe APIs; validate input strictly",
                                    cwe="CWE-78",
                                    owasp="A03:2021 - Injection",
                                )
                            )

        return findings

    def _analyze_reflection_context(self, html: str, payload: str) -> dict:
        """Analyze the context where payload reflects in HTML."""
        # Find payload position
        idx = html.find(payload)
        if idx == -1:
            return {"dangerous": False, "context": "unknown"}

        # Get surrounding context (100 chars before and after)
        start = max(0, idx - 100)
        end = min(len(html), idx + len(payload) + 100)
        context_html = html[start:end]

        # Determine context
        context_html_lower = context_html.lower()

        # In script tag
        if "<script" in context_html_lower and "</script>" in context_html_lower:
            return {"dangerous": True, "context": "script"}

        # In event handler
        event_handlers = [
            "onclick",
            "onload",
            "onerror",
            "onmouseover",
            "onfocus",
            "onblur",
            "onchange",
        ]
        for eh in event_handlers:
            if eh + "=" in context_html_lower:
                return {"dangerous": True, "context": f"event handler ({eh})"}

        # In javascript: URL
        if "javascript:" in context_html_lower:
            return {"dangerous": True, "context": "javascript URL"}

        # In attribute without quotes
        if "=" in context_html and '"' not in context_html and "'" not in context_html:
            return {"dangerous": True, "context": "unquoted attribute"}

        # In HTML body (potentially dangerous if not encoded)
        if (
            ">" in context_html[: context_html.find(payload) - start]
            and "<" in context_html[context_html.find(payload) - start + len(payload) :]
        ):
            return {"dangerous": True, "context": "HTML element"}

        return {"dangerous": False, "context": "text/attribute (likely safe)"}

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
