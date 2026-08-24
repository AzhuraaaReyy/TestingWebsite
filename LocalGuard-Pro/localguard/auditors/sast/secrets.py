"""Secret Scanner for LocalGuard-Pro (SAST)."""

import logging
import re
import time
from pathlib import Path

from localguard.auditors.base import AuditorResult, SASTAuditor
from localguard.core.config import SASTConfig
from localguard.core.constants import Category, Severity
from localguard.core.models import Finding, Target
from localguard.utils.entropy import is_high_entropy, shannon_entropy
from localguard.utils.filesystem import iter_source_files, read_file_safely
from localguard.utils.patterns import SECRET_PATTERNS, SecretPattern

logger = logging.getLogger(__name__)


class SecretScanner(SASTAuditor):
    """Scanner for hardcoded secrets in source code."""

    def __init__(self):
        super().__init__("Secrets")
        self._compiled_patterns: list[tuple[SecretPattern, re.Pattern]] = []
        self._ignore_patterns: set[str] = set()

    def _compile_patterns(self, config: SASTConfig) -> list[tuple[SecretPattern, re.Pattern]]:
        """Compile regex patterns for secret detection."""
        compiled = []

        # Built-in patterns
        for pattern in SECRET_PATTERNS:
            compiled.append((pattern, pattern.regex))

        # Custom patterns from config
        for custom_pattern in config.custom_patterns:
            try:
                regex = re.compile(custom_pattern)
                custom_sp = SecretPattern(
                    name="Custom Pattern",
                    regex=regex,
                    severity="High",
                    description="User-defined secret pattern",
                )
                compiled.append((custom_sp, regex))
            except re.error as e:
                logger.warning("Invalid custom regex pattern: %s - %s", custom_pattern, e)

        return compiled

    def _load_ignore_file(self, project_root: Path) -> None:
        """Load .localguard-ignore patterns."""
        ignore_file = project_root / ".localguard-ignore"
        if ignore_file.exists():
            content = read_file_safely(ignore_file)
            if content:
                for line in content.splitlines():
                    line = line.strip()
                    if line and not line.startswith("#"):
                        self._ignore_patterns.add(line)
                logger.debug(
                    "Loaded %d ignore patterns from .localguard-ignore", len(self._ignore_patterns)
                )

    def _should_ignore(self, file_path: Path, project_root: Path) -> bool:
        """Check if file should be ignored based on .localguard-ignore."""
        if not self._ignore_patterns:
            return False

        try:
            relative = file_path.relative_to(project_root)
            relative_str = str(relative)

            for pattern in self._ignore_patterns:
                if self._match_pattern(relative_str, pattern):
                    return True
        except ValueError:
            pass
        return False

    def _match_pattern(self, path: str, pattern: str) -> bool:
        """Match path against glob pattern."""
        import fnmatch

        return fnmatch.fnmatch(path, pattern) or fnmatch.fnmatch(Path(path).name, pattern)

    # Filename glob patterns that indicate test files
    TEST_FILE_GLOBS = ["test_*.py", "*_test.py", "*.test.*", "*.spec.*", "conftest.py"]
    # Directory names that indicate non-production code
    SKIP_DIRS = {
        "tests",
        "test",
        "spec",
        "__tests__",
        "__pycache__",
        "node_modules",
        "vendor",
        ".git",
        "dist",
        "build",
        ".pytest_cache",
    }

    def _is_likely_secret_context(self, file_path: Path, line: str, line_num: int) -> bool:
        """Check if the match is in a likely secret context (not test/example)."""
        import fnmatch

        # Skip well-known test/vendor directories and test-named files.
        # Uses exact dir-name / glob matching instead of substring matching,
        # so legitimate files like "test.py" or ".env.example" are still scanned.
        name = file_path.name.lower()
        for glob_pattern in self.TEST_FILE_GLOBS:
            if fnmatch.fnmatch(name, glob_pattern):
                return False
        for part in file_path.parent.parts:
            if part.lower() in self.SKIP_DIRS:
                return False

        # Skip commented lines ("--" requires trailing space so that
        # PEM headers like "-----BEGIN ..." are not treated as comments)
        stripped = line.strip()
        if stripped.startswith(("#", "//", "/*", "*", "-- ")) or stripped == "--":
            return False

        # Skip lines that look like placeholders
        placeholder_patterns = [
            r"your[_-]?key",
            r"your[_-]?secret",
            r"your[_-]?token",
            r"placeholder",
            r"dummy",
            r"fake",
            r"change[_-]?me",
            r"replace[_-]?me",
            r"xxx+",
            r"yyy+",
        ]
        return not any(re.search(pattern, line, re.IGNORECASE) for pattern in placeholder_patterns)

    def _classify_supabase_key(self, key: str) -> tuple[str, Severity]:
        """Classify Supabase key as Anon (Low) or Service Role (Critical)."""
        try:
            import base64
            import json

            # JWT has 3 parts separated by dots
            parts = key.split(".")
            if len(parts) != 3:
                return "Unknown", Severity.HIGH

            # Decode payload (second part)
            payload = parts[1]
            # Add padding if needed
            payload += "=" * ((4 - len(payload) % 4) % 4)
            decoded = base64.urlsafe_b64decode(payload)
            claims = json.loads(decoded)

            # Check for service_role claim
            role = claims.get("role", "")
            if role == "service_role":
                return "Service Role Key", Severity.CRITICAL

            # Check for anon role
            if role == "anon" or claims.get("is_anonymous") is True:
                return "Anon Key", Severity.LOW

            return "Unknown Role", Severity.HIGH
        except Exception:
            return "Unknown", Severity.HIGH

    async def audit(self, target: Target, config: SASTConfig) -> AuditorResult:
        start_time = time.time()
        findings: list[Finding] = []
        errors: list[str] = []

        try:
            # Compile patterns
            self._compiled_patterns = self._compile_patterns(config)

            # Load ignore file
            project_root = Path(target.project_root)
            self._load_ignore_file(project_root)

            # Iterate source files
            exclude_patterns = config.exclude_patterns

            for file_info in iter_source_files(project_root, exclude_patterns):
                if self._should_ignore(file_info.path, project_root):
                    continue

                if file_info.is_binary:
                    continue

                content = read_file_safely(file_info.path)
                if not content:
                    continue

                file_findings = self._scan_file(file_info.path, project_root, content, config)
                findings.extend(file_findings)

        except Exception as e:
            errors.append(f"SecretScanner: {str(e)}")
            logger.exception("SecretScanner failed")

        return AuditorResult(
            auditor_name=self.name,
            findings=findings,
            errors=errors,
            duration_seconds=time.time() - start_time,
        )

    def _scan_file(
        self, file_path: Path, project_root: Path, content: str, config: SASTConfig
    ) -> list[Finding]:
        """Scan a single file for secrets."""
        findings = []
        lines = content.splitlines()

        for line_num, line in enumerate(lines, 1):
            if not self._is_likely_secret_context(file_path, line, line_num):
                continue

            # Check regex patterns
            for pattern_obj, regex in self._compiled_patterns:
                matches = regex.finditer(line)
                for match in matches:
                    matched_text = match.group(0)

                    # Entropy gate only for generic/broad patterns; curated
                    # patterns (AWS, PEM headers, etc.) match structured
                    # strings that are not necessarily high entropy.
                    if pattern_obj.name.startswith("Generic") and not is_high_entropy(
                        matched_text, config.entropy_threshold
                    ):
                        continue

                    # Special handling for Supabase keys
                    if "supabase" in pattern_obj.name.lower() or "SUPABASE" in matched_text.upper():
                        key_type, severity = self._classify_supabase_key(matched_text)
                        finding_id = self._generate_finding_id(pattern_obj, "SUPABASE")
                        findings.append(
                            self._create_finding(
                                finding_id=finding_id,
                                severity=severity,
                                title=f"Hardcoded Supabase {key_type}",
                                endpoint=str(file_path.relative_to(project_root)),
                                parameter=f"line {line_num}",
                                evidence=f"Line {line_num}: {matched_text[:50]}...",
                                impact=f"Supabase {key_type} exposed in source code"
                                + (
                                    " - Full admin access!"
                                    if severity == Severity.CRITICAL
                                    else " - Public access only"
                                ),
                                remediation=f"Remove Supabase {key_type} from source code; use environment variables",
                                cwe="CWE-798",
                                owasp="A07:2021 - Identification and Authentication Failures",
                                file_path=str(file_path.relative_to(project_root)),
                                line_number=line_num,
                            )
                        )
                        continue

                    # Special handling for Laravel/committed .env files
                    if file_path.name in (
                        ".env",
                        ".env.example",
                        ".env.local",
                        ".env.production",
                        ".env.staging",
                    ):
                        finding_id = self._generate_finding_id(pattern_obj, "ENV_EXAMPLE")
                        findings.append(
                            self._create_finding(
                                finding_id=finding_id,
                                severity=Severity.CRITICAL,
                                title=f"Secret in Committed Env File ({pattern_obj.name}): {file_path.name}",
                                endpoint=str(file_path.relative_to(project_root)),
                                parameter=f"line {line_num}",
                                evidence=f"Line {line_num}: {matched_text[:50]}...",
                                impact="Committed secrets in version control accessible to all developers",
                                remediation=f"Remove secret from {file_path.name}; use .env for local values only",
                                cwe="CWE-798",
                                owasp="A07:2021 - Identification and Authentication Failures",
                                file_path=str(file_path.relative_to(project_root)),
                                line_number=line_num,
                            )
                        )
                        continue

                    # Generic secret finding
                    finding_id = self._generate_finding_id(pattern_obj, "GENERIC")
                    findings.append(
                        self._create_finding(
                            finding_id=finding_id,
                            severity=self._severity_from_string(pattern_obj.severity),
                            title=f"Hardcoded {pattern_obj.name}",
                            endpoint=str(file_path.relative_to(project_root)),
                            parameter=f"line {line_num}",
                            evidence=f"Line {line_num}: {matched_text[:50]}...",
                            impact=pattern_obj.description,
                            remediation=f"Remove {pattern_obj.name.lower()} from source code; use environment variables or secret manager",
                            cwe="CWE-798",
                            owasp="A07:2021 - Identification and Authentication Failures",
                            file_path=str(file_path.relative_to(project_root)),
                            line_number=line_num,
                        )
                    )

            # Entropy-based detection for strings not caught by regex
            entropy_findings = self._check_entropy(line, line_num, file_path, project_root, config)
            findings.extend(entropy_findings)

        return findings

    def _check_entropy(
        self, line: str, line_num: int, file_path: Path, project_root: Path, config: SASTConfig
    ) -> list[Finding]:
        """Check for high-entropy strings that might be secrets."""
        findings = []

        # Look for potential secret patterns (quoted strings, assignments)
        potential_secrets = re.finditer(
            r'["\']([A-Za-z0-9+/=]{20,})["\']',  # Base64-like strings in quotes
            line,
        )

        for match in potential_secrets:
            secret = match.group(1)
            if len(secret) < 20:
                continue

            entropy = shannon_entropy(secret)
            if entropy >= config.entropy_threshold:
                # Check if already caught by regex patterns
                already_found = any(regex.search(secret) for _, regex in self._compiled_patterns)

                if not already_found and self._is_likely_secret_context(file_path, line, line_num):
                    findings.append(
                        self._create_finding(
                            finding_id=f"LG-SAST-ENTROPY-{abs(hash(secret)) % 10000:04d}",
                            severity=Severity.HIGH,
                            title="High Entropy String (Potential Secret)",
                            endpoint=str(file_path.relative_to(project_root)),
                            parameter=f"line {line_num}",
                            evidence=f"Line {line_num}: Entropy={entropy:.2f}, Value={secret[:30]}...",
                            impact="High entropy string may be a hardcoded secret/key",
                            remediation="Verify if this is a secret; if so, move to environment variables",
                            cwe="CWE-798",
                            owasp="A07:2021 - Identification and Authentication Failures",
                            file_path=str(file_path.relative_to(project_root)),
                            line_number=line_num,
                        )
                    )

        return findings

    def _generate_finding_id(self, pattern_obj: SecretPattern, category: str) -> str:
        """Generate unique finding ID."""
        return f"LG-SAST-{category}-{hash(pattern_obj.name) % 10000:04d}"

    def _severity_from_string(self, severity_str: str) -> Severity:
        """Convert severity string to Severity enum."""
        mapping = {
            "Critical": Severity.CRITICAL,
            "High": Severity.HIGH,
            "Medium": Severity.MEDIUM,
            "Low": Severity.LOW,
            "Info": Severity.INFO,
        }
        return mapping.get(severity_str, Severity.HIGH)

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
        file_path: str | None = None,
        line_number: int | None = None,
    ) -> Finding:
        return Finding(
            id=finding_id,
            severity=severity,
            category=Category.SAST,
            title=title,
            endpoint=endpoint,
            parameter=parameter,
            evidence=evidence,
            impact=impact,
            remediation=remediation,
            cwe=cwe,
            owasp=owasp,
            file_path=file_path,
            line_number=line_number,
        )
