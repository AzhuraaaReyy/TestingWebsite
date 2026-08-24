"""Core data models for LocalGuard-Pro."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum

from localguard.core.constants import Category, Severity


class FindingStatus(str, Enum):
    """Status of a finding."""

    OPEN = "open"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    FIXED = "fixed"
    IGNORED = "ignored"


@dataclass(frozen=True, slots=True)
class Finding:
    """Represents a single security finding."""

    id: str
    severity: Severity
    category: Category
    title: str
    endpoint: str
    parameter: str | None = None
    evidence: str = ""
    impact: str = ""
    remediation: str = ""
    cwe: str | None = None
    owasp: str | None = None
    references: list[str] = field(default_factory=list)
    status: FindingStatus = FindingStatus.OPEN
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    file_path: str | None = None
    line_number: int | None = None

    def __lt__(self, other: "Finding") -> bool:
        """Sort by severity (Critical first), then by title."""
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }
        self_order = severity_order.get(self.severity, 5)
        other_order = severity_order.get(other.severity, 5)
        if self_order != other_order:
            return self_order < other_order
        return self.title < other.title

    @classmethod
    def from_dict(cls, data: dict) -> "Finding":
        """Reconstruct a Finding from its dictionary form (see to_dict)."""
        created_at_raw = data.get("created_at")
        return cls(
            id=data["id"],
            severity=Severity(data.get("severity", Severity.INFO.value)),
            category=Category(data.get("category", Category.SAST.value)),
            title=data.get("title", ""),
            endpoint=data.get("endpoint", ""),
            parameter=data.get("parameter"),
            evidence=data.get("evidence", ""),
            impact=data.get("impact", ""),
            remediation=data.get("remediation", ""),
            cwe=data.get("cwe"),
            owasp=data.get("owasp"),
            references=list(data.get("references") or []),
            status=FindingStatus(data.get("status", FindingStatus.OPEN.value)),
            created_at=(
                datetime.fromisoformat(created_at_raw)
                if created_at_raw
                else datetime.now(timezone.utc)
            ),
            file_path=data.get("file_path"),
            line_number=data.get("line_number"),
        )

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "id": self.id,
            "severity": self.severity.value,
            "category": self.category.value,
            "title": self.title,
            "endpoint": self.endpoint,
            "parameter": self.parameter,
            "evidence": self.evidence,
            "impact": self.impact,
            "remediation": self.remediation,
            "cwe": self.cwe,
            "owasp": self.owasp,
            "references": self.references,
            "status": self.status.value,
            "created_at": self.created_at.isoformat(),
            "file_path": self.file_path,
            "line_number": self.line_number,
        }


@dataclass(frozen=True, slots=True)
class Target:
    """Represents a scan target."""

    url: str
    project_root: str
    config_path: str | None = None

    @property
    def host(self) -> str:
        """Extract host from URL."""
        from urllib.parse import urlparse

        return urlparse(self.url).netloc

    @property
    def scheme(self) -> str:
        """Extract scheme from URL."""
        from urllib.parse import urlparse

        return urlparse(self.url).scheme

    @property
    def base_url(self) -> str:
        """Get base URL (scheme + host)."""
        from urllib.parse import urlparse

        parsed = urlparse(self.url)
        return f"{parsed.scheme}://{parsed.netloc}"


@dataclass(frozen=True, slots=True)
class ScanResult:
    """Represents the result of a complete scan."""

    target: Target
    findings: list[Finding]
    start_time: datetime
    end_time: datetime
    duration_seconds: float
    auditors_run: list[str]
    errors: list[str] = field(default_factory=list)

    @property
    def severity_counts(self) -> dict[Severity, int]:
        """Count findings by severity."""
        counts = dict.fromkeys(Severity, 0)
        for finding in self.findings:
            counts[finding.severity] += 1
        return counts

    @property
    def total_findings(self) -> int:
        """Total number of findings."""
        return len(self.findings)

    @property
    def category_counts(self) -> dict[Category, int]:
        """Count findings by category."""
        counts = dict.fromkeys(Category, 0)
        for finding in self.findings:
            counts[finding.category] += 1
        return counts

    @property
    def has_critical_or_high(self) -> bool:
        """Check if there are Critical or High findings."""
        return any(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in self.findings)

    @property
    def exit_code(self) -> int:
        """Determine exit code based on findings and errors.

        Exit codes:
        - 0 (CLEAN): No Critical/High findings
        - 1 (VULNERABILITIES_FOUND): Has Critical/High findings
        - 2 (RUNTIME_ERROR): System/config errors (not network errors)
        - 3 (BLOCKED): Target blocked by host validation
        """
        from localguard.core.constants import ExitCode

        # Check for critical/high findings first
        if self.has_critical_or_high:
            return ExitCode.VULNERABILITIES_FOUND

        # Check for non-network errors (system/config errors)
        # Network errors from DAST auditors are expected when target is down
        non_network_errors = [
            e
            for e in self.errors
            if not any(
                net_err in e.lower()
                for net_err in [
                    "connection refused",
                    "connection timeout",
                    "connection error",
                    "network error",
                    "unreachable",
                    "failed to connect",
                    "name or service not known",
                    "connect call failed",
                ]
            )
        ]

        if non_network_errors:
            return ExitCode.RUNTIME_ERROR

        return ExitCode.CLEAN

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "target": self.target.url,
            "project_root": self.target.project_root,
            "scan_duration_seconds": self.duration_seconds,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat(),
            "auditors_run": self.auditors_run,
            "errors": self.errors,
            "severity_counts": {k.value: v for k, v in self.severity_counts.items()},
            "category_counts": {k.value: v for k, v in self.category_counts.items()},
            "findings": [f.to_dict() for f in self.findings],
            "exit_code": self.exit_code,
        }

    @classmethod
    def from_report_dict(cls, data: dict) -> "ScanResult":
        """Reconstruct a ScanResult from a JSON report (see JSONReportWriter.write)."""
        target_data = data.get("target", {})
        scan_info = data.get("scan_info", {})
        now = datetime.now(timezone.utc)

        def _parse_dt(value: str | None) -> datetime:
            if not value:
                return now
            parsed = datetime.fromisoformat(value)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed

        return cls(
            target=Target(
                url=target_data.get("url", ""),
                project_root=target_data.get("project_root", "."),
            ),
            findings=[Finding.from_dict(f) for f in data.get("findings", [])],
            start_time=_parse_dt(scan_info.get("start_time")),
            end_time=_parse_dt(scan_info.get("end_time")),
            duration_seconds=float(scan_info.get("duration_seconds", 0.0)),
            auditors_run=list(scan_info.get("auditors_run") or []),
            errors=list(data.get("errors") or []),
        )
