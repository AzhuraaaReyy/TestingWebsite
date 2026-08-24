"""Base auditor classes for LocalGuard-Pro."""

from abc import ABC, abstractmethod
from dataclasses import dataclass

from localguard.core.config import DASTConfig, SASTConfig, SCAConfig
from localguard.core.constants import Category, Severity
from localguard.core.models import Finding, Target


@dataclass
class AuditorResult:
    """Result of an auditor run."""

    auditor_name: str
    findings: list[Finding]
    errors: list[str]
    duration_seconds: float


class BaseAuditor(ABC):
    """Abstract base class for all auditors."""

    def __init__(self, name: str):
        self.name = name

    @abstractmethod
    async def audit(self, target: Target, config) -> AuditorResult:
        """
        Run the audit.

        Args:
            target: Target to audit
            config: Configuration object

        Returns:
            AuditorResult with findings and errors
        """
        pass

    def _create_finding(
        self,
        finding_id: str,
        severity: Severity,
        category: Category,
        title: str,
        endpoint: str,
        parameter: str | None = None,
        evidence: str = "",
        impact: str = "",
        remediation: str = "",
        cwe: str | None = None,
        owasp: str | None = None,
        references: list[str] | None = None,
        file_path: str | None = None,
        line_number: int | None = None,
    ) -> Finding:
        """Helper to create a Finding with consistent ID format."""
        return Finding(
            id=finding_id,
            severity=severity,
            category=category,
            title=title,
            endpoint=endpoint,
            parameter=parameter,
            evidence=evidence,
            impact=impact,
            remediation=remediation,
            cwe=cwe,
            owasp=owasp,
            references=references or [],
            file_path=file_path,
            line_number=line_number,
        )


class DASTAuditor(BaseAuditor):
    """Base class for DAST auditors."""

    def __init__(self, name: str):
        super().__init__(f"DAST-{name}")

    @abstractmethod
    async def audit(self, target: Target, config: DASTConfig) -> AuditorResult:
        pass


class SASTAuditor(BaseAuditor):
    """Base class for SAST auditors."""

    def __init__(self, name: str):
        super().__init__(f"SAST-{name}")

    @abstractmethod
    async def audit(self, target: Target, config: SASTConfig) -> AuditorResult:
        pass


class SCAAuditor(BaseAuditor):
    """Base class for SCA auditors."""

    def __init__(self, name: str):
        super().__init__(f"SCA-{name}")

    @abstractmethod
    async def audit(self, target: Target, config: SCAConfig) -> AuditorResult:
        pass
