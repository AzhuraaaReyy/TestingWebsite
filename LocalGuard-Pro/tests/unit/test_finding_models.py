"""Unit tests for Finding models."""

from datetime import datetime, timezone

from localguard.core.constants import Category, Severity
from localguard.core.models import Finding, FindingStatus, ScanResult, Target


class TestFinding:
    """Tests for Finding model."""

    def test_finding_creation(self):
        """Test creating a finding."""
        finding = Finding(
            id="LG-TEST-001",
            severity=Severity.HIGH,
            category=Category.DAST,
            title="Test Finding",
            endpoint="http://localhost:8000/api/test",
            parameter="id",
            evidence="Test evidence",
            impact="Test impact",
            remediation="Test remediation",
            cwe="CWE-123",
            owasp="A01:2021",
            references=["https://example.com"],
        )

        assert finding.id == "LG-TEST-001"
        assert finding.severity == Severity.HIGH
        assert finding.category == Category.DAST
        assert finding.status == FindingStatus.OPEN
        assert isinstance(finding.created_at, datetime)

    def test_finding_to_dict(self):
        """Test finding serialization to dict."""
        finding = Finding(
            id="LG-TEST-001",
            severity=Severity.HIGH,
            category=Category.DAST,
            title="Test Finding",
            endpoint="http://localhost:8000/api/test",
        )

        data = finding.to_dict()

        assert data["id"] == "LG-TEST-001"
        assert data["severity"] == "High"
        assert data["category"] == "DAST"
        assert data["title"] == "Test Finding"
        assert data["endpoint"] == "http://localhost:8000/api/test"
        assert "created_at" in data

    def test_finding_sorting(self):
        """Test findings sort by severity (Critical first)."""
        findings = [
            Finding(
                id="1",
                severity=Severity.LOW,
                category=Category.DAST,
                title="Low",
                endpoint="http://test",
            ),
            Finding(
                id="2",
                severity=Severity.CRITICAL,
                category=Category.DAST,
                title="Critical",
                endpoint="http://test",
            ),
            Finding(
                id="3",
                severity=Severity.HIGH,
                category=Category.DAST,
                title="High",
                endpoint="http://test",
            ),
            Finding(
                id="4",
                severity=Severity.MEDIUM,
                category=Category.DAST,
                title="Medium",
                endpoint="http://test",
            ),
        ]

        sorted_findings = sorted(findings)

        assert sorted_findings[0].severity == Severity.CRITICAL
        assert sorted_findings[1].severity == Severity.HIGH
        assert sorted_findings[2].severity == Severity.MEDIUM
        assert sorted_findings[3].severity == Severity.LOW


class TestTarget:
    """Tests for Target model."""

    def test_target_creation(self):
        """Test creating a target."""
        target = Target(
            url="http://localhost:8000/api/test",
            project_root="/path/to/project",
        )

        assert target.url == "http://localhost:8000/api/test"
        assert target.project_root == "/path/to/project"

    def test_target_host_property(self):
        """Test host property extraction."""
        target = Target(url="http://localhost:8000/api/test", project_root="/tmp")
        assert target.host == "localhost:8000"

        target2 = Target(url="https://example.com:8443/path", project_root="/tmp")
        assert target2.host == "example.com:8443"

    def test_target_scheme_property(self):
        """Test scheme property extraction."""
        target = Target(url="https://localhost:8000", project_root="/tmp")
        assert target.scheme == "https"

    def test_target_base_url_property(self):
        """Test base_url property."""
        target = Target(url="http://localhost:8000/api/test?param=1", project_root="/tmp")
        assert target.base_url == "http://localhost:8000"


class TestScanResult:
    """Tests for ScanResult model."""

    def setup_method(self):
        self.target = Target(url="http://localhost:8000", project_root="/tmp")
        self.findings = [
            Finding(
                id="1",
                severity=Severity.CRITICAL,
                category=Category.DAST,
                title="Critical",
                endpoint="http://test",
            ),
            Finding(
                id="2",
                severity=Severity.HIGH,
                category=Category.SAST,
                title="High",
                endpoint="http://test",
            ),
            Finding(
                id="3",
                severity=Severity.MEDIUM,
                category=Category.SCA,
                title="Medium",
                endpoint="http://test",
            ),
            Finding(
                id="4",
                severity=Severity.LOW,
                category=Category.DAST,
                title="Low",
                endpoint="http://test",
            ),
            Finding(
                id="5",
                severity=Severity.INFO,
                category=Category.SCA,
                title="Info",
                endpoint="http://test",
            ),
        ]

    def test_scan_result_creation(self):
        """Test creating a scan result."""
        start_time = datetime.now(timezone.utc)
        end_time = datetime.now(timezone.utc)

        result = ScanResult(
            target=Target(url="http://localhost:8000", project_root="/tmp"),
            findings=self.findings,
            start_time=start_time,
            end_time=end_time,
            duration_seconds=10.5,
            auditors_run=["DAST-HeaderCookie", "SAST-Secrets"],
            errors=["Test error"],
        )

        assert result.target.url == "http://localhost:8000"
        assert len(result.findings) == 5
        assert result.duration_seconds == 10.5
        assert "DAST-HeaderCookie" in result.auditors_run

    def test_severity_counts(self):
        """Test severity counts property."""
        result = ScanResult(
            target=Target(url="http://localhost:8000", project_root="/tmp"),
            findings=self.findings,
            start_time=datetime.now(timezone.utc),
            end_time=datetime.now(timezone.utc),
            duration_seconds=10.0,
            auditors_run=[],
            errors=[],
        )

        counts = result.severity_counts
        assert counts[Severity.CRITICAL] == 1
        assert counts[Severity.HIGH] == 1
        assert counts[Severity.MEDIUM] == 1
        assert counts[Severity.LOW] == 1
        assert counts[Severity.INFO] == 1

    def test_category_counts(self):
        """Test category counts property."""
        result = ScanResult(
            target=Target(url="http://localhost:8000", project_root="/tmp"),
            findings=self.findings,
            start_time=datetime.now(timezone.utc),
            end_time=datetime.now(timezone.utc),
            duration_seconds=10.0,
            auditors_run=[],
            errors=[],
        )

        counts = result.category_counts
        assert counts[Category.DAST] == 2
        assert counts[Category.SAST] == 1
        assert counts[Category.SCA] == 2

    def test_has_critical_or_high(self):
        """Test has_critical_or_high property."""
        # With critical
        result = ScanResult(
            target=Target(url="http://localhost:8000", project_root="/tmp"),
            findings=self.findings[:1],  # Only critical
            start_time=datetime.now(timezone.utc),
            end_time=datetime.now(timezone.utc),
            duration_seconds=10.0,
            auditors_run=[],
            errors=[],
        )
        assert result.has_critical_or_high is True

        # Without critical/high
        result2 = ScanResult(
            target=Target(url="http://localhost:8000", project_root="/tmp"),
            findings=self.findings[2:],  # Medium, Low, Info
            start_time=datetime.now(timezone.utc),
            end_time=datetime.now(timezone.utc),
            duration_seconds=10.0,
            auditors_run=[],
            errors=[],
        )
        assert result2.has_critical_or_high is False

    def test_exit_code_clean(self):
        """Test exit code for clean scan."""
        result = ScanResult(
            target=Target(url="http://localhost:8000", project_root="/tmp"),
            findings=[],  # No findings
            start_time=datetime.now(timezone.utc),
            end_time=datetime.now(timezone.utc),
            duration_seconds=10.0,
            auditors_run=[],
            errors=[],
        )
        assert result.exit_code == 0  # CLEAN

    def test_exit_code_vulnerabilities(self):
        """Test exit code for vulnerabilities found."""
        result = ScanResult(
            target=Target(url="http://localhost:8000", project_root="/tmp"),
            findings=self.findings,  # Has critical/high
            start_time=datetime.now(timezone.utc),
            end_time=datetime.now(timezone.utc),
            duration_seconds=10.0,
            auditors_run=[],
            errors=[],
        )
        assert result.exit_code == 1  # VULNERABILITIES_FOUND

    def test_exit_code_runtime_error(self):
        """Test exit code for runtime errors."""
        result = ScanResult(
            target=Target(url="http://localhost:8000", project_root="/tmp"),
            findings=[],
            start_time=datetime.now(timezone.utc),
            end_time=datetime.now(timezone.utc),
            duration_seconds=10.0,
            auditors_run=[],
            errors=["Config parse error", "File not found"],
        )
        assert result.exit_code == 2  # RUNTIME_ERROR

    def test_exit_code_network_errors_ignored(self):
        """Test that network errors don't trigger runtime error exit code."""
        result = ScanResult(
            target=Target(url="http://localhost:8000", project_root="/tmp"),
            findings=[],
            start_time=datetime.now(timezone.utc),
            end_time=datetime.now(timezone.utc),
            duration_seconds=10.0,
            auditors_run=[],
            errors=[
                "Connection refused",
                "Connection timeout",
                "Failed to connect to http://localhost:8000",
            ],
        )
        # Should be CLEAN (0) since only network errors
        assert result.exit_code == 0
