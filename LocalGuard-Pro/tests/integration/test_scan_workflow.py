"""Integration tests for LocalGuard-Pro scan workflows."""

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from localguard.auditors.dast.header_cookie import HeaderCookieAuditor
from localguard.auditors.sast.secrets import SecretScanner
from localguard.auditors.sca.scanner import DependencyScanner
from localguard.core.config import ReportConfig, SASTConfig, SCAConfig, TargetConfig
from localguard.core.models import ScanResult, Target
from localguard.reporting.generator import ReportGenerator
from localguard.validation.host_validator import HostValidationEngine

pytestmark = pytest.mark.integration

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"
SAMPLE_PROJECT = FIXTURES_DIR / "sample_project"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _MinimalHandler(BaseHTTPRequestHandler):
    """Minimal HTTP server that emits no security headers (by design)."""

    def do_GET(self):  # noqa: N802
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<html><body>ok</body></html>")

    def log_message(self, *args):  # silence request logging
        pass


@pytest.fixture
def local_server():
    """Start a real local HTTP server on an ephemeral port."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), _MinimalHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://localhost:{server.server_address[1]}"
    server.shutdown()
    server.server_close()


@pytest.fixture
def sample_target():
    return Target(url="http://localhost", project_root=str(SAMPLE_PROJECT))


# ---------------------------------------------------------------------------
# SCA integration
# ---------------------------------------------------------------------------


class TestSCAIntegration:
    """End-to-end SCA scans against the vulnerable fixture project."""

    @pytest.mark.asyncio
    async def test_sca_finds_composer_vulnerability(self, sample_target):
        scanner = DependencyScanner()
        result = await scanner.audit(sample_target, SCAConfig())

        laravel = [f for f in result.findings if "CVE-2023-48217" in f.id]
        assert len(laravel) > 0
        assert "laravel-framework" in laravel[0].id

    @pytest.mark.asyncio
    async def test_sca_finds_npm_vulnerability(self, sample_target):
        scanner = DependencyScanner()
        result = await scanner.audit(sample_target, SCAConfig())

        lodash = [f for f in result.findings if "lodash" in f.id]
        assert len(lodash) > 0
        assert lodash[0].severity.value == "High"

    @pytest.mark.asyncio
    async def test_sca_finds_pip_vulnerability_when_enabled(self, sample_target):
        config = SCAConfig(ecosystems=["composer", "npm", "pip"])
        scanner = DependencyScanner()
        result = await scanner.audit(sample_target, config)

        django = [f for f in result.findings if "django" in f.id]
        assert len(django) > 0
        assert "CVE-2023-48229" in django[0].id

    @pytest.mark.asyncio
    async def test_sca_skips_pip_when_not_enabled(self, sample_target):
        config = SCAConfig(ecosystems=["composer"])
        scanner = DependencyScanner()
        result = await scanner.audit(sample_target, config)

        django = [f for f in result.findings if "django" in f.id]
        assert len(django) == 0


# ---------------------------------------------------------------------------
# SAST integration
# ---------------------------------------------------------------------------


class TestSASTIntegration:
    """End-to-end SAST scans against the fixture project.

    Fixtures are copied to a temp dir before scanning because the scanner
    (correctly) skips files under directories named "tests".
    """

    @pytest.fixture
    def copied_project(self, tmp_path):
        import shutil

        dest = tmp_path / "sample_project"
        shutil.copytree(SAMPLE_PROJECT, dest, dirs_exist_ok=True)
        return Target(url="http://localhost", project_root=str(dest))

    @pytest.mark.asyncio
    async def test_sast_finds_secrets_in_fixture_project(self, copied_project):
        scanner = SecretScanner()
        result = await scanner.audit(copied_project, SASTConfig())

        aws = [f for f in result.findings if "AWS" in f.title]
        assert len(aws) > 0
        assert aws[0].severity.value == "Critical"

        env_file = [f for f in result.findings if ".env.example" in (f.file_path or "")]
        assert len(env_file) > 0

    @pytest.mark.asyncio
    async def test_sast_respects_localguard_ignore(self, copied_project):
        project_root = Path(copied_project.project_root)
        ignore_file = project_root / ".localguard-ignore"
        ignore_file.write_text("config.py\n")

        # Fresh scanner instance so ignore patterns are reloaded
        scanner = SecretScanner()
        result = await scanner.audit(copied_project, SASTConfig())
        aws = [f for f in result.findings if "AWS" in f.title]
        assert len(aws) == 0


# ---------------------------------------------------------------------------
# DAST integration (real local HTTP server)
# ---------------------------------------------------------------------------


class TestDASTIntegration:
    """DAST audits against a real local HTTP server."""

    @pytest.mark.asyncio
    async def test_host_validation_accepts_local_server(self, local_server):
        engine = HostValidationEngine(TargetConfig())
        # Must not raise
        engine.validate(local_server)

    @pytest.mark.asyncio
    async def test_header_cookie_audit_runs_and_reports(self, local_server):
        from localguard.core.config import DASTConfig

        target = Target(url=local_server, project_root=".")
        auditor = HeaderCookieAuditor()
        result = await auditor.audit(target, DASTConfig(timeout=5, rate_limit_delay=0.1))

        assert not result.errors
        # The minimal server intentionally omits all security headers,
        # so the auditor must report missing headers.
        missing = [
            f for f in result.findings if "Missing" in f.title or "missing" in f.title.lower()
        ]
        assert len(missing) > 0


# ---------------------------------------------------------------------------
# Reporting end-to-end
# ---------------------------------------------------------------------------


class TestReportingIntegration:
    """Report generation from real scan results."""

    @pytest.mark.asyncio
    async def test_json_report_written_from_sca_results(self, sample_target, tmp_path):
        from datetime import datetime, timezone

        scanner = DependencyScanner()
        sca_result = await scanner.audit(
            sample_target, SCAConfig(ecosystems=["composer", "npm", "pip"])
        )

        now = datetime.now(timezone.utc)
        scan_result = ScanResult(
            target=sample_target,
            findings=sca_result.findings,
            start_time=now,
            end_time=now,
            duration_seconds=sca_result.duration_seconds,
            auditors_run=["Dependencies"],
            errors=sca_result.errors,
        )
        assert scan_result.exit_code == 1  # vulnerabilities found

        config = ReportConfig(output_dir=str(tmp_path), formats=["json"])
        ReportGenerator(config).generate(scan_result)

        reports = list(tmp_path.glob("security_report_*.json"))
        assert len(reports) == 1

        payload = json.loads(reports[0].read_text(encoding="utf-8"))
        flat = json.dumps(payload)
        assert "CVE-2023-48217" in flat
        assert "CVE-2023-48222" in flat

    @pytest.mark.asyncio
    async def test_html_report_renders_findings(self, sample_target, tmp_path):
        """Regression: template must receive findings; previously rendered 'No Findings!'."""
        from datetime import datetime, timezone

        scanner = DependencyScanner()
        sca_result = await scanner.audit(sample_target, SCAConfig(ecosystems=["composer"]))

        now = datetime.now(timezone.utc)
        scan_result = ScanResult(
            target=sample_target,
            findings=sca_result.findings,
            start_time=now,
            end_time=now,
            duration_seconds=1.0,
            auditors_run=["Dependencies"],
            errors=[],
        )
        config = ReportConfig(output_dir=str(tmp_path), formats=["html"])
        ReportGenerator(config).generate(scan_result)

        html_files = list(tmp_path.glob("security_report_*.html"))
        assert len(html_files) == 1
        html = html_files[0].read_text(encoding="utf-8")

        assert "No Findings!" not in html
        # Every SCA finding must appear as a card in the findings container
        assert html.count('class="card finding-card') == len(sca_result.findings)
        assert len(sca_result.findings) > 0
        assert "Vulnerable Dependency" in html
