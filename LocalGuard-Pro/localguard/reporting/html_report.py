"""HTML report writer for LocalGuard-Pro."""

import logging
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from localguard.core.config import ReportConfig
from localguard.core.constants import Category, Severity
from localguard.core.models import ScanResult

logger = logging.getLogger(__name__)


class HTMLReportWriter:
    """Writes scan results to HTML format with Bootstrap 5."""

    def __init__(self, config: ReportConfig):
        self.config = config
        # Template ships inside the package (localguard/templates/) so it is
        # available in wheel installs regardless of CWD; fall back to CWD for
        # project-local template overrides.
        package_templates = Path(__file__).resolve().parent.parent / "templates"
        cwd_templates = Path.cwd() / "templates"
        if package_templates.exists():
            self.templates_dir = package_templates
        elif cwd_templates.exists():
            self.templates_dir = cwd_templates
        else:  # pragma: no cover - templates ship with the package
            self.templates_dir = package_templates
        self._setup_jinja()

    def _setup_jinja(self) -> None:
        """Setup Jinja2 environment."""
        # nosec: python.flask.security.xss.audit.direct-use-of-jinja2
        self.jinja_env = Environment(
            loader=FileSystemLoader(self.templates_dir),
            autoescape=select_autoescape(["html", "xml"]),
            trim_blocks=True,
            lstrip_blocks=True,
        )
        # Add custom filters
        self.jinja_env.filters["severity_color"] = self._severity_color
        self.jinja_env.filters["severity_badge"] = self._severity_badge

    def _severity_color(self, severity: Severity) -> str:
        """Get Bootstrap color class for severity."""
        colors = {
            Severity.CRITICAL: "danger",
            Severity.HIGH: "danger",
            Severity.MEDIUM: "warning",
            Severity.LOW: "success",
            Severity.INFO: "info",
        }
        return colors.get(severity, "secondary")

    def _severity_badge(self, severity: Severity) -> str:
        """Get Bootstrap badge class for severity."""
        badges = {
            Severity.CRITICAL: "bg-danger",
            Severity.HIGH: "bg-danger",
            Severity.MEDIUM: "bg-warning text-dark",
            Severity.LOW: "bg-success",
            Severity.INFO: "bg-info",
        }
        return badges.get(severity, "bg-secondary")

    def write(self, result: ScanResult, output_path: Path) -> None:
        """Write scan result to HTML file."""
        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)

            template = self.jinja_env.get_template("report.html.j2")

            html = template.render(
                result=result,
                findings=result.findings,
                config=self.config,
                report_title=self.config.title,
                company_name=self.config.company_name,
                html_theme=self.config.html_theme,
                severity_order=[
                    Severity.CRITICAL,
                    Severity.HIGH,
                    Severity.MEDIUM,
                    Severity.LOW,
                    Severity.INFO,
                ],
                categories=[Category.DAST, Category.SAST, Category.SCA],
                generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            )

            with open(output_path, "w", encoding="utf-8") as f:
                f.write(html)

            logger.info(f"HTML report written to {output_path}")

        except Exception as e:
            logger.error(f"Failed to write HTML report: {e}")
            raise
