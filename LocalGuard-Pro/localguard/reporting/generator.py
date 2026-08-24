"""Report generator orchestration for LocalGuard-Pro."""

import logging
from datetime import datetime, timezone
from pathlib import Path

from localguard.core.config import ReportConfig
from localguard.core.models import ScanResult
from localguard.reporting.html_report import HTMLReportWriter
from localguard.reporting.json_report import JSONReportWriter
from localguard.reporting.terminal import TerminalRenderer

logger = logging.getLogger(__name__)


class ReportGenerator:
    """Generates reports in multiple formats."""

    def __init__(self, config: ReportConfig):
        self.config = config
        self.terminal_renderer = TerminalRenderer(config)
        self.json_writer = JSONReportWriter(config)
        self.html_writer = HTMLReportWriter(config)

    def generate(self, result: ScanResult) -> None:
        """Generate all configured report formats."""
        output_dir = Path(self.config.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        base_name = f"security_report_{timestamp}"

        # Terminal output (always)
        if "terminal" in self.config.formats:
            logger.info("Rendering terminal report...")
            self.terminal_renderer.render(result)

        # JSON report
        if "json" in self.config.formats:
            json_path = output_dir / f"{base_name}.json"
            logger.info(f"Writing JSON report to {json_path}")
            self.json_writer.write(result, json_path)

        # HTML report
        if "html" in self.config.formats:
            html_path = output_dir / f"{base_name}.html"
            logger.info(f"Writing HTML report to {html_path}")
            self.html_writer.write(result, html_path)

        logger.info(f"All reports generated in {output_dir}")
