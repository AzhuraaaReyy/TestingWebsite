"""JSON report writer for LocalGuard-Pro."""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from localguard.core.config import ReportConfig
from localguard.core.models import Finding, ScanResult

logger = logging.getLogger(__name__)


class JSONReportWriter:
    """Writes scan results to JSON format."""

    def __init__(self, config: ReportConfig):
        self.config = config

    def write(self, result: ScanResult, output_path: Path) -> None:
        """Write scan result to JSON file."""
        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)

            report = {
                "metadata": {
                    "tool": "LocalGuard-Pro",
                    "version": "1.0.0",
                    "generated_at": datetime.now(timezone.utc).isoformat(),
                    "scan_id": f"lg-{int(datetime.now(timezone.utc).timestamp())}",
                },
                "target": {
                    "url": result.target.url,
                    "project_root": result.target.project_root,
                },
                "scan_info": {
                    "start_time": result.start_time.isoformat(),
                    "end_time": result.end_time.isoformat(),
                    "duration_seconds": result.duration_seconds,
                    "auditors_run": result.auditors_run,
                    "exit_code": result.exit_code,
                },
                "summary": {
                    "total_findings": len(result.findings),
                    "severity_counts": {k.value: v for k, v in result.severity_counts.items()},
                    "category_counts": {k.value: v for k, v in result.category_counts.items()},
                },
                "findings": [self._finding_to_dict(f) for f in result.findings],
                "errors": result.errors,
            }

            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2, ensure_ascii=False)

            logger.info(f"JSON report written to {output_path}")

        except Exception as e:
            logger.error(f"Failed to write JSON report: {e}")
            raise

    def _finding_to_dict(self, finding: Finding) -> dict:
        """Convert Finding to dictionary."""
        return {
            "id": finding.id,
            "severity": finding.severity.value,
            "category": finding.category.value,
            "title": finding.title,
            "endpoint": finding.endpoint,
            "parameter": finding.parameter,
            "evidence": finding.evidence,
            "impact": finding.impact,
            "remediation": finding.remediation,
            "cwe": finding.cwe,
            "owasp": finding.owasp,
            "references": finding.references,
            "status": finding.status.value,
            "created_at": finding.created_at.isoformat(),
            "file_path": finding.file_path,
            "line_number": finding.line_number,
        }
