"""Terminal report renderer for LocalGuard-Pro."""

import logging

from rich.box import ROUNDED
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from localguard.core.config import ReportConfig
from localguard.core.constants import Category, ExitCode, Severity
from localguard.core.models import Finding, ScanResult

logger = logging.getLogger(__name__)


class TerminalRenderer:
    """Renders scan results to terminal with rich formatting."""

    def __init__(self, config: ReportConfig):
        self.config = config
        self.console = Console()

    def render(self, result: ScanResult) -> None:
        """Render complete scan report to terminal."""
        self._render_header(result)
        self._render_statistics(result)
        self._render_category_breakdown(result)
        self._render_top_findings(result)
        self._render_footer(result)

    def _render_header(self, result: ScanResult) -> None:
        """Render scan header with target info."""
        duration_str = f"{result.duration_seconds:.2f}s"
        start_time = result.start_time.strftime("%Y-%m-%d %H:%M:%S")
        end_time = result.end_time.strftime("%Y-%m-%d %H:%M:%S")

        header_text = Text()
        header_text.append("LocalGuard-Pro Security Audit Report\n", style="bold cyan")
        header_text.append(f"Target: {result.target.url}\n", style="yellow")
        header_text.append(f"Project: {result.target.project_root}\n", style="dim")
        header_text.append(
            f"Scan Duration: {duration_str} | Started: {start_time} | Completed: {end_time}\n",
            style="dim",
        )

        panel = Panel(
            header_text,
            title="[bold cyan]Scan Summary[/bold cyan]",
            border_style="cyan",
            box=ROUNDED,
        )
        self.console.print(panel)
        self.console.print()

    def _render_statistics(self, result: ScanResult) -> None:
        """Render severity statistics table."""
        severity_counts = result.severity_counts
        total = sum(severity_counts.values())

        table = Table(title="[bold]Findings by Severity[/bold]", box=ROUNDED, show_header=True)
        table.add_column("Severity", style="bold", width=12)
        table.add_column("Count", justify="right", width=8)
        table.add_column("Percentage", justify="right", width=12)
        table.add_column("Visual", width=30)

        severity_order = [
            (Severity.CRITICAL, "Critical", "red"),
            (Severity.HIGH, "High", "red"),
            (Severity.MEDIUM, "Medium", "yellow"),
            (Severity.LOW, "Low", "green"),
            (Severity.INFO, "Info", "blue"),
        ]

        for severity, label, color in severity_order:
            count = severity_counts.get(severity, 0)
            pct = (count / total * 100) if total > 0 else 0
            bar = "#" * int(pct / 5) if pct > 0 else ""
            table.add_row(
                f"[{color}]{label}[/{color}]",
                f"[{color}]{count}[/{color}]",
                f"[{color}]{pct:.1f}%[/{color}]",
                f"[{color}]{bar}[/{color}]",
            )

        # Total row
        table.add_row(
            "[bold]Total[/bold]",
            f"[bold]{total}[/bold]",
            "[bold]100.0%[/bold]",
            "",
        )

        self.console.print(table)
        self.console.print()

    def _render_category_breakdown(self, result: ScanResult) -> None:
        """Render findings by category."""
        category_counts = result.category_counts

        table = Table(title="[bold]Findings by Category[/bold]", box=ROUNDED, show_header=True)
        table.add_column("Category", style="bold", width=12)
        table.add_column("Count", justify="right", width=8)
        table.add_column("Percentage", justify="right", width=12)

        for category in Category:
            count = category_counts.get(category, 0)
            pct = (
                (count / sum(category_counts.values()) * 100)
                if sum(category_counts.values()) > 0
                else 0
            )
            color = self._get_category_color(category)
            table.add_row(
                f"[{color}]{category.value}[/{color}]",
                f"[{color}]{count}[/{color}]",
                f"[{color}]{pct:.1f}%[/{color}]",
            )

        self.console.print(table)
        self.console.print()

    def _get_category_color(self, category: Category) -> str:
        """Get color for category."""
        colors = {
            Category.DAST: "cyan",
            Category.SAST: "green",
            Category.SCA: "blue",
        }
        return colors.get(category, "white")

    def _render_top_findings(self, result: ScanResult) -> None:
        """Render top critical/high findings."""
        critical_high = [
            f for f in result.findings if f.severity in (Severity.CRITICAL, Severity.HIGH)
        ]

        if not critical_high:
            self.console.print(
                Panel(
                    "[green][OK] No Critical or High severity findings detected![/green]",
                    title="[bold green]Top Findings[/bold green]",
                    border_style="green",
                    box=ROUNDED,
                )
            )
            return

        # Sort by severity (Critical first) then by title
        critical_high.sort(key=lambda f: (0 if f.severity == Severity.CRITICAL else 1, f.title))

        self.console.print(
            f"[bold red]Top {min(5, len(critical_high))} Critical/High Findings:[/bold red]"
        )
        self.console.print()

        for i, finding in enumerate(critical_high[:5], 1):
            severity_color = "red" if finding.severity == Severity.CRITICAL else "red"
            severity_label = finding.severity.value

            finding_panel = Panel(
                self._format_finding_detail(finding),
                title=f"[bold {severity_color}]{i}. {finding.title}[/bold {severity_color}] [{severity_color}]{severity_label}[/{severity_color}]",
                subtitle=f"[dim]{finding.id} | {finding.category.value}[/dim]",
                border_style=severity_color,
                box=ROUNDED,
            )
            self.console.print(finding_panel)

        if len(critical_high) > 5:
            self.console.print(
                f"[dim]... and {len(critical_high) - 5} more Critical/High findings[/dim]"
            )
        self.console.print()

    def _format_finding_detail(self, finding: Finding) -> Text:
        """Format finding detail as rich text."""
        text = Text()
        text.append("Endpoint: ", style="bold")
        text.append(f"{finding.endpoint}\n", style="cyan")

        if finding.parameter:
            text.append("Parameter: ", style="bold")
            text.append(f"{finding.parameter}\n", style="yellow")

        if finding.file_path:
            text.append("File: ", style="bold")
            text.append(f"{finding.file_path}", style="yellow")
            if finding.line_number:
                text.append(f":{finding.line_number}", style="yellow")
            text.append("\n")

        text.append("Evidence: ", style="bold")
        text.append(
            f"{finding.evidence[:200]}{'...' if len(finding.evidence) > 200 else ''}\n", style="dim"
        )

        text.append("Impact: ", style="bold")
        text.append(
            f"{finding.impact[:150]}{'...' if len(finding.impact) > 150 else ''}\n", style="red"
        )

        text.append("Remediation: ", style="bold")
        text.append(
            f"{finding.remediation[:150]}{'...' if len(finding.remediation) > 150 else ''}",
            style="green",
        )

        return text

    def _render_footer(self, result: ScanResult) -> None:
        """Render scan footer with exit code info."""
        exit_code = result.exit_code
        exit_messages = {
            ExitCode.CLEAN: ("[green]CLEAN[/green]", "No Critical/High findings"),
            ExitCode.VULNERABILITIES_FOUND: (
                "[red]VULNERABILITIES FOUND[/red]",
                "Critical/High findings detected",
            ),
            ExitCode.RUNTIME_ERROR: ("[red]RUNTIME ERROR[/red]", "Scan encountered errors"),
            ExitCode.BLOCKED: ("[yellow]BLOCKED[/yellow]", "Target blocked by host validation"),
        }

        label, msg = exit_messages.get(
            ExitCode(exit_code), ("[dim]UNKNOWN[/dim]", "Unknown status")
        )

        footer_text = Text()
        footer_text.append(f"Exit Code: {exit_code} ({label})\n", style="bold")
        footer_text.append(f"{msg}\n", style="dim")
        footer_text.append(f"Total Findings: {len(result.findings)} | ", style="dim")
        footer_text.append(f"Auditors Run: {', '.join(result.auditors_run)}", style="dim")

        if result.errors:
            footer_text.append(f"\nErrors: {len(result.errors)}", style="red")

        panel = Panel(
            footer_text,
            title="[bold]Scan Complete[/bold]",
            border_style="green" if exit_code == ExitCode.CLEAN else "red",
            box=ROUNDED,
        )
        self.console.print(panel)
