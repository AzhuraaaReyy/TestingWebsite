"""Rich console setup for LocalGuard-Pro."""

from rich.console import Console
from rich.theme import Theme

# Custom theme for LocalGuard-Pro
LOCALGUARD_THEME = Theme(
    {
        "info": "cyan",
        "warning": "yellow",
        "danger": "red",
        "success": "green",
        "critical": "bold red",
        "high": "red",
        "medium": "yellow",
        "low": "green",
        "debug": "dim cyan",
        "path": "blue",
        "url": "underline cyan",
        "finding_id": "bold magenta",
        "severity.critical": "bold red on white",
        "severity.high": "red",
        "severity.medium": "yellow",
        "severity.low": "green",
        "severity.info": "cyan",
    }
)

console = Console(theme=LOCALGUARD_THEME)
error_console = Console(stderr=True, theme=LOCALGUARD_THEME)


def print_banner():
    """Print LocalGuard-Pro banner."""
    console.print("""
[bold cyan]╔══════════════════════════════════════════════════════════╗
║                    LocalGuard-Pro v1.0.0                    ║
║         Internal Security Auditor for Local/Staging         ║
║                    DAST + SAST + SCA                        ║
╚══════════════════════════════════════════════════════════╝[/bold cyan]
""")


def print_legal_warning():
    """Print legal warning."""
    from localguard.core.constants import LEGAL_WARNING

    console.print(LEGAL_WARNING)


def print_scan_start(target: str, project_root: str):
    """Print scan start information."""
    from rich.panel import Panel

    console.print(
        Panel.fit(
            f"[bold]Target:[/bold] [url]{target}[/url]\n"
            f"[bold]Project:[/bold] [path]{project_root}[/path]",
            title="[cyan]Starting Security Scan[/cyan]",
            border_style="cyan",
        )
    )


def print_scan_complete(duration: float, findings_count: int, exit_code: int):
    """Print scan completion summary."""
    from rich.panel import Panel

    from localguard.core.constants import ExitCode

    status_map = {
        ExitCode.CLEAN: ("[success]CLEAN[/success]", "No High/Critical findings"),
        ExitCode.VULNERABILITIES_FOUND: (
            "[danger]VULNERABILITIES FOUND[/danger]",
            "High/Critical findings detected",
        ),
        ExitCode.RUNTIME_ERROR: ("[danger]ERROR[/danger]", "Runtime error occurred"),
        ExitCode.BLOCKED: ("[warning]BLOCKED[/warning]", "Target not allowed"),
    }

    status, msg = status_map.get(ExitCode(exit_code), ("[dim]UNKNOWN[/dim]", "Unknown status"))

    console.print(
        Panel.fit(
            f"[bold]Duration:[/bold] {duration:.2f}s\n"
            f"[bold]Findings:[/bold] {findings_count}\n"
            f"[bold]Status:[/bold] {status}\n"
            f"[dim]{msg}[/dim]",
            title="[cyan]Scan Complete[/cyan]",
            border_style="green" if exit_code == ExitCode.CLEAN else "red",
        )
    )
