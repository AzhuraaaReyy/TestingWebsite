"""Main CLI entry point for LocalGuard-Pro."""

import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path

import typer
import yaml
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)

from localguard.auditors import (
    AccessControlAuditor,
    CORSAuditor,
    DependencyScanner,
    FormInjectionAuditor,
    HeaderCookieAuditor,
    SecretScanner,
    SensitivePathScanner,
)
from localguard.core.config import Config, DASTConfig
from localguard.core.constants import LEGAL_WARNING, ExitCode
from localguard.core.exceptions import ConsentError, LocalGuardError, ValidationError
from localguard.core.models import ScanResult, Target
from localguard.http import RateLimitedHTTPClient
from localguard.reporting import ReportGenerator
from localguard.reporting.html_report import HTMLReportWriter
from localguard.reporting.json_report import JSONReportWriter
from localguard.reporting.terminal import TerminalRenderer
from localguard.validation import ConsentManager, HostValidationEngine

app = typer.Typer(
    name="localguard",
    help="LocalGuard-Pro - Internal Security Auditor for Local/Staging Web Applications",
    add_completion=True,
    rich_markup_mode="rich",
)

console = Console()


def version_callback(value: bool):
    if value:
        from localguard import __version__

        console.print(f"LocalGuard-Pro v{__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        False,
        "--version",
        "-v",
        callback=version_callback,
        is_eager=True,
        help="Show version and exit",
    ),
    config: str | None = typer.Option(None, "--config", "-c", help="Path to config file"),
    verbose: bool = typer.Option(False, "--verbose", help="Enable verbose output"),
):
    """
    LocalGuard-Pro - Internal Security Auditor

    Triple-layer security audit: DAST + SAST + SCA
    Target: React TypeScript + Laravel/Supabase applications
    """
    pass


async def run_scan(
    target_url: str,
    project_root: str,
    config_file: str | None,
    online_cve: bool,
    output_dir: str | None,
    auto_consent: bool,
    formats: str | None,
) -> ScanResult:
    """Run the complete security scan."""

    # Load configuration
    config = Config.load_from_file(config_file)

    # Override config with CLI args
    if online_cve:
        config.scan.sca.online_cve = True
    if output_dir:
        config.scan.report.output_dir = output_dir
    if formats:
        config.scan.report.formats = [f.strip() for f in formats.split(",")]

    # 1. Host Validation
    console.print("[cyan]Validating target host...[/cyan]")
    validator = HostValidationEngine(config.scan.target)
    try:
        validator.validate(target_url)
    except ValidationError as e:
        console.print(LEGAL_WARNING)
        console.print(f"[red]Blocked: {e.message}[/red]")
        raise typer.Exit(ExitCode.BLOCKED) from e

    # 2. Consent
    console.print("[cyan]Requesting consent...[/cyan]")
    consent_manager = ConsentManager(auto_consent=auto_consent)
    try:
        consent_manager.request_consent(target_url, non_interactive=auto_consent)
    except ConsentError as e:
        console.print(f"[red]Consent required: {e.message}[/red]")
        raise typer.Exit(ExitCode.RUNTIME_ERROR) from e

    # 3. Create Target
    target = Target(
        url=target_url,
        project_root=project_root,
        config_path=config_file,
    )

    # Quick connectivity check for DAST auditors (very short timeout)
    console.print("[cyan]Checking target connectivity...[/cyan]")
    dast_enabled = True
    try:
        # Create a client with very short timeout for quick connectivity check
        # (values must satisfy DASTConfig constraints: timeout >= 5, rate_limit_delay >= 0.1)
        quick_config = DASTConfig(timeout=5, rate_limit_delay=0.1, follow_redirects=False)
        async with RateLimitedHTTPClient(quick_config) as client:
            resp = await client.get(target.base_url)
            if resp.status_code >= 500:
                console.print(
                    f"[yellow]Target returned {resp.status_code}, DAST auditors may have limited results[/yellow]"
                )
    except Exception as e:
        console.print(f"[yellow]Target unreachable: {e}. Skipping DAST auditors.[/yellow]")
        dast_enabled = False

    # 4. Run Auditors
    start_time = datetime.now(timezone.utc)
    all_findings = []
    auditors_run = []
    errors = []

    # Initialize auditors
    dast_auditors = [
        ("HeaderCookie", HeaderCookieAuditor()),
        ("SensitivePaths", SensitivePathScanner()),
        ("FormsInjection", FormInjectionAuditor()),
        ("AccessControl", AccessControlAuditor()),
        ("CORS", CORSAuditor()),
    ]

    sast_auditors = [
        ("Secrets", SecretScanner()),
    ]

    sca_auditors = [
        ("Dependencies", DependencyScanner()),
    ]

    # Prepare progress display
    total_auditors = (
        (len(dast_auditors) if dast_enabled else 0) + len(sast_auditors) + len(sca_auditors)
    )

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        overall_task = progress.add_task("[cyan]Overall Progress", total=total_auditors)

        # Run DAST auditors (only if target is reachable)
        if dast_enabled:
            for name, dast_auditor in dast_auditors:
                task = progress.add_task(f"[cyan]{name}", total=1)
                try:
                    progress.update(task, description=f"[cyan]Running {name}...")
                    auditor_result = await dast_auditor.audit(target, config.scan.dast)
                    all_findings.extend(auditor_result.findings)
                    errors.extend(auditor_result.errors)
                    auditors_run.append(f"DAST-{name}")
                    progress.update(task, completed=1)
                except Exception as e:
                    errors.append(f"DAST-{name}: {str(e)}")
                    progress.update(task, completed=1)
                progress.update(overall_task, advance=1)
        else:
            console.print("[yellow]Skipping DAST auditors (target unreachable)[/yellow]")

        # Run SAST auditors
        for name, sast_auditor in sast_auditors:
            task = progress.add_task(f"[green]{name}", total=1)
            try:
                progress.update(task, description=f"[green]Running {name}...")
                auditor_result = await sast_auditor.audit(target, config.scan.sast)
                all_findings.extend(auditor_result.findings)
                errors.extend(auditor_result.errors)
                auditors_run.append(f"SAST-{name}")
                progress.update(task, completed=1)
            except Exception as e:
                errors.append(f"SAST-{name}: {str(e)}")
                progress.update(task, completed=1)
            progress.update(overall_task, advance=1)

        # Run SCA auditors
        for name, sca_auditor in sca_auditors:
            task = progress.add_task(f"[blue]{name}", total=1)
            try:
                progress.update(task, description=f"[blue]Running {name}...")
                auditor_result = await sca_auditor.audit(target, config.scan.sca)
                all_findings.extend(auditor_result.findings)
                errors.extend(auditor_result.errors)
                auditors_run.append(f"SCA-{name}")
                progress.update(task, completed=1)
            except Exception as e:
                errors.append(f"SCA-{name}: {str(e)}")
                progress.update(task, completed=1)
            progress.update(overall_task, advance=1)

    # Create scan result
    end_time = datetime.now(timezone.utc)
    scan_result = ScanResult(
        target=target,
        findings=all_findings,
        start_time=start_time,
        end_time=end_time,
        duration_seconds=(end_time - start_time).total_seconds(),
        auditors_run=auditors_run,
        errors=errors,
    )

    return scan_result


@app.command()
def scan(
    target: str = typer.Option(..., "--target", "-t", help="Target URL (must be local)"),
    project_root: str = typer.Option(".", "--project-root", "-p", help="Project root directory"),
    config_file: str | None = typer.Option(None, "--config", "-c", help="Config file path"),
    online_cve: bool = typer.Option(False, "--online-cve", help="Enable online CVE lookup"),
    output_dir: str | None = typer.Option(None, "--output-dir", "-o", help="Output directory"),
    auto_consent: bool = typer.Option(False, "--auto-consent", help="Skip consent prompt (CI/CD)"),
    formats: str | None = typer.Option(
        None, "--formats", "-f", help="Report formats (json,html,terminal)"
    ),
):
    """
    Run security scan on target application.

    Performs DAST, SAST, and SCA audits.
    """
    try:
        console.print(
            Panel.fit(
                "[bold cyan]LocalGuard-Pro Security Scan[/bold cyan]\n"
                f"Target: [yellow]{target}[/yellow]\n"
                f"Project: [yellow]{project_root}[/yellow]",
                border_style="cyan",
            )
        )

        # Run scan
        result = asyncio.run(
            run_scan(
                target_url=target,
                project_root=project_root,
                config_file=config_file,
                online_cve=online_cve,
                output_dir=output_dir,
                auto_consent=auto_consent,
                formats=formats,
            )
        )

        # Generate reports
        config = Config.load_from_file(None)
        # Re-apply CLI options: run_scan used its own config instance,
        # so without this the -o/--formats options would be silently ignored.
        if output_dir:
            config.scan.report.output_dir = output_dir
        if formats:
            config.scan.report.formats = [f.strip() for f in formats.split(",")]

        report_generator = ReportGenerator(config.scan.report)
        report_generator.generate(result)

        # Exit with appropriate code
        raise typer.Exit(result.exit_code)

    except LocalGuardError as e:
        console.print(f"[red]Error: {e.message}[/red]")
        raise typer.Exit(e.exit_code) from e
    except typer.Exit:
        raise
    except Exception as e:
        console.print(f"[red]Unexpected error: {e}[/red]")
        raise typer.Exit(ExitCode.RUNTIME_ERROR) from e


@app.command()
def report(
    input_file: str = typer.Argument(..., help="Input JSON report file"),
    format: str = typer.Option(
        "html", "--format", "-f", help="Output format (html, json, terminal)"
    ),
    output: str | None = typer.Option(None, "--output", "-o", help="Output file path"),
):
    """
    Generate report from existing scan results.
    """
    input_path = Path(input_file)
    if not input_path.exists():
        console.print(f"[red]Input file not found: {input_file}[/red]")
        raise typer.Exit(ExitCode.RUNTIME_ERROR)

    try:
        data = json.loads(input_path.read_text(encoding="utf-8"))
        result = ScanResult.from_report_dict(data)
    except (json.JSONDecodeError, KeyError, TypeError) as e:
        console.print(f"[red]Invalid report file: {e}[/red]")
        raise typer.Exit(ExitCode.RUNTIME_ERROR) from e

    config = Config.load_from_file(None)

    if format == "terminal":
        TerminalRenderer(config.scan.report).render(result)
        raise typer.Exit(ExitCode.CLEAN)

    if output:
        output_path = Path(output)
    elif format == "html":
        output_path = input_path.with_suffix(".html")
    else:
        output_path = input_path.with_suffix(".rendered.json")

    if format == "html":
        HTMLReportWriter(config.scan.report).write(result, output_path)
    elif format == "json":
        JSONReportWriter(config.scan.report).write(result, output_path)
    else:
        console.print(f"[red]Unknown format '{format}'. Use: html, json, terminal[/red]")
        raise typer.Exit(ExitCode.RUNTIME_ERROR)

    console.print(f"[green]Report written to {output_path}[/green]")
    raise typer.Exit(result.exit_code)


@app.command()
def config(
    show: bool = typer.Option(False, "--show", help="Show current configuration"),
    validate: bool = typer.Option(False, "--validate", help="Validate configuration"),
    init: bool = typer.Option(False, "--init", help="Create default config file"),
):
    """
    Manage configuration.
    """
    if init:
        target_file = Path("localguard.yaml")
        if target_file.exists():
            console.print(f"[yellow]{target_file} already exists; not overwriting.[/yellow]")
            raise typer.Exit(ExitCode.RUNTIME_ERROR)
        default_config = Config()
        yaml_text = yaml.safe_dump(
            default_config.model_dump(mode="json"), sort_keys=False, allow_unicode=True
        )
        target_file.write_text(yaml_text, encoding="utf-8")
        console.print(f"[green]Default configuration written to {target_file}[/green]")
    elif show:
        loaded = Config.load_from_file()
        yaml_text = yaml.safe_dump(
            loaded.model_dump(mode="json"), sort_keys=False, allow_unicode=True
        )
        from rich.syntax import Syntax

        console.print(Syntax(yaml_text, "yaml", background_color="default"))
    elif validate:
        try:
            Config.load_from_file()
            console.print("[green]Configuration valid[/green]")
        except Exception as e:
            console.print(f"[red]Configuration invalid: {e}[/red]")
            raise typer.Exit(ExitCode.RUNTIME_ERROR) from e
    else:
        console.print("Use --show, --validate, or --init")


@app.command()
def ignore(
    add: str | None = typer.Option(None, "--add", help="Add ignore pattern"),
    remove: str | None = typer.Option(None, "--remove", help="Remove ignore pattern"),
    list_all: bool = typer.Option(False, "--list", help="List ignore patterns"),
):
    """
    Manage ignore patterns (.localguard-ignore).
    """
    ignore_file = Path(".localguard-ignore")

    existing: list[str] = []
    if ignore_file.exists():
        existing = [
            line.strip()
            for line in ignore_file.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]

    if list_all:
        if not existing:
            console.print("[dim]No ignore patterns defined.[/dim]")
        else:
            for pattern in existing:
                console.print(f"  {pattern}")
        raise typer.Exit(ExitCode.CLEAN)

    if add:
        if add in existing:
            console.print(f"[yellow]Pattern already present: {add}[/yellow]")
            raise typer.Exit(ExitCode.CLEAN)
        with ignore_file.open("a", encoding="utf-8") as f:
            f.write(f"{add}\n")
        console.print(f"[green]Added ignore pattern: {add}[/green]")
        raise typer.Exit(ExitCode.CLEAN)

    if remove:
        if remove not in existing:
            console.print(f"[yellow]Pattern not found: {remove}[/yellow]")
            raise typer.Exit(ExitCode.RUNTIME_ERROR)
        remaining = [p for p in existing if p != remove]
        header = "# LocalGuard-Pro ignore patterns\n"
        ignore_file.write_text(header + "".join(f"{p}\n" for p in remaining), encoding="utf-8")
        console.print(f"[green]Removed ignore pattern: {remove}[/green]")
        raise typer.Exit(ExitCode.CLEAN)

    console.print("Use --list, --add <pattern>, or --remove <pattern>")


if __name__ == "__main__":
    app()
