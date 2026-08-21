import asyncio
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from syntinel.core.config import Settings
from syntinel.core.logging import configure_root_logger
from syntinel.infrastructure.reporting import render_json, render_markdown
from syntinel.services.scan_service import ScanCallbacks, ScanOptions, ScanService

app = typer.Typer(help="Syntinel — adversarial AI security scanner.")
console = Console()

_VALID_SEVERITIES = {"low", "medium", "high", "critical"}


@app.command()
def version() -> None:
    """Print the installed Syntinel version."""
    from syntinel import __version__

    console.print(f"syntinel {__version__}")


@app.command()
def scan(
    path: Path = typer.Argument(..., help="Directory to scan."),  # noqa: B008
    output: str = typer.Option(None, "--output", "-o", help="Report output path."),
    fmt: str = typer.Option("markdown", "--format", "-f", help="markdown | json | both"),
    severity: str = typer.Option("low", "--severity", "-s", help="Minimum severity to report."),
    max_files: int = typer.Option(None, "--max-files", help="Scan only the N most relevant files."),  # noqa: B008
    no_semgrep: bool = typer.Option(False, "--no-semgrep", help="Disable the Semgrep pass."),
    no_llm: bool = typer.Option(False, "--no-llm", help="Disable the LLM pass."),
    no_cache: bool = typer.Option(False, "--no-cache", help="Bypass the on-disk result cache."),
    concurrency: int = typer.Option(5, "--concurrency", help="Concurrent LLM chunk reviews."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose logging."),
) -> None:
    """Scan a codebase for security vulnerabilities and produce a report."""
    configure_root_logger("DEBUG" if verbose else "INFO")

    if severity.lower() not in _VALID_SEVERITIES:
        choices = ", ".join(_VALID_SEVERITIES)
        console.print(f"[red]Invalid --severity '{severity}'. Choose from: {choices}[/red]")
        raise typer.Exit(code=2)
    if fmt.lower() not in {"markdown", "json", "both"}:
        console.print(f"[red]Invalid --format '{fmt}'. Choose from: markdown, json, both[/red]")
        raise typer.Exit(code=2)

    settings = Settings()
    options = ScanOptions(
        max_files=max_files,
        min_severity=severity.lower(),
        use_semgrep=not no_semgrep,
        use_llm=not no_llm,
        use_cache=not no_cache,
        concurrency=concurrency,
    )

    console.print(f"[bold]Scanning[/bold] {path} ...")
    service = ScanService(settings)
    seen: set[str] = set()

    def on_start(p: str) -> None:
        if p not in seen:
            seen.add(p)

    callbacks = ScanCallbacks(on_file_start=on_start, on_file_done=lambda _p: None)
    report = asyncio.run(service.scan(str(path), options, callbacks))

    _write_reports(report, path, output, fmt.lower())
    _print_summary(report)

    if report.has_critical:
        raise typer.Exit(code=1)


def _write_reports(report, path: Path, output: str | None, fmt: str) -> None:
    base = Path(output) if output else Path("syntinel-report")

    if fmt in ("markdown", "both"):
        target = base if base.suffix in (".md",) else base.with_suffix(".md")
        target.write_text(render_markdown(report, target=str(path)), encoding="utf-8")
        console.print(f"Markdown report written to [cyan]{target}[/cyan]")

    if fmt in ("json", "both"):
        target = base if base.suffix in (".json",) else base.with_suffix(".json")
        target.write_text(render_json(report), encoding="utf-8")
        console.print(f"JSON report written to [cyan]{target}[/cyan]")


def _print_summary(report) -> None:
    table = Table(title="Syntinel Scan Summary")
    table.add_column("Severity")
    table.add_column("Count", justify="right")
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in report.findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    for sev, count in counts.items():
        table.add_row(sev, str(count))
    console.print(table)
    console.print(
        f"{len(report.findings)} issue(s) found across {report.files_scanned} file(s) "
        f"in {report.duration_seconds:.1f}s."
    )
    if report.has_critical:
        console.print("[bold red]CRITICAL findings present — fix before committing.[/bold red]")


if __name__ == "__main__":
    app()
