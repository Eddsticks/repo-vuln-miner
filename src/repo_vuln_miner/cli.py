"""Punto de entrada de la interfaz de línea de comandos."""

from pathlib import Path

import typer

from repo_vuln_miner import __version__
from repo_vuln_miner.codeql.analysis import CodeQLRunner
from repo_vuln_miner.codeql.sarif import SarifNormalizer
from repo_vuln_miner.github.catalog import GitHubCatalog
from repo_vuln_miner.languages.adapters import default_language_registry
from repo_vuln_miner.orchestration.scan import ScanOrchestrationError, ScanOrchestrator
from repo_vuln_miner.reporting.serialization import write_report_json

app = typer.Typer(
    name="miner",
    help="Mina hallazgos de seguridad de repositorios mediante GitHub y CodeQL.",
    invoke_without_command=True,
)


@app.callback()
def root(
    ctx: typer.Context,
    version: bool = typer.Option(
        False,
        "--version",
        "-V",
        help="Muestra la versión instalada y termina.",
    ),
) -> None:
    """Punto de entrada para los comandos del miner."""
    if version:
        typer.echo(__version__)
        raise typer.Exit()
    if ctx.invoked_subcommand is None:
        typer.echo(ctx.get_help())


def create_scan_orchestrator() -> ScanOrchestrator:
    """Construye las dependencias por defecto del comando de escaneo."""
    return ScanOrchestrator(
        catalog=GitHubCatalog.from_environment(),
        language_registry=default_language_registry(),
        codeql_runner=CodeQLRunner(),
        sarif_normalizer=SarifNormalizer(),
    )


@app.command()
def scan(
    organization: str = typer.Option(..., "--organization", help="Organización de GitHub a analizar."),
    output: Path = typer.Option(..., "--output", help="Archivo JSON de salida."),
    repository: list[str] | None = typer.Option(
        None,
        "--repository",
        help="Repositorio a incluir; puede repetirse.",
    ),
) -> None:
    """Analiza repositorios GitHub y escribe el informe JSON indicado."""
    try:
        report = create_scan_orchestrator().scan(
            organization,
            selected_repositories=repository or None,
            progress=lambda message: typer.echo(message, err=True),
        )
    except ScanOrchestrationError as error:
        typer.echo(f"Error: {error.message}", err=True)
        raise typer.Exit(code=1) from error

    try:
        typer.echo(f"Writing report to {output}", err=True)
        write_report_json(report, output)
    except OSError as error:
        typer.echo("Error: report could not be written", err=True)
        raise typer.Exit(code=1) from error

    typer.echo(
        f"Scan complete: {report.summary.repositories} repositories, "
        f"{report.summary.findings} findings",
        err=True,
    )


def main() -> None:
    """Ejecuta la aplicación de línea de comandos."""
    app()
