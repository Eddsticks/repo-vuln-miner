"""Punto de entrada de la interfaz de línea de comandos."""

from pathlib import Path

import typer

from repo_vuln_miner import __version__
from repo_vuln_miner.codeql.analysis import CodeQLRunner
from repo_vuln_miner.codeql.sarif import SarifNormalizer
from repo_vuln_miner.github.catalog import GitHubAuthenticationError, GitHubCatalog
from repo_vuln_miner.github.workspace import RepositoryWorkspace
from repo_vuln_miner.languages.adapters import default_language_registry
from repo_vuln_miner.orchestration.scan import ScanOrchestrationError, ScanOrchestrator
from repo_vuln_miner.reporting.serialization import write_report_json
from repo_vuln_miner.syft.generation import SyftRunner

app = typer.Typer(
    name="miner",
    help="Mina hallazgos de seguridad con CodeQL y genera inventarios SBOM con Syft.",
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


def create_scan_orchestrator(repos_directory: Path = Path(".miner/repos")) -> ScanOrchestrator:
    """Construye las dependencias por defecto del comando de escaneo."""
    return ScanOrchestrator(
        catalog=GitHubCatalog.from_environment(),
        language_registry=default_language_registry(),
        codeql_runner=CodeQLRunner(),
        sarif_normalizer=SarifNormalizer(),
        workspace_factory=lambda: RepositoryWorkspace(repos_directory=repos_directory),
        syft_runner_factory=SyftRunner,
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
    repos_dir: Path = typer.Option(
        Path(".miner/repos"),
        "--repos-dir",
        help="Directorio persistente de clones administrados por el miner.",
    ),
) -> None:
    """Genera SBOMs, analiza repositorios GitHub y escribe el informe JSON indicado."""
    try:
        report = create_scan_orchestrator(repos_directory=repos_dir).scan(
            organization,
            selected_repositories=repository or None,
            progress=lambda message: typer.echo(message, err=True),
            sbom_directory=output.parent / "sboms",
        )
    except (GitHubAuthenticationError, ScanOrchestrationError) as error:
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
        f"{report.summary.findings} findings; "
        f"SBOMs: {report.sbom_summary.generated} generated, "
        f"{report.sbom_summary.failed} failed, {report.sbom_summary.skipped} skipped, "
        f"{report.sbom_summary.components} components",
        err=True,
    )


def main() -> None:
    """Ejecuta la aplicación de línea de comandos."""
    app()
