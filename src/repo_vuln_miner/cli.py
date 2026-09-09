"""Punto de entrada de la interfaz de línea de comandos."""

import typer

from repo_vuln_miner import __version__

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


def main() -> None:
    """Ejecuta la aplicación de línea de comandos."""
    app()
