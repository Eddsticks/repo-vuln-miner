"""Punto de entrada de la interfaz de línea de comandos."""

import typer

app = typer.Typer(
    name="miner",
    help="Mina hallazgos de seguridad de repositorios mediante GitHub y CodeQL.",
    no_args_is_help=True,
)


@app.callback()
def root() -> None:
    """Punto de entrada para los comandos del miner."""


def main() -> None:
    """Ejecuta la aplicación de línea de comandos."""
    app()
