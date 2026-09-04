"""Pruebas de la interfaz de línea de comandos base."""

from typer.testing import CliRunner

from repo_vuln_miner.cli import app


def test_help_is_available() -> None:
    result = CliRunner().invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "Mina hallazgos de seguridad" in result.stdout
