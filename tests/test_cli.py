"""Pruebas de la interfaz de línea de comandos base."""

from typer.testing import CliRunner

from repo_vuln_miner import __version__
from repo_vuln_miner.cli import app


def test_help_is_available() -> None:
    result = CliRunner().invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "Mina hallazgos de seguridad" in result.stdout


def test_help_is_shown_without_arguments() -> None:
    result = CliRunner().invoke(app)

    assert result.exit_code == 0
    assert "Usage: miner [OPTIONS] COMMAND [ARGS]..." in result.stdout
    assert "Mina hallazgos de seguridad" in result.stdout


def test_version_is_available() -> None:
    result = CliRunner().invoke(app, ["--version"])

    assert result.exit_code == 0
    assert result.stdout.strip() == __version__
