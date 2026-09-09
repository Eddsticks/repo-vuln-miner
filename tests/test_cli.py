"""Pruebas de la interfaz de línea de comandos base."""

import re

from typer.testing import CliRunner

from repo_vuln_miner import __version__
from repo_vuln_miner.cli import app

ANSI_ESCAPE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


def plain_output(output: str) -> str:
    """Elimina estilos ANSI que Typer/Rich puede emitir en CI."""
    return ANSI_ESCAPE.sub("", output)


def test_plain_output_removes_ansi_styles() -> None:
    assert plain_output("\x1b[1mUsage: miner\x1b[0m") == "Usage: miner"


def test_help_is_available() -> None:
    result = CliRunner().invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "Mina hallazgos de seguridad" in plain_output(result.stdout)


def test_help_is_shown_without_arguments() -> None:
    result = CliRunner().invoke(app)
    output = plain_output(result.stdout)

    assert result.exit_code == 0
    assert "Usage: miner [OPTIONS] COMMAND [ARGS]..." in output
    assert "Mina hallazgos de seguridad" in output


def test_version_is_available() -> None:
    result = CliRunner().invoke(app, ["--version"])

    assert result.exit_code == 0
    assert result.stdout.strip() == __version__
