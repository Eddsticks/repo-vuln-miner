"""Pruebas de la interfaz de línea de comandos base."""

import re
from pathlib import Path

from typer.testing import CliRunner

from repo_vuln_miner import __version__
from repo_vuln_miner import cli
from repo_vuln_miner.cli import app
from repo_vuln_miner.domain.models import AnalysisError, AnalysisStatus, OrganizationScan, RepositoryResult
from repo_vuln_miner.orchestration.scan import ScanOrchestrationError

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


class FakeScanOrchestrator:
    def __init__(self, report: OrganizationScan | None = None, error: Exception | None = None) -> None:
        self.report = report
        self.error = error
        self.calls: list[tuple[str, list[str] | None]] = []

    def scan(
        self,
        organization: str,
        selected_repositories: list[str] | None,
        progress,
    ) -> OrganizationScan:
        self.calls.append((organization, selected_repositories))
        progress("Discovering repositories for example")
        if self.error is not None:
            raise self.error
        assert self.report is not None
        return self.report


def partial_report() -> OrganizationScan:
    return OrganizationScan(
        organization="example",
        repositories=[
            RepositoryResult(
                name="broken",
                url="https://github.com/example/broken",
                status=AnalysisStatus.FAILED,
                error=AnalysisError(stage="clone", message="Git could not clone the repository"),
            )
        ],
    )


def test_scan_writes_only_json_output_and_reports_progress_to_stderr(
    tmp_path: Path,
    monkeypatch,
) -> None:
    output = tmp_path / "result.json"
    scan_orchestrator = FakeScanOrchestrator(partial_report())
    monkeypatch.setattr(cli, "create_scan_orchestrator", lambda: scan_orchestrator)

    result = CliRunner().invoke(
        app,
        [
            "scan",
            "--organization",
            "example",
            "--output",
            str(output),
            "--repository",
            "broken",
            "--repository",
            "another",
        ],
    )

    assert result.exit_code == 0
    assert result.stdout == ""
    assert "Discovering repositories" in result.stderr
    assert "Writing report" in result.stderr
    assert scan_orchestrator.calls == [("example", ["broken", "another"])]
    assert '"status": "failed"' in output.read_text(encoding="utf-8")


def test_scan_global_error_preserves_existing_output(tmp_path: Path, monkeypatch) -> None:
    output = tmp_path / "result.json"
    output.write_text("existing report", encoding="utf-8")
    scan_orchestrator = FakeScanOrchestrator(
        error=ScanOrchestrationError("repository_discovery", "GitHub could not list repositories")
    )
    monkeypatch.setattr(cli, "create_scan_orchestrator", lambda: scan_orchestrator)

    result = CliRunner().invoke(
        app,
        ["scan", "--organization", "example", "--output", str(output)],
    )

    assert result.exit_code == 1
    assert result.stdout == ""
    assert "Error: GitHub could not list repositories" in result.stderr
    assert output.read_text(encoding="utf-8") == "existing report"


def test_scan_without_repository_option_does_not_apply_a_filter(tmp_path: Path, monkeypatch) -> None:
    output = tmp_path / "result.json"
    scan_orchestrator = FakeScanOrchestrator(partial_report())
    monkeypatch.setattr(cli, "create_scan_orchestrator", lambda: scan_orchestrator)

    result = CliRunner().invoke(
        app,
        ["scan", "--organization", "example", "--output", str(output)],
    )

    assert result.exit_code == 0
    assert scan_orchestrator.calls == [("example", None)]


def test_scan_write_error_preserves_existing_output(tmp_path: Path, monkeypatch) -> None:
    output = tmp_path / "result.json"
    output.write_text("existing report", encoding="utf-8")
    monkeypatch.setattr(cli, "create_scan_orchestrator", lambda: FakeScanOrchestrator(partial_report()))

    def failing_writer(*_: object) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(cli, "write_report_json", failing_writer)
    result = CliRunner().invoke(
        app,
        ["scan", "--organization", "example", "--output", str(output)],
    )

    assert result.exit_code == 1
    assert result.stdout == ""
    assert "Error: report could not be written" in result.stderr
    assert output.read_text(encoding="utf-8") == "existing report"
