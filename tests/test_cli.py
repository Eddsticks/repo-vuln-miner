"""Pruebas de la interfaz de línea de comandos base."""

import json
import re
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from typer.testing import CliRunner

from repo_vuln_miner import __version__
from repo_vuln_miner import cli
from repo_vuln_miner.cli import app
from repo_vuln_miner.domain.models import AnalysisError, AnalysisStatus, OrganizationScan, RepositoryResult
from repo_vuln_miner.orchestration.scan import ScanOrchestrationError
from repo_vuln_miner.domain.models import Finding
from repo_vuln_miner.github.catalog import GitHubRepository
from repo_vuln_miner.github.workspace import ClonedRepository
from repo_vuln_miner.syft.generation import SyftRunner

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
        self.sbom_directories: list[Path] = []

    def scan(
        self,
        organization: str,
        selected_repositories: list[str] | None,
        progress,
        sbom_directory: Path,
    ) -> OrganizationScan:
        self.calls.append((organization, selected_repositories))
        self.sbom_directories.append(sbom_directory)
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
    monkeypatch.setattr(cli, "create_scan_orchestrator", lambda **_: scan_orchestrator)

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
    assert scan_orchestrator.sbom_directories == [output.parent / "sboms"]
    assert '"status": "failed"' in output.read_text(encoding="utf-8")


def test_scan_global_error_preserves_existing_output(tmp_path: Path, monkeypatch) -> None:
    output = tmp_path / "result.json"
    output.write_text("existing report", encoding="utf-8")
    scan_orchestrator = FakeScanOrchestrator(
        error=ScanOrchestrationError("repository_discovery", "GitHub could not list repositories")
    )
    monkeypatch.setattr(cli, "create_scan_orchestrator", lambda **_: scan_orchestrator)

    result = CliRunner().invoke(
        app,
        ["scan", "--organization", "example", "--output", str(output)],
    )

    assert result.exit_code == 1
    assert result.stdout == ""
    assert "Error: GitHub could not list repositories" in result.stderr
    assert output.read_text(encoding="utf-8") == "existing report"


def test_scan_without_github_token_preserves_existing_output(tmp_path: Path, monkeypatch) -> None:
    output = tmp_path / "result.json"
    output.write_text("existing report", encoding="utf-8")
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)

    result = CliRunner().invoke(
        app,
        ["scan", "--organization", "example", "--output", str(output)],
    )

    assert result.exit_code == 1
    assert result.stdout == ""
    assert "Error: GITHUB_TOKEN must be configured" in result.stderr
    assert output.read_text(encoding="utf-8") == "existing report"


def test_scan_without_repository_option_does_not_apply_a_filter(tmp_path: Path, monkeypatch) -> None:
    output = tmp_path / "result.json"
    scan_orchestrator = FakeScanOrchestrator(partial_report())
    monkeypatch.setattr(cli, "create_scan_orchestrator", lambda **_: scan_orchestrator)

    result = CliRunner().invoke(
        app,
        ["scan", "--organization", "example", "--output", str(output)],
    )

    assert result.exit_code == 0
    assert scan_orchestrator.calls == [("example", None)]


def test_scan_write_error_preserves_existing_output(tmp_path: Path, monkeypatch) -> None:
    output = tmp_path / "result.json"
    output.write_text("existing report", encoding="utf-8")
    monkeypatch.setattr(cli, "create_scan_orchestrator", lambda **_: FakeScanOrchestrator(partial_report()))

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


@pytest.mark.parametrize("custom_directory", [False, True])
def test_scan_passes_persistent_repository_directory(
    tmp_path: Path, monkeypatch, custom_directory: bool,
) -> None:
    expected = tmp_path / "persistent clones" if custom_directory else Path(".miner/repos")
    configured: list[Path] = []

    def create_orchestrator(repos_directory: Path) -> FakeScanOrchestrator:
        configured.append(repos_directory)
        return FakeScanOrchestrator(partial_report())

    monkeypatch.setattr(cli, "create_scan_orchestrator", create_orchestrator)
    args = ["scan", "--organization", "example", "--output", str(tmp_path / "report.json")]
    if custom_directory:
        args.extend(["--repos-dir", str(expected)])
    result = CliRunner().invoke(app, args)
    assert result.exit_code == 0
    assert configured == [expected]


@pytest.mark.parametrize("syft_failure", [False, True])
def test_scan_cli_connects_syft_and_preserves_independent_results(
    tmp_path: Path, monkeypatch, syft_failure: bool,
) -> None:
    repositories = [GitHubRepository(
        owner="example", name=name, url=f"https://github.com/example/{name}",
        clone_url=f"https://github.com/example/{name}.git", default_branch="main",
    ) for name in ("api", "docs")]
    catalog = SimpleNamespace(
        list_repositories=lambda organization, selected: repositories,
        get_languages=lambda repository: ["javascript"] if repository.name == "api" else [],
    )
    monkeypatch.setattr(cli.GitHubCatalog, "from_environment", lambda: catalog)
    codeql_calls: list[str] = []

    def analyze(repository, adapter, workspace_root):
        codeql_calls.append(repository.repository.name)
        return object()

    monkeypatch.setattr(cli, "CodeQLRunner", lambda: SimpleNamespace(analyze=analyze))
    monkeypatch.setattr(cli, "SarifNormalizer", lambda: SimpleNamespace(
        normalize=lambda artifact, repository: [Finding(
            language="javascript", rule_id="js/example", message="Example finding",
        )],
    ))

    class LocalWorkspace:
        def __init__(self, repos_directory: Path):
            self.repos_directory = repos_directory
            self.root = tmp_path / "temporary-artifacts"

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def clone(self, repository):
            source = self.repos_directory / repository.owner / repository.name
            source.mkdir(parents=True, exist_ok=True)
            return ClonedRepository(repository, source, "a" * 40)

    monkeypatch.setattr(cli, "RepositoryWorkspace", LocalWorkspace)
    syft_commands: list[list[str]] = []

    def syft_process(command, **kwargs):
        syft_commands.append(command)
        if command[1] == "version":
            return subprocess.CompletedProcess(command, 0, '{"version":"1.0.0"}', "")
        temporary = Path(command[-1].removeprefix("cyclonedx-json="))
        temporary.write_text('{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}', encoding="utf-8")
        failed = syft_failure and command[2].endswith("/api")
        return subprocess.CompletedProcess(command, int(failed), "", "")

    monkeypatch.setattr(cli, "SyftRunner", lambda: SyftRunner(runner=syft_process))
    output = tmp_path / "reports" / "scan.json"
    result = CliRunner().invoke(app, [
        "scan", "--organization", "example", "--repos-dir", str(tmp_path / "repos"),
        "--output", str(output),
    ])
    assert result.exit_code == 0
    assert result.stdout == ""
    assert codeql_calls == ["api"]
    assert [command[1] for command in syft_commands] == ["version", "scan", "scan"]
    payload = json.loads(output.read_text(encoding="utf-8"))
    api, docs = payload["repositories"]
    assert api["status"] == "analyzed"
    assert api["full_name"] == "example/api"
    assert api["commit_sha"] == "a" * 40
    assert api["finding_count"] == 1
    assert api["sbom"]["status"] == ("failed" if syft_failure else "generated")
    assert docs["status"] == "unsupported"
    assert docs["sbom"]["status"] == "generated"
    assert docs["sbom"]["component_count"] == 0
    assert Path(docs["sbom"]["path"]).is_relative_to(output.parent / "sboms")
    assert Path(docs["sbom"]["path"]).is_file()
    assert payload["sbom_summary"]["generated"] == (1 if syft_failure else 2)
    assert payload["sbom_summary"]["failed"] == int(syft_failure)
    assert f"{int(syft_failure)} failed, 0 skipped, 0 components" in result.stderr
    assert len(list((output.parent / "sboms").rglob("*.cdx.json"))) == (1 if syft_failure else 2)
    if syft_failure:
        assert "path" not in api["sbom"]
        assert "component_count" not in api["sbom"]
        assert "api: SBOM failed during sbom_generation" in result.stderr
