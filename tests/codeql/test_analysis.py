"""Pruebas del ejecutor CodeQL sin requerir el binario real."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import pytest

from repo_vuln_miner.codeql.analysis import CodeQLAnalysisError, CodeQLRunner
from repo_vuln_miner.github.catalog import GitHubRepository
from repo_vuln_miner.github.workspace import ClonedRepository
from repo_vuln_miner.languages.adapters import default_language_registry


def make_cloned_repository(tmp_path: Path) -> ClonedRepository:
    source_path = tmp_path / "source"
    source_path.mkdir()
    repository = GitHubRepository(
        owner="expressjs",
        name="express",
        url="https://github.com/expressjs/express",
        clone_url="https://github.com/expressjs/express.git",
        default_branch="master",
    )
    return ClonedRepository(repository=repository, source_path=source_path, commit_sha="abc123")


def javascript_adapter():
    return default_language_registry().resolve(["javascript"])[0]


class SuccessfulCodeQLProcess:
    def __init__(self) -> None:
        self.calls: list[list[str]] = []

    def __call__(self, command: list[str], **_: Any) -> subprocess.CompletedProcess[str]:
        self.calls.append(command)
        if command[2] == "create":
            Path(command[3]).mkdir()
        else:
            output = next(argument for argument in command if argument.startswith("--output="))
            Path(output.removeprefix("--output=")).write_text("{}", encoding="utf-8")
        return subprocess.CompletedProcess(command, 0, "", "")


def test_runner_creates_database_and_sarif_with_adapter_configuration(tmp_path: Path) -> None:
    process = SuccessfulCodeQLProcess()
    cloned_repository = make_cloned_repository(tmp_path)

    artifact = CodeQLRunner(runner=process).analyze(
        cloned_repository,
        javascript_adapter(),
        tmp_path,
    )

    assert artifact.database_path == tmp_path / "codeql-db-javascript-typescript"
    assert artifact.sarif_path == tmp_path / "results-javascript-typescript.sarif"
    assert artifact.sarif_path.is_file()
    assert process.calls == [
        [
            "codeql",
            "database",
            "create",
            str(artifact.database_path),
            "--language=javascript",
            "--build-mode=none",
            f"--source-root={cloned_repository.source_path}",
        ],
        [
            "codeql",
            "database",
            "analyze",
            str(artifact.database_path),
            "codeql/javascript-queries:codeql-suites/javascript-security-extended.qls",
            "--format=sarifv2.1.0",
            f"--output={artifact.sarif_path}",
            "--sarif-category=javascript",
            "--no-sarif-add-file-contents",
            "--no-sarif-add-snippets",
            "--sarif-include-query-help=never",
        ],
    ]


def test_runner_wraps_database_creation_failure_without_exposing_paths(tmp_path: Path) -> None:
    secret_source = tmp_path / "secret-source"
    secret_source.mkdir()
    repository = make_cloned_repository(tmp_path)
    repository = ClonedRepository(repository.repository, secret_source, repository.commit_sha)

    def failing_process(command: list[str], **_: Any) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(command, 1, "", "secret diagnostic")

    with pytest.raises(CodeQLAnalysisError, match="database_create") as error:
        CodeQLRunner(runner=failing_process).analyze(repository, javascript_adapter(), tmp_path)

    assert error.value.stage == "database_create"
    assert "secret" not in str(error.value)


def test_runner_wraps_analysis_failure(tmp_path: Path) -> None:
    calls = 0

    def failing_analysis(command: list[str], **_: Any) -> subprocess.CompletedProcess[str]:
        nonlocal calls
        calls += 1
        if calls == 1:
            Path(command[3]).mkdir()
            return subprocess.CompletedProcess(command, 0, "", "")
        return subprocess.CompletedProcess(command, 2, "", "failed")

    with pytest.raises(CodeQLAnalysisError, match="analysis") as error:
        CodeQLRunner(runner=failing_analysis).analyze(
            make_cloned_repository(tmp_path),
            javascript_adapter(),
            tmp_path,
        )

    assert error.value.stage == "analysis"


def test_runner_rejects_missing_sarif_after_successful_analysis(tmp_path: Path) -> None:
    def no_sarif_process(command: list[str], **_: Any) -> subprocess.CompletedProcess[str]:
        if command[2] == "create":
            Path(command[3]).mkdir()
        return subprocess.CompletedProcess(command, 0, "", "")

    with pytest.raises(CodeQLAnalysisError, match="did not produce a SARIF"):
        CodeQLRunner(runner=no_sarif_process).analyze(
            make_cloned_repository(tmp_path),
            javascript_adapter(),
            tmp_path,
        )


def test_runner_wraps_missing_codeql_executable(tmp_path: Path) -> None:
    def missing_executable(*_: Any, **__: Any) -> subprocess.CompletedProcess[str]:
        raise FileNotFoundError

    with pytest.raises(CodeQLAnalysisError, match="CodeQL executable was not found") as error:
        CodeQLRunner(runner=missing_executable).analyze(
            make_cloned_repository(tmp_path),
            javascript_adapter(),
            tmp_path,
        )

    assert error.value.stage == "database_create"
