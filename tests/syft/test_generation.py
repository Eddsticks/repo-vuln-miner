"""Pruebas del ejecutor Syft sin depender del binario ni de la red."""

from __future__ import annotations

import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from repo_vuln_miner.domain.models import SbomStatus
from repo_vuln_miner.github.catalog import GitHubRepository
from repo_vuln_miner.github.workspace import ClonedRepository
from repo_vuln_miner.syft.generation import SyftExecutionError, SyftRunner


ORIGINAL_SBOM = b'''{
  "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
  "metadata": {"component": {"type": "application", "name": "source"}},
  "components": [
    {"type": "library", "name": "express", "version": "4.21.0"},
    {"type": "library", "name": "accepts", "version": "1.3.8"}
  ]
}
'''


def cloned_repository(tmp_path: Path, owner: str = "example", name: str = "app") -> ClonedRepository:
    source = tmp_path / "clones with spaces" / owner / name
    source.mkdir(parents=True, exist_ok=True)
    return ClonedRepository(
        repository=GitHubRepository(
            owner=owner, name=name, url=f"https://github.com/{owner}/{name}",
            clone_url=f"https://github.com/{owner}/{name}.git", default_branch="main",
        ),
        source_path=source,
        commit_sha="a" * 40,
    )


class SyftProcess:
    def __init__(self, content: bytes | None = ORIGINAL_SBOM) -> None:
        self.content = content
        self.version_output = '{"application":"syft","version":"1.0.0"}'
        self.scan_returncode = 0
        self.calls: list[tuple[list[str], dict[str, Any]]] = []

    def __call__(self, command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        self.calls.append((command, kwargs))
        if command[1] == "version":
            return subprocess.CompletedProcess(command, 0, self.version_output, "")
        if self.content is not None:
            output = Path(command[-1].removeprefix("cyclonedx-json="))
            output.write_bytes(self.content)
        return subprocess.CompletedProcess(command, self.scan_returncode, "", "")


def assert_no_artifacts(output: Path) -> None:
    assert not list(output.rglob("*.cdx.json"))
    assert not list(output.rglob(".sbom-*"))


def test_generation_preserves_original_bytes_and_counts_components(tmp_path: Path) -> None:
    repository = cloned_repository(tmp_path)
    process = SyftProcess()
    runner = SyftRunner(syft_binary="/tools with spaces/syft", runner=process)
    output = tmp_path / "output with spaces"
    before = datetime.now(timezone.utc)

    result = runner.generate(repository, output)

    assert result.status is SbomStatus.GENERATED
    assert result.syft_version == "1.0.0"
    assert result.component_count == 2  # metadata.component no cuenta como dependencia.
    assert before <= result.generated_at <= datetime.now(timezone.utc)
    assert result.generated_at.utcoffset().total_seconds() == 0
    assert result.path == output / runner.run_id / "example" / "app.cdx.json"
    assert result.path.read_bytes() == ORIGINAL_SBOM
    assert not list(output.rglob(".sbom-*"))
    version_command, scan_command = [command for command, _ in process.calls]
    assert version_command == ["/tools with spaces/syft", "version", "-o", "json"]
    assert scan_command[:4] == ["/tools with spaces/syft", "scan", f"dir:{repository.source_path}", "-o"]
    assert scan_command[-1].startswith("cyclonedx-json=")
    temporary_path = Path(scan_command[-1].split("=", 1)[1])
    assert temporary_path.parent.parent == result.path.parent
    assert not temporary_path.exists()
    for _, kwargs in process.calls:
        assert kwargs["timeout"] == 300.0
        assert kwargs["check"] is False
        assert kwargs.get("shell", False) is False
        assert kwargs["encoding"] == "utf-8"


@pytest.mark.parametrize("components", [None, []])
def test_absent_or_empty_components_is_success(tmp_path: Path, components: list | None) -> None:
    payload = {"bomFormat": "CycloneDX", "specVersion": "1.6"}
    if components is not None:
        payload["components"] = components
    result = SyftRunner(runner=SyftProcess(json.dumps(payload).encode())).generate(
        cloned_repository(tmp_path), tmp_path / "output",
    )
    assert result.status is SbomStatus.GENERATED
    assert result.component_count == 0
    assert result.path.is_file()


def test_version_is_cached_across_repositories_and_explicit_queries(tmp_path: Path) -> None:
    process = SyftProcess()
    runner = SyftRunner(runner=process, timeout=12.5)
    assert runner.get_version() == "1.0.0"
    first = runner.generate(cloned_repository(tmp_path, owner="first"), tmp_path / "output")
    second = runner.generate(cloned_repository(tmp_path, owner="second"), tmp_path / "output")
    assert runner.get_version() == "1.0.0"
    assert [command[1] for command, _ in process.calls] == ["version", "scan", "scan"]
    assert all(kwargs["timeout"] == 12.5 for _, kwargs in process.calls)
    assert first.path != second.path
    assert first.path.read_bytes() == second.path.read_bytes() == ORIGINAL_SBOM


def test_new_runs_keep_previous_artifacts(tmp_path: Path) -> None:
    repository = cloned_repository(tmp_path)
    output = tmp_path / "output"
    first = SyftRunner(runner=SyftProcess()).generate(repository, output)
    second = SyftRunner(runner=SyftProcess()).generate(repository, output)
    assert first.path != second.path
    assert first.path.read_bytes() == second.path.read_bytes() == ORIGINAL_SBOM


def test_same_run_cannot_overwrite_successful_artifact(tmp_path: Path) -> None:
    repository = cloned_repository(tmp_path)
    process = SyftProcess()
    runner = SyftRunner(runner=process)
    output = tmp_path / "output"
    result = runner.generate(repository, output)
    with pytest.raises(SyftExecutionError, match="already exists") as error:
        runner.generate(repository, output)
    assert error.value.stage == "sbom_write"
    assert result.path.read_bytes() == ORIGINAL_SBOM
    assert len(process.calls) == 2


@pytest.mark.parametrize("version_output", ["", "{", "[]", "null", "{}", '{"version":null}',
                                           '{"version":1}', '{"version":" "}', '{"version":NaN}'])
def test_invalid_version_is_a_cached_error(tmp_path: Path, version_output: str) -> None:
    process = SyftProcess()
    process.version_output = version_output
    runner = SyftRunner(runner=process)
    output = tmp_path / "output"
    for name in ["first", "second"]:
        with pytest.raises(SyftExecutionError) as error:
            runner.generate(cloned_repository(tmp_path, name=name), output)
        assert error.value.stage == "syft_version"
        assert error.value.syft_version is None
    assert len(process.calls) == 1
    assert_no_artifacts(output)


@pytest.mark.parametrize("failure,expected", [
    (FileNotFoundError("secret executable path"), "executable was not found"),
    (PermissionError("secret path"), "could not be executed"),
    (subprocess.TimeoutExpired("secret command", 1, stderr="secret token"), "timed out"),
    (UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid"), "could not be executed"),
])
@pytest.mark.parametrize("stage", ["version", "scan"])
def test_process_errors_are_typed_safe_and_cleaned_up(
    tmp_path: Path, failure: Exception, expected: str, stage: str,
) -> None:
    process = SyftProcess()

    def failing_process(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        if command[1] == stage:
            if stage == "scan":
                process(command, **kwargs)  # Syft puede fallar después de escribir una salida parcial.
            raise failure
        return process(command, **kwargs)

    runner = SyftRunner(runner=failing_process)
    output = tmp_path / "output"
    with pytest.raises(SyftExecutionError, match=expected) as error:
        runner.generate(cloned_repository(tmp_path), output)
    assert error.value.stage == ("syft_version" if stage == "version" else "sbom_generation")
    assert error.value.syft_version == (None if stage == "version" else "1.0.0")
    assert "secret" not in str(error.value)
    assert_no_artifacts(output)


@pytest.mark.parametrize("stage", ["version", "scan"])
def test_nonzero_exit_is_failure_even_with_valid_output(tmp_path: Path, stage: str) -> None:
    process = SyftProcess()

    def failing_process(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        result = process(command, **kwargs)
        if command[1] == stage:
            return subprocess.CompletedProcess(command, 1, result.stdout, "token=secret")
        return result

    output = tmp_path / "output"
    with pytest.raises(SyftExecutionError, match="command failed") as error:
        SyftRunner(runner=failing_process).generate(cloned_repository(tmp_path), output)
    assert "secret" not in str(error.value)
    assert_no_artifacts(output)


@pytest.mark.parametrize("content", [None, b"", b"{", b"\xff", b"[]", b"null", b"{}",
                                     b'{"bomFormat":"SPDX","specVersion":"1.6"}'])
def test_missing_or_invalid_sbom_never_becomes_an_empty_success(tmp_path: Path, content: bytes | None) -> None:
    output = tmp_path / "output"
    with pytest.raises(SyftExecutionError) as error:
        SyftRunner(runner=SyftProcess(content)).generate(cloned_repository(tmp_path), output)
    assert error.value.stage == "sbom_validation"
    assert error.value.syft_version == "1.0.0"
    assert_no_artifacts(output)


@pytest.mark.parametrize("changes", [
    {"specVersion": None}, {"specVersion": ""}, {"specVersion": "invalid"},
    {"version": 0}, {"version": True}, {"version": "1"},
    {"components": None}, {"components": {}}, {"components": ""},
    {"components": [None]}, {"components": [{}]},
    {"components": [{"type": "library", "name": " "}]},
    {"components": [{"type": "", "name": "package"}]},
    {"other": float("nan")},
])
def test_invalid_cyclonedx_structure_is_rejected(tmp_path: Path, changes: dict) -> None:
    payload = {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}
    payload.update(changes)
    output = tmp_path / "output"
    with pytest.raises(SyftExecutionError) as error:
        SyftRunner(runner=SyftProcess(json.dumps(payload).encode())).generate(
            cloned_repository(tmp_path), output,
        )
    assert error.value.stage == "sbom_validation"
    assert_no_artifacts(output)


def test_one_failed_generation_does_not_poison_other_repositories(tmp_path: Path) -> None:
    process = SyftProcess()
    process.scan_returncode = 1
    runner = SyftRunner(runner=process)
    output = tmp_path / "output"
    with pytest.raises(SyftExecutionError):
        runner.generate(cloned_repository(tmp_path, name="broken"), output)
    process.scan_returncode = 0
    result = runner.generate(cloned_repository(tmp_path, name="healthy"), output)
    assert result.status is SbomStatus.GENERATED
    assert list(output.rglob("*.cdx.json")) == [result.path]
    assert [command[1] for command, _ in process.calls] == ["version", "scan", "scan"]


def test_publication_failure_preserves_previous_runs(tmp_path: Path, monkeypatch) -> None:
    repository = cloned_repository(tmp_path)
    output = tmp_path / "output"
    previous = SyftRunner(runner=SyftProcess()).generate(repository, output)
    runner = SyftRunner(runner=SyftProcess())

    def failed_replace(*args) -> None:
        raise OSError("secret filesystem detail")

    monkeypatch.setattr("repo_vuln_miner.syft.generation.os.replace", failed_replace)
    with pytest.raises(SyftExecutionError, match="could not be written") as error:
        runner.generate(repository, output)
    assert error.value.stage == "sbom_write"
    assert error.value.syft_version == "1.0.0"
    assert previous.path.read_bytes() == ORIGINAL_SBOM
    assert_no_artifacts(output / runner.run_id)


def test_output_directory_creation_failure_is_typed(tmp_path: Path) -> None:
    output = tmp_path / "not-a-directory"
    output.write_text("keep")
    with pytest.raises(SyftExecutionError, match="could not be written") as error:
        SyftRunner(runner=SyftProcess()).generate(cloned_repository(tmp_path), output)
    assert error.value.stage == "sbom_write"
    assert output.read_text() == "keep"


@pytest.mark.parametrize("inside", ["", "sboms"])
def test_output_inside_source_is_rejected_before_running_syft(tmp_path: Path, inside: str) -> None:
    process = SyftProcess()
    repository = cloned_repository(tmp_path)
    with pytest.raises(SyftExecutionError, match="outside the repository"):
        SyftRunner(runner=process).generate(repository, repository.source_path / inside)
    assert not process.calls


def test_missing_source_is_rejected_before_running_syft(tmp_path: Path) -> None:
    process = SyftProcess()
    repository = cloned_repository(tmp_path)
    repository.source_path.rmdir()
    with pytest.raises(SyftExecutionError, match="directory is missing"):
        SyftRunner(runner=process).generate(repository, tmp_path / "output")
    assert not process.calls


def test_invalid_identity_cannot_escape_output_directory(tmp_path: Path) -> None:
    process = SyftProcess()
    repository = cloned_repository(tmp_path)
    invalid = ClonedRepository(
        repository.repository.model_copy(update={"owner": "../outside"}),
        repository.source_path, repository.commit_sha,
    )
    with pytest.raises(SyftExecutionError, match="identity is invalid"):
        SyftRunner(runner=process).generate(invalid, tmp_path / "output")
    assert not process.calls


@pytest.mark.parametrize("timeout", [0, -1, float("inf"), float("nan")])
def test_invalid_timeout_is_rejected(timeout: float) -> None:
    with pytest.raises(ValueError, match="finite and positive"):
        SyftRunner(timeout=timeout)
