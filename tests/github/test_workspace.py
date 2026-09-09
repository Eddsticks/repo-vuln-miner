"""Pruebas del workspace temporal y la integración con Git."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import pytest

from repo_vuln_miner.github.catalog import GitHubRepository
from repo_vuln_miner.github.workspace import RepositoryCloneError, RepositoryWorkspace


def make_repository(clone_url: str = "https://github.com/expressjs/express.git") -> GitHubRepository:
    return GitHubRepository(
        owner="expressjs",
        name="express",
        url="https://github.com/expressjs/express",
        clone_url=clone_url,
        default_branch="master",
    )


class SuccessfulGitRunner:
    def __init__(self) -> None:
        self.calls: list[list[str]] = []

    def __call__(self, command: list[str], **_: Any) -> subprocess.CompletedProcess[str]:
        self.calls.append(command)
        if command[1] == "clone":
            Path(command[-1]).mkdir()
            return subprocess.CompletedProcess(command, 0, "", "")
        return subprocess.CompletedProcess(command, 0, "abc123\n", "")


def test_workspace_clones_default_branch_and_cleans_up(tmp_path: Path) -> None:
    runner = SuccessfulGitRunner()
    workspace = RepositoryWorkspace(base_directory=tmp_path, runner=runner)

    with workspace as active_workspace:
        root = active_workspace.root
        cloned = active_workspace.clone(make_repository())

        assert cloned.source_path == root / "source"
        assert cloned.source_path.exists()
        assert cloned.commit_sha == "abc123"

    assert not root.exists()
    assert runner.calls == [
        [
            "git",
            "clone",
            "--depth",
            "1",
            "--single-branch",
            "--branch",
            "master",
            "https://github.com/expressjs/express.git",
            str(root / "source"),
        ],
        ["git", "-C", str(root / "source"), "rev-parse", "HEAD"],
    ]


def test_workspace_rejects_clone_outside_active_context() -> None:
    with pytest.raises(RuntimeError, match="workspace is not active"):
        RepositoryWorkspace().clone(make_repository())


def test_workspace_wraps_clone_errors_without_exposing_clone_url(tmp_path: Path) -> None:
    secret_url = "https://token:secret@github.com/expressjs/express.git"

    def failing_runner(command: list[str], **_: Any) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(command, 128, "", "fatal")

    with pytest.raises(RepositoryCloneError, match="Git could not clone") as error:
        with RepositoryWorkspace(base_directory=tmp_path, runner=failing_runner) as workspace:
            workspace.clone(make_repository(clone_url=secret_url))

    assert secret_url not in str(error.value)
    assert "secret" not in str(error.value)


def test_workspace_wraps_revision_failures(tmp_path: Path) -> None:
    def runner(command: list[str], **_: Any) -> subprocess.CompletedProcess[str]:
        if command[1] == "clone":
            Path(command[-1]).mkdir()
            return subprocess.CompletedProcess(command, 0, "", "")
        return subprocess.CompletedProcess(command, 1, "", "fatal")

    with pytest.raises(RepositoryCloneError, match="resolve the cloned commit"):
        with RepositoryWorkspace(base_directory=tmp_path, runner=runner) as workspace:
            workspace.clone(make_repository())


def test_workspace_wraps_missing_git_executable(tmp_path: Path) -> None:
    def missing_git(*_: Any, **__: Any) -> subprocess.CompletedProcess[str]:
        raise FileNotFoundError

    with pytest.raises(RepositoryCloneError, match="Git executable was not found"):
        with RepositoryWorkspace(base_directory=tmp_path, runner=missing_git) as workspace:
            workspace.clone(make_repository())
