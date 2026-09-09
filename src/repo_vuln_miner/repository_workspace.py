"""Clonación aislada de repositorios para las fases de análisis."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, Callable, Self

from repo_vuln_miner.github_catalog import GitHubRepository

GitRunner = Callable[..., subprocess.CompletedProcess[str]]


@dataclass(frozen=True)
class ClonedRepository:
    """Repositorio clonado y la revisión exacta disponible para análisis."""

    repository: GitHubRepository
    source_path: Path
    commit_sha: str


class RepositoryCloneError(RuntimeError):
    """Error seguro ocurrido al clonar o identificar una revisión Git."""

    def __init__(self, repository_name: str, reason: str) -> None:
        self.repository_name = repository_name
        self.reason = reason
        super().__init__(f"Repository '{repository_name}' could not be prepared: {reason}")


class RepositoryWorkspace:
    """Workspace temporal de un repositorio, eliminado al cerrar el contexto."""

    def __init__(
        self,
        base_directory: Path | None = None,
        git_binary: str = "git",
        runner: GitRunner = subprocess.run,
    ) -> None:
        self._base_directory = base_directory
        self._git_binary = git_binary
        self._runner = runner
        self._temporary_directory: TemporaryDirectory[str] | None = None
        self._root: Path | None = None

    def __enter__(self) -> Self:
        if self._temporary_directory is not None:
            raise RuntimeError("workspace is already active")
        self._temporary_directory = TemporaryDirectory(
            prefix="repo-vuln-miner-",
            dir=self._base_directory,
        )
        self._root = Path(self._temporary_directory.name)
        return self

    def __exit__(self, *args: Any) -> None:
        if self._temporary_directory is not None:
            self._temporary_directory.cleanup()
        self._temporary_directory = None
        self._root = None

    @property
    def root(self) -> Path:
        """Ruta temporal activa del workspace."""
        if self._root is None:
            raise RuntimeError("workspace is not active")
        return self._root

    def clone(self, repository: GitHubRepository) -> ClonedRepository:
        """Clona superficialmente la rama predeterminada y obtiene su SHA."""
        source_path = self.root / "source"
        clone_command = [
            self._git_binary,
            "clone",
            "--depth",
            "1",
            "--single-branch",
            "--branch",
            repository.default_branch,
            repository.clone_url,
            str(source_path),
        ]
        clone_result = self._run(repository.name, clone_command, "Git could not clone the repository")
        if clone_result.returncode != 0:
            raise RepositoryCloneError(repository.name, "Git could not clone the repository")

        revision_command = [self._git_binary, "-C", str(source_path), "rev-parse", "HEAD"]
        revision_result = self._run(
            repository.name,
            revision_command,
            "Git could not resolve the cloned commit",
        )
        commit_sha = revision_result.stdout.strip()
        if revision_result.returncode != 0 or not commit_sha:
            raise RepositoryCloneError(repository.name, "Git could not resolve the cloned commit")

        return ClonedRepository(
            repository=repository,
            source_path=source_path,
            commit_sha=commit_sha,
        )

    def _run(
        self,
        repository_name: str,
        command: list[str],
        failure_reason: str,
    ) -> subprocess.CompletedProcess[str]:
        try:
            return self._runner(command, capture_output=True, text=True, check=False)
        except FileNotFoundError as error:
            raise RepositoryCloneError(repository_name, "Git executable was not found") from error
        except OSError as error:
            raise RepositoryCloneError(repository_name, failure_reason) from error
