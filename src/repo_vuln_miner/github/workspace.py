"""Clones persistentes y artefactos temporales para las fases de análisis."""

from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from tempfile import NamedTemporaryFile, TemporaryDirectory
from typing import Any, Callable, Self

from repo_vuln_miner.github.catalog import GitHubRepository
from repo_vuln_miner.github.manifest import (
    RegisteredRepository,
    RepositoryManifest,
    validate_repository_identifier,
)

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
    """Conserva clones; elimina solamente los artefactos de análisis al cerrar."""

    def __init__(
        self,
        base_directory: Path | None = None,
        git_binary: str = "git",
        runner: GitRunner = subprocess.run,
        repos_directory: Path = Path(".miner/repos"),
    ) -> None:
        self._base_directory = base_directory
        self._git_binary = git_binary
        self._runner = runner
        self.repos_directory = repos_directory.resolve()
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
        """Prepara un clon registrado o crea uno nuevo, sin actualizar su rama."""
        self.root  # Exigir un contexto activo también cuando el clon ya existe.
        source_path = self._source_path(repository.owner, repository.name)
        manifest = self.read_manifest()
        registered = self._find_registered(manifest, repository.owner, repository.name)
        try:
            if registered is not None:
                source_path = self._source_path(registered.owner, registered.name)
                commit_sha = self._validate_clone(repository.name, source_path)
                # La rama registrada pertenece al clon, no a una consulta posterior a GitHub.
                default_branch = registered.default_branch
            else:
                if source_path.exists():
                    raise RepositoryCloneError(
                        repository.name, "Repository directory exists but is not registered"
                    )
                source_path.parent.mkdir(parents=True, exist_ok=True)
                # Un fallo no deja un directorio definitivo que parezca reutilizable.
                with TemporaryDirectory(prefix=".clone-", dir=source_path.parent) as staging:
                    staged_source = Path(staging) / "source"
                    self._run(
                        repository.name,
                        [
                            self._git_binary, "clone", "--depth", "1", "--single-branch",
                            "--branch", repository.default_branch, "--",
                            repository.clone_url, str(staged_source),
                        ],
                        "Git could not clone the repository",
                    )
                    commit_sha = self._validate_clone(repository.name, staged_source)
                    staged_source.rename(source_path)
                default_branch = repository.default_branch

            entry = RegisteredRepository(
                owner=source_path.parent.name,
                name=source_path.name,
                default_branch=default_branch,
                relative_path=source_path.relative_to(self.repos_directory).as_posix(),
                commit_sha=commit_sha,
            )
            manifest.repositories = [
                item for item in manifest.repositories
                if item.full_name.casefold() != entry.full_name.casefold()
            ] + [entry]
            self._write_manifest(RepositoryManifest(repositories=manifest.repositories))
        except OSError as error:
            raise RepositoryCloneError(
                repository.name, "Repository workspace could not be written"
            ) from error
        return ClonedRepository(repository, source_path, commit_sha)

    def read_manifest(self) -> RepositoryManifest:
        """Lee el catálogo local sin abrir un contexto ni acceder a la red."""
        path = self.repos_directory / "manifest.json"
        try:
            return RepositoryManifest.model_validate_json(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return RepositoryManifest()
        except (OSError, ValueError) as error:
            raise RepositoryCloneError("workspace", "Repository manifest could not be read") from error

    def open_registered(self, owner: str, name: str) -> ClonedRepository:
        """Reutiliza solamente un clon registrado; nunca clona ni consulta GitHub."""
        self.root
        self._source_path(owner, name)
        entry = self._find_registered(self.read_manifest(), owner, name)
        if entry is None:
            raise RepositoryCloneError(name, "Repository is not registered")
        return self.clone(entry.as_repository())

    @staticmethod
    def _find_registered(
        manifest: RepositoryManifest, owner: str, name: str,
    ) -> RegisteredRepository | None:
        full_name = f"{owner}/{name}".casefold()
        return next(
            (entry for entry in manifest.repositories if entry.full_name.casefold() == full_name),
            None,
        )

    def _source_path(self, owner: str, name: str) -> Path:
        try:
            validate_repository_identifier(owner)
            validate_repository_identifier(name)
        except ValueError as error:
            raise RepositoryCloneError(name, "Repository identity is invalid") from error
        source_path = self.repos_directory / owner / name
        if source_path.parent.is_symlink() or source_path.is_symlink():
            raise RepositoryCloneError(name, "Repository path must not be a symbolic link")
        return source_path

    def _validate_clone(self, name: str, source_path: Path) -> str:
        if not (source_path / ".git").is_dir() or (source_path / ".git").is_symlink():
            raise RepositoryCloneError(name, "Registered repository is missing or incomplete")
        top_level = self._run(
            name, [self._git_binary, "-C", str(source_path), "rev-parse", "--show-toplevel"],
            "Git could not validate the repository",
        ).stdout.strip()
        if not top_level or Path(top_level).resolve() != source_path.resolve():
            raise RepositoryCloneError(name, "Repository directory is not a Git worktree root")
        revision = self._run(
            name, [self._git_binary, "-C", str(source_path), "rev-parse", "HEAD"],
            "Git could not resolve the cloned commit",
        ).stdout.strip()
        if not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", revision):
            raise RepositoryCloneError(name, "Git could not resolve the cloned commit")
        status = self._run(
            name,
            [self._git_binary, "-C", str(source_path), "status", "--porcelain",
             "--untracked-files=all", "--ignored=matching"],
            "Git could not inspect repository changes",
        )
        if status.stdout.strip():
            raise RepositoryCloneError(name, "Repository contains local changes or additional files")
        return revision

    def _write_manifest(self, manifest: RepositoryManifest) -> None:
        temporary_path: Path | None = None
        try:
            with NamedTemporaryFile(
                mode="w", encoding="utf-8", dir=self.repos_directory,
                prefix=".manifest-", suffix=".tmp", delete=False,
            ) as temporary_file:
                temporary_path = Path(temporary_file.name)
                temporary_file.write(manifest.model_dump_json(indent=2))
                temporary_file.flush()
                os.fsync(temporary_file.fileno())
            os.replace(temporary_path, self.repos_directory / "manifest.json")
        finally:
            if temporary_path is not None:
                temporary_path.unlink(missing_ok=True)

    def _run(
        self,
        repository_name: str,
        command: list[str],
        failure_reason: str,
    ) -> subprocess.CompletedProcess[str]:
        try:
            result = self._runner(command, capture_output=True, text=True, check=False)
        except FileNotFoundError as error:
            raise RepositoryCloneError(repository_name, "Git executable was not found") from error
        except OSError as error:
            raise RepositoryCloneError(repository_name, failure_reason) from error
        if result.returncode != 0:
            raise RepositoryCloneError(repository_name, failure_reason)
        return result
