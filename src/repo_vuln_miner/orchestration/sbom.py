"""Regeneración de SBOMs desde clones persistentes, sin GitHub ni CodeQL."""

from __future__ import annotations

from collections.abc import Callable, Collection
from contextlib import AbstractContextManager
from pathlib import Path

from repo_vuln_miner.domain.models import (
    AnalysisError,
    SbomReport,
    SbomRepositoryResult,
    SbomResult,
    SbomStatus,
)
from repo_vuln_miner.github.manifest import RegisteredRepository
from repo_vuln_miner.github.workspace import RepositoryCloneError, RepositoryWorkspace
from repo_vuln_miner.syft.generation import SyftExecutionError, SyftRunner

ProgressReporter = Callable[[str], None]
WorkspaceFactory = Callable[[], AbstractContextManager[RepositoryWorkspace]]
SyftRunnerFactory = Callable[[], SyftRunner]


class SbomOrchestrationError(RuntimeError):
    """Fallo global que impide construir un informe de regeneración."""

    def __init__(self, message: str) -> None:
        self.message = message
        super().__init__(message)


class SbomOrchestrator:
    """Usa solo el manifiesto local, Git local y Syft para producir un SbomReport."""

    def __init__(
        self,
        workspace_factory: WorkspaceFactory = RepositoryWorkspace,
        syft_runner_factory: SyftRunnerFactory = SyftRunner,
    ) -> None:
        self._workspace_factory = workspace_factory
        self._syft_runner_factory = syft_runner_factory

    def generate(
        self,
        organization: str,
        output_directory: Path,
        selected_repositories: Collection[str] | None = None,
        progress: ProgressReporter | None = None,
    ) -> SbomReport:
        """Regenera los SBOMs locales seleccionados sin clonar ni consultar GitHub."""
        normalized_organization = organization.strip()
        if not normalized_organization:
            raise SbomOrchestrationError("Organization must not be blank")
        emit = progress or (lambda _message: None)
        try:
            with self._workspace_factory() as workspace:
                emit(f"Reading registered repositories for {normalized_organization}")
                entries = self._select_entries(
                    workspace.read_manifest().repositories,
                    normalized_organization,
                    selected_repositories,
                )
                syft_runner = self._syft_runner_factory()
                results = [
                    self._generate_entry(entry, workspace, syft_runner, output_directory, emit)
                    for entry in entries
                ]
        except RepositoryCloneError as error:
            if error.repository_name == "workspace":
                raise SbomOrchestrationError("Repository manifest could not be read") from error
            raise
        except OSError as error:
            raise SbomOrchestrationError("Repository workspace could not be accessed") from error
        return SbomReport(organization=normalized_organization, repositories=results)

    @staticmethod
    def _select_entries(
        entries: list[RegisteredRepository],
        organization: str,
        selected_repositories: Collection[str] | None,
    ) -> list[RegisteredRepository]:
        organization_entries = [
            entry for entry in entries if entry.owner.casefold() == organization.casefold()
        ]
        if selected_repositories is None:
            return organization_entries
        selected = {name.casefold() for name in selected_repositories if name.strip()}
        if not selected:
            return organization_entries
        known = {entry.name.casefold() for entry in organization_entries}
        missing = sorted(selected - known)
        if missing:
            raise SbomOrchestrationError(
                f"Requested repositories are not registered: {', '.join(missing)}"
            )
        return [entry for entry in organization_entries if entry.name.casefold() in selected]

    @staticmethod
    def _generate_entry(
        entry: RegisteredRepository,
        workspace: RepositoryWorkspace,
        syft_runner: SyftRunner,
        output_directory: Path,
        emit: ProgressReporter,
    ) -> SbomRepositoryResult:
        emit(f"{entry.full_name}: opening registered repository")
        try:
            cloned_repository = workspace.open_registered(entry.owner, entry.name)
        except RepositoryCloneError as error:
            emit(f"{entry.full_name}: failed during repository preparation")
            return SbomRepositoryResult(
                full_name=entry.full_name,
                commit_sha=entry.commit_sha,
                sbom=SbomResult(
                    status=SbomStatus.FAILED,
                    error=AnalysisError(stage="repository_prepare", message=error.reason),
                ),
            )

        emit(f"{entry.full_name}: generating SBOM")
        try:
            sbom = syft_runner.generate(cloned_repository, output_directory)
        except SyftExecutionError as error:
            emit(f"{entry.full_name}: SBOM failed during {error.stage}: {error.message}")
            sbom = SbomResult(
                status=SbomStatus.FAILED,
                syft_version=error.syft_version,
                error=AnalysisError(stage=error.stage, message=error.message),
            )
        else:
            emit(f"{entry.full_name}: SBOM generated: {sbom.component_count} components")
        return SbomRepositoryResult(
            full_name=entry.full_name,
            commit_sha=cloned_repository.commit_sha,
            sbom=sbom,
        )
