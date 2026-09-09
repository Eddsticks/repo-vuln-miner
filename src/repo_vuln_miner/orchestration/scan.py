"""Orquestación secuencial de un escaneo completo de organización."""

from __future__ import annotations

from collections.abc import Callable, Collection
from contextlib import AbstractContextManager

from repo_vuln_miner.codeql.analysis import CodeQLAnalysisError, CodeQLRunner
from repo_vuln_miner.codeql.sarif import SarifNormalizationError, SarifNormalizer
from repo_vuln_miner.domain.models import (
    AnalysisError,
    AnalysisStatus,
    Finding,
    OrganizationScan,
    RepositoryResult,
)
from repo_vuln_miner.github.catalog import GitHubCatalog, GitHubCatalogError, GitHubRepository
from repo_vuln_miner.github.workspace import ClonedRepository, RepositoryCloneError, RepositoryWorkspace
from repo_vuln_miner.languages.adapters import LanguageAdapterRegistry, ResolvedLanguageAdapter

ProgressReporter = Callable[[str], None]
WorkspaceFactory = Callable[[], AbstractContextManager[RepositoryWorkspace]]


class ScanOrchestrationError(RuntimeError):
    """Fallo global que impide construir un informe de organización."""

    def __init__(self, stage: str, message: str) -> None:
        self.stage = stage
        self.message = message
        super().__init__(f"Scan {stage} failed: {message}")


class ScanOrchestrator:
    """Conecta catálogo, clonación, CodeQL y SARIF sin depender de la CLI."""

    def __init__(
        self,
        catalog: GitHubCatalog,
        language_registry: LanguageAdapterRegistry,
        codeql_runner: CodeQLRunner,
        sarif_normalizer: SarifNormalizer,
        workspace_factory: WorkspaceFactory = RepositoryWorkspace,
    ) -> None:
        self._catalog = catalog
        self._language_registry = language_registry
        self._codeql_runner = codeql_runner
        self._sarif_normalizer = sarif_normalizer
        self._workspace_factory = workspace_factory

    def scan(
        self,
        organization: str,
        selected_repositories: Collection[str] | None = None,
        progress: ProgressReporter | None = None,
    ) -> OrganizationScan:
        """Analiza los repositorios seleccionados y devuelve un informe completo o parcial."""
        emit = progress or (lambda _message: None)
        emit(f"Discovering repositories for {organization}")
        try:
            repositories = self._catalog.list_repositories(organization, selected_repositories)
        except (GitHubCatalogError, ValueError) as error:
            raise ScanOrchestrationError(
                "repository_discovery", "GitHub could not list the requested repositories"
            ) from error

        results: list[RepositoryResult] = []
        for repository in repositories:
            emit(f"{repository.name}: detecting languages")
            results.append(self._scan_repository(repository, emit))
        return OrganizationScan(organization=organization.strip(), repositories=results)

    def _scan_repository(
        self,
        repository: GitHubRepository,
        emit: ProgressReporter,
    ) -> RepositoryResult:
        try:
            detected_languages = self._catalog.get_languages(repository)
        except GitHubCatalogError:
            emit(f"{repository.name}: failed during language detection")
            return self._failed_result(
                repository,
                [],
                "language_detection",
                "GitHub could not retrieve repository languages",
            )

        adapters = self._language_registry.resolve(detected_languages)
        if not adapters:
            emit(f"{repository.name}: no supported languages")
            return RepositoryResult(
                name=repository.name,
                url=repository.url,
                status=AnalysisStatus.UNSUPPORTED,
                detected_languages=detected_languages,
                default_branch=repository.default_branch,
            )

        try:
            with self._workspace_factory() as workspace:
                emit(f"{repository.name}: cloning")
                cloned_repository = workspace.clone(repository)
                findings = self._analyze_adapters(
                    repository.name,
                    cloned_repository,
                    adapters,
                    workspace,
                    emit,
                )
        except RepositoryCloneError as error:
            emit(f"{repository.name}: failed during clone")
            return self._failed_result(repository, detected_languages, "clone", error.reason)
        except CodeQLAnalysisError as error:
            emit(f"{repository.name}: failed during {error.stage}")
            return self._failed_result(repository, detected_languages, error.stage, error.message)
        except SarifNormalizationError as error:
            emit(f"{repository.name}: failed during {error.stage}")
            return self._failed_result(repository, detected_languages, error.stage, error.message)

        return RepositoryResult(
            name=repository.name,
            url=repository.url,
            status=AnalysisStatus.ANALYZED,
            detected_languages=detected_languages,
            analyzed_languages=[
                adapter.adapter.configuration.codeql_language for adapter in adapters
            ],
            findings=findings,
            default_branch=repository.default_branch,
            commit_sha=cloned_repository.commit_sha,
        )

    def _analyze_adapters(
        self,
        repository_name: str,
        cloned_repository: ClonedRepository,
        adapters: list[ResolvedLanguageAdapter],
        workspace: RepositoryWorkspace,
        emit: ProgressReporter,
    ) -> list[Finding]:
        findings: list[Finding] = []
        for adapter in adapters:
            emit(f"{repository_name}: analyzing {adapter.adapter.identifier}")
            artifact = self._codeql_runner.analyze(cloned_repository, adapter, workspace.root)
            emit(f"{repository_name}: normalizing {adapter.adapter.identifier}")
            findings.extend(self._sarif_normalizer.normalize(artifact, cloned_repository))
        return findings

    @staticmethod
    def _failed_result(
        repository: GitHubRepository,
        detected_languages: Collection[str],
        stage: str,
        message: str,
    ) -> RepositoryResult:
        return RepositoryResult(
            name=repository.name,
            url=repository.url,
            status=AnalysisStatus.FAILED,
            detected_languages=list(detected_languages),
            error=AnalysisError(stage=stage, message=message),
            default_branch=repository.default_branch,
        )
