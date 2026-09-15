"""Orquestación secuencial de un escaneo completo de organización."""

from __future__ import annotations

from collections.abc import Callable, Collection
from contextlib import AbstractContextManager
from pathlib import Path

from repo_vuln_miner.codeql.analysis import CodeQLAnalysisError, CodeQLRunner
from repo_vuln_miner.codeql.sarif import SarifNormalizationError, SarifNormalizer
from repo_vuln_miner.domain.models import (
    AnalysisError,
    AnalysisStatus,
    Finding,
    OrganizationScan,
    RepositoryResult,
    SbomResult,
    SbomStatus,
)
from repo_vuln_miner.github.catalog import GitHubCatalog, GitHubCatalogError, GitHubRepository
from repo_vuln_miner.github.workspace import ClonedRepository, RepositoryCloneError, RepositoryWorkspace
from repo_vuln_miner.languages.adapters import LanguageAdapterRegistry, ResolvedLanguageAdapter
from repo_vuln_miner.syft.generation import SyftExecutionError, SyftRunner

ProgressReporter = Callable[[str], None]
WorkspaceFactory = Callable[[], AbstractContextManager[RepositoryWorkspace]]
SyftRunnerFactory = Callable[[], SyftRunner]


class ScanOrchestrationError(RuntimeError):
    """Fallo global que impide construir un informe de organización."""

    def __init__(self, stage: str, message: str) -> None:
        self.stage = stage
        self.message = message
        super().__init__(f"Scan {stage} failed: {message}")


class ScanOrchestrator:
    """Coordina clones, Syft y CodeQL con resultados independientes de cada etapa."""

    def __init__(
        self,
        catalog: GitHubCatalog,
        language_registry: LanguageAdapterRegistry,
        codeql_runner: CodeQLRunner,
        sarif_normalizer: SarifNormalizer,
        workspace_factory: WorkspaceFactory = RepositoryWorkspace,
        syft_runner_factory: SyftRunnerFactory = SyftRunner,
    ) -> None:
        self._catalog = catalog
        self._language_registry = language_registry
        self._codeql_runner = codeql_runner
        self._sarif_normalizer = sarif_normalizer
        self._workspace_factory = workspace_factory
        self._syft_runner_factory = syft_runner_factory

    def scan(
        self,
        organization: str,
        selected_repositories: Collection[str] | None = None,
        progress: ProgressReporter | None = None,
        sbom_directory: Path = Path("results/sboms"),
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
        syft_runner = self._syft_runner_factory()
        for repository in repositories:
            results.append(self._scan_repository(repository, syft_runner, sbom_directory, emit))
        return OrganizationScan(organization=organization.strip(), repositories=results)

    def _scan_repository(
        self,
        repository: GitHubRepository,
        syft_runner: SyftRunner,
        sbom_directory: Path,
        emit: ProgressReporter,
    ) -> RepositoryResult:
        cloned_repository: ClonedRepository | None = None
        sbom: SbomResult | None = None
        detected_languages: list[str] = []
        try:
            with self._workspace_factory() as workspace:
                emit(f"{repository.name}: preparing repository")
                cloned_repository = workspace.clone(repository)
                sbom = self._generate_sbom(cloned_repository, syft_runner, sbom_directory, emit)

                emit(f"{repository.name}: detecting languages")
                try:
                    detected_languages = self._catalog.get_languages(repository)
                except GitHubCatalogError:
                    emit(f"{repository.name}: failed during language detection")
                    return self._failed_result(
                        repository, [], "language_detection",
                        "GitHub could not retrieve repository languages",
                        cloned_repository=cloned_repository, sbom=sbom,
                    )

                adapters = self._language_registry.resolve(detected_languages)
                if not adapters:
                    emit(f"{repository.name}: no supported languages")
                    return RepositoryResult(
                        name=repository.name,
                        full_name=f"{repository.owner}/{repository.name}",
                        url=repository.url,
                        status=AnalysisStatus.UNSUPPORTED,
                        detected_languages=detected_languages,
                        default_branch=repository.default_branch,
                        commit_sha=cloned_repository.commit_sha,
                        sbom=sbom,
                    )

                findings = self._analyze_adapters(
                    repository.name,
                    cloned_repository,
                    adapters,
                    workspace,
                    emit,
                )
        except RepositoryCloneError as error:
            emit(f"{repository.name}: failed during clone")
            return self._failed_result(
                repository, detected_languages, "clone", error.reason,
                cloned_repository=cloned_repository, sbom=sbom,
            )
        except (CodeQLAnalysisError, SarifNormalizationError) as error:
            emit(f"{repository.name}: failed during {error.stage}")
            return self._failed_result(
                repository, detected_languages, error.stage, error.message,
                cloned_repository=cloned_repository, sbom=sbom,
            )
        except OSError:
            emit(f"{repository.name}: failed during workspace access or cleanup")
            return self._failed_result(
                repository, detected_languages, "workspace",
                "Repository workspace could not be accessed or cleaned up",
                cloned_repository=cloned_repository, sbom=sbom,
            )

        return RepositoryResult(
            name=repository.name,
            full_name=f"{repository.owner}/{repository.name}",
            url=repository.url,
            status=AnalysisStatus.ANALYZED,
            detected_languages=detected_languages,
            analyzed_languages=[
                adapter.adapter.configuration.codeql_language for adapter in adapters
            ],
            findings=findings,
            default_branch=repository.default_branch,
            commit_sha=cloned_repository.commit_sha,
            sbom=sbom,
        )

    @staticmethod
    def _generate_sbom(
        cloned_repository: ClonedRepository,
        syft_runner: SyftRunner,
        sbom_directory: Path,
        emit: ProgressReporter,
    ) -> SbomResult:
        name = cloned_repository.repository.name
        emit(f"{name}: generating SBOM")
        try:
            result = syft_runner.generate(cloned_repository, sbom_directory)
        except SyftExecutionError as error:
            emit(f"{name}: SBOM failed during {error.stage}: {error.message}")
            return SbomResult(
                status=SbomStatus.FAILED,
                syft_version=error.syft_version,
                error=AnalysisError(stage=error.stage, message=error.message),
            )
        emit(f"{name}: SBOM generated: {result.component_count} components")
        return result

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
        *,
        cloned_repository: ClonedRepository | None = None,
        sbom: SbomResult | None = None,
    ) -> RepositoryResult:
        error = AnalysisError(stage=stage, message=message)
        return RepositoryResult(
            name=repository.name,
            full_name=f"{repository.owner}/{repository.name}",
            url=repository.url,
            status=AnalysisStatus.FAILED,
            detected_languages=list(detected_languages),
            error=error,
            default_branch=repository.default_branch,
            commit_sha=cloned_repository.commit_sha if cloned_repository is not None else None,
            sbom=sbom if sbom is not None else SbomResult(status=SbomStatus.SKIPPED, error=error),
        )
