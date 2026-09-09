"""Pruebas de la coordinación completa de análisis por organización."""

from __future__ import annotations

from collections.abc import Collection
from pathlib import Path

import pytest

from repo_vuln_miner.codeql.analysis import CodeQLAnalysisArtifact, CodeQLAnalysisError
from repo_vuln_miner.codeql.sarif import SarifNormalizationError
from repo_vuln_miner.domain.models import AnalysisStatus, Finding
from repo_vuln_miner.github.catalog import GitHubCatalogError, GitHubRepository
from repo_vuln_miner.github.workspace import ClonedRepository, RepositoryCloneError
from repo_vuln_miner.languages.adapters import (
    CodeQLConfiguration,
    LanguageAdapter,
    LanguageAdapterRegistry,
    ResolvedLanguageAdapter,
    default_language_registry,
)
from repo_vuln_miner.orchestration.scan import ScanOrchestrationError, ScanOrchestrator


def repository(name: str) -> GitHubRepository:
    return GitHubRepository(
        owner="example",
        name=name,
        url=f"https://github.com/example/{name}",
        clone_url=f"https://github.com/example/{name}.git",
        default_branch="main",
    )


class FakeCatalog:
    def __init__(
        self,
        repositories: list[GitHubRepository],
        languages: dict[str, list[str] | Exception],
        list_error: Exception | None = None,
    ) -> None:
        self.repositories = repositories
        self.languages = languages
        self.list_error = list_error
        self.selected_repositories: Collection[str] | None = None

    def list_repositories(
        self,
        _organization: str,
        selected_names: Collection[str] | None = None,
    ) -> list[GitHubRepository]:
        self.selected_repositories = selected_names
        if self.list_error is not None:
            raise self.list_error
        return self.repositories

    def get_languages(self, current_repository: GitHubRepository) -> list[str]:
        value = self.languages[current_repository.name]
        if isinstance(value, Exception):
            raise value
        return value


class FakeWorkspace:
    def __init__(self, root: Path, clone_error: Exception | None = None) -> None:
        self.root = root
        self.clone_error = clone_error
        self.clone_calls: list[str] = []

    def __enter__(self) -> FakeWorkspace:
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def clone(self, current_repository: GitHubRepository) -> ClonedRepository:
        self.clone_calls.append(current_repository.name)
        if self.clone_error is not None and current_repository.name == "broken":
            raise self.clone_error
        source = self.root / current_repository.name
        source.mkdir(exist_ok=True)
        return ClonedRepository(current_repository, source, f"{current_repository.name}-sha")


class FakeCodeQLRunner:
    def __init__(self, error: Exception | None = None) -> None:
        self.error = error
        self.calls: list[str] = []

    def analyze(
        self,
        _cloned_repository: ClonedRepository,
        adapter: ResolvedLanguageAdapter,
        workspace_root: Path,
    ) -> CodeQLAnalysisArtifact:
        self.calls.append(adapter.adapter.identifier)
        if self.error is not None and _cloned_repository.repository.name == "broken":
            raise self.error
        return CodeQLAnalysisArtifact(
            adapter=adapter,
            database_path=workspace_root / "database",
            sarif_path=workspace_root / "results.sarif",
        )


class FakeSarifNormalizer:
    def __init__(self, error: Exception | None = None) -> None:
        self.error = error

    def normalize(
        self,
        artifact: CodeQLAnalysisArtifact,
        _cloned_repository: ClonedRepository,
    ) -> list[Finding]:
        if self.error is not None and _cloned_repository.repository.name == "broken":
            raise self.error
        return [
            Finding(
                language=artifact.adapter.adapter.configuration.codeql_language,
                rule_id=f"{artifact.adapter.adapter.identifier}/rule",
                message="Finding",
            )
        ]


def orchestrator(
    tmp_path: Path,
    catalog: FakeCatalog,
    *,
    registry: LanguageAdapterRegistry | None = None,
    workspace_error: Exception | None = None,
    codeql_error: Exception | None = None,
    sarif_error: Exception | None = None,
) -> ScanOrchestrator:
    return ScanOrchestrator(
        catalog=catalog,  # type: ignore[arg-type]
        language_registry=registry or default_language_registry(),
        codeql_runner=FakeCodeQLRunner(codeql_error),  # type: ignore[arg-type]
        sarif_normalizer=FakeSarifNormalizer(sarif_error),  # type: ignore[arg-type]
        workspace_factory=lambda: FakeWorkspace(tmp_path, workspace_error),  # type: ignore[arg-type]
    )


def test_scan_analyzes_repositories_and_uses_codeql_languages(tmp_path: Path) -> None:
    express = repository("express")
    catalog = FakeCatalog([express], {"express": ["typescript"]})
    progress: list[str] = []

    report = orchestrator(tmp_path, catalog).scan(
        "example",
        selected_repositories=["express"],
        progress=progress.append,
    )

    result = report.repositories[0]
    assert catalog.selected_repositories == ["express"]
    assert result.status is AnalysisStatus.ANALYZED
    assert result.detected_languages == ["typescript"]
    assert result.analyzed_languages == ["javascript"]
    assert result.findings[0].language == "javascript"
    assert result.commit_sha == "express-sha"
    assert progress == [
        "Discovering repositories for example",
        "express: detecting languages",
        "express: cloning",
        "express: analyzing javascript-typescript",
        "express: normalizing javascript-typescript",
    ]


def test_scan_marks_unadapted_repository_as_unsupported_without_cloning(tmp_path: Path) -> None:
    rust_project = repository("rust-project")
    catalog = FakeCatalog([rust_project], {"rust-project": ["rust"]})

    report = orchestrator(tmp_path, catalog).scan("example")

    result = report.repositories[0]
    assert result.status is AnalysisStatus.UNSUPPORTED
    assert result.detected_languages == ["rust"]
    assert result.analyzed_languages == []


@pytest.mark.parametrize(
    ("failure", "expected_stage"),
    [
        ("language", "language_detection"),
        ("clone", "clone"),
        ("codeql", "analysis"),
        ("sarif", "sarif_normalization"),
    ],
)
def test_scan_preserves_other_repositories_when_one_repository_fails(
    tmp_path: Path,
    failure: str,
    expected_stage: str,
) -> None:
    broken = repository("broken")
    healthy = repository("healthy")
    language_value: list[str] | Exception = ["javascript"]
    workspace_error: Exception | None = None
    codeql_error: Exception | None = None
    sarif_error: Exception | None = None
    if failure == "language":
        language_value = GitHubCatalogError("network failure")
    elif failure == "clone":
        workspace_error = RepositoryCloneError("broken", "Git could not clone the repository")
    elif failure == "codeql":
        codeql_error = CodeQLAnalysisError("analysis", "CodeQL command failed")
    else:
        sarif_error = SarifNormalizationError("SARIF file is not valid JSON")
    catalog = FakeCatalog(
        [broken, healthy],
        {"broken": language_value, "healthy": ["javascript"]},
    )

    report = orchestrator(
        tmp_path,
        catalog,
        workspace_error=workspace_error,
        codeql_error=codeql_error,
        sarif_error=sarif_error,
    ).scan("example")

    failed, analyzed = report.repositories
    assert failed.name == "broken"
    assert failed.status is AnalysisStatus.FAILED
    assert failed.error is not None
    assert failed.error.stage == expected_stage
    assert failed.findings == []
    assert failed.analyzed_languages == []
    assert analyzed.name == "healthy"
    assert analyzed.status is AnalysisStatus.ANALYZED


def test_scan_discards_successful_adapter_results_when_later_adapter_fails(tmp_path: Path) -> None:
    first = LanguageAdapter(
        "first",
        frozenset({"first-language"}),
        CodeQLConfiguration("first-language", "none", "first-suite", "first"),
    )
    second = LanguageAdapter(
        "second",
        frozenset({"second-language"}),
        CodeQLConfiguration("second-language", "none", "second-suite", "second"),
    )
    catalog = FakeCatalog(
        [repository("mixed")],
        {"mixed": ["first-language", "second-language"]},
    )

    class FailingSecondRunner(FakeCodeQLRunner):
        def analyze(
            self,
            cloned_repository: ClonedRepository,
            adapter: ResolvedLanguageAdapter,
            workspace_root: Path,
        ) -> CodeQLAnalysisArtifact:
            if adapter.adapter.identifier == "second":
                raise CodeQLAnalysisError("analysis", "CodeQL command failed")
            return super().analyze(cloned_repository, adapter, workspace_root)

    scan_orchestrator = ScanOrchestrator(
        catalog=catalog,  # type: ignore[arg-type]
        language_registry=LanguageAdapterRegistry([first, second]),
        codeql_runner=FailingSecondRunner(),  # type: ignore[arg-type]
        sarif_normalizer=FakeSarifNormalizer(),  # type: ignore[arg-type]
        workspace_factory=lambda: FakeWorkspace(tmp_path),  # type: ignore[arg-type]
    )

    result = scan_orchestrator.scan("example").repositories[0]

    assert result.status is AnalysisStatus.FAILED
    assert result.findings == []
    assert result.analyzed_languages == []
    assert result.error is not None
    assert result.error.stage == "analysis"


def test_scan_raises_typed_error_when_repository_discovery_fails(tmp_path: Path) -> None:
    catalog = FakeCatalog([], {}, list_error=GitHubCatalogError("network failure"))

    with pytest.raises(ScanOrchestrationError, match="repository_discovery") as error:
        orchestrator(tmp_path, catalog).scan("example")

    assert error.value.stage == "repository_discovery"
