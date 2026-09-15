"""Pruebas de la coordinación completa de análisis por organización."""

from __future__ import annotations

from collections.abc import Collection
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess

import pytest

from repo_vuln_miner.codeql.analysis import CodeQLAnalysisArtifact, CodeQLAnalysisError
from repo_vuln_miner.codeql.sarif import SarifNormalizationError
from repo_vuln_miner.domain.models import AnalysisStatus, Finding, SbomResult, SbomStatus
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
from repo_vuln_miner.syft.generation import SyftExecutionError, SyftRunner


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
        self.language_calls: list[str] = []

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
        self.language_calls.append(current_repository.name)
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


class FakeSyftRunner:
    def __init__(self, error: SyftExecutionError | None = None, component_count: int = 2) -> None:
        self.error = error
        self.component_count = component_count
        self.calls: list[str] = []

    def generate(self, cloned_repository: ClonedRepository, output_directory: Path) -> SbomResult:
        name = cloned_repository.repository.name
        self.calls.append(name)
        assert cloned_repository.source_path.is_dir()
        if self.error is not None and name == "broken":
            raise self.error
        path = output_directory.resolve() / "test-run" / cloned_repository.repository.owner / f"{name}.cdx.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({
            "bomFormat": "CycloneDX", "specVersion": "1.6",
            "components": [{"type": "library", "name": f"package-{i}"} for i in range(self.component_count)],
        }), encoding="utf-8")
        return SbomResult(
            status=SbomStatus.GENERATED,
            generated_at=datetime(2026, 9, 15, tzinfo=timezone.utc),
            syft_version="1.0.0",
            component_count=self.component_count,
            path=path,
        )


def orchestrator(
    tmp_path: Path,
    catalog: FakeCatalog,
    *,
    registry: LanguageAdapterRegistry | None = None,
    workspace_error: Exception | None = None,
    codeql_error: Exception | None = None,
    sarif_error: Exception | None = None,
    syft_error: SyftExecutionError | None = None,
) -> ScanOrchestrator:
    return ScanOrchestrator(
        catalog=catalog,  # type: ignore[arg-type]
        language_registry=registry or default_language_registry(),
        codeql_runner=FakeCodeQLRunner(codeql_error),  # type: ignore[arg-type]
        sarif_normalizer=FakeSarifNormalizer(sarif_error),  # type: ignore[arg-type]
        workspace_factory=lambda: FakeWorkspace(tmp_path, workspace_error),  # type: ignore[arg-type]
        syft_runner_factory=lambda: FakeSyftRunner(syft_error),  # type: ignore[arg-type]
    )


def test_scan_analyzes_repositories_and_uses_codeql_languages(tmp_path: Path) -> None:
    express = repository("express")
    catalog = FakeCatalog([express], {"express": ["typescript"]})
    progress: list[str] = []

    report = orchestrator(tmp_path, catalog).scan(
        "example",
        selected_repositories=["express"],
        progress=progress.append,
        sbom_directory=tmp_path / "sboms",
    )

    result = report.repositories[0]
    assert catalog.selected_repositories == ["express"]
    assert result.status is AnalysisStatus.ANALYZED
    assert result.detected_languages == ["typescript"]
    assert result.analyzed_languages == ["javascript"]
    assert result.findings[0].language == "javascript"
    assert result.commit_sha == "express-sha"
    assert result.full_name == "example/express"
    assert result.sbom.status is SbomStatus.GENERATED
    assert result.sbom.path.is_file()
    assert progress == [
        "Discovering repositories for example",
        "express: preparing repository",
        "express: generating SBOM",
        "express: SBOM generated: 2 components",
        "express: detecting languages",
        "express: analyzing javascript-typescript",
        "express: normalizing javascript-typescript",
    ]


@pytest.mark.parametrize("languages", [["rust"], []])
def test_scan_generates_sbom_for_repositories_without_supported_languages(tmp_path: Path, languages) -> None:
    rust_project = repository("rust-project")
    catalog = FakeCatalog([rust_project], {"rust-project": languages})
    workspace = FakeWorkspace(tmp_path)
    codeql_runner = FakeCodeQLRunner()
    syft_runner = FakeSyftRunner()

    scan = ScanOrchestrator(
        catalog=catalog,  # type: ignore[arg-type]
        language_registry=default_language_registry(),
        codeql_runner=codeql_runner,  # type: ignore[arg-type]
        sarif_normalizer=FakeSarifNormalizer(),  # type: ignore[arg-type]
        workspace_factory=lambda: workspace,  # type: ignore[arg-type]
        syft_runner_factory=lambda: syft_runner,  # type: ignore[arg-type]
    )
    report = scan.scan("example", sbom_directory=tmp_path / "sboms")

    result = report.repositories[0]
    assert result.status is AnalysisStatus.UNSUPPORTED
    assert result.detected_languages == languages
    assert result.analyzed_languages == []
    assert workspace.clone_calls == ["rust-project"]
    assert syft_runner.calls == ["rust-project"]
    assert codeql_runner.calls == []
    assert result.commit_sha == "rust-project-sha"
    assert result.sbom.status is SbomStatus.GENERATED
    assert result.sbom.path.is_file()
    assert report.summary.unsupported == 1
    assert report.sbom_summary.generated == 1


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
    ).scan("example", sbom_directory=tmp_path / "sboms")

    failed, analyzed = report.repositories
    assert failed.name == "broken"
    assert failed.status is AnalysisStatus.FAILED
    assert failed.error is not None
    assert failed.error.stage == expected_stage
    assert failed.findings == []
    assert failed.analyzed_languages == []
    assert analyzed.name == "healthy"
    assert analyzed.status is AnalysisStatus.ANALYZED
    assert analyzed.sbom.status is SbomStatus.GENERATED
    assert failed.full_name == "example/broken"
    if failure == "clone":
        assert failed.commit_sha is None
        assert failed.sbom.status is SbomStatus.SKIPPED
        assert failed.sbom.error.stage == "clone"
        assert failed.sbom.path is None
        assert "broken" not in catalog.language_calls
    else:
        assert failed.commit_sha == "broken-sha"
        assert failed.sbom.status is SbomStatus.GENERATED
        assert failed.sbom.path.is_file()


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
        syft_runner_factory=FakeSyftRunner,  # type: ignore[arg-type]
    )

    result = scan_orchestrator.scan("example", sbom_directory=tmp_path / "sboms").repositories[0]

    assert result.status is AnalysisStatus.FAILED
    assert result.findings == []
    assert result.analyzed_languages == []
    assert result.error is not None
    assert result.error.stage == "analysis"
    assert result.commit_sha == "mixed-sha"
    assert result.sbom.status is SbomStatus.GENERATED
    assert result.sbom.path.is_file()


def test_scan_raises_typed_error_when_repository_discovery_fails(tmp_path: Path) -> None:
    catalog = FakeCatalog([], {}, list_error=GitHubCatalogError("network failure"))

    with pytest.raises(ScanOrchestrationError, match="repository_discovery") as error:
        orchestrator(tmp_path, catalog).scan("example")

    assert error.value.stage == "repository_discovery"


@pytest.mark.parametrize("stage,version", [
    ("syft_version", None),
    ("sbom_generation", "1.0.0"),
    ("sbom_validation", "1.0.0"),
    ("sbom_write", "1.0.0"),
])
def test_syft_failure_preserves_codeql_and_other_repositories(tmp_path: Path, stage: str, version) -> None:
    catalog = FakeCatalog(
        [repository("broken"), repository("healthy")],
        {"broken": ["javascript"], "healthy": ["javascript"]},
    )
    progress: list[str] = []
    report = orchestrator(
        tmp_path, catalog, syft_error=SyftExecutionError(stage, "Syft failed safely", version),
    ).scan("example", sbom_directory=tmp_path / "sboms", progress=progress.append)

    broken, healthy = report.repositories
    assert broken.status is AnalysisStatus.ANALYZED
    assert broken.finding_count == 1
    assert broken.error is None
    assert broken.commit_sha == "broken-sha"
    assert broken.sbom.status is SbomStatus.FAILED
    assert broken.sbom.error.stage == stage
    assert broken.sbom.syft_version == version
    assert broken.sbom.component_count is None
    assert broken.sbom.path is None
    assert healthy.status is AnalysisStatus.ANALYZED
    assert healthy.sbom.status is SbomStatus.GENERATED
    assert report.summary.failed == 0
    assert report.sbom_summary.failed == 1
    assert f"broken: SBOM failed during {stage}: Syft failed safely" in progress


@pytest.mark.parametrize("language_failure", [False, True])
def test_both_tool_failures_are_preserved_independently(tmp_path: Path, language_failure: bool) -> None:
    catalog = FakeCatalog([repository("broken")], {
        "broken": GitHubCatalogError("private detail") if language_failure else ["javascript"],
    })
    report = orchestrator(
        tmp_path, catalog,
        syft_error=SyftExecutionError("sbom_generation", "Syft timed out", "1.0.0"),
        codeql_error=CodeQLAnalysisError("database_create", "CodeQL failed"),
    ).scan("example", sbom_directory=tmp_path / "sboms")
    result = report.repositories[0]
    assert result.status is AnalysisStatus.FAILED
    assert result.error.stage == ("language_detection" if language_failure else "database_create")
    assert result.sbom.status is SbomStatus.FAILED
    assert result.sbom.error.stage == "sbom_generation"
    assert result.commit_sha == "broken-sha"
    assert report.summary.failed == report.sbom_summary.failed == 1


@pytest.mark.parametrize("failure_phase", ["enter", "exit"])
def test_workspace_errors_are_local_and_preserve_completed_sbom(tmp_path: Path, failure_phase: str) -> None:
    instances: list[FakeWorkspace] = []

    class FailingWorkspace(FakeWorkspace):
        def __enter__(self):
            if failure_phase == "enter":
                raise OSError("private filesystem detail")
            return super().__enter__()

        def __exit__(self, *args):
            if failure_phase == "exit":
                raise OSError("private filesystem detail")
            return None

    def workspace_factory():
        workspace = FailingWorkspace(tmp_path) if not instances else FakeWorkspace(tmp_path)
        instances.append(workspace)
        return workspace

    syft_runner = FakeSyftRunner()
    scanner = ScanOrchestrator(
        catalog=FakeCatalog(  # type: ignore[arg-type]
            [repository("broken"), repository("healthy")],
            {"broken": ["javascript"], "healthy": ["javascript"]},
        ),
        language_registry=default_language_registry(),
        codeql_runner=FakeCodeQLRunner(),  # type: ignore[arg-type]
        sarif_normalizer=FakeSarifNormalizer(),  # type: ignore[arg-type]
        workspace_factory=workspace_factory,  # type: ignore[arg-type]
        syft_runner_factory=lambda: syft_runner,  # type: ignore[arg-type]
    )
    broken, healthy = scanner.scan("example", sbom_directory=tmp_path / "sboms").repositories
    assert broken.status is AnalysisStatus.FAILED
    assert broken.error.stage == "workspace"
    assert "private" not in broken.error.message
    assert healthy.status is AnalysisStatus.ANALYZED
    assert healthy.sbom.status is SbomStatus.GENERATED
    if failure_phase == "enter":
        assert broken.sbom.status is SbomStatus.SKIPPED
        assert broken.commit_sha is None
        assert syft_runner.calls == ["healthy"]
    else:
        assert broken.sbom.status is SbomStatus.GENERATED
        assert broken.sbom.path.is_file()
        assert broken.commit_sha == "broken-sha"


def test_real_syft_runner_is_shared_per_scan_and_renewed_for_next_scan(tmp_path: Path) -> None:
    commands: list[list[str]] = []

    def syft_process(command, **kwargs):
        commands.append(command)
        if command[1] == "version":
            return subprocess.CompletedProcess(command, 0, '{"version":"1.0.0"}', "")
        path = Path(command[-1].removeprefix("cyclonedx-json="))
        path.write_text('{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}', encoding="utf-8")
        return subprocess.CompletedProcess(command, 0, "", "")

    runners: list[SyftRunner] = []

    def syft_factory():
        runner = SyftRunner(runner=syft_process)
        runners.append(runner)
        return runner

    scanner = ScanOrchestrator(
        catalog=FakeCatalog(  # type: ignore[arg-type]
            [repository("api"), repository("docs")], {"api": ["javascript"], "docs": []},
        ),
        language_registry=default_language_registry(),
        codeql_runner=FakeCodeQLRunner(),  # type: ignore[arg-type]
        sarif_normalizer=FakeSarifNormalizer(),  # type: ignore[arg-type]
        workspace_factory=lambda: FakeWorkspace(tmp_path),  # type: ignore[arg-type]
        syft_runner_factory=syft_factory,
    )
    first = scanner.scan("example", sbom_directory=tmp_path / "sboms")
    second = scanner.scan("example", sbom_directory=tmp_path / "sboms")
    assert len(runners) == 2
    assert runners[0].run_id != runners[1].run_id
    assert [command[1] for command in commands] == ["version", "scan", "scan", "version", "scan", "scan"]
    for report in (first, second):
        assert report.summary.analyzed == report.summary.unsupported == 1
        assert report.sbom_summary.generated == 2
        assert report.sbom_summary.components == 0
        for result in report.repositories:
            assert result.sbom.component_count == 0
            assert result.sbom.path.is_file()
    assert first.repositories[0].sbom.path != second.repositories[0].sbom.path


def test_missing_syft_is_reported_for_every_repository_without_stopping_codeql(tmp_path: Path) -> None:
    commands: list[list[str]] = []

    def missing_syft(command, **kwargs):
        commands.append(command)
        raise FileNotFoundError("private executable path")

    syft_runner = SyftRunner(runner=missing_syft)
    scanner = ScanOrchestrator(
        catalog=FakeCatalog(  # type: ignore[arg-type]
            [repository("first"), repository("second")],
            {"first": ["javascript"], "second": ["javascript"]},
        ),
        language_registry=default_language_registry(),
        codeql_runner=FakeCodeQLRunner(),  # type: ignore[arg-type]
        sarif_normalizer=FakeSarifNormalizer(),  # type: ignore[arg-type]
        workspace_factory=lambda: FakeWorkspace(tmp_path),  # type: ignore[arg-type]
        syft_runner_factory=lambda: syft_runner,
    )
    report = scanner.scan("example", sbom_directory=tmp_path / "sboms")
    assert len(commands) == 1
    assert report.summary.analyzed == 2
    assert report.sbom_summary.failed == 2
    for result in report.repositories:
        assert result.sbom.error.stage == "syft_version"
        assert result.sbom.syft_version is None
        assert result.commit_sha is not None
        assert result.finding_count == 1


def test_clone_failure_runs_neither_syft_nor_language_detection(tmp_path: Path) -> None:
    catalog = FakeCatalog([repository("broken")], {})
    syft_runner = FakeSyftRunner()
    codeql_runner = FakeCodeQLRunner()
    scanner = ScanOrchestrator(
        catalog=catalog,  # type: ignore[arg-type]
        language_registry=default_language_registry(),
        codeql_runner=codeql_runner,  # type: ignore[arg-type]
        sarif_normalizer=FakeSarifNormalizer(),  # type: ignore[arg-type]
        workspace_factory=lambda: FakeWorkspace(  # type: ignore[arg-type]
            tmp_path, RepositoryCloneError("broken", "Clone failed"),
        ),
        syft_runner_factory=lambda: syft_runner,  # type: ignore[arg-type]
    )
    result = scanner.scan("example", sbom_directory=tmp_path / "sboms").repositories[0]
    assert result.status is AnalysisStatus.FAILED
    assert result.full_name == "example/broken"
    assert result.sbom.status is SbomStatus.SKIPPED
    assert syft_runner.calls == catalog.language_calls == codeql_runner.calls == []
