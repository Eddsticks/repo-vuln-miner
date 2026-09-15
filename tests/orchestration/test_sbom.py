"""Regeneración SBOM basada solamente en clones y manifiesto locales."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from repo_vuln_miner.domain.models import SbomResult, SbomStatus
from repo_vuln_miner.github.manifest import RegisteredRepository, RepositoryManifest
from repo_vuln_miner.github.workspace import ClonedRepository, RepositoryCloneError
from repo_vuln_miner.orchestration.sbom import SbomOrchestrationError, SbomOrchestrator
from repo_vuln_miner.syft.generation import SyftExecutionError


def entry(owner: str, name: str, commit: str | None = None) -> RegisteredRepository:
    return RegisteredRepository(
        owner=owner,
        name=name,
        default_branch="main",
        relative_path=f"{owner}/{name}",
        commit_sha=commit or f"{sum(map(ord, name)):040x}",
    )


class FakeWorkspace:
    def __init__(
        self,
        root: Path,
        entries: list[RegisteredRepository],
        errors: dict[str, RepositoryCloneError] | None = None,
        manifest_error: RepositoryCloneError | None = None,
    ) -> None:
        self.root = root
        self.entries = entries
        self.errors = errors or {}
        self.manifest_error = manifest_error
        self.open_calls: list[tuple[str, str]] = []

    def __enter__(self) -> FakeWorkspace:
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def read_manifest(self) -> RepositoryManifest:
        if self.manifest_error is not None:
            raise self.manifest_error
        return RepositoryManifest(repositories=self.entries)

    def open_registered(self, owner: str, name: str) -> ClonedRepository:
        self.open_calls.append((owner, name))
        if name in self.errors:
            raise self.errors[name]
        registered = next(item for item in self.entries if item.owner == owner and item.name == name)
        source = self.root / owner / name
        source.mkdir(parents=True, exist_ok=True)
        return ClonedRepository(registered.as_repository(), source, registered.commit_sha)


class FakeSyftRunner:
    def __init__(self, errors: dict[str, SyftExecutionError] | None = None) -> None:
        self.errors = errors or {}
        self.calls: list[str] = []

    def generate(self, repository: ClonedRepository, output: Path) -> SbomResult:
        name = repository.repository.name
        self.calls.append(name)
        if name in self.errors:
            raise self.errors[name]
        artifact = output.resolve() / "run" / repository.repository.owner / f"{name}.cdx.json"
        artifact.parent.mkdir(parents=True, exist_ok=True)
        artifact.write_text("{}", encoding="utf-8")
        return SbomResult(
            status=SbomStatus.GENERATED,
            generated_at=datetime(2026, 9, 15, tzinfo=timezone.utc),
            syft_version="1.0.0",
            component_count=0,
            path=artifact,
        )


def orchestrator(workspace: FakeWorkspace, syft: FakeSyftRunner) -> SbomOrchestrator:
    return SbomOrchestrator(
        workspace_factory=lambda: workspace,  # type: ignore[arg-type]
        syft_runner_factory=lambda: syft,  # type: ignore[arg-type]
    )


def test_generate_uses_registered_clones_without_github_or_codeql(tmp_path: Path) -> None:
    workspace = FakeWorkspace(tmp_path, [entry("example", "api"), entry("example", "docs")])
    syft = FakeSyftRunner()
    progress: list[str] = []

    report = orchestrator(workspace, syft).generate(
        "example", tmp_path / "output", progress=progress.append,
    )

    assert [item.full_name for item in report.repositories] == ["example/api", "example/docs"]
    assert workspace.open_calls == [("example", "api"), ("example", "docs")]
    assert syft.calls == ["api", "docs"]
    assert report.summary.model_dump() == {
        "repositories": 2, "generated": 2, "failed": 0, "skipped": 0, "components": 0,
    }
    assert progress == [
        "Reading registered repositories for example",
        "example/api: opening registered repository",
        "example/api: generating SBOM",
        "example/api: SBOM generated: 0 components",
        "example/docs: opening registered repository",
        "example/docs: generating SBOM",
        "example/docs: SBOM generated: 0 components",
    ]


def test_generate_filters_by_organization_and_repositories_case_insensitively(tmp_path: Path) -> None:
    workspace = FakeWorkspace(tmp_path, [
        entry("example", "api"), entry("example", "docs"), entry("other", "api"),
    ])
    syft = FakeSyftRunner()

    report = orchestrator(workspace, syft).generate(
        "EXAMPLE", tmp_path / "output", selected_repositories=["API"],
    )

    assert [item.full_name for item in report.repositories] == ["example/api"]
    assert workspace.open_calls == [("example", "api")]
    assert syft.calls == ["api"]


@pytest.mark.parametrize("selected", [["unknown"], ["api", "unknown"]])
def test_unknown_selected_repository_is_global_error_before_opening(
    tmp_path: Path, selected: list[str],
) -> None:
    workspace = FakeWorkspace(tmp_path, [entry("example", "api")])
    with pytest.raises(SbomOrchestrationError, match="not registered"):
        orchestrator(workspace, FakeSyftRunner()).generate(
            "example", tmp_path / "output", selected_repositories=selected,
        )
    assert workspace.open_calls == []


def test_empty_organization_has_an_empty_successful_report(tmp_path: Path) -> None:
    workspace = FakeWorkspace(tmp_path, [entry("other", "api")])
    report = orchestrator(workspace, FakeSyftRunner()).generate("example", tmp_path / "output")
    assert report.repositories == []
    assert report.summary.repositories == 0


@pytest.mark.parametrize("organization", ["", "   "])
def test_blank_organization_is_rejected_without_reading_manifest(tmp_path: Path, organization: str) -> None:
    workspace = FakeWorkspace(tmp_path, [entry("example", "api")])
    with pytest.raises(SbomOrchestrationError, match="must not be blank"):
        orchestrator(workspace, FakeSyftRunner()).generate(organization, tmp_path / "output")
    assert workspace.open_calls == []


def test_clone_preparation_failure_is_recorded_and_other_entries_continue(tmp_path: Path) -> None:
    workspace = FakeWorkspace(
        tmp_path,
        [entry("example", "broken"), entry("example", "healthy")],
        errors={"broken": RepositoryCloneError("broken", "Repository contains local changes")},
    )
    syft = FakeSyftRunner()
    report = orchestrator(workspace, syft).generate("example", tmp_path / "output")
    broken, healthy = report.repositories
    assert broken.commit_sha == entry("example", "broken").commit_sha
    assert broken.sbom.status is SbomStatus.FAILED
    assert broken.sbom.error.stage == "repository_prepare"
    assert broken.sbom.path is None
    assert healthy.sbom.status is SbomStatus.GENERATED
    assert syft.calls == ["healthy"]
    assert report.summary.failed == 1


@pytest.mark.parametrize("stage,version", [
    ("syft_version", None), ("sbom_generation", "1.0.0"), ("sbom_validation", "1.0.0"),
])
def test_syft_failures_are_recorded_and_other_entries_continue(
    tmp_path: Path, stage: str, version: str | None,
) -> None:
    workspace = FakeWorkspace(tmp_path, [entry("example", "broken"), entry("example", "healthy")])
    syft = FakeSyftRunner({"broken": SyftExecutionError(stage, "Syft failed safely", version)})
    report = orchestrator(workspace, syft).generate("example", tmp_path / "output")
    broken, healthy = report.repositories
    assert broken.commit_sha == entry("example", "broken").commit_sha
    assert broken.sbom.status is SbomStatus.FAILED
    assert broken.sbom.error.stage == stage
    assert broken.sbom.syft_version == version
    assert healthy.sbom.status is SbomStatus.GENERATED
    assert syft.calls == ["broken", "healthy"]
    assert report.summary.generated == report.summary.failed == 1


def test_manifest_failure_is_global_and_hides_underlying_detail(tmp_path: Path) -> None:
    workspace = FakeWorkspace(
        tmp_path, [], manifest_error=RepositoryCloneError("workspace", "private filesystem detail"),
    )
    with pytest.raises(SbomOrchestrationError, match="manifest could not be read") as error:
        orchestrator(workspace, FakeSyftRunner()).generate("example", tmp_path / "output")
    assert "private" not in str(error.value)
