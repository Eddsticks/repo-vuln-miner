"""Contrato de metadatos SBOM, estados independientes y compatibilidad."""

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from pydantic import ValidationError

from repo_vuln_miner.domain.models import (
    AnalysisError,
    AnalysisStatus,
    OrganizationScan,
    RepositoryResult,
    SbomReport,
    SbomRepositoryResult,
    SbomResult,
    SbomStatus,
)


GENERATED_AT = datetime(2026, 9, 15, 18, 30, tzinfo=timezone.utc)
COMMIT_SHA = "a" * 40


def generated_sbom(**changes: object) -> SbomResult:
    values: dict[str, object] = {
        "status": "generated",
        "generated_at": GENERATED_AT,
        "syft_version": "1.0.0",
        "component_count": 3,
        "path": Path("/reports/example/app.cdx.json"),
    }
    values.update(changes)
    return SbomResult(**values)


def failed_sbom(status: str = "failed", **changes: object) -> SbomResult:
    values: dict[str, object] = {
        "status": status,
        "error": {"stage": "syft", "message": "SBOM could not be generated"},
    }
    values.update(changes)
    return SbomResult(**values)


def repository_result(**changes: object) -> RepositoryResult:
    values: dict[str, object] = {
        "name": "app",
        "full_name": "example/app",
        "url": "https://github.com/example/app",
        "commit_sha": COMMIT_SHA,
        "status": "analyzed",
        "analyzed_languages": ["javascript"],
        "sbom": generated_sbom(),
    }
    values.update(changes)
    return RepositoryResult(**values)


def test_zero_components_is_success_and_is_preserved_in_json() -> None:
    result = generated_sbom(component_count=0)
    assert result.status is SbomStatus.GENERATED
    payload = result.model_dump(mode="json", exclude_none=True)
    assert payload["component_count"] == 0
    assert payload["path"] == "/reports/example/app.cdx.json"
    assert "error" not in payload


@pytest.mark.parametrize("field", ["generated_at", "syft_version", "component_count", "path"])
def test_generated_sbom_requires_all_artifact_metadata(field: str) -> None:
    with pytest.raises(ValidationError, match="generated SBOMs require"):
        generated_sbom(**{field: None})


@pytest.mark.parametrize("count", [-1, True, 1.5, "3"])
def test_component_count_must_be_a_nonnegative_integer(count: object) -> None:
    with pytest.raises(ValidationError):
        generated_sbom(component_count=count)


def test_generated_sbom_cannot_include_an_error() -> None:
    with pytest.raises(ValidationError, match="cannot include an error"):
        generated_sbom(error=AnalysisError(stage="syft", message="Failed"))


@pytest.mark.parametrize("status", ["failed", "skipped"])
def test_non_generated_results_require_a_reason(status: str) -> None:
    with pytest.raises(ValidationError, match="must include an error or reason"):
        SbomResult(status=status)
    result = failed_sbom(status, syft_version="1.0.0")
    payload = result.model_dump(mode="json", exclude_none=True)
    assert payload["status"] == status
    assert payload["syft_version"] == "1.0.0"
    assert not {"path", "generated_at", "component_count"}.intersection(payload)


@pytest.mark.parametrize("status", ["failed", "skipped"])
@pytest.mark.parametrize("field,value", [
    ("component_count", 0),
    ("component_count", 3),
    ("path", Path("/reports/old.cdx.json")),
    ("generated_at", GENERATED_AT),
])
def test_failures_cannot_look_like_generated_artifacts(status: str, field: str, value: object) -> None:
    with pytest.raises(ValidationError, match="cannot include generated artifact metadata"):
        failed_sbom(status, **{field: value})


def test_generation_time_is_normalized_to_utc() -> None:
    local_time = GENERATED_AT.astimezone(timezone(timedelta(hours=-3)))
    result = generated_sbom(generated_at=local_time)
    assert result.generated_at == GENERATED_AT
    assert result.generated_at.utcoffset() == timedelta(0)
    assert result.model_dump(mode="json")["generated_at"] == "2026-09-15T18:30:00Z"


def test_generation_time_requires_a_timezone() -> None:
    with pytest.raises(ValidationError):
        generated_sbom(generated_at=datetime(2026, 9, 15, 18, 30))


@pytest.mark.parametrize("path", ["relative/app.cdx.json", ""])
def test_artifact_path_must_be_absolute(path: str) -> None:
    with pytest.raises(ValidationError, match="path must be absolute"):
        generated_sbom(path=path)


def test_blank_version_and_embedded_components_are_rejected() -> None:
    with pytest.raises(ValidationError, match="must not be blank"):
        generated_sbom(syft_version="  ")
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        generated_sbom(components=[{"name": "a-package"}])


@pytest.mark.parametrize("full_name", ["app", "example/app/extra", "../app", "example/..", " /app"])
def test_repository_identity_requires_owner_and_name(full_name: str) -> None:
    with pytest.raises(ValidationError):
        repository_result(full_name=full_name)
    with pytest.raises(ValidationError):
        SbomRepositoryResult(full_name=full_name, commit_sha=COMMIT_SHA, sbom=generated_sbom())


def test_general_result_requires_full_name_when_sbom_is_present() -> None:
    with pytest.raises(ValidationError, match="must include full_name"):
        repository_result(full_name=None)
    with pytest.raises(ValidationError, match="must match repository name"):
        repository_result(full_name="example/another")


def test_generated_artifact_requires_its_commit_in_both_reports() -> None:
    with pytest.raises(ValidationError, match="identify the analyzed commit"):
        repository_result(commit_sha=None)
    with pytest.raises(ValidationError, match="identify the analyzed commit"):
        SbomRepositoryResult(full_name="example/app", sbom=generated_sbom())


@pytest.mark.parametrize("status", ["failed", "skipped"])
def test_non_generated_artifact_may_have_unknown_commit(status: str) -> None:
    result = SbomRepositoryResult(full_name="example/app", sbom=failed_sbom(status))
    assert result.commit_sha is None


@pytest.mark.parametrize("codeql_status", list(AnalysisStatus))
@pytest.mark.parametrize("sbom_status", list(SbomStatus))
def test_codeql_and_sbom_states_are_independent(
    codeql_status: AnalysisStatus, sbom_status: SbomStatus,
) -> None:
    result = repository_result(
        status=codeql_status,
        analyzed_languages=["javascript"] if codeql_status is AnalysisStatus.ANALYZED else [],
        error=AnalysisError(stage="codeql", message="CodeQL failed")
        if codeql_status is AnalysisStatus.FAILED else None,
        sbom=generated_sbom() if sbom_status is SbomStatus.GENERATED else failed_sbom(sbom_status),
    )
    assert result.status is codeql_status
    assert result.sbom.status is sbom_status
    assert result.commit_sha == COMMIT_SHA


def test_general_report_has_independent_summaries_and_excludes_absent_sboms() -> None:
    report = OrganizationScan(organization="example", repositories=[
        repository_result(
            name="empty", full_name="example/empty", sbom=generated_sbom(component_count=0),
        ),
        repository_result(
            name="failed-codeql", full_name="example/failed-codeql",
            status="failed", analyzed_languages=[],
            error=AnalysisError(stage="codeql", message="CodeQL failed"),
        ),
        repository_result(name="failed-syft", full_name="example/failed-syft", sbom=failed_sbom()),
        repository_result(
            name="skipped", full_name="example/skipped", sbom=failed_sbom("skipped"),
        ),
        repository_result(name="legacy", full_name=None, sbom=None),
    ])
    assert report.summary.repositories == 5
    assert report.summary.analyzed == 4
    assert report.summary.failed == 1
    assert report.sbom_summary.model_dump() == {
        "repositories": 4, "generated": 2, "failed": 1, "skipped": 1, "components": 3,
    }


def test_standalone_report_sorts_full_names_and_keeps_same_name_for_different_owners() -> None:
    report = SbomReport(organization="example", repositories=[
        SbomRepositoryResult(full_name="z-owner/app", sbom=failed_sbom()),
        SbomRepositoryResult(full_name="a-owner/app", commit_sha=COMMIT_SHA, sbom=generated_sbom()),
    ])
    assert [item.full_name for item in report.repositories] == ["a-owner/app", "z-owner/app"]
    assert report.summary.model_dump() == {
        "repositories": 2, "generated": 1, "failed": 1, "skipped": 0, "components": 3,
    }
    payload = report.model_dump(mode="json")
    assert "findings" not in payload["repositories"][0]
    assert "status" not in payload["repositories"][0]


def test_standalone_report_rejects_case_insensitive_duplicates() -> None:
    with pytest.raises(ValidationError, match="full names must be unique"):
        SbomReport(organization="example", repositories=[
            SbomRepositoryResult(full_name="example/app", sbom=failed_sbom()),
            SbomRepositoryResult(full_name="EXAMPLE/APP", sbom=failed_sbom()),
        ])


def test_empty_reports_have_zero_sbom_counters() -> None:
    general = OrganizationScan(organization="example")
    standalone = SbomReport(organization="example")
    assert general.sbom_summary == standalone.summary
    assert set(standalone.summary.model_dump().values()) == {0}


def test_loading_legacy_report_recomputes_serialized_counters() -> None:
    payload = {
        "organization": "example",
        "repositories": [{
            "name": "app", "url": "https://github.com/example/app",
            "status": "analyzed", "analyzed_languages": ["javascript"],
            "findings": [], "finding_count": 999,
        }],
        "summary": {"repositories": 999, "findings": 999},
    }
    report = OrganizationScan.model_validate(payload)
    assert report.repositories[0].sbom is None
    assert report.repositories[0].full_name is None
    assert report.repositories[0].finding_count == 0
    assert report.summary.repositories == 1
    assert report.summary.findings == 0
    assert report.sbom_summary.repositories == 0
    assert payload["repositories"][0]["finding_count"] == 999


def test_unknown_fields_remain_forbidden_when_loading_reports() -> None:
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        OrganizationScan.model_validate({"organization": "example", "typo": 1})
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        SbomReport.model_validate({"organization": "example", "typo": 1})
