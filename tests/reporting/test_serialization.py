"""Pruebas para la escritura de informes JSON."""

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from repo_vuln_miner.domain.models import (
    AnalysisError,
    AnalysisStatus,
    Finding,
    OrganizationScan,
    RepositoryResult,
    SbomReport,
    SbomRepositoryResult,
    SbomResult,
)
from repo_vuln_miner.reporting.serialization import write_report_json


def make_repository(**changes: object) -> RepositoryResult:
    values: dict[str, object] = {
        "name": "express",
        "url": "https://github.com/expressjs/express",
        "status": AnalysisStatus.ANALYZED,
        "detected_languages": ["JavaScript"],
        "analyzed_languages": ["JavaScript"],
    }
    values.update(changes)
    return RepositoryResult(**values)


def test_writer_creates_parent_and_emits_model_json(tmp_path) -> None:
    report = OrganizationScan(
        organization="expressjs",
        repositories=[
            make_repository(
                default_branch="master",
                commit_sha="abc123",
                findings=[
                    Finding(
                        language="javascript",
                        rule_id="js/example",
                        severity="warning",
                        message="Example finding",
                        file="src/example.js",
                        start_line=42,
                    )
                ],
            )
        ],
    )
    output = tmp_path / "reports" / "result.json"

    write_report_json(report, output)

    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["organization"] == "expressjs"
    assert payload["summary"]["findings"] == 1
    assert payload["repositories"][0]["finding_count"] == 1
    assert "error" not in payload["repositories"][0]
    assert not list(output.parent.glob(".*.tmp"))


def test_optional_values_are_omitted_and_error_is_safe(tmp_path) -> None:
    report = OrganizationScan(
        organization="expressjs",
        repositories=[
            make_repository(
                status=AnalysisStatus.FAILED,
                detected_languages=[],
                analyzed_languages=[],
                error=AnalysisError(stage="database_create", message="CodeQL failed"),
            )
        ],
    )
    output = tmp_path / "result.json"

    write_report_json(report, output)

    repository = json.loads(output.read_text(encoding="utf-8"))["repositories"][0]
    assert "default_branch" not in repository
    assert "commit_sha" not in repository
    assert repository["error"] == {"stage": "database_create", "message": "CodeQL failed"}


def make_sbom_report(standalone: bool, artifact: Path) -> OrganizationScan | SbomReport:
    sbom = SbomResult(
        status="generated",
        generated_at=datetime(2026, 9, 15, 18, 30, tzinfo=timezone.utc),
        syft_version="1.0.0",
        component_count=0,
        path=artifact,
    )
    failed = SbomResult(
        status="failed",
        error=AnalysisError(stage="syft", message="Syft executable was not found"),
    )
    if standalone:
        return SbomReport(organization="expressjs", repositories=[
            SbomRepositoryResult(full_name="expressjs/express", commit_sha="a" * 40, sbom=sbom),
            SbomRepositoryResult(full_name="expressjs/broken", sbom=failed),
        ])
    return OrganizationScan(organization="expressjs", repositories=[
        make_repository(full_name="expressjs/express", commit_sha="a" * 40, sbom=sbom),
        make_repository(name="broken", full_name="expressjs/broken", sbom=failed),
    ])


@pytest.mark.parametrize("standalone", [False, True])
def test_sbom_reports_round_trip_and_preserve_original_artifact(tmp_path, standalone: bool) -> None:
    artifact = tmp_path / "express.cdx.json"
    original = b'{ "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "components": [] }\n'
    artifact.write_bytes(original)
    report = make_sbom_report(standalone, artifact)
    output = tmp_path / "reports" / "report.json"

    write_report_json(report, output)

    payload = json.loads(output.read_text(encoding="utf-8"))
    failed, generated = payload["repositories"]
    assert generated["full_name"] == "expressjs/express"
    assert generated["commit_sha"] == "a" * 40
    assert generated["sbom"] == {
        "status": "generated", "generated_at": "2026-09-15T18:30:00Z",
        "syft_version": "1.0.0", "component_count": 0, "path": str(artifact),
    }
    assert failed["sbom"] == {
        "status": "failed",
        "error": {"stage": "syft", "message": "Syft executable was not found"},
    }
    summary = payload["summary" if standalone else "sbom_summary"]
    assert summary == {"repositories": 2, "generated": 1, "failed": 1, "skipped": 0, "components": 0}
    assert type(report).model_validate_json(output.read_text(encoding="utf-8")) == report
    assert artifact.read_bytes() == original
    assert not list(output.parent.glob(".*.tmp"))


@pytest.mark.parametrize("standalone", [False, True])
def test_loading_report_recomputes_sbom_summary(tmp_path, standalone: bool) -> None:
    report = make_sbom_report(standalone, tmp_path / "express.cdx.json")
    payload = report.model_dump(mode="json")
    summary_key = "summary" if standalone else "sbom_summary"
    payload[summary_key]["generated"] = 999
    payload[summary_key]["components"] = 999
    reloaded = type(report).model_validate(payload)
    assert reloaded.model_dump(mode="json")[summary_key]["generated"] == 1
    assert reloaded.model_dump(mode="json")[summary_key]["components"] == 0


@pytest.mark.parametrize("standalone", [False, True])
def test_atomic_write_failure_preserves_previous_report(tmp_path, monkeypatch, standalone: bool) -> None:
    output = tmp_path / "report.json"
    output.write_text("previous report", encoding="utf-8")
    report = make_sbom_report(standalone, tmp_path / "express.cdx.json")

    def fail_replace(*args) -> None:
        raise OSError("disk full")

    monkeypatch.setattr("repo_vuln_miner.reporting.serialization.os.replace", fail_replace)
    with pytest.raises(OSError, match="disk full"):
        write_report_json(report, output)
    assert output.read_text(encoding="utf-8") == "previous report"
    assert not list(output.parent.glob(".*.tmp"))
