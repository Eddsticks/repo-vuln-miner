"""Pruebas para la escritura de informes JSON."""

import json

from repo_vuln_miner.domain.models import (
    AnalysisError,
    AnalysisStatus,
    Finding,
    OrganizationScan,
    RepositoryResult,
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
