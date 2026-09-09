"""Pruebas para los modelos de dominio del miner."""

import pytest
from pydantic import ValidationError

from repo_vuln_miner.domain.models import (
    AnalysisError,
    AnalysisStatus,
    Finding,
    OrganizationScan,
    RepositoryResult,
)


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


def test_report_calculates_summary_and_orders_results() -> None:
    later_finding = Finding(
        language="JavaScript",
        rule_id="js/z-rule",
        message="Later finding",
        file="src/z.js",
        start_line=20,
    )
    earlier_finding = Finding(
        language="javascript",
        rule_id="js/a-rule",
        message="Earlier finding",
        file="src/a.js",
        start_line=2,
    )
    report = OrganizationScan(
        organization="expressjs",
        repositories=[
            make_repository(name="multer", findings=[later_finding, earlier_finding]),
            make_repository(
                name="body-parser",
                status=AnalysisStatus.FAILED,
                detected_languages=[],
                analyzed_languages=[],
                error=AnalysisError(stage="clone", message="Repository could not be cloned"),
            ),
            make_repository(
                name="accepts",
                status=AnalysisStatus.UNSUPPORTED,
                detected_languages=["Rust"],
                analyzed_languages=[],
            ),
        ],
    )

    assert [repository.name for repository in report.repositories] == [
        "accepts",
        "body-parser",
        "multer",
    ]
    assert [finding.rule_id for finding in report.repositories[2].findings] == [
        "js/a-rule",
        "js/z-rule",
    ]
    assert report.repositories[2].finding_count == 2
    assert report.summary.repositories == 3
    assert report.summary.analyzed == 1
    assert report.summary.failed == 1
    assert report.summary.unsupported == 1
    assert report.summary.findings == 2


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"analyzed_languages": []}, "analyzed repositories"),
        ({"status": AnalysisStatus.FAILED}, "failed repositories"),
        (
            {
                "status": AnalysisStatus.UNSUPPORTED,
                "analyzed_languages": [],
                "findings": [
                    Finding(language="javascript", rule_id="js/rule", message="Finding")
                ],
            },
            "unsupported repositories",
        ),
    ],
)
def test_repository_state_invariants_are_validated(changes: dict[str, object], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        make_repository(**changes)


def test_finding_location_must_be_positive() -> None:
    with pytest.raises(ValidationError):
        Finding(
            language="javascript",
            rule_id="js/rule",
            message="Finding",
            start_line=0,
        )


def test_repository_names_must_be_unique_case_insensitively() -> None:
    with pytest.raises(ValidationError, match="repository names must be unique"):
        OrganizationScan(
            organization="expressjs",
            repositories=[make_repository(name="express"), make_repository(name="Express")],
        )
