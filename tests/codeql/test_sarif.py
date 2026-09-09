"""Pruebas de la conversión aislada de SARIF a hallazgos."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from repo_vuln_miner.codeql.analysis import CodeQLAnalysisArtifact
from repo_vuln_miner.codeql.sarif import SarifNormalizationError, SarifNormalizer
from repo_vuln_miner.github.catalog import GitHubRepository
from repo_vuln_miner.github.workspace import ClonedRepository
from repo_vuln_miner.languages.adapters import (
    CodeQLConfiguration,
    LanguageAdapter,
    ResolvedLanguageAdapter,
    default_language_registry,
)


def cloned_repository(tmp_path: Path) -> ClonedRepository:
    source_path = tmp_path / "source"
    source_path.mkdir()
    repository = GitHubRepository(
        owner="expressjs",
        name="express",
        url="https://github.com/expressjs/express",
        clone_url="https://github.com/expressjs/express.git",
        default_branch="master",
    )
    return ClonedRepository(repository, source_path, "abc123")


def artifact(tmp_path: Path, document: object, adapter: ResolvedLanguageAdapter | None = None):
    sarif_path = tmp_path / "results.sarif"
    sarif_path.write_text(json.dumps(document), encoding="utf-8")
    return CodeQLAnalysisArtifact(
        adapter=adapter or default_language_registry().resolve(["javascript"])[0],
        database_path=tmp_path / "database",
        sarif_path=sarif_path,
    )


def result(
    rule_id: str = "js/example",
    message: object = {"text": "Example finding"},
    **extra: object,
) -> dict[str, object]:
    return {"ruleId": rule_id, "message": message, **extra}


def normalize(tmp_path: Path, document: object):
    repository = cloned_repository(tmp_path)
    return SarifNormalizer().normalize(artifact(tmp_path, document), repository)


def test_normalizes_relative_path_region_message_and_result_severity(tmp_path: Path) -> None:
    findings = normalize(
        tmp_path,
        {
            "runs": [
                {
                    "results": [
                        result(
                            level="error",
                            locations=[
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "src/app.js"},
                                        "region": {"startLine": 12, "startColumn": 4},
                                    }
                                }
                            ],
                        )
                    ]
                }
            ]
        },
    )

    assert [finding.model_dump() for finding in findings] == [
        {
            "language": "javascript",
            "rule_id": "js/example",
            "severity": "error",
            "message": "Example finding",
            "file": "src/app.js",
            "start_line": 12,
            "start_column": 4,
        }
    ]


def test_uses_markdown_and_rule_default_severity_when_result_omits_them(tmp_path: Path) -> None:
    findings = normalize(
        tmp_path,
        {
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "rules": [
                                {
                                    "id": "js/example",
                                    "defaultConfiguration": {"level": "warning"},
                                }
                            ]
                        }
                    },
                    "results": [result(message={"markdown": "**Example finding**"})],
                }
            ]
        },
    )

    assert findings[0].message == "**Example finding**"
    assert findings[0].severity == "warning"


def test_normalizes_absolute_and_file_uris_inside_the_clone(tmp_path: Path) -> None:
    repository = cloned_repository(tmp_path)
    absolute_path = repository.source_path / "src" / "absolute.js"
    file_uri_path = repository.source_path / "src" / "uri.js"
    document = {
        "runs": [
            {
                "results": [
                    result(
                        rule_id="absolute",
                        locations=[
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": str(absolute_path)},
                                    "region": {"startLine": 2},
                                }
                            }
                        ],
                    ),
                    result(
                        rule_id="uri",
                        locations=[
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": file_uri_path.as_uri()},
                                    "region": {"startLine": 3},
                                }
                            }
                        ],
                    ),
                ]
            }
        ]
    }

    findings = SarifNormalizer().normalize(artifact(tmp_path, document), repository)

    assert [(finding.rule_id, finding.file) for finding in findings] == [
        ("absolute", "src/absolute.js"),
        ("uri", "src/uri.js"),
    ]


def test_keeps_finding_without_location_or_with_external_location_without_leaking_path(
    tmp_path: Path,
) -> None:
    repository = cloned_repository(tmp_path)
    external_path = tmp_path / "other-workspace" / "secret.js"
    document = {
        "runs": [
            {
                "results": [
                    result(rule_id="missing"),
                    result(
                        rule_id="external",
                        locations=[
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": str(external_path)},
                                    "region": {"startLine": 8, "startColumn": 2},
                                }
                            }
                        ],
                    ),
                ]
            }
        ]
    }

    findings = SarifNormalizer().normalize(artifact(tmp_path, document), repository)

    assert [(finding.rule_id, finding.file, finding.start_line, finding.start_column) for finding in findings] == [
        ("missing", None, None, None),
        ("external", None, 8, 2),
    ]


def test_sorts_findings_stably_across_runs_and_uses_codeql_language_for_multi_language_adapter(
    tmp_path: Path,
) -> None:
    document = {
        "runs": [
            {
                "results": [
                    result(
                        rule_id="second",
                        message={"text": "B"},
                        locations=[
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "z.js"},
                                    "region": {"startLine": 1},
                                }
                            }
                        ],
                    )
                ]
            },
            {
                "results": [
                    result(
                        rule_id="later-rule",
                        message={"text": "A"},
                        locations=[
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "a.js"},
                                    "region": {"startLine": 2},
                                }
                            }
                        ],
                    ),
                    result(
                        rule_id="first-rule",
                        message={"text": "Z"},
                        locations=[
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "a.js"},
                                    "region": {"startLine": 2},
                                }
                            }
                        ],
                    ),
                ]
            },
        ]
    }

    findings = normalize(tmp_path, document)

    assert [(finding.file, finding.start_line, finding.rule_id, finding.language) for finding in findings] == [
        ("a.js", 2, "first-rule", "javascript"),
        ("a.js", 2, "later-rule", "javascript"),
        ("z.js", 1, "second", "javascript"),
    ]


def test_uses_the_only_supported_language_for_a_single_language_adapter(tmp_path: Path) -> None:
    adapter = ResolvedLanguageAdapter(
        adapter=LanguageAdapter(
            identifier="python",
            supported_languages=frozenset({"python"}),
            configuration=CodeQLConfiguration(
                codeql_language="python",
                build_mode="none",
                query_suite="suite",
                sarif_category="python",
            ),
        ),
        detected_languages=("python",),
    )
    repository = cloned_repository(tmp_path)

    findings = SarifNormalizer().normalize(
        artifact(tmp_path, {"runs": [{"results": [result()]}]}, adapter), repository
    )

    assert findings[0].language == "python"


def test_skips_incomplete_results_and_preserves_valid_ones(tmp_path: Path) -> None:
    findings = normalize(
        tmp_path,
        {
            "runs": [
                {
                    "results": [
                        result(),
                        result(rule_id=" "),
                        result(message={"text": " "}),
                        result(message={}),
                        {"ruleId": "missing-message"},
                    ]
                }
            ]
        },
    )

    assert [(finding.rule_id, finding.message) for finding in findings] == [
        ("js/example", "Example finding")
    ]


@pytest.mark.parametrize(
    ("contents", "expected_message"),
    [
        ("not json", "not valid JSON"),
        (json.dumps({"runs": {}}), "invalid root structure"),
    ],
)
def test_raises_typed_error_for_invalid_sarif_documents(
    tmp_path: Path,
    contents: str,
    expected_message: str,
) -> None:
    repository = cloned_repository(tmp_path)
    sarif_path = tmp_path / "results.sarif"
    sarif_path.write_text(contents, encoding="utf-8")
    analysis_artifact = CodeQLAnalysisArtifact(
        adapter=default_language_registry().resolve(["javascript"])[0],
        database_path=tmp_path / "database",
        sarif_path=sarif_path,
    )

    with pytest.raises(SarifNormalizationError, match=expected_message):
        SarifNormalizer().normalize(analysis_artifact, repository)


def test_raises_typed_error_for_a_missing_sarif_file(tmp_path: Path) -> None:
    repository = cloned_repository(tmp_path)
    analysis_artifact = CodeQLAnalysisArtifact(
        adapter=default_language_registry().resolve(["javascript"])[0],
        database_path=tmp_path / "database",
        sarif_path=tmp_path / "missing.sarif",
    )

    with pytest.raises(SarifNormalizationError, match="was not found"):
        SarifNormalizer().normalize(analysis_artifact, repository)
