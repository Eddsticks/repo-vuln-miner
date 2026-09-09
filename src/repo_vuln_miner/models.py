"""Modelos de dominio y salida pública del miner."""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, computed_field, field_validator, model_validator


class AnalysisStatus(str, Enum):
    """Estado final del análisis de un repositorio."""

    ANALYZED = "analyzed"
    FAILED = "failed"
    UNSUPPORTED = "unsupported"


class AnalysisError(BaseModel):
    """Información segura sobre un error producido durante el análisis."""

    model_config = ConfigDict(extra="forbid")

    stage: str = Field(min_length=1)
    message: str = Field(min_length=1)


class Finding(BaseModel):
    """Hallazgo normalizado desde los resultados de CodeQL."""

    model_config = ConfigDict(extra="forbid")

    language: str = Field(min_length=1)
    rule_id: str = Field(min_length=1)
    severity: str | None = Field(default=None, min_length=1)
    message: str = Field(min_length=1)
    file: str | None = Field(default=None, min_length=1)
    start_line: int | None = Field(default=None, gt=0)
    start_column: int | None = Field(default=None, gt=0)

    @field_validator("language")
    @classmethod
    def normalize_language(cls, language: str) -> str:
        normalized = language.strip().lower()
        if not normalized:
            raise ValueError("language must not be blank")
        return normalized


class RepositoryResult(BaseModel):
    """Resultado consolidado del análisis de un repositorio."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1)
    url: str = Field(min_length=1)
    status: AnalysisStatus
    detected_languages: list[str] = Field(default_factory=list)
    analyzed_languages: list[str] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    error: AnalysisError | None = None
    default_branch: str | None = Field(default=None, min_length=1)
    commit_sha: str | None = Field(default=None, min_length=1)

    @field_validator("detected_languages", "analyzed_languages")
    @classmethod
    def normalize_languages(cls, languages: list[str]) -> list[str]:
        normalized_languages: list[str] = []
        for language in languages:
            normalized = language.strip().lower()
            if not normalized:
                raise ValueError("languages must not contain blank values")
            normalized_languages.append(normalized)
        return sorted(set(normalized_languages))

    @model_validator(mode="after")
    def validate_state_and_sort_findings(self) -> RepositoryResult:
        detected = set(self.detected_languages)
        analyzed = set(self.analyzed_languages)

        if not analyzed.issubset(detected):
            raise ValueError("analyzed_languages must be included in detected_languages")
        if self.status is AnalysisStatus.ANALYZED and not analyzed:
            raise ValueError("analyzed repositories must have an analyzed language")
        if self.status is AnalysisStatus.FAILED and self.error is None:
            raise ValueError("failed repositories must include an error")
        if self.status is AnalysisStatus.UNSUPPORTED:
            if analyzed:
                raise ValueError("unsupported repositories cannot have analyzed languages")
            if self.findings:
                raise ValueError("unsupported repositories cannot have findings")
        if any(finding.language not in analyzed for finding in self.findings):
            raise ValueError("finding languages must be included in analyzed_languages")

        self.findings.sort(
            key=lambda finding: (
                finding.file or "",
                finding.start_line or 0,
                finding.rule_id,
                finding.message,
                finding.language,
            )
        )
        return self

    @computed_field
    @property
    def finding_count(self) -> int:
        """Cantidad de hallazgos asociados al repositorio."""
        return len(self.findings)


class ScanSummary(BaseModel):
    """Contadores agregados de una corrida del miner."""

    model_config = ConfigDict(extra="forbid")

    repositories: int = Field(ge=0)
    analyzed: int = Field(ge=0)
    failed: int = Field(ge=0)
    unsupported: int = Field(ge=0)
    findings: int = Field(ge=0)


class OrganizationScan(BaseModel):
    """Informe completo y reproducible para una organización."""

    model_config = ConfigDict(extra="forbid")

    organization: str = Field(min_length=1)
    repositories: list[RepositoryResult] = Field(default_factory=list)

    @model_validator(mode="after")
    def sort_repositories_and_validate_names(self) -> OrganizationScan:
        names = [repository.name.casefold() for repository in self.repositories]
        if len(names) != len(set(names)):
            raise ValueError("repository names must be unique")
        self.repositories.sort(key=lambda repository: (repository.name.casefold(), repository.name))
        return self

    @computed_field
    @property
    def summary(self) -> ScanSummary:
        """Resumen calculado desde los resultados de repositorio."""
        return ScanSummary(
            repositories=len(self.repositories),
            analyzed=sum(
                repository.status is AnalysisStatus.ANALYZED for repository in self.repositories
            ),
            failed=sum(
                repository.status is AnalysisStatus.FAILED for repository in self.repositories
            ),
            unsupported=sum(
                repository.status is AnalysisStatus.UNSUPPORTED
                for repository in self.repositories
            ),
            findings=sum(repository.finding_count for repository in self.repositories),
        )
