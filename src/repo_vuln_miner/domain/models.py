"""Modelos de dominio y salida pública del miner."""

from __future__ import annotations

import re
from collections.abc import Iterable
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    computed_field,
    field_validator,
    model_validator,
)


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


class SbomStatus(str, Enum):
    """Estado de generación, independiente del resultado de CodeQL."""

    GENERATED = "generated"
    FAILED = "failed"
    SKIPPED = "skipped"


class SbomResult(BaseModel):
    """Metadatos del inventario; el CycloneDX original permanece en su archivo."""

    model_config = ConfigDict(extra="forbid")

    status: SbomStatus
    generated_at: AwareDatetime | None = None
    syft_version: str | None = Field(default=None, min_length=1)
    component_count: int | None = Field(default=None, ge=0, strict=True)
    path: Path | None = None
    error: AnalysisError | None = None

    @field_validator("generated_at")
    @classmethod
    def normalize_generation_time(cls, value: datetime | None) -> datetime | None:
        return value.astimezone(timezone.utc) if value is not None else None

    @field_validator("syft_version")
    @classmethod
    def normalize_syft_version(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        if not normalized:
            raise ValueError("syft_version must not be blank")
        return normalized

    @field_validator("path")
    @classmethod
    def validate_absolute_path(cls, value: Path | None) -> Path | None:
        if value is not None and not value.is_absolute():
            raise ValueError("SBOM path must be absolute")
        return value

    @model_validator(mode="after")
    def validate_state(self) -> SbomResult:
        if self.status is SbomStatus.GENERATED:
            if any(value is None for value in (
                self.generated_at, self.syft_version, self.component_count, self.path,
            )):
                raise ValueError("generated SBOMs require date, version, component count and path")
            if self.error is not None:
                raise ValueError("generated SBOMs cannot include an error")
        else:
            if self.error is None:
                raise ValueError("failed or skipped SBOMs must include an error or reason")
            if any(value is not None for value in (
                self.generated_at, self.component_count, self.path,
            )):
                raise ValueError("failed or skipped SBOMs cannot include generated artifact metadata")
        return self


class SbomSummary(BaseModel):
    """Contadores SBOM; los repositorios sin resultado SBOM no se contabilizan."""

    model_config = ConfigDict(extra="forbid")

    repositories: int = Field(ge=0)
    generated: int = Field(ge=0)
    failed: int = Field(ge=0)
    skipped: int = Field(ge=0)
    components: int = Field(ge=0)

    @classmethod
    def from_results(cls, results: Iterable[SbomResult]) -> SbomSummary:
        items = list(results)
        return cls(
            repositories=len(items),
            generated=sum(item.status is SbomStatus.GENERATED for item in items),
            failed=sum(item.status is SbomStatus.FAILED for item in items),
            skipped=sum(item.status is SbomStatus.SKIPPED for item in items),
            components=sum(item.component_count or 0 for item in items),
        )


def _validate_full_name(value: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", value):
        raise ValueError("full_name must have the form owner/repository")
    if any(part in {".", ".."} for part in value.split("/")):
        raise ValueError("full_name must not contain relative path segments")
    return value


class SbomRepositoryResult(BaseModel):
    """Identidad, revisión disponible y resultado para una corrida solo de SBOM."""

    model_config = ConfigDict(extra="forbid")

    full_name: str
    commit_sha: str | None = Field(default=None, min_length=1)
    sbom: SbomResult

    @field_validator("full_name")
    @classmethod
    def validate_full_name(cls, value: str) -> str:
        return _validate_full_name(value)

    @model_validator(mode="after")
    def require_generated_commit(self) -> SbomRepositoryResult:
        if self.sbom.status is SbomStatus.GENERATED and not self.commit_sha:
            raise ValueError("generated SBOMs must identify the analyzed commit")
        return self


class SbomReport(BaseModel):
    """Informe independiente, sin estados ni hallazgos ficticios de CodeQL."""

    model_config = ConfigDict(extra="forbid")

    organization: str = Field(min_length=1)
    repositories: list[SbomRepositoryResult] = Field(default_factory=list)

    @model_validator(mode="before")
    @classmethod
    def discard_serialized_summary(cls, value: Any) -> Any:
        if isinstance(value, dict):
            return {key: item for key, item in value.items() if key != "summary"}
        return value

    @model_validator(mode="after")
    def sort_repositories_and_validate_names(self) -> SbomReport:
        names = [repository.full_name.casefold() for repository in self.repositories]
        if len(names) != len(set(names)):
            raise ValueError("repository full names must be unique")
        self.repositories.sort(key=lambda repository: repository.full_name.casefold())
        return self

    @computed_field
    @property
    def summary(self) -> SbomSummary:
        return SbomSummary.from_results(repository.sbom for repository in self.repositories)


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
    full_name: str | None = None
    sbom: SbomResult | None = None

    @model_validator(mode="before")
    @classmethod
    def discard_serialized_finding_count(cls, value: Any) -> Any:
        if isinstance(value, dict):
            return {key: item for key, item in value.items() if key != "finding_count"}
        return value

    @field_validator("full_name")
    @classmethod
    def validate_full_name(cls, value: str | None) -> str | None:
        return _validate_full_name(value) if value is not None else None

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
        analyzed = set(self.analyzed_languages)

        if self.full_name is not None and self.full_name.split("/")[1].casefold() != self.name.casefold():
            raise ValueError("full_name must match repository name")
        if self.sbom is not None:
            if self.full_name is None:
                raise ValueError("repositories with SBOM results must include full_name")
            if self.sbom.status is SbomStatus.GENERATED and not self.commit_sha:
                raise ValueError("generated SBOMs must identify the analyzed commit")

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

    @model_validator(mode="before")
    @classmethod
    def discard_serialized_summaries(cls, value: Any) -> Any:
        if isinstance(value, dict):
            return {
                key: item for key, item in value.items()
                if key not in {"summary", "sbom_summary"}
            }
        return value

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

    @computed_field
    @property
    def sbom_summary(self) -> SbomSummary:
        """Resumen SBOM separado de los contadores históricos de CodeQL."""
        return SbomSummary.from_results(
            repository.sbom for repository in self.repositories if repository.sbom is not None
        )
