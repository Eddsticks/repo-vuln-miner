"""Metadatos locales de los clones administrados por el miner."""

from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from repo_vuln_miner.github.catalog import GitHubRepository


def validate_repository_identifier(value: str) -> str:
    """Valida un segmento de identidad antes de usarlo como ruta local."""
    if value in {".", ".."} or not re.fullmatch(r"[A-Za-z0-9_.-]+", value):
        raise ValueError("repository identity must be a single path segment")
    return value


class RegisteredRepository(BaseModel):
    """Identidad y última revisión comprobada, sin URLs ni credenciales."""

    model_config = ConfigDict(extra="forbid")

    owner: str
    name: str
    default_branch: str = Field(min_length=1)
    relative_path: str
    commit_sha: str = Field(pattern=r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")

    @field_validator("owner", "name")
    @classmethod
    def validate_identifier(cls, value: str) -> str:
        return validate_repository_identifier(value)

    @model_validator(mode="after")
    def validate_relative_path(self) -> RegisteredRepository:
        if self.relative_path != self.full_name:
            raise ValueError("repository path must match its identity")
        return self

    @property
    def full_name(self) -> str:
        return f"{self.owner}/{self.name}"

    def as_repository(self) -> GitHubRepository:
        """Reconstruye la identidad sin consultas a GitHub."""
        url = f"https://github.com/{self.full_name}"
        return GitHubRepository(
            owner=self.owner,
            name=self.name,
            url=url,
            clone_url=f"{url}.git",
            default_branch=self.default_branch,
        )


class RepositoryManifest(BaseModel):
    """Índice versionado; las rutas se resuelven respecto de repos_directory."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1] = 1
    repositories: list[RegisteredRepository] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_identities(self) -> RepositoryManifest:
        names = [repository.full_name.casefold() for repository in self.repositories]
        if len(names) != len(set(names)):
            raise ValueError("repository identities must be unique")
        self.repositories.sort(key=lambda repository: repository.full_name.casefold())
        return self
