"""Cliente REST para descubrir repositorios y lenguajes en GitHub."""

from __future__ import annotations

import os
from collections.abc import Collection, Mapping
from typing import Any
from urllib.parse import quote

import requests
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from repo_vuln_miner import __version__

DEFAULT_API_URL = "https://api.github.com"
GITHUB_API_VERSION = "2026-03-10"


class GitHubCatalogError(RuntimeError):
    """Error controlado al comunicarse con la API de GitHub."""


class GitHubAuthenticationError(GitHubCatalogError):
    """No se configuró un token válido para las solicitudes GitHub."""

    def __init__(self) -> None:
        self.message = "GITHUB_TOKEN must be configured"
        super().__init__(self.message)


class GitHubResponseError(GitHubCatalogError):
    """La API devolvió una respuesta que no cumple el contrato esperado."""


class RequestedRepositoriesNotFound(GitHubCatalogError):
    """La selección solicitada contiene repositorios ausentes de la organización."""

    def __init__(self, missing_names: Collection[str]) -> None:
        self.missing_names = tuple(sorted(missing_names, key=str.casefold))
        super().__init__(f"Requested repositories were not found: {', '.join(self.missing_names)}")


class GitHubRepository(BaseModel):
    """Metadatos de un repositorio necesarios para las fases posteriores."""

    model_config = ConfigDict(extra="forbid")

    owner: str = Field(min_length=1)
    name: str = Field(min_length=1)
    url: str = Field(min_length=1)
    clone_url: str = Field(min_length=1)
    default_branch: str = Field(min_length=1)


class GitHubCatalog:
    """Consulta el catálogo de una organización mediante GitHub REST API."""

    def __init__(
        self,
        token: str | None = None,
        session: requests.Session | None = None,
        base_url: str = DEFAULT_API_URL,
        timeout: float = 30.0,
    ) -> None:
        normalized_token = token.strip() if isinstance(token, str) else ""
        if not normalized_token:
            raise GitHubAuthenticationError
        normalized_base_url = base_url.rstrip("/")
        if not normalized_base_url:
            raise ValueError("base_url must not be blank")
        if timeout <= 0:
            raise ValueError("timeout must be positive")

        self._base_url = normalized_base_url
        self._session = session or requests.Session()
        self._timeout = timeout
        self._headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": f"repo-vuln-miner/{__version__}",
            "X-GitHub-Api-Version": GITHUB_API_VERSION,
        }
        self._headers["Authorization"] = f"Bearer {normalized_token}"

    @classmethod
    def from_environment(cls, **kwargs: Any) -> GitHubCatalog:
        """Construye el catálogo usando el ``GITHUB_TOKEN`` obligatorio."""
        token = os.environ.get("GITHUB_TOKEN", "").strip()
        if not token:
            raise GitHubAuthenticationError
        return cls(token=token, **kwargs)

    def list_repositories(
        self,
        organization: str,
        selected_names: Collection[str] | None = None,
    ) -> list[GitHubRepository]:
        """Lista todos los repositorios visibles de una organización."""
        normalized_organization = self._normalize_identifier(organization, "organization")
        url = f"{self._base_url}/orgs/{quote(normalized_organization, safe='')}/repos"
        params: dict[str, str | int] | None = {
            "type": "all",
            "sort": "full_name",
            "direction": "asc",
            "per_page": 100,
        }
        repositories: list[GitHubRepository] = []

        while url:
            payload, response = self._get_json(url, params=params)
            if not isinstance(payload, list):
                raise GitHubResponseError("GitHub repository list must be an array")
            repositories.extend(
                self._repository_from_payload(item, normalized_organization) for item in payload
            )
            next_link = getattr(response, "links", {}).get("next", {})
            url = next_link.get("url")
            params = None

        repositories.sort(key=lambda repository: (repository.name.casefold(), repository.name))
        return self._select_repositories(repositories, selected_names)

    def get_languages(self, repository: GitHubRepository) -> list[str]:
        """Obtiene los lenguajes detectados para un repositorio bajo demanda."""
        owner = quote(repository.owner, safe="")
        name = quote(repository.name, safe="")
        payload, _ = self._get_json(f"{self._base_url}/repos/{owner}/{name}/languages")
        if not isinstance(payload, Mapping) or not all(isinstance(key, str) for key in payload):
            raise GitHubResponseError("GitHub languages response must be an object with language names")
        return sorted({language.strip().lower() for language in payload if language.strip()})

    def _get_json(
        self,
        url: str,
        params: Mapping[str, str | int] | None = None,
    ) -> tuple[Any, requests.Response]:
        try:
            response = self._session.get(
                url,
                params=params,
                headers=self._headers,
                timeout=self._timeout,
            )
            response.raise_for_status()
        except requests.RequestException as error:
            raise GitHubCatalogError(f"GitHub request failed: {error}") from error

        try:
            return response.json(), response
        except ValueError as error:
            raise GitHubResponseError("GitHub response is not valid JSON") from error

    @staticmethod
    def _normalize_identifier(value: str, field_name: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError(f"{field_name} must not be blank")
        return normalized

    @staticmethod
    def _repository_from_payload(payload: Any, organization: str) -> GitHubRepository:
        if not isinstance(payload, Mapping):
            raise GitHubResponseError("GitHub repository item must be an object")
        try:
            return GitHubRepository.model_validate(
                {
                    "owner": payload.get("owner", {}).get("login", organization),
                    "name": payload["name"],
                    "url": payload["html_url"],
                    "clone_url": payload["clone_url"],
                    "default_branch": payload["default_branch"],
                }
            )
        except (KeyError, AttributeError, ValidationError) as error:
            raise GitHubResponseError("GitHub repository item is missing required metadata") from error

    @staticmethod
    def _select_repositories(
        repositories: list[GitHubRepository],
        selected_names: Collection[str] | None,
    ) -> list[GitHubRepository]:
        if selected_names is None:
            return repositories

        normalized_selected = {
            GitHubCatalog._normalize_identifier(name, "repository name").casefold()
            for name in selected_names
        }
        by_name = {repository.name.casefold(): repository for repository in repositories}
        missing_names = normalized_selected.difference(by_name)
        if missing_names:
            raise RequestedRepositoriesNotFound(missing_names)
        return [repository for repository in repositories if repository.name.casefold() in normalized_selected]
