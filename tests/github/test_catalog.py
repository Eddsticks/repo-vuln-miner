"""Pruebas aisladas del catálogo REST de GitHub."""

from __future__ import annotations

from typing import Any

import pytest
import requests

from repo_vuln_miner.github.catalog import (
    GITHUB_API_VERSION,
    GitHubAuthenticationError,
    GitHubCatalog,
    GitHubCatalogError,
    GitHubRepository,
    GitHubResponseError,
    RequestedRepositoriesNotFound,
)


class FakeResponse:
    def __init__(
        self,
        payload: Any = None,
        *,
        links: dict[str, dict[str, str]] | None = None,
        error: requests.RequestException | None = None,
    ) -> None:
        self._payload = payload
        self.links = links or {}
        self._error = error

    def raise_for_status(self) -> None:
        if self._error:
            raise self._error

    def json(self) -> Any:
        if isinstance(self._payload, Exception):
            raise self._payload
        return self._payload


class FakeSession:
    def __init__(self, responses: list[FakeResponse | requests.RequestException]) -> None:
        self.responses = responses
        self.calls: list[dict[str, Any]] = []

    def get(self, url: str, **kwargs: Any) -> FakeResponse:
        self.calls.append({"url": url, **kwargs})
        response = self.responses.pop(0)
        if isinstance(response, requests.RequestException):
            raise response
        return response


def repository_payload(name: str) -> dict[str, Any]:
    return {
        "name": name,
        "html_url": f"https://github.com/expressjs/{name}",
        "clone_url": f"https://github.com/expressjs/{name}.git",
        "default_branch": "master",
        "owner": {"login": "expressjs"},
    }


def test_list_repositories_follows_pagination_and_orders_results() -> None:
    session = FakeSession(
        [
            FakeResponse(
                [repository_payload("multer")],
                links={"next": {"url": "https://api.github.com/orgs/expressjs/repos?page=2"}},
            ),
            FakeResponse([repository_payload("body-parser"), repository_payload("express")]),
        ]
    )
    catalog = GitHubCatalog(token="test-token", session=session)

    repositories = catalog.list_repositories("expressjs")

    assert [repository.name for repository in repositories] == ["body-parser", "express", "multer"]
    assert repositories[1].clone_url == "https://github.com/expressjs/express.git"
    assert session.calls[0]["params"] == {
        "type": "all",
        "sort": "full_name",
        "direction": "asc",
        "per_page": 100,
    }
    assert session.calls[1]["params"] is None


def test_catalog_uses_required_token_from_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "test-token")
    session = FakeSession([FakeResponse([])])

    GitHubCatalog.from_environment(session=session).list_repositories("expressjs")

    assert session.calls[0]["headers"]["Authorization"] == "Bearer test-token"
    assert session.calls[0]["headers"]["X-GitHub-Api-Version"] == GITHUB_API_VERSION


@pytest.mark.parametrize("token", [None, "", "   "])
def test_catalog_rejects_missing_or_blank_environment_token(
    monkeypatch: pytest.MonkeyPatch,
    token: str | None,
) -> None:
    if token is None:
        monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    else:
        monkeypatch.setenv("GITHUB_TOKEN", token)
    session = FakeSession([FakeResponse([])])

    with pytest.raises(GitHubAuthenticationError, match="GITHUB_TOKEN"):
        GitHubCatalog.from_environment(session=session)

    assert session.calls == []


@pytest.mark.parametrize("token", [None, "", "   "])
def test_catalog_rejects_missing_or_blank_direct_token(token: str | None) -> None:
    with pytest.raises(GitHubAuthenticationError, match="GITHUB_TOKEN"):
        GitHubCatalog(token=token)


def test_catalog_supports_a_custom_api_base_url() -> None:
    session = FakeSession([FakeResponse([])])

    GitHubCatalog(token="test-token", session=session, base_url="https://github.example/api/v3/").list_repositories(
        "expressjs"
    )

    assert session.calls[0]["url"] == "https://github.example/api/v3/orgs/expressjs/repos"


def test_list_repositories_filters_case_insensitively() -> None:
    session = FakeSession([FakeResponse([repository_payload("multer"), repository_payload("express")])])

    repositories = GitHubCatalog(token="test-token", session=session).list_repositories(
        "expressjs", selected_names=["EXPRESS"]
    )

    assert [repository.name for repository in repositories] == ["express"]


def test_list_repositories_rejects_missing_selected_names() -> None:
    session = FakeSession([FakeResponse([repository_payload("express")])])

    with pytest.raises(RequestedRepositoriesNotFound, match="multer"):
        GitHubCatalog(token="test-token", session=session).list_repositories(
            "expressjs", selected_names=["express", "multer"]
        )


def test_get_languages_normalizes_and_orders_values() -> None:
    session = FakeSession([FakeResponse({"TypeScript": 100, "JavaScript": 200})])
    repository = GitHubRepository(
        owner="expressjs",
        name="express",
        url="https://github.com/expressjs/express",
        clone_url="https://github.com/expressjs/express.git",
        default_branch="master",
    )

    languages = GitHubCatalog(token="test-token", session=session).get_languages(repository)

    assert languages == ["javascript", "typescript"]
    assert session.calls[0]["url"].endswith("/repos/expressjs/express/languages")


@pytest.mark.parametrize(
    "response",
    [
        FakeResponse({"name": "not-a-list"}),
        FakeResponse(ValueError("invalid JSON")),
    ],
)
def test_list_repositories_rejects_invalid_responses(response: FakeResponse) -> None:
    with pytest.raises(GitHubResponseError):
        GitHubCatalog(token="test-token", session=FakeSession([response])).list_repositories(
            "expressjs"
        )


def test_catalog_wraps_request_errors() -> None:
    session = FakeSession([requests.ConnectionError("network unavailable")])

    with pytest.raises(GitHubCatalogError, match="GitHub request failed"):
        GitHubCatalog(token="test-token", session=session).list_repositories("expressjs")
