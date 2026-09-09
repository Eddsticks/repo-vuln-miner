"""Pruebas del registro extensible de adaptadores de lenguaje."""

import pytest

from repo_vuln_miner.languages.adapters import (
    CodeQLConfiguration,
    LanguageAdapter,
    LanguageAdapterRegistry,
    default_language_registry,
)


def make_adapter(identifier: str, languages: frozenset[str]) -> LanguageAdapter:
    return LanguageAdapter(
        identifier=identifier,
        supported_languages=languages,
        configuration=CodeQLConfiguration(
            codeql_language=identifier,
            build_mode="none",
            query_suite=f"example/{identifier}.qls",
            sarif_category=identifier,
        ),
    )


def test_default_registry_resolves_javascript_and_typescript_once() -> None:
    resolved = default_language_registry().resolve(["TypeScript", "javascript", "JavaScript"])

    assert len(resolved) == 1
    assert resolved[0].adapter.identifier == "javascript-typescript"
    assert resolved[0].detected_languages == ("javascript", "typescript")
    assert resolved[0].adapter.configuration == CodeQLConfiguration(
        codeql_language="javascript",
        build_mode="none",
        query_suite="codeql/javascript-queries:codeql-suites/javascript-security-extended.qls",
        sarif_category="javascript",
    )


def test_registry_returns_no_adapter_for_unsupported_languages() -> None:
    assert default_language_registry().resolve(["python", "rust"]) == []


def test_registry_resolves_adapters_in_deterministic_order() -> None:
    registry = LanguageAdapterRegistry(
        [make_adapter("python", frozenset({"python"})), make_adapter("javascript", frozenset({"js"}))]
    )

    resolved = registry.resolve(["python", "js"])

    assert [item.adapter.identifier for item in resolved] == ["javascript", "python"]


def test_registry_rejects_duplicate_identifiers() -> None:
    registry = LanguageAdapterRegistry([make_adapter("javascript", frozenset({"javascript"}))])

    with pytest.raises(ValueError, match="identifier is already registered"):
        registry.register(make_adapter("JavaScript", frozenset({"typescript"})))


def test_registry_rejects_overlapping_languages() -> None:
    registry = LanguageAdapterRegistry([make_adapter("javascript", frozenset({"javascript"}))])

    with pytest.raises(ValueError, match="languages are already registered"):
        registry.register(make_adapter("typescript", frozenset({"JavaScript"})))


def test_adapter_configuration_rejects_invalid_build_mode() -> None:
    with pytest.raises(ValueError, match="build_mode is not supported"):
        CodeQLConfiguration(
            codeql_language="javascript",
            build_mode="invalid",
            query_suite="example/query.qls",
            sarif_category="javascript",
        )
