"""Registro extensible de lenguajes detectados hacia configuraciones CodeQL."""

from __future__ import annotations

from collections.abc import Collection, Iterable
from dataclasses import dataclass

SUPPORTED_BUILD_MODES = frozenset({"none", "autobuild", "manual"})


def _normalize(value: str, field_name: str) -> str:
    normalized = value.strip().lower()
    if not normalized:
        raise ValueError(f"{field_name} must not be blank")
    return normalized


@dataclass(frozen=True)
class CodeQLConfiguration:
    """Parámetros requeridos para analizar un lenguaje mediante CodeQL."""

    codeql_language: str
    build_mode: str
    query_suite: str
    sarif_category: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "codeql_language", _normalize(self.codeql_language, "codeql_language"))
        normalized_build_mode = _normalize(self.build_mode, "build_mode")
        if normalized_build_mode not in SUPPORTED_BUILD_MODES:
            raise ValueError("build_mode is not supported")
        object.__setattr__(self, "build_mode", normalized_build_mode)
        object.__setattr__(self, "query_suite", self.query_suite.strip())
        object.__setattr__(self, "sarif_category", _normalize(self.sarif_category, "sarif_category"))
        if not self.query_suite:
            raise ValueError("query_suite must not be blank")


@dataclass(frozen=True)
class LanguageAdapter:
    """Asocia lenguajes de GitHub con una configuración concreta de CodeQL."""

    identifier: str
    supported_languages: frozenset[str]
    configuration: CodeQLConfiguration

    def __post_init__(self) -> None:
        object.__setattr__(self, "identifier", _normalize(self.identifier, "identifier"))
        normalized_languages = frozenset(
            _normalize(language, "supported language") for language in self.supported_languages
        )
        if not normalized_languages:
            raise ValueError("an adapter must support at least one language")
        object.__setattr__(self, "supported_languages", normalized_languages)


@dataclass(frozen=True)
class ResolvedLanguageAdapter:
    """Adaptador aplicable y los lenguajes detectados que cubre."""

    adapter: LanguageAdapter
    detected_languages: tuple[str, ...]


class LanguageAdapterRegistry:
    """Registro que evita solapamientos y resuelve adaptadores reproduciblemente."""

    def __init__(self, adapters: Iterable[LanguageAdapter] = ()) -> None:
        self._adapters: dict[str, LanguageAdapter] = {}
        self._languages: dict[str, str] = {}
        for adapter in adapters:
            self.register(adapter)

    def register(self, adapter: LanguageAdapter) -> None:
        """Registra un adaptador, rechazando identificadores o lenguajes repetidos."""
        if adapter.identifier in self._adapters:
            raise ValueError(f"adapter identifier is already registered: {adapter.identifier}")

        overlapping_languages = sorted(
            language for language in adapter.supported_languages if language in self._languages
        )
        if overlapping_languages:
            raise ValueError(
                f"adapter languages are already registered: {', '.join(overlapping_languages)}"
            )

        self._adapters[adapter.identifier] = adapter
        for language in adapter.supported_languages:
            self._languages[language] = adapter.identifier

    def resolve(self, detected_languages: Collection[str]) -> list[ResolvedLanguageAdapter]:
        """Devuelve los adaptadores aplicables, ordenados por identificador."""
        resolved_languages: dict[str, set[str]] = {}
        for language in detected_languages:
            normalized_language = _normalize(language, "detected language")
            identifier = self._languages.get(normalized_language)
            if identifier is not None:
                resolved_languages.setdefault(identifier, set()).add(normalized_language)

        return [
            ResolvedLanguageAdapter(
                adapter=self._adapters[identifier],
                detected_languages=tuple(sorted(languages)),
            )
            for identifier, languages in sorted(resolved_languages.items())
        ]


JAVASCRIPT_TYPESCRIPT_ADAPTER = LanguageAdapter(
    identifier="javascript-typescript",
    supported_languages=frozenset({"javascript", "typescript"}),
    configuration=CodeQLConfiguration(
        codeql_language="javascript",
        build_mode="none",
        query_suite="codeql/javascript-queries:codeql-suites/javascript-security-extended.qls",
        sarif_category="javascript",
    ),
)


def default_language_registry() -> LanguageAdapterRegistry:
    """Crea el registro de la v1 con JavaScript y TypeScript habilitados."""
    return LanguageAdapterRegistry([JAVASCRIPT_TYPESCRIPT_ADAPTER])
