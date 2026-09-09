"""Transformación determinista de resultados SARIF de CodeQL a hallazgos."""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path, PurePosixPath
from urllib.parse import unquote, urlsplit

from repo_vuln_miner.codeql.analysis import CodeQLAnalysisArtifact
from repo_vuln_miner.domain.models import Finding
from repo_vuln_miner.github.workspace import ClonedRepository


class SarifNormalizationError(RuntimeError):
    """Error seguro al leer o validar el documento SARIF de CodeQL."""

    stage = "sarif_normalization"

    def __init__(self, message: str) -> None:
        self.message = message
        super().__init__(f"SARIF normalization failed: {message}")


class SarifNormalizer:
    """Lee el SARIF de un adaptador y produce instancias ordenadas de ``Finding``."""

    def normalize(
        self,
        artifact: CodeQLAnalysisArtifact,
        cloned_repository: ClonedRepository,
    ) -> list[Finding]:
        """Normaliza los resultados válidos del artefacto sin exponer rutas temporales."""
        document = self._read_document(artifact.sarif_path)
        language = self._finding_language(artifact)
        source_path = cloned_repository.source_path.resolve()
        findings: list[Finding] = []

        for run in document["runs"]:
            if not isinstance(run, Mapping):
                continue
            rule_severities = self._rule_severities(run)
            results = run.get("results", [])
            if not isinstance(results, list):
                continue
            for result in results:
                finding = self._finding_from_result(
                    result,
                    language,
                    source_path,
                    rule_severities,
                )
                if finding is not None:
                    findings.append(finding)

        return sorted(
            findings,
            key=lambda finding: (
                finding.file or "",
                finding.start_line or 0,
                finding.rule_id,
                finding.message,
                finding.language,
            ),
        )

    @staticmethod
    def _read_document(sarif_path: Path) -> dict[str, object]:
        try:
            contents = sarif_path.read_text(encoding="utf-8")
        except FileNotFoundError as error:
            raise SarifNormalizationError("SARIF file was not found") from error
        except (OSError, UnicodeError) as error:
            raise SarifNormalizationError("SARIF file could not be read") from error

        try:
            document = json.loads(contents)
        except json.JSONDecodeError as error:
            raise SarifNormalizationError("SARIF file is not valid JSON") from error

        if not isinstance(document, dict) or not isinstance(document.get("runs"), list):
            raise SarifNormalizationError("SARIF document has an invalid root structure")
        return document

    @staticmethod
    def _finding_language(artifact: CodeQLAnalysisArtifact) -> str:
        adapter = artifact.adapter.adapter
        if len(adapter.supported_languages) == 1:
            return next(iter(adapter.supported_languages))
        return adapter.configuration.codeql_language

    @staticmethod
    def _rule_severities(run: Mapping[str, object]) -> dict[str, str]:
        tool = run.get("tool")
        if not isinstance(tool, Mapping):
            return {}
        driver = tool.get("driver")
        if not isinstance(driver, Mapping):
            return {}
        rules = driver.get("rules")
        if not isinstance(rules, list):
            return {}

        severities: dict[str, str] = {}
        for rule in rules:
            if not isinstance(rule, Mapping):
                continue
            rule_id = SarifNormalizer._useful_text(rule.get("id"))
            configuration = rule.get("defaultConfiguration")
            if not rule_id or not isinstance(configuration, Mapping):
                continue
            severity = SarifNormalizer._useful_text(configuration.get("level"))
            if severity is not None:
                severities[rule_id] = severity
        return severities

    def _finding_from_result(
        self,
        result: object,
        language: str,
        source_path: Path,
        rule_severities: Mapping[str, str],
    ) -> Finding | None:
        if not isinstance(result, Mapping):
            return None
        rule_id = self._useful_text(result.get("ruleId"))
        message = self._message(result.get("message"))
        if rule_id is None or message is None:
            return None

        file, start_line, start_column = self._location(result.get("locations"), source_path)
        severity = self._useful_text(result.get("level")) or rule_severities.get(rule_id)
        return Finding(
            language=language,
            rule_id=rule_id,
            severity=severity,
            message=message,
            file=file,
            start_line=start_line,
            start_column=start_column,
        )

    @staticmethod
    def _message(value: object) -> str | None:
        if not isinstance(value, Mapping):
            return None
        return SarifNormalizer._useful_text(value.get("text")) or SarifNormalizer._useful_text(
            value.get("markdown")
        )

    def _location(self, locations: object, source_path: Path) -> tuple[str | None, int | None, int | None]:
        if not isinstance(locations, list):
            return None, None, None
        for location in locations:
            if not isinstance(location, Mapping):
                continue
            physical_location = location.get("physicalLocation")
            if not isinstance(physical_location, Mapping):
                continue
            artifact_location = physical_location.get("artifactLocation")
            file = None
            if isinstance(artifact_location, Mapping):
                file = self._normalized_file(artifact_location.get("uri"), source_path)
            region = physical_location.get("region")
            if not isinstance(region, Mapping):
                return file, None, None
            return (
                file,
                self._positive_integer(region.get("startLine")),
                self._positive_integer(region.get("startColumn")),
            )
        return None, None, None

    @staticmethod
    def _normalized_file(uri: object, source_path: Path) -> str | None:
        if not isinstance(uri, str) or not uri.strip():
            return None
        parsed = urlsplit(uri)
        if parsed.scheme == "file":
            if parsed.netloc not in ("", "localhost"):
                return None
            candidate = Path(unquote(parsed.path))
        elif parsed.scheme:
            return None
        else:
            candidate = Path(uri)

        if not candidate.is_absolute():
            relative = PurePosixPath(uri.replace("\\", "/"))
            if relative.is_absolute() or ".." in relative.parts:
                return None
            return relative.as_posix()

        try:
            return candidate.resolve().relative_to(source_path).as_posix()
        except ValueError:
            return None

    @staticmethod
    def _useful_text(value: object) -> str | None:
        if not isinstance(value, str):
            return None
        value = value.strip()
        return value or None

    @staticmethod
    def _positive_integer(value: object) -> int | None:
        if isinstance(value, int) and not isinstance(value, bool) and value > 0:
            return value
        return None
