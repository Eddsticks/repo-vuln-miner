"""Ejecución aislada de CodeQL sobre repositorios ya clonados."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from repo_vuln_miner.github.workspace import ClonedRepository
from repo_vuln_miner.languages.adapters import ResolvedLanguageAdapter

CodeQLRunnerProcess = Callable[..., subprocess.CompletedProcess[str]]


@dataclass(frozen=True)
class CodeQLAnalysisArtifact:
    """Artefactos temporales producidos por CodeQL para un adaptador."""

    adapter: ResolvedLanguageAdapter
    database_path: Path
    sarif_path: Path


class CodeQLAnalysisError(RuntimeError):
    """Fallo seguro ocurrido al crear una base o analizarla con CodeQL."""

    def __init__(self, stage: str, message: str) -> None:
        self.stage = stage
        self.message = message
        super().__init__(f"CodeQL {stage} failed: {message}")


class CodeQLRunner:
    """Crea bases CodeQL y ejecuta suites de consultas sin interpretar SARIF."""

    def __init__(
        self,
        codeql_binary: str = "codeql",
        runner: CodeQLRunnerProcess = subprocess.run,
    ) -> None:
        self._codeql_binary = codeql_binary
        self._runner = runner

    def analyze(
        self,
        cloned_repository: ClonedRepository,
        adapter: ResolvedLanguageAdapter,
        workspace_root: Path,
    ) -> CodeQLAnalysisArtifact:
        """Crea una base y un SARIF temporal para el adaptador indicado."""
        configuration = adapter.adapter.configuration
        database_path = workspace_root / f"codeql-db-{adapter.adapter.identifier}"
        sarif_path = workspace_root / f"results-{adapter.adapter.identifier}.sarif"

        self._run(
            "database_create",
            [
                self._codeql_binary,
                "database",
                "create",
                str(database_path),
                f"--language={configuration.codeql_language}",
                f"--build-mode={configuration.build_mode}",
                f"--source-root={cloned_repository.source_path}",
            ],
        )
        self._run(
            "analysis",
            [
                self._codeql_binary,
                "database",
                "analyze",
                str(database_path),
                configuration.query_suite,
                "--format=sarifv2.1.0",
                f"--output={sarif_path}",
                f"--sarif-category={configuration.sarif_category}",
                "--no-sarif-add-file-contents",
                "--no-sarif-add-snippets",
                "--sarif-include-query-help=never",
            ],
        )
        if not sarif_path.is_file():
            raise CodeQLAnalysisError("analysis", "CodeQL did not produce a SARIF file")

        return CodeQLAnalysisArtifact(
            adapter=adapter,
            database_path=database_path,
            sarif_path=sarif_path,
        )

    def _run(self, stage: str, command: list[str]) -> None:
        try:
            result = self._runner(command, capture_output=True, text=True, check=False)
        except FileNotFoundError as error:
            raise CodeQLAnalysisError(stage, "CodeQL executable was not found") from error
        except OSError as error:
            raise CodeQLAnalysisError(stage, "CodeQL command could not be started") from error

        if result.returncode != 0:
            raise CodeQLAnalysisError(stage, "CodeQL command failed")
