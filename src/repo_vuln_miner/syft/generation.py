"""Ejecución de Syft sobre clones locales y publicación de SBOMs originales."""

from __future__ import annotations

import json
import math
import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Callable
from uuid import uuid4

from repo_vuln_miner.domain.models import SbomResult, SbomStatus
from repo_vuln_miner.github.manifest import validate_repository_identifier
from repo_vuln_miner.github.workspace import ClonedRepository

SyftRunnerProcess = Callable[..., subprocess.CompletedProcess[str]]


class SyftExecutionError(RuntimeError):
    """Error seguro que la orquestación puede registrar sin exponer stderr."""

    def __init__(self, stage: str, message: str, syft_version: str | None = None) -> None:
        self.stage = stage
        self.message = message
        self.syft_version = syft_version
        super().__init__(f"Syft {stage} failed: {message}")


def _reject_json_constant(value: str) -> None:
    """JSON no admite NaN ni infinitos, aunque json.loads los acepte por defecto."""
    raise ValueError("nonstandard JSON constant")


class SyftRunner:
    """Una instancia por corrida secuencial: comparte versión e identificador."""

    def __init__(
        self,
        syft_binary: str = "syft",
        runner: SyftRunnerProcess = subprocess.run,
        timeout: float = 300.0,
    ) -> None:
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("Syft timeout must be finite and positive")
        self._syft_binary = syft_binary
        self._runner = runner
        self._timeout = timeout
        self._run_id = uuid4().hex
        self._version: str | None = None
        self._version_error: tuple[str, str] | None = None

    @property
    def run_id(self) -> str:
        """Identifica el directorio de artefactos de esta corrida."""
        return self._run_id

    def get_version(self) -> str:
        """Consulta la versión una sola vez, incluso cuando falla la consulta."""
        if self._version_error is not None:
            raise SyftExecutionError(*self._version_error)
        if self._version is not None:
            return self._version
        try:
            result = self._run("syft_version", [self._syft_binary, "version", "-o", "json"])
            try:
                payload = json.loads(result.stdout, parse_constant=_reject_json_constant)
            except (ValueError, RecursionError) as error:
                raise SyftExecutionError("syft_version", "Syft version output is not valid JSON") from error
            version = payload.get("version") if isinstance(payload, dict) else None
            if not isinstance(version, str) or not version.strip():
                raise SyftExecutionError("syft_version", "Syft did not report a valid version")
            self._version = version.strip()
        except SyftExecutionError as error:
            self._version_error = (error.stage, error.message)
            raise
        return self._version

    def generate(self, cloned_repository: ClonedRepository, output_directory: Path) -> SbomResult:
        """Devuelve metadatos de éxito; los errores se comunican mediante SyftExecutionError."""
        try:
            validate_repository_identifier(cloned_repository.repository.owner)
            validate_repository_identifier(cloned_repository.repository.name)
        except ValueError as error:
            raise SyftExecutionError("sbom_source", "Repository identity is invalid", self._version) from error

        try:
            source_path = cloned_repository.source_path.resolve()
            output_root = output_directory.resolve()
            source_exists = source_path.is_dir()
        except (OSError, RuntimeError) as error:
            raise SyftExecutionError("sbom_source", "Repository paths could not be resolved", self._version) from error
        if not source_exists:
            raise SyftExecutionError("sbom_source", "Repository directory is missing", self._version)
        if output_root.is_relative_to(source_path):
            raise SyftExecutionError(
                "sbom_write", "SBOM output directory must be outside the repository", self._version,
            )

        version = self.get_version()
        artifact_path = (
            output_root / self.run_id / cloned_repository.repository.owner
            / f"{cloned_repository.repository.name}.cdx.json"
        )
        try:
            # No reutilizar un resultado previo como si perteneciera a este intento.
            if artifact_path.exists() or artifact_path.is_symlink():
                raise SyftExecutionError("sbom_write", "SBOM artifact already exists for this run", version)
            artifact_path.parent.mkdir(parents=True, exist_ok=True)
            with TemporaryDirectory(prefix=".sbom-", dir=artifact_path.parent) as temporary_directory:
                temporary_path = Path(temporary_directory) / "sbom.cdx.json"
                self._run(
                    "sbom_generation",
                    [self._syft_binary, "scan", f"dir:{source_path}",
                     "-o", f"cyclonedx-json={temporary_path}"],
                )
                component_count = self._component_count(temporary_path)
                result = SbomResult(
                    status=SbomStatus.GENERATED,
                    generated_at=datetime.now(timezone.utc),
                    syft_version=version,
                    component_count=component_count,
                    path=artifact_path,
                )
                # Publicar los bytes originales en el mismo filesystem, sin reserializar.
                os.replace(temporary_path, artifact_path)
            return result
        except OSError as error:
            raise SyftExecutionError("sbom_write", "SBOM artifact could not be written", version) from error

    def _component_count(self, path: Path) -> int:
        try:
            if not path.is_file() or path.is_symlink():
                raise SyftExecutionError("sbom_validation", "Syft did not produce an SBOM file", self._version)
            payload = json.loads(path.read_text(encoding="utf-8"), parse_constant=_reject_json_constant)
        except OSError as error:
            raise SyftExecutionError("sbom_validation", "SBOM artifact could not be read", self._version) from error
        except (ValueError, RecursionError) as error:
            raise SyftExecutionError("sbom_validation", "SBOM file is not valid JSON", self._version) from error
        if not isinstance(payload, dict) or payload.get("bomFormat") != "CycloneDX":
            raise SyftExecutionError("sbom_validation", "SBOM file is not CycloneDX", self._version)
        specification = payload.get("specVersion")
        if not isinstance(specification, str) or not re.fullmatch(r"[0-9]+\.[0-9]+", specification):
            raise SyftExecutionError("sbom_validation", "CycloneDX specification version is invalid", self._version)
        bom_version = payload.get("version", 1)
        if type(bom_version) is not int or bom_version < 1:
            raise SyftExecutionError("sbom_validation", "CycloneDX BOM version is invalid", self._version)
        components = payload.get("components", [])
        if not isinstance(components, list) or any(
            not isinstance(component, dict)
            or not isinstance(component.get("name"), str)
            or not component["name"].strip()
            or not isinstance(component.get("type"), str)
            or not component["type"].strip()
            for component in components
        ):
            raise SyftExecutionError("sbom_validation", "CycloneDX components are invalid", self._version)
        # metadata.component identifica la fuente; no es una dependencia adicional.
        return len(components)

    def _run(self, stage: str, command: list[str]) -> subprocess.CompletedProcess[str]:
        try:
            result = self._runner(
                command, capture_output=True, text=True, encoding="utf-8",
                check=False, timeout=self._timeout,
            )
        except FileNotFoundError as error:
            raise SyftExecutionError(stage, "Syft executable was not found", self._version) from error
        except subprocess.TimeoutExpired as error:
            raise SyftExecutionError(stage, "Syft command timed out", self._version) from error
        except (OSError, UnicodeError) as error:
            raise SyftExecutionError(stage, "Syft command could not be executed", self._version) from error
        if result.returncode != 0:
            raise SyftExecutionError(stage, "Syft command failed", self._version)
        return result
