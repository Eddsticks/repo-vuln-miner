"""Comprobación de Syft real sobre archivos de dependencias versionados."""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

import pytest

from repo_vuln_miner.github.catalog import GitHubRepository
from repo_vuln_miner.github.workspace import ClonedRepository
from repo_vuln_miner.syft.generation import SyftRunner

FIXTURES = Path(__file__).parents[1] / "fixtures" / "sbom"


def syft_binary() -> str:
    """Permite que CI fije el binario y que desarrollo use uno disponible en PATH."""
    binary = os.environ.get("SYFT_BINARY") or shutil.which("syft")
    if binary is None:
        pytest.skip("Syft is not installed; set SYFT_BINARY to run integration tests")
    return binary


@pytest.mark.parametrize(
    ("fixture_name", "expected_component"),
    [
        ("node", ("express", "4.21.0")),
        ("python", ("requests", "2.32.3")),
    ],
)
def test_syft_real_reports_declared_or_locked_dependency(
    tmp_path: Path,
    fixture_name: str,
    expected_component: tuple[str, str],
) -> None:
    source = FIXTURES / fixture_name
    repository = GitHubRepository(
        owner="fixtures",
        name=fixture_name,
        url=f"https://example.test/fixtures/{fixture_name}",
        clone_url=f"https://example.test/fixtures/{fixture_name}.git",
        default_branch="main",
    )
    cloned = ClonedRepository(repository, source, "a" * 40)

    result = SyftRunner(syft_binary=syft_binary()).generate(cloned, tmp_path / "sboms")

    payload = json.loads(result.path.read_text(encoding="utf-8"))
    components = {
        (component.get("name"), component.get("version"))
        for component in payload["components"]
    }
    assert payload["bomFormat"] == "CycloneDX"
    assert expected_component in components
    assert result.component_count == len(payload["components"])
    assert result.syft_version
    expected_version = os.environ.get("EXPECTED_SYFT_VERSION")
    if expected_version is not None:
        assert result.syft_version == expected_version
