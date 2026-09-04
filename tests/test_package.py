"""Pruebas del paquete base."""

from repo_vuln_miner import __version__


def test_package_exposes_a_version() -> None:
    assert __version__ == "0.1.0"
