"""Escritura segura de los informes JSON del miner."""

from __future__ import annotations

import os
from pathlib import Path
from tempfile import NamedTemporaryFile

from repo_vuln_miner.models import OrganizationScan


def write_report_json(report: OrganizationScan, output: Path) -> None:
    """Serializa un informe Pydantic y lo reemplaza atómicamente en ``output``."""
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: Path | None = None

    try:
        with NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=output.parent,
            prefix=f".{output.name}.",
            suffix=".tmp",
            delete=False,
        ) as temporary_file:
            temporary_path = Path(temporary_file.name)
            temporary_file.write(report.model_dump_json(indent=2, exclude_none=True))
            temporary_file.flush()
            os.fsync(temporary_file.fileno())

        os.replace(temporary_path, output)
    except BaseException:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
        raise
