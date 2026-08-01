"""JSON export for prompt packages and validation reports."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, IO

from ..models import PromptPackage, ValidationReport


def export_json(
    package: PromptPackage,
    validation_report: ValidationReport | None,
    target_path: str | Path | IO[Any],
    indent: int = 2,
) -> Path | IO[Any]:
    """Export a package and its validation report as JSON.

    Accepts a filesystem path or a writable file-like object (e.g. BytesIO).
    """
    payload: dict[str, Any] = {
        "package": package.to_dict(),
        "validation_report": validation_report.to_dict() if validation_report else None,
    }

    if hasattr(target_path, "write"):
        target_path.write(json.dumps(payload, indent=indent, ensure_ascii=False).encode("utf-8"))
        return target_path

    path = Path(target_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, indent=indent, ensure_ascii=False)
    return path
