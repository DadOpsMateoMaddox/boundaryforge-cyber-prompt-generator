"""Markdown export for prompt packages and validation reports."""

from __future__ import annotations

from pathlib import Path
from typing import Any, IO

from ..models import DangerLevel, PromptPackage, ValidationReport


def export_markdown(
    package: PromptPackage,
    validation_report: ValidationReport | None,
    target_path: str | Path | IO[Any],
) -> Path | IO[Any]:
    """Export a package and its validation report as a Markdown document.

    Accepts a filesystem path or a writable file-like object (e.g. BytesIO).
    """
    lines: list[str] = []

    lines.append(f"# Prompt Package: {package.package_id}")
    lines.append("")
    lines.append(f"- **Domain:** {package.task_spec.domain}")
    lines.append(f"- **Exchange Type:** {package.task_spec.exchange_type.value}")
    lines.append(f"- **Shared Topic:** {package.task_spec.shared_topic}")
    lines.append(f"- **BoundaryForge Version:** {package.task_spec.boundary_forge_version}")
    lines.append(f"- **Generated At:** {package.generated_at}")
    lines.append("")

    for level in DangerLevel:
        variant = next((v for v in package.task_spec.variants() if v.danger_level == level), None)
        if variant is None:
            continue
        lines.append(f"## {level.value.capitalize()} Variant")
        lines.append("")
        lines.append(f"**Task Categories:** {', '.join(tc.value for tc in variant.task_category)}")
        lines.append("")
        lines.append("### Prompt")
        lines.append("")
        for turn in variant.turns:
            lines.append(f"**{turn.role.capitalize()}:** {turn.content}")
            lines.append("")
        lines.append("### Danger Rationale")
        lines.append("")
        lines.append(variant.danger_rationale)
        lines.append("")
        if variant.attack_vector:
            lines.append("### Attack Vector")
            lines.append("")
            lines.append(variant.attack_vector)
            lines.append("")
        if variant.attack_vector_rationale:
            lines.append("### Attack Vector Rationale")
            lines.append("")
            lines.append(variant.attack_vector_rationale)
            lines.append("")

    if validation_report:
        lines.append("# Validation Report")
        lines.append("")
        lines.append(f"**Readiness Status:** {validation_report.readiness_status.value}")
        lines.append("")

        def _section(title: str, findings: list[Any]) -> None:
            lines.append(f"## {title}")
            lines.append("")
            if not findings:
                lines.append("No findings.")
                lines.append("")
                return
            for finding in findings:
                if hasattr(finding, "to_dict"):
                    data = finding.to_dict()
                else:
                    data = finding
                lines.append(f"- **{data.get('code', 'FINDING')}:** {data.get('message', '')}")
                details = {k: v for k, v in data.items() if k not in {"code", "message"}}
                if details:
                    lines.append(f"  - {details}")
            lines.append("")

        _section("Mechanical Findings", validation_report.mechanical_findings)
        _section("Semantic Findings", validation_report.semantic_findings)
        _section("Contrastive Findings", validation_report.contrastive_findings)
        _section("Duplicate Findings", validation_report.duplicate_findings)

    content = "\n".join(lines)

    if hasattr(target_path, "write"):
        target_path.write(content.encode("utf-8"))
        return target_path

    path = Path(target_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path
