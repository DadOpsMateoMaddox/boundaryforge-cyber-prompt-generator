"""Command-line interface for BoundaryForge.

Exit codes:
  0 - Generation succeeded and package is READY (or READY_AFTER_MECHANICAL_FIXES).
  1 - Deterministic validation error / invalid package.
  2 - Semantic or classification review required.
  3 - Blocked by missing information.
  4 - Internal execution failure.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .export.json import export_json
from .export.markdown import export_markdown
from .generation import generate_package
from .integrations.promptfoo import export_promptfoo_dataset, write_promptfoo_config
from .models import (
    BoundaryForgeViolation,
    ConstraintViolation,
    DangerLevel,
    ExchangeType,
    GenerationPhase,
    ModelEvaluation,
    PromptPackage,
    PromptVariant,
    ReadinessStatus,
    Severity,
    TaskCategory,
    TaskSpec,
    Turn,
    ValidationReport,
)
from .task_spec import SUPPORTED_DOMAINS
from .validators import BoundaryForgeValidator, ConstraintValidator


def _load_package(data: dict) -> PromptPackage:
    """Reconstruct a PromptPackage from its exported dictionary form."""

    def _turn(d: dict) -> Turn:
        return Turn(role=d["role"], content=d["content"], rationale=d.get("rationale", ""))

    def _variant(d: dict) -> PromptVariant:
        return PromptVariant(
            danger_level=DangerLevel(d["danger_level"]),
            task_category=[TaskCategory(tc) for tc in d.get("task_category", [])],
            prompt_text=d.get("prompt_text", ""),
            turns=[_turn(t) for t in d.get("turns", [])],
            danger_rationale=d.get("danger_rationale", ""),
            attack_vector=d.get("attack_vector", ""),
            attack_vector_rationale=d.get("attack_vector_rationale", ""),
            placeholders=d.get("placeholders", {}),
            model_access=d.get("model_access", []),
        )

    def _task_spec(d: dict) -> TaskSpec:
        return TaskSpec(
            domain=d["domain"],
            exchange_type=ExchangeType(d["exchange_type"]),
            shared_topic=d["shared_topic"],
            boundary_forge_version=d.get("boundary_forge_version", "2024.1"),
            benign=_variant(d["benign"]),
            warn=_variant(d["warn"]),
            dangerous=_variant(d["dangerous"]),
        )

    def _violation(cls, d: dict):
        return cls(
            code=d["code"],
            message=d["message"],
            severity=Severity(d["severity"]),
            path=d["path"],
            phase=GenerationPhase(d.get("phase", "generated")),
            expected=d.get("expected"),
            actual=d.get("actual"),
        )

    def _report(d: dict | None) -> ValidationReport | None:
        if not d:
            return None
        return ValidationReport(
            package_id=d["package_id"],
            mechanical_findings=[_violation(ConstraintViolation, f) for f in d.get("mechanical_findings", [])],
            semantic_findings=[_violation(BoundaryForgeViolation, f) for f in d.get("semantic_findings", [])],
            contrastive_findings=d.get("contrastive_findings", []),
            duplicate_findings=d.get("duplicate_findings", []),
            readiness_status=ReadinessStatus(d.get("readiness_status", "technical_or_classification_review_required")),
        )

    def _model_evaluation(d: dict) -> ModelEvaluation:
        return ModelEvaluation(
            variant_id=d["variant_id"],
            generated_response=d.get("generated_response", ""),
            model_response_types=d.get("model_response_types", []),
            response_rationale=d.get("response_rationale", ""),
            generation_metadata=d.get("generation_metadata", {}),
        )

    package = data["package"]
    return PromptPackage(
        package_id=package["package_id"],
        task_spec=_task_spec(package["task_spec"]),
        validation_report=_report(data.get("validation_report")),
        model_evaluations=[_model_evaluation(me) for me in package.get("model_evaluations", [])],
        generated_at=package.get("generated_at", ""),
    )


def _readiness_to_exit_code(status: ReadinessStatus, strict: bool = False) -> int:
    if status == ReadinessStatus.READY:
        return 0
    if status == ReadinessStatus.READY_AFTER_MECHANICAL_FIXES:
        return 1 if strict else 0
    if status == ReadinessStatus.TECHNICAL_OR_CLASSIFICATION_REVIEW_REQUIRED:
        return 2
    if status == ReadinessStatus.BLOCKED_BY_MISSING_INFORMATION:
        return 3
    return 4


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="boundaryforge",
        description="Generate and validate contrastive cybersecurity red-team prompts.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    generate = subparsers.add_parser("generate", help="Generate a new prompt package.")
    generate.add_argument(
        "--domain",
        required=True,
        choices=sorted(SUPPORTED_DOMAINS),
        help="Technical domain shared across all danger levels.",
    )
    generate.add_argument(
        "--exchange-type",
        required=True,
        choices=[et.value for et in ExchangeType],
        help="Conversation format shared across the package.",
    )
    generate.add_argument(
        "--no-humanize",
        action="store_true",
        help="Disable the humanization pass.",
    )
    generate.add_argument(
        "--seed",
        type=int,
        default=None,
        help="Random seed for reproducible humanization.",
    )
    generate.add_argument(
        "--output-dir",
        type=Path,
        default=Path("./boundaryforge-output"),
        help="Directory for exported files.",
    )
    generate.add_argument(
        "--format",
        choices=["json", "markdown", "promptfoo", "all"],
        default="all",
        help="Export format.",
    )
    generate.add_argument(
        "--phase",
        choices=[p.value for p in GenerationPhase],
        default=GenerationPhase.SUBMISSION_READY.value,
        help="Validation phase to target.",
    )

    validate = subparsers.add_parser("validate", help="Validate an existing package.")
    validate.add_argument(
        "--package",
        type=Path,
        required=True,
        help="Path to a boundaryforge_package.json file.",
    )
    validate.add_argument(
        "--strict",
        action="store_true",
        help="Treat any unresolved warning as a nonzero exit.",
    )
    validate.add_argument(
        "--phase",
        choices=[p.value for p in GenerationPhase],
        default=GenerationPhase.SUBMISSION_READY.value,
        help="Validation phase to target.",
    )

    return parser


def _print_report(report: ValidationReport) -> None:
    print(f"Readiness status: {report.readiness_status.value}")
    print(f"Mechanical findings: {len(report.mechanical_findings)}")
    print(f"Semantic findings: {len(report.semantic_findings)}")
    print(f"Contrastive findings: {len(report.contrastive_findings)}")
    print(f"Duplicate findings: {len(report.duplicate_findings)}")


def _export_package(package: PromptPackage, report: ValidationReport, output_dir: Path, fmt: str) -> list[Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []

    if fmt in ("json", "all"):
        written.append(export_json(package, report, output_dir / "boundaryforge_package.json"))
    if fmt in ("markdown", "all"):
        written.append(export_markdown(package, report, output_dir / "package.md"))
    if fmt in ("promptfoo", "all"):
        dataset_path = output_dir / "promptfoo_dataset.json"
        written.append(export_promptfoo_dataset(package, dataset_path))
        written.append(write_promptfoo_config(dataset_path, output_dir / "promptfooconfig.yaml"))

    return written


def _cmd_generate(args: argparse.Namespace) -> int:
    exchange_type = ExchangeType(args.exchange_type)
    phase = GenerationPhase(args.phase)

    package = generate_package(
        domain=args.domain,
        exchange_type=exchange_type,
        humanize=not args.no_humanize,
        seed=args.seed,
    )

    constraint_validator = ConstraintValidator()
    boundary_forge_validator = BoundaryForgeValidator()
    mechanical = constraint_validator.validate_task_spec(package.task_spec, phase)
    report = boundary_forge_validator.validate(package, phase)
    report.mechanical_findings = mechanical
    report.readiness_status = boundary_forge_validator._compute_readiness(report, phase)

    object.__setattr__(package, "validation_report", report)

    written = _export_package(package, report, args.output_dir, args.format)

    print(f"Generated package: {package.package_id}")
    _print_report(report)
    print("Exported files:")
    for path in written:
        print(f"  - {path}")

    return _readiness_to_exit_code(report.readiness_status, strict=False)


def _cmd_validate(args: argparse.Namespace) -> int:
    phase = GenerationPhase(args.phase)
    package_path: Path = args.package

    if not package_path.exists():
        print(f"error: package not found: {package_path}", file=sys.stderr)
        return 4

    try:
        data = json.loads(package_path.read_text(encoding="utf-8"))
        package = _load_package(data)
    except (json.JSONDecodeError, KeyError, ValueError) as exc:
        print(f"error: invalid package in {package_path}: {exc}", file=sys.stderr)
        return 4

    constraint_validator = ConstraintValidator()
    boundary_forge_validator = BoundaryForgeValidator()
    mechanical = constraint_validator.validate_task_spec(package.task_spec, phase)
    report = boundary_forge_validator.validate(package, phase)
    report.mechanical_findings = mechanical
    report.readiness_status = boundary_forge_validator._compute_readiness(report, phase)

    _print_report(report)

    return _readiness_to_exit_code(report.readiness_status, strict=args.strict)


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "generate":
            return _cmd_generate(args)
        if args.command == "validate":
            return _cmd_validate(args)
    except Exception as exc:  # pragma: no cover - defensive CLI wrapper
        print(f"error: {exc}", file=sys.stderr)
        return 4

    return 4


if __name__ == "__main__":
    sys.exit(main())
