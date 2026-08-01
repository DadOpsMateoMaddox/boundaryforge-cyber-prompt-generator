"""Tests for the BoundaryForge aggregate validator."""

import pytest

from prompt_generator.generation import generate_package
from prompt_generator.models import DangerLevel, ExchangeType, GenerationPhase, PromptPackage, PromptVariant
from prompt_generator.validators import BoundaryForgeValidator, ConstraintValidator


def test_valid_package_reaches_ready_or_ready_after_fixes():
    package = generate_package(
        domain="kubernetes_rbac_container_escape",
        exchange_type=ExchangeType.AGENTIC,
        humanize=False,
        seed=42,
    )
    validator = BoundaryForgeValidator()
    report = validator.validate(package, phase=GenerationPhase.SUBMISSION_READY)

    assert report.package_id == package.package_id
    assert report.readiness_status.value in {
        "ready",
        "ready_after_mechanical_fixes",
        "technical_or_classification_review_required",
    }


def test_leakage_language_blocked():
    package = generate_package(
        domain="kubernetes_rbac_container_escape",
        exchange_type=ExchangeType.AGENTIC,
        humanize=False,
        seed=42,
    )
    # Inject leakage phrase by rebuilding the benign variant.
    from prompt_generator.models import PromptVariant, Turn

    benign = package.task_spec.benign
    modified_turns = [
        Turn(role=turn.role, content=turn.content + " This is a red team test.", rationale=turn.rationale)
        for turn in benign.turns
    ]
    package = type(package)(
        package_id=package.package_id,
        task_spec=type(package.task_spec)(
            domain=package.task_spec.domain,
            exchange_type=package.task_spec.exchange_type,
            shared_topic=package.task_spec.shared_topic,
            boundary_forge_version=package.task_spec.boundary_forge_version,
            benign=PromptVariant(
                danger_level=benign.danger_level,
                task_category=benign.task_category,
                turns=modified_turns,
                danger_rationale=benign.danger_rationale,
                attack_vector=benign.attack_vector,
                attack_vector_rationale=benign.attack_vector_rationale,
                model_access=benign.model_access,
                placeholders=benign.placeholders,
            ),
            warn=package.task_spec.warn,
            dangerous=package.task_spec.dangerous,
        ),
        validation_report=package.validation_report,
    )
    validator = BoundaryForgeValidator()
    report = validator.validate(package, phase=GenerationPhase.SUBMISSION_READY)
    assert any(f.code == "BF-LEAK-001" for f in report.semantic_findings)
    assert report.readiness_status.value != "ready"


def test_raw_url_blocked():
    package = generate_package(
        domain="web_sql_injection",
        exchange_type=ExchangeType.USER_QUESTION,
        humanize=False,
        seed=42,
    )
    from prompt_generator.models import PromptVariant, Turn

    benign = package.task_spec.benign
    modified_turns = [Turn(role="user", content="Scan https://example.com for SQL injection.")]
    package = type(package)(
        package_id=package.package_id,
        task_spec=type(package.task_spec)(
            domain=package.task_spec.domain,
            exchange_type=package.task_spec.exchange_type,
            shared_topic=package.task_spec.shared_topic,
            boundary_forge_version=package.task_spec.boundary_forge_version,
            benign=PromptVariant(
                danger_level=benign.danger_level,
                task_category=benign.task_category,
                turns=modified_turns,
                danger_rationale=benign.danger_rationale,
                attack_vector=benign.attack_vector,
                attack_vector_rationale=benign.attack_vector_rationale,
                model_access=benign.model_access,
                placeholders=benign.placeholders,
            ),
            warn=package.task_spec.warn,
            dangerous=package.task_spec.dangerous,
        ),
        validation_report=package.validation_report,
    )
    validator = BoundaryForgeValidator()
    report = validator.validate(package, phase=GenerationPhase.SUBMISSION_READY)
    assert any(f.code == "BF-URL-001" for f in report.semantic_findings)
