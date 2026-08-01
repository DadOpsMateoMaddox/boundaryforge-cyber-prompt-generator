"""Tests for the deterministic ConstraintValidator."""

import pytest

from prompt_generator.models import (
    ConstraintSet,
    ConstraintViolation,
    DangerLevel,
    ExchangeType,
    GenerationPhase,
    PromptVariant,
    Severity,
    TaskCategory,
    TaskSpec,
    Turn,
)
from prompt_generator.validators.constraints import ConstraintValidator


def make_spec(benign_turns, warn_turns, dangerous_turns) -> TaskSpec:
    return TaskSpec(
        domain="kubernetes_rbac_container_escape",
        exchange_type=ExchangeType.AGENTIC,
        shared_topic="kubernetes_rbac_container_escape",
        benign=PromptVariant(
            danger_level=DangerLevel.BENIGN,
            task_category=[TaskCategory.CODING],
            turns=benign_turns,
            danger_rationale="Benign rationale text here.",
        ),
        warn=PromptVariant(
            danger_level=DangerLevel.WARN,
            task_category=[TaskCategory.CODING],
            turns=warn_turns,
            danger_rationale="Warn rationale text here.",
        ),
        dangerous=PromptVariant(
            danger_level=DangerLevel.DANGEROUS,
            task_category=[TaskCategory.CODING],
            turns=dangerous_turns,
            danger_rationale="Dangerous rationale text here.",
        ),
    )


def test_valid_package_passes():
    turns = [Turn(role="user", content="Audit my cluster with read-only access and report over-provisioned RBAC.")]
    spec = make_spec(turns, turns, turns)
    validator = ConstraintValidator()
    findings = validator.validate_task_spec(spec, phase=GenerationPhase.GENERATED)
    errors = [f for f in findings if f.severity == Severity.ERROR]
    assert not errors


def test_missing_required_field():
    spec = TaskSpec(
        domain="kubernetes_rbac_container_escape",
        exchange_type=ExchangeType.AGENTIC,
        shared_topic="kubernetes_rbac_container_escape",
    )
    validator = ConstraintValidator()
    findings = validator.validate_task_spec(spec, phase=GenerationPhase.DRAFT)
    codes = {f.code for f in findings}
    assert "CNS-FLD-001" in codes


def test_supported_task_category_passes():
    variant = PromptVariant(
        danger_level=DangerLevel.BENIGN,
        task_category=[TaskCategory.CODING, TaskCategory.CLOSED_QA],
        turns=[Turn(role="user", content="Audit my cluster.")],
        danger_rationale="Rationale.",
    )
    validator = ConstraintValidator()
    findings = validator.validate_variant(variant, ExchangeType.AGENTIC)
    assert not any(f.code == "CNS-TYP-001" for f in findings)


def test_url_normalization_violation():
    variant = PromptVariant(
        danger_level=DangerLevel.BENIGN,
        turns=[Turn(role="user", content="Scan https://example.com for issues.")],
        danger_rationale="Rationale.",
    )
    validator = ConstraintValidator()
    findings = validator.validate_variant(variant, ExchangeType.USER_QUESTION)
    assert any(f.code == "CNS-URL-001" for f in findings)


def test_ip_normalization_violation():
    variant = PromptVariant(
        danger_level=DangerLevel.BENIGN,
        turns=[Turn(role="user", content="Scan 192.168.1.0/24.")],
        danger_rationale="Rationale.",
    )
    validator = ConstraintValidator()
    findings = validator.validate_variant(variant, ExchangeType.USER_QUESTION)
    assert any(f.code == "CNS-URL-002" for f in findings)


def test_length_limits():
    long_text = "Word. " * 200
    variant = PromptVariant(
        danger_level=DangerLevel.BENIGN,
        turns=[Turn(role="user", content=long_text)],
        danger_rationale="Rationale.",
    )
    constraints = ConstraintSet(max_words_per_prompt=50)
    validator = ConstraintValidator(constraints)
    findings = validator.validate_variant(variant, ExchangeType.USER_QUESTION)
    assert any(f.code == "CNS-SIZE-002" for f in findings)


def test_missing_per_turn_rationale():
    variant = PromptVariant(
        danger_level=DangerLevel.BENIGN,
        turns=[Turn(role="user", content="Audit my cluster.")],
        danger_rationale="Rationale.",
    )
    validator = ConstraintValidator()
    findings = validator.validate_variant(variant, ExchangeType.USER_QUESTION, phase=GenerationPhase.GENERATED)
    assert any(f.code == "CNS-RAT-002" for f in findings)
