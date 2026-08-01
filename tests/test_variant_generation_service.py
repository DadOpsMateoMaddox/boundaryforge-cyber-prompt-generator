"""Tests for the VariantGenerationService orchestration layer."""

import pytest

from prompt_generator.models import DangerLevel, ExchangeType, TaskCategory
from prompt_generator.services import VariantGenerationRequest, VariantGenerationService


@pytest.fixture
def service() -> VariantGenerationService:
    return VariantGenerationService()


def test_generate_warn_variant(service: VariantGenerationService) -> None:
    request = VariantGenerationRequest(
        danger_level=DangerLevel.WARN,
        domain="kubernetes_rbac_container_escape",
        exchange_type=ExchangeType.AGENTIC,
        task_category=TaskCategory.CODING,
        shared_topic="kubernetes_rbac_container_escape",
        scenario_context="Target is a staging cluster.",
        safeguards=("no_extraction",),
        humanization_intensity=0.0,
    )
    result = service.generate(request)

    assert result.selected_variant.danger_level == DangerLevel.WARN
    assert result.task_spec.warn is result.selected_variant
    assert "staging cluster" in result.selected_variant.prompt_text
    assert "Do not extract application data" in result.selected_variant.prompt_text
    assert result.risk_vector is not None
    assert result.evidence is not None
    assert result.validation_report.package_id


def test_generate_dangerous_variant(service: VariantGenerationService) -> None:
    request = VariantGenerationRequest(
        danger_level=DangerLevel.DANGEROUS,
        domain="web_sql_injection",
        exchange_type=ExchangeType.USER_QUESTION,
        task_category=TaskCategory.OPEN_ENDED,
        shared_topic="web_sql_injection",
        uplift_controls=("autonomy_full", "depth_end_to_end", "extraction_sensitive"),
        humanization_intensity=0.0,
    )
    result = service.generate(request)

    assert result.selected_variant.danger_level == DangerLevel.DANGEROUS
    assert result.task_spec.dangerous is result.selected_variant
    assert "autonomously" in result.selected_variant.prompt_text.lower() or "end-to-end" in result.selected_variant.prompt_text.lower()
    assert result.risk_vector is not None
    assert result.validation_report is not None


def test_humanize_existing(service: VariantGenerationService) -> None:
    request = VariantGenerationRequest(
        danger_level=DangerLevel.WARN,
        domain="kubernetes_rbac_container_escape",
        exchange_type=ExchangeType.AGENTIC,
        task_category=TaskCategory.CODING,
        shared_topic="kubernetes_rbac_container_escape",
        humanization_intensity=0.0,
    )
    result = service.generate(request)
    original = result.selected_variant.prompt_text

    humanized = service.humanize_existing(result, intensity=1.0)
    assert humanized.selected_variant.prompt_text != original
    assert humanized.validation_report is not None


def test_revalidate_with_edits(service: VariantGenerationService) -> None:
    request = VariantGenerationRequest(
        danger_level=DangerLevel.WARN,
        domain="kubernetes_rbac_container_escape",
        exchange_type=ExchangeType.AGENTIC,
        task_category=TaskCategory.CODING,
        shared_topic="kubernetes_rbac_container_escape",
        humanization_intensity=0.0,
    )
    result = service.generate(request)
    edited = service.revalidate_with_edits(
        result,
        prompt_text=result.selected_variant.prompt_text + " Additional context.",
        danger_rationale=result.selected_variant.danger_rationale,
    )

    assert "Additional context." in edited.selected_variant.prompt_text
    assert edited.validation_report is not None


def test_benign_generation_rejected(service: VariantGenerationService) -> None:
    request = VariantGenerationRequest(
        danger_level=DangerLevel.BENIGN,
        domain="kubernetes_rbac_container_escape",
        exchange_type=ExchangeType.AGENTIC,
        task_category=TaskCategory.CODING,
        shared_topic="kubernetes_rbac_container_escape",
    )
    with pytest.raises(ValueError):
        service.generate(request)
