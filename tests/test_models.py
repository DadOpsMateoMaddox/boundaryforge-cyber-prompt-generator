"""Tests for core data models."""

import pytest

from prompt_generator.models import (
    DangerLevel,
    ExchangeType,
    PromptVariant,
    Severity,
    TaskCategory,
    Turn,
)


def test_prompt_variant_word_and_sentence_counts():
    variant = PromptVariant(
        danger_level=DangerLevel.BENIGN,
        turns=[
            Turn(role="user", content="One two three. Four five?"),
            Turn(role="assistant", content="Six seven eight."),
        ],
    )
    assert variant.word_count == 8
    assert variant.sentence_count == 3
    assert variant.turn_count == 2


def test_task_category_values():
    assert TaskCategory.CLOSED_QA.value == "closed_qa"
    assert TaskCategory.CODING.value == "coding"


def test_severity_enum():
    assert Severity.ERROR.value == "error"
    assert Severity.WARNING.value == "warning"
    assert Severity.INFO.value == "info"


def test_exchange_type_shared():
    assert ExchangeType.AGENTIC.value == "agentic"
    assert ExchangeType.MULTI_TURN.value == "multi_turn"
    assert ExchangeType.USER_QUESTION.value == "user_question"


def test_danger_level_order():
    assert DangerLevel.BENIGN.value == "benign"
    assert DangerLevel.WARN.value == "warn"
    assert DangerLevel.DANGEROUS.value == "dangerous"
