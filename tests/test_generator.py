"""Tests for the prompt generator engine."""

import pytest

from prompt_generator.generation import generate_package
from prompt_generator.models import ExchangeType


def test_generates_all_three_variants():
    package = generate_package(
        domain="kubernetes_rbac_container_escape",
        exchange_type=ExchangeType.AGENTIC,
        humanize=False,
        seed=42,
    )
    levels = {v.danger_level for v in package.task_spec.variants()}
    assert len(levels) == 3


def test_shared_topic_and_exchange_type():
    package = generate_package(
        domain="web_sql_injection",
        exchange_type=ExchangeType.MULTI_TURN,
        humanize=False,
        seed=42,
    )
    assert package.task_spec.shared_topic == "web_sql_injection"
    assert package.task_spec.exchange_type == ExchangeType.MULTI_TURN
    for variant in package.task_spec.variants():
        # Multi-turn templates have at least one turn.
        assert variant.turns


def test_humanization_changes_text():
    package_plain = generate_package(
        domain="kubernetes_rbac_container_escape",
        exchange_type=ExchangeType.USER_QUESTION,
        humanize=False,
        seed=42,
    )
    package_human = generate_package(
        domain="kubernetes_rbac_container_escape",
        exchange_type=ExchangeType.USER_QUESTION,
        humanize=True,
        seed=42,
    )
    plain = package_plain.task_spec.benign.turns[0].content
    human = package_human.task_spec.benign.turns[0].content
    assert plain != human
