"""Tests for the humanizer with locked technical fields."""

import pytest

from prompt_generator.generation.humanizer import Humanizer
from prompt_generator.models import DangerLevel, PromptVariant, Turn


def test_preserves_placeholders():
    humanizer = Humanizer(intensity=1.0)
    variant = PromptVariant(
        danger_level=DangerLevel.BENIGN,
        turns=[Turn(role="user", content="Scan [URL] and [IP] for issues, then email [email].")],
        danger_rationale="Rationale.",
    )
    result = humanizer.humanize_variant(variant)
    text = result.turns[0].content
    assert "[URL]" in text
    assert "[IP]" in text
    assert "[email]" in text


def test_preserves_technical_terms():
    humanizer = Humanizer(intensity=1.0)
    variant = PromptVariant(
        danger_level=DangerLevel.BENIGN,
        turns=[Turn(role="user", content="Check hostPID and hostNetwork on the kubelet node.")],
        danger_rationale="Rationale.",
    )
    result = humanizer.humanize_variant(variant)
    text = result.turns[0].content
    assert "hostPID" in text
    assert "hostNetwork" in text
    assert "kubelet" in text


def test_removes_rubric_phrases():
    humanizer = Humanizer(intensity=1.0)
    variant = PromptVariant(
        danger_level=DangerLevel.BENIGN,
        turns=[Turn(role="user", content="This prompt asks the model to summarize the response type.")],
        danger_rationale="Rationale.",
    )
    result = humanizer.humanize_variant(variant)
    text = result.turns[0].content.lower()
    assert "this prompt" not in text
    assert "response type" not in text


def test_humanizes_user_turns_only():
    import random

    humanizer = Humanizer(rng=random.Random(42), intensity=1.0)
    variant = PromptVariant(
        danger_level=DangerLevel.BENIGN,
        turns=[
            Turn(role="system", content="You are an agent."),
            Turn(role="user", content="Do this task."),
        ],
        danger_rationale="Rationale.",
    )
    result = humanizer.humanize_variant(variant)
    assert result.turns[0].content == "You are an agent."
    assert result.turns[1].content != "Do this task."
