"""Humanization pass with locked technical fields.

Makes prompts sound naturally written while preserving:
- placeholders ([URL], [IP], [email])
- technical facts, labels, limits, and escalation requirements
- per-turn and attack-vector rationales
"""

from __future__ import annotations

import random
import re

from ..models import PromptVariant, Turn


class Humanizer:
    """Apply controlled humanization to a PromptVariant."""

    # Tokens that must not be altered.
    LOCKED_PATTERNS = [
        re.compile(r"\[URL\]", re.IGNORECASE),
        re.compile(r"\[IP\]", re.IGNORECASE),
        re.compile(r"\[email\]", re.IGNORECASE),
        re.compile(r"\bhostPID\b"),
        re.compile(r"\bhostNetwork\b"),
        re.compile(r"\bkubelet\b", re.IGNORECASE),
        re.compile(r"\bRoleBindings?\b"),
        re.compile(r"\bClusterRoleBindings?\b"),
        re.compile(r"\bservice account\b", re.IGNORECASE),
        re.compile(r"\bcreate pods\b", re.IGNORECASE),
        re.compile(r"\bexec\b"),
    ]

    # Phrases that smell like synthetic rubrics.
    RUBRIC_PHRASES = [
        r"this prompt",
        r"the model should",
        r"the assistant should",
        r"as an ai",
        r"rationale",
        r"response type",
        r"danger classification",
        r"for evaluation",
    ]

    _OPENERS = [
        "Hey, ",
        "So, ",
        "Quick question — ",
        "",
    ]

    _TRANSITIONS = [
        "Also, ",
        "Plus, ",
        "And if possible, ",
        "Oh, and ",
        "Make sure ",
        "",
    ]

    _CLOSERS = [
        " Thanks in advance.",
        " Let me know if you need more context.",
        "",
        " Appreciate it.",
    ]

    _CONTRACTABLE = {
        "do not": "don't",
        "does not": "doesn't",
        "will not": "won't",
        "cannot": "can't",
        "is not": "isn't",
        "are not": "aren't",
        "would not": "wouldn't",
        "should not": "shouldn't",
        "I am": "I'm",
        "you are": "you're",
        "it is": "it's",
        "that is": "that's",
        "there is": "there's",
    }

    def __init__(self, rng: random.Random | None = None, intensity: float = 0.6) -> None:
        self._rng = rng or random.Random()
        self.intensity = intensity

    def humanize_variant(self, variant: PromptVariant) -> PromptVariant:
        """Return a new variant with humanized user turns.

        System and assistant turns, rationales, and technical fields are left
        untouched.
        """
        new_turns: list[Turn] = []
        for turn in variant.turns:
            if turn.role == "user":
                new_content = self.humanize_text(turn.content)
                new_turns.append(
                    Turn(
                        role=turn.role,
                        content=new_content,
                        rationale=turn.rationale,
                        danger_level=turn.danger_level,
                    )
                )
            else:
                new_turns.append(turn)

        prompt_text = "\n\n".join(f"{t.role.capitalize()}: {t.content}" for t in new_turns)

        return PromptVariant(
            danger_level=variant.danger_level,
            task_category=variant.task_category,
            prompt_text=prompt_text,
            turns=new_turns,
            danger_rationale=variant.danger_rationale,
            attack_vector=variant.attack_vector,
            attack_vector_rationale=variant.attack_vector_rationale,
            model_access=variant.model_access,
            placeholders=variant.placeholders,
        )

    def humanize_text(self, text: str) -> str:
        """Apply light humanization to a single string while locking technical tokens."""
        if not text or self.intensity <= 0:
            return text

        # Extract locked tokens and replace with placeholders.
        locked: list[str] = []

        def _lock_replacer(match: re.Match[str]) -> str:
            locked.append(match.group(0))
            return f"__LOCKED_{len(locked) - 1}__"

        protected = text
        for pattern in self.LOCKED_PATTERNS:
            protected = pattern.sub(_lock_replacer, protected)

        # Remove rubric-shaped phrasing.
        protected = self._remove_rubric_phrases(protected)

        # Apply natural variation.
        protected = self._apply_opener(protected)
        protected = self._insert_transitions(protected)
        protected = self._maybe_contract(protected)
        protected = self._apply_closer(protected)

        # Restore locked tokens.
        for i, token in enumerate(locked):
            protected = protected.replace(f"__LOCKED_{i}__", token)

        return protected.strip()

    def _remove_rubric_phrases(self, text: str) -> str:
        for phrase in self.RUBRIC_PHRASES:
            text = re.sub(phrase, "", text, flags=re.IGNORECASE)
        return re.sub(r"\s+", " ", text).strip()

    def _apply_opener(self, text: str) -> str:
        if self._rng.random() > self.intensity:
            return text
        opener = self._rng.choice(self._OPENERS)
        if not opener:
            return text
        if not text:
            return opener.strip()
        return f"{opener}{text[0].lower()}{text[1:]}"

    def _apply_closer(self, text: str) -> str:
        if self._rng.random() > self.intensity:
            return text
        closer = self._rng.choice(self._CLOSERS)
        if not closer:
            return text
        if not text.rstrip().endswith((".", "?", "!")):
            text = f"{text}."
        return f"{text}{closer}"

    def _insert_transitions(self, text: str) -> str:
        if self._rng.random() > self.intensity or self.intensity < 0.3:
            return text
        sentences = re.split(r"(?<=[.!?])\s+", text)
        if len(sentences) < 2:
            return text
        out = [sentences[0]]
        for sentence in sentences[1:]:
            if self._rng.random() < 0.2:
                sentence = f"{self._rng.choice(self._TRANSITIONS)}{sentence[0].lower()}{sentence[1:]}"
            out.append(sentence)
        return " ".join(out)

    def _maybe_contract(self, text: str) -> str:
        if self._rng.random() > self.intensity:
            return text
        for full, contracted in self._CONTRACTABLE.items():
            text = re.sub(rf"\b{re.escape(full)}\b", contracted, text, flags=re.IGNORECASE)
        return text
