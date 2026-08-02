"""Prompt generation engine.

Builds a PromptPackage from a TaskSpec by selecting templates, substituting
placeholders, humanizing, and auditing the contrastive gradient before and
after humanization.
"""

from __future__ import annotations

import copy
import random
from typing import Any

from ..models import (
    ConstraintSet,
    DangerLevel,
    ExchangeType,
    GenerationPhase,
    PromptPackage,
    PromptVariant,
    TaskSpec,
    Turn,
    short_id,
)
from ..normalization.text import collapse_whitespace
from ..validators.contrastive import ContrastiveAuditor
from .humanizer import Humanizer
from .templates import Template, get_template


class PromptGenerator:
    """Generate contrastive prompt packages from a TaskSpec."""

    def __init__(
        self,
        constraints: ConstraintSet | None = None,
        humanize: bool = True,
        humanize_intensity: float = 0.6,
        seed: int | None = None,
    ) -> None:
        self.constraints = constraints or ConstraintSet()
        self.humanize = humanize
        self.humanize_intensity = humanize_intensity
        self._rng = random.Random(seed)
        self._humanizer = Humanizer(rng=self._rng, intensity=humanize_intensity)
        self._contrastive_auditor = ContrastiveAuditor()

    def generate(self, spec: TaskSpec) -> PromptPackage:
        """Generate a full package with pre- and post-humanization audits."""
        # Pre-humanization generation.
        variants = [self._render_variant(spec, level) for level in DangerLevel]

        # Attach variants to a temporary spec for the first contrastive audit.
        draft_spec = copy.deepcopy(spec)
        draft_spec.benign, draft_spec.warn, draft_spec.dangerous = variants
        pre_audit = self._contrastive_auditor.audit(draft_spec)

        # Humanization pass.
        if self.humanize:
            variants = [self._humanizer.humanize_variant(v) for v in variants]

        # Re-audit after humanization.
        final_spec = copy.deepcopy(spec)
        final_spec.benign, final_spec.warn, final_spec.dangerous = variants
        post_audit = self._contrastive_auditor.audit(final_spec)

        # Aggregate audit notes.
        audit_notes: list[str] = []
        if pre_audit:
            audit_notes.append(f"Pre-humanization contrastive findings: {len(pre_audit)}")
        if post_audit:
            audit_notes.append(f"Post-humanization contrastive findings: {len(post_audit)}")

        package = PromptPackage(
            package_id=f"bf-{short_id()}",
            task_spec=final_spec,
            validation_report=None,  # type: ignore[arg-type]
        )
        return package

    def _render_variant(self, spec: TaskSpec, danger_level: DangerLevel) -> PromptVariant:
        template = get_template(spec.domain, spec.exchange_type, danger_level)
        if template is None:
            raise ValueError(
                f"No template for domain={spec.domain!r}, exchange_type={spec.exchange_type.value!r}, "
                f"danger_level={danger_level.value!r}"
            )

        turns = [self._render_turn(t, template.placeholders) for t in template.turns]
        prompt_text = "\n\n".join(f"{t.role.capitalize()}: {t.content}" for t in turns)

        return PromptVariant(
            danger_level=danger_level,
            task_category=template.task_categories,
            prompt_text=prompt_text,
            turns=turns,
            danger_rationale=template.danger_rationale,
            attack_vector=template.attack_vector,
            attack_vector_rationale=template.attack_vector_rationale,
            model_access=template.model_access,
            placeholders=template.placeholders,
        )

    @staticmethod
    def _render_turn(turn: Turn, placeholders: dict[str, str]) -> Turn:
        content = turn.content
        for key, value in placeholders.items():
            content = content.replace(f"{{{key}}}", value)
        content = collapse_whitespace(content)
        return Turn(
            role=turn.role,
            content=content,
            rationale=turn.rationale,
            danger_level=turn.danger_level,
        )


def generate_package(
    domain: str,
    exchange_type: ExchangeType,
    humanize: bool = True,
    seed: int | None = None,
) -> PromptPackage:
    """Convenience function for one-off package generation."""
    from ..task_spec import build_task_spec

    spec = build_task_spec(domain=domain, exchange_type=exchange_type)
    generator = PromptGenerator(humanize=humanize, seed=seed)
    return generator.generate(spec)
