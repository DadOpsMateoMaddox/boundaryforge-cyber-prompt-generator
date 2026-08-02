"""Deterministic, mechanical constraint validation.

The ConstraintValidator never decides whether a prompt is truly Benign, Warn,
or Dangerous. It only checks measurable properties such as length, required
fields, placeholder normalization, and structural consistency.

Each rule declares the earliest GenerationPhase at which it applies, so drafts
are not penalized for missing information that is produced later in the
pipeline.
"""

from __future__ import annotations

from ..models import (
    ConstraintSet,
    ConstraintViolation,
    DangerLevel,
    ExchangeType,
    GenerationPhase,
    PromptPackage,
    PromptVariant,
    Severity,
    TaskCategory,
    TaskSpec,
)
from ..normalization.urls import scan_for_unnormalized_references


SUPPORTED_TASK_CATEGORIES = set(TaskCategory)
SUPPORTED_RESPONSE_TYPES = {
    "compliance_report",
    "risk_assessment",
    "vulnerability_report",
    "reconnaissance_report",
    "attack_automation",
    "malicious_code",
    "educational_guidance",
}


class ConstraintValidator:
    """Validate mechanical constraints on a TaskSpec and its variants."""

    def __init__(self, constraints: ConstraintSet | None = None) -> None:
        self.constraints = constraints or ConstraintSet()

    def validate_task_spec(
        self,
        spec: TaskSpec,
        phase: GenerationPhase = GenerationPhase.DRAFT,
    ) -> list[ConstraintViolation]:
        """Validate the whole spec: shared topic, shared exchange type, variants."""
        findings: list[ConstraintViolation] = []
        findings.extend(self._check_shared_fields(spec, phase))
        for variant in spec.variants():
            findings.extend(self.validate_variant(variant, spec.exchange_type, phase))
        return findings

    def validate_package(
        self,
        package: PromptPackage,
        phase: GenerationPhase = GenerationPhase.GENERATED,
    ) -> list[ConstraintViolation]:
        """Validate a completed package, optionally including model evaluations."""
        findings: list[ConstraintViolation] = []
        findings.extend(self.validate_task_spec(package.task_spec, phase))
        if phase.value >= GenerationPhase.MODEL_EVALUATED.value:
            findings.extend(self._check_model_evaluations(package, phase))
        return findings

    def validate_variant(
        self,
        variant: PromptVariant,
        expected_exchange_type: ExchangeType,
        phase: GenerationPhase = GenerationPhase.DRAFT,
    ) -> list[ConstraintViolation]:
        """Validate a single prompt variant."""
        findings: list[ConstraintViolation] = []
        path_prefix = f"{variant.danger_level.value}"

        findings.extend(self._check_required_fields(variant, path_prefix, phase))
        findings.extend(self._check_task_categories(variant, path_prefix, phase))
        findings.extend(self._check_turn_limits(variant, path_prefix, phase))
        findings.extend(self._check_prompt_length(variant, path_prefix, phase))
        findings.extend(self._check_rationale_length(variant, path_prefix, phase))
        findings.extend(self._check_per_turn_rationales(variant, path_prefix, phase))
        findings.extend(self._check_exchange_type_constraints(variant, expected_exchange_type, path_prefix, phase))
        findings.extend(self._check_per_turn_labels(variant, path_prefix, phase))
        findings.extend(self._check_url_normalization(variant, path_prefix, phase))
        findings.extend(self._check_attack_vector_fields(variant, path_prefix, phase))
        findings.extend(self._check_no_model_response_tags(variant, path_prefix, phase))

        return findings

    def _check_shared_fields(
        self,
        spec: TaskSpec,
        phase: GenerationPhase,
    ) -> list[ConstraintViolation]:
        findings: list[ConstraintViolation] = []
        topics = {v.placeholders.get("topic", spec.shared_topic) for v in spec.variants()}
        if len(topics) > 1:
            findings.append(
                ConstraintViolation(
                    code="CNS-TOP-001",
                    message="All variants in a package must share the same topic.",
                    severity=Severity.ERROR,
                    path="task_spec.shared_topic",
                    phase=phase,
                    expected=spec.shared_topic,
                    actual=sorted(topics),
                )
            )
        return findings

    def _check_required_fields(
        self,
        variant: PromptVariant,
        path: str,
        phase: GenerationPhase,
    ) -> list[ConstraintViolation]:
        findings: list[ConstraintViolation] = []

        # DRAFT: at least one of prompt_text or turns should exist.
        if phase.value >= GenerationPhase.DRAFT.value:
            if not variant.prompt_text and not variant.turns:
                findings.append(
                    ConstraintViolation(
                        code="CNS-FLD-001",
                        message="Variant must have either prompt_text or at least one turn.",
                        severity=Severity.ERROR,
                        path=f"{path}.prompt_text",
                        phase=phase,
                        expected="non-empty prompt_text or turns",
                        actual="empty",
                    )
                )

        # GENERATED: danger rationale is required once generation is complete.
        if phase.value >= GenerationPhase.GENERATED.value:
            if not variant.danger_rationale:
                findings.append(
                    ConstraintViolation(
                        code="CNS-FLD-001",
                        message="Danger rationale is a required field.",
                        severity=Severity.ERROR,
                        path=f"{path}.danger_rationale",
                        phase=phase,
                        expected="non-empty string",
                        actual="empty",
                    )
                )

        return findings

    def _check_task_categories(
        self,
        variant: PromptVariant,
        path: str,
        phase: GenerationPhase,
    ) -> list[ConstraintViolation]:
        findings: list[ConstraintViolation] = []
        for category in variant.task_category:
            if category not in SUPPORTED_TASK_CATEGORIES:
                findings.append(
                    ConstraintViolation(
                        code="CNS-TYP-001",
                        message=f"Unsupported task category: {category.value!r}.",
                        severity=Severity.ERROR,
                        path=f"{path}.task_category",
                        phase=phase,
                        expected=f"one of {[c.value for c in TaskCategory]}",
                        actual=category.value,
                    )
                )
        return findings

    def _check_turn_limits(
        self,
        variant: PromptVariant,
        path: str,
        phase: GenerationPhase,
    ) -> list[ConstraintViolation]:
        findings: list[ConstraintViolation] = []
        c = self.constraints

        if variant.turn_count > c.max_turns_per_prompt:
            findings.append(
                ConstraintViolation(
                    code="CNS-SIZE-003",
                    message=f"Prompt has {variant.turn_count} turns (max {c.max_turns_per_prompt}).",
                    severity=Severity.ERROR,
                    path=f"{path}.turns",
                    phase=phase,
                    expected=f"<= {c.max_turns_per_prompt}",
                    actual=variant.turn_count,
                )
            )

        for i, turn in enumerate(variant.turns):
            word_count = len(turn.content.split())
            sentence_count = turn.content.count(".") + turn.content.count("?") + turn.content.count("!")
            if word_count > c.max_words_per_turn:
                findings.append(
                    ConstraintViolation(
                        code="CNS-SIZE-004",
                        message=f"Turn {i} has {word_count} words (max {c.max_words_per_turn}).",
                        severity=Severity.ERROR,
                        path=f"{path}.turns[{i}].content",
                        phase=phase,
                        expected=f"<= {c.max_words_per_turn}",
                        actual=word_count,
                    )
                )
            if sentence_count > c.max_sentences_per_turn:
                findings.append(
                    ConstraintViolation(
                        code="CNS-SIZE-005",
                        message=f"Turn {i} has {sentence_count} sentences (max {c.max_sentences_per_turn}).",
                        severity=Severity.ERROR,
                        path=f"{path}.turns[{i}].content",
                        phase=phase,
                        expected=f"<= {c.max_sentences_per_turn}",
                        actual=sentence_count,
                    )
                )

        return findings

    def _check_prompt_length(
        self,
        variant: PromptVariant,
        path: str,
        phase: GenerationPhase,
    ) -> list[ConstraintViolation]:
        findings: list[ConstraintViolation] = []
        c = self.constraints

        if variant.word_count > c.max_words_per_prompt:
            findings.append(
                ConstraintViolation(
                    code="CNS-SIZE-002",
                    message=f"Prompt has {variant.word_count} words (max {c.max_words_per_prompt}).",
                    severity=Severity.ERROR,
                    path=f"{path}.turns",
                    phase=phase,
                    expected=f"<= {c.max_words_per_prompt}",
                    actual=variant.word_count,
                )
            )
        if variant.sentence_count > c.max_sentences_per_prompt:
            findings.append(
                ConstraintViolation(
                    code="CNS-SIZE-001",
                    message=f"Prompt has {variant.sentence_count} sentences (max {c.max_sentences_per_prompt}).",
                    severity=Severity.ERROR,
                    path=f"{path}.turns",
                    phase=phase,
                    expected=f"<= {c.max_sentences_per_prompt}",
                    actual=variant.sentence_count,
                )
            )
        return findings

    def _check_rationale_length(
        self,
        variant: PromptVariant,
        path: str,
        phase: GenerationPhase,
    ) -> list[ConstraintViolation]:
        findings: list[ConstraintViolation] = []
        if phase.value < GenerationPhase.GENERATED.value:
            return findings

        word_count = len(variant.danger_rationale.split())
        if word_count < 5:
            findings.append(
                ConstraintViolation(
                    code="CNS-RAT-001",
                    message=f"Danger rationale is only {word_count} words (minimum 5).",
                    severity=Severity.WARNING,
                    path=f"{path}.danger_rationale",
                    phase=phase,
                    expected=">= 5 words",
                    actual=word_count,
                )
            )
        return findings

    def _check_per_turn_rationales(
        self,
        variant: PromptVariant,
        path: str,
        phase: GenerationPhase,
    ) -> list[ConstraintViolation]:
        findings: list[ConstraintViolation] = []
        if phase.value < GenerationPhase.GENERATED.value:
            return findings

        for i, turn in enumerate(variant.turns):
            if not turn.rationale:
                findings.append(
                    ConstraintViolation(
                        code="CNS-RAT-002",
                        message=f"Turn {i} is missing a per-turn rationale.",
                        severity=Severity.WARNING,
                        path=f"{path}.turns[{i}].rationale",
                        phase=phase,
                        expected="non-empty rationale",
                        actual="empty",
                    )
                )
        return findings

    def _check_exchange_type_constraints(
        self,
        variant: PromptVariant,
        exchange_type: ExchangeType,
        path: str,
        phase: GenerationPhase,
    ) -> list[ConstraintViolation]:
        """Enforce dataset-specific length rules for single-turn/agentic vs multi-turn prompts."""
        findings: list[ConstraintViolation] = []
        if phase.value < GenerationPhase.GENERATED.value:
            return findings

        c = self.constraints
        if exchange_type == ExchangeType.MULTI_TURN:
            if variant.turn_count != c.multi_turn_target_turns:
                findings.append(
                    ConstraintViolation(
                        code="CNS-SIZE-006",
                        message=(
                            f"Multi-turn prompt has {variant.turn_count} turns "
                            f"(target {c.multi_turn_target_turns})."
                        ),
                        severity=Severity.WARNING,
                        path=f"{path}.turns",
                        phase=phase,
                        expected=f"== {c.multi_turn_target_turns}",
                        actual=variant.turn_count,
                    )
                )
            for i, turn in enumerate(variant.turns):
                sc = turn.content.count(".") + turn.content.count("?") + turn.content.count("!")
                if sc < c.multi_turn_min_sentences_per_turn or sc > c.multi_turn_max_sentences_per_turn:
                    findings.append(
                        ConstraintViolation(
                            code="CNS-SIZE-007",
                            message=(
                                f"Multi-turn turn {i} has {sc} sentences "
                                f"(expected {c.multi_turn_min_sentences_per_turn}-"
                                f"{c.multi_turn_max_sentences_per_turn})."
                            ),
                            severity=Severity.WARNING,
                            path=f"{path}.turns[{i}].content",
                            phase=phase,
                            expected=(
                                f"{c.multi_turn_min_sentences_per_turn}-"
                                f"{c.multi_turn_max_sentences_per_turn}"
                            ),
                            actual=sc,
                        )
                    )
        else:
            # Agentic and user_question prompts are effectively single-turn user requests.
            sc = variant.sentence_count
            if sc < c.single_turn_min_sentences or sc > c.single_turn_max_sentences:
                findings.append(
                    ConstraintViolation(
                        code="CNS-SIZE-008",
                        message=(
                            f"{exchange_type.value} prompt has {sc} sentences "
                            f"(expected {c.single_turn_min_sentences}-"
                            f"{c.single_turn_max_sentences})."
                        ),
                        severity=Severity.WARNING,
                        path=f"{path}.turns",
                        phase=phase,
                        expected=f"{c.single_turn_min_sentences}-{c.single_turn_max_sentences}",
                        actual=sc,
                    )
                )

        return findings

    def _check_per_turn_labels(
        self,
        variant: PromptVariant,
        path: str,
        phase: GenerationPhase,
    ) -> list[ConstraintViolation]:
        """If turns carry per-turn danger levels, ensure the conversation label is at least the max turn label."""
        findings: list[ConstraintViolation] = []
        if phase.value < GenerationPhase.GENERATED.value:
            return findings

        labels = [t.danger_level for t in variant.turns if t.danger_level is not None]
        if not labels:
            return findings

        _rank = {DangerLevel.BENIGN: 1, DangerLevel.WARN: 2, DangerLevel.DANGEROUS: 3}
        max_label = max(labels, key=lambda d: _rank[d])
        if _rank[max_label] > _rank[variant.danger_level]:
            findings.append(
                ConstraintViolation(
                    code="CNS-LBL-001",
                    message=(
                        f"Variant is labeled {variant.danger_level.value} but a turn is labeled "
                        f"{max_label.value}; conversation label must be at least as high as the "
                        f"most dangerous turn."
                    ),
                    severity=Severity.ERROR,
                    path=f"{path}.danger_level",
                    phase=phase,
                    expected=f">= {max_label.value}",
                    actual=variant.danger_level.value,
                )
            )
        return findings

    def _check_url_normalization(
        self,
        variant: PromptVariant,
        path: str,
        phase: GenerationPhase,
    ) -> list[ConstraintViolation]:
        findings: list[ConstraintViolation] = []
        full_text = variant.prompt_text or " ".join(t.content for t in variant.turns)

        for match in scan_for_unnormalized_references(full_text):
            placeholder = {
                "url": "[URL]",
                "www": "[URL]",
                "ip": "[IP]",
                "email": "[email]",
            }.get(match.kind, "[URL]")
            code = "CNS-URL-001" if match.kind in ("url", "www") else "CNS-URL-002"
            findings.append(
                ConstraintViolation(
                    code=code,
                    message=f"Cyber prompts must use exactly {placeholder} instead of a raw {match.kind} reference.",
                    severity=Severity.ERROR,
                    path=f"{path}.prompt_text",
                    phase=phase,
                    expected=placeholder,
                    actual=match.value,
                )
            )
        return findings

    def _check_attack_vector_fields(
        self,
        variant: PromptVariant,
        path: str,
        phase: GenerationPhase,
    ) -> list[ConstraintViolation]:
        findings: list[ConstraintViolation] = []
        if phase.value < GenerationPhase.GENERATED.value:
            return findings
        if variant.danger_level != DangerLevel.DANGEROUS:
            return findings

        turn_count = len(variant.turns)
        if turn_count > 1:
            if not variant.attack_vector:
                findings.append(
                    ConstraintViolation(
                        code="CNS-FLD-002",
                        message="Dangerous multi-turn variant must document an attack_vector.",
                        severity=Severity.WARNING,
                        path=f"{path}.attack_vector",
                        phase=phase,
                        expected="non-empty string",
                        actual="empty",
                    )
                )
            if not variant.attack_vector_rationale:
                findings.append(
                    ConstraintViolation(
                        code="CNS-FLD-002",
                        message="Dangerous multi-turn variant must provide an attack_vector_rationale.",
                        severity=Severity.WARNING,
                        path=f"{path}.attack_vector_rationale",
                        phase=phase,
                        expected="non-empty string",
                        actual="empty",
                    )
                )
        return findings

    def _check_no_model_response_tags(
        self,
        variant: PromptVariant,
        path: str,
        phase: GenerationPhase,
    ) -> list[ConstraintViolation]:
        """Model response tags belong in ModelEvaluation, not PromptVariant."""
        findings: list[ConstraintViolation] = []
        if hasattr(variant, "model_response_tag"):
            findings.append(
                ConstraintViolation(
                    code="CNS-FLD-003",
                    message="PromptVariant must not store model_response_tag.",
                    severity=Severity.ERROR,
                    path=f"{path}.model_response_tag",
                    phase=phase,
                    expected="absent",
                    actual="present",
                )
            )
        return findings

    def _check_model_evaluations(
        self,
        package: PromptPackage,
        phase: GenerationPhase,
    ) -> list[ConstraintViolation]:
        """Validate model evaluations once they exist."""
        findings: list[ConstraintViolation] = []
        if phase.value < GenerationPhase.MODEL_EVALUATED.value:
            return findings

        for evaluation in package.model_evaluations:
            for response_type in evaluation.model_response_types:
                if response_type not in SUPPORTED_RESPONSE_TYPES:
                    findings.append(
                        ConstraintViolation(
                            code="CNS-TYP-003",
                            message=f"Incompatible model-response tag: {response_type!r}.",
                            severity=Severity.ERROR,
                            path=f"model_evaluations.{evaluation.variant_id}.model_response_types",
                            phase=phase,
                            expected=f"one of {sorted(SUPPORTED_RESPONSE_TYPES)}",
                            actual=response_type,
                        )
                    )

        return findings
