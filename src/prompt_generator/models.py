"""Typed schemas for the red-team prompt generator.

These models are UI-agnostic. The dashboard, CLI, tests, CI, and future API all
operate on the same objects.
"""

from __future__ import annotations

import secrets
import string
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class DangerLevel(str, Enum):
    """Misuse-potential classification of a single prompt variant."""

    BENIGN = "benign"
    WARN = "warn"
    DANGEROUS = "dangerous"


class ExchangeType(str, Enum):
    """Conversation format shared across a contrastive package."""

    AGENTIC = "agentic"
    MULTI_TURN = "multi_turn"
    USER_QUESTION = "user_question"


class TaskCategory(str, Enum):
    """Task category of a single prompt variant within the shared exchange type."""

    CLOSED_QA = "closed_qa"
    CODING = "coding"
    OPEN_ENDED = "open_ended"
    BRAINSTORMING = "brainstorming"
    EXTRACTION = "extraction"
    SUMMARIZATION = "summarization"
    CLASSIFICATION = "classification"


class ReadinessStatus(str, Enum):
    """Overall readiness of a generated and validated package."""

    READY = "ready"
    READY_AFTER_MECHANICAL_FIXES = "ready_after_mechanical_fixes"
    TECHNICAL_OR_CLASSIFICATION_REVIEW_REQUIRED = "technical_or_classification_review_required"
    BLOCKED_BY_MISSING_INFORMATION = "blocked_by_missing_information"


class Severity(str, Enum):
    """Severity of a validation finding."""

    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


class GenerationPhase(str, Enum):
    """Lifecycle phase of a prompt package.

    Rules declare the earliest phase at which they apply so that early-stage
    drafts are not penalized for information that does not yet exist.
    """

    DRAFT = "draft"
    GENERATED = "generated"
    MODEL_EVALUATED = "model_evaluated"
    SUBMISSION_READY = "submission_ready"


@dataclass(frozen=True, slots=True)
class ConstraintViolation:
    """A deterministic mechanical finding with stable rule IDs."""

    code: str
    message: str
    severity: Severity
    path: str
    phase: GenerationPhase = GenerationPhase.DRAFT
    expected: Any | None = None
    actual: Any | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "message": self.message,
            "severity": self.severity.value,
            "path": self.path,
            "phase": self.phase.value,
            "expected": self.expected,
            "actual": self.actual,
        }


@dataclass(frozen=True)
class BoundaryForgeViolation:
    """A semantic or compliance-level finding from the BoundaryForge aggregate validator."""

    code: str
    message: str
    severity: Severity
    path: str
    phase: GenerationPhase = GenerationPhase.GENERATED
    expected: Any | None = None
    actual: Any | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "message": self.message,
            "severity": self.severity.value,
            "path": self.path,
            "phase": self.phase.value,
            "expected": self.expected,
            "actual": self.actual,
        }


@dataclass(frozen=True)
class Turn:
    """A single conversational turn."""

    role: str
    content: str
    rationale: str = ""  # Why this turn exists in the arc.
    danger_level: DangerLevel | None = None  # Per-turn label when required.

    def to_dict(self) -> dict[str, Any]:
        return {
            "role": self.role,
            "content": self.content,
            "rationale": self.rationale,
            "danger_level": self.danger_level.value if self.danger_level else None,
        }


@dataclass(frozen=True)
class PromptVariant:
    """One danger-level variant of a shared-topic prompt package."""

    danger_level: DangerLevel
    task_category: list[TaskCategory] = field(default_factory=list)
    prompt_text: str = ""
    turns: list[Turn] = field(default_factory=list)
    danger_rationale: str = ""
    attack_vector: str = ""  # Dangerous multi-turn only: the vector being chained.
    attack_vector_rationale: str = ""  # Cumulative chain explanation.
    placeholders: dict[str, str] = field(default_factory=dict)
    model_access: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "danger_level": self.danger_level.value,
            "task_category": [tc.value for tc in self.task_category],
            "prompt_text": self.prompt_text,
            "turns": [t.to_dict() for t in self.turns],
            "danger_rationale": self.danger_rationale,
            "attack_vector": self.attack_vector,
            "attack_vector_rationale": self.attack_vector_rationale,
            "placeholders": self.placeholders,
            "model_access": self.model_access,
        }

    @property
    def word_count(self) -> int:
        return sum(len(t.content.split()) for t in self.turns)

    @property
    def sentence_count(self) -> int:
        return sum(
            t.content.count(".") + t.content.count("?") + t.content.count("!") for t in self.turns
        )

    @property
    def turn_count(self) -> int:
        return len(self.turns)

    @property
    def user_text(self) -> str:
        return " ".join(t.content for t in self.turns if t.role == "user")


@dataclass
class TaskSpec:
    """User-facing task specification."""

    domain: str
    exchange_type: ExchangeType
    shared_topic: str
    boundary_forge_version: str = "2024.1"
    benign: PromptVariant = field(default_factory=lambda: PromptVariant(DangerLevel.BENIGN))
    warn: PromptVariant = field(default_factory=lambda: PromptVariant(DangerLevel.WARN))
    dangerous: PromptVariant = field(default_factory=lambda: PromptVariant(DangerLevel.DANGEROUS))

    def variants(self) -> list[PromptVariant]:
        return [self.benign, self.warn, self.dangerous]

    def to_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "exchange_type": self.exchange_type.value,
            "shared_topic": self.shared_topic,
            "boundary_forge_version": self.boundary_forge_version,
            "benign": self.benign.to_dict(),
            "warn": self.warn.to_dict(),
            "dangerous": self.dangerous.to_dict(),
        }


@dataclass
class ConstraintSet:
    """Hard and soft generation limits."""

    max_words_per_prompt: int = 350
    max_sentences_per_prompt: int = 25
    max_turns_per_prompt: int = 6
    max_words_per_turn: int = 150
    max_sentences_per_turn: int = 8
    require_url_placeholders: bool = True
    normalize_urls: bool = True
    near_duplicate_threshold: float = 0.85
    reference_material_max_words: int = 250
    single_turn_min_sentences: int = 3
    single_turn_max_sentences: int = 8
    multi_turn_target_turns: int = 3
    multi_turn_min_sentences_per_turn: int = 2
    multi_turn_max_sentences_per_turn: int = 6


@dataclass
class ModelEvaluation:
    """Evaluation of what the model actually returned for a prompt variant.

    Model-response tags live here, not inside PromptVariant.
    """

    variant_id: str
    generated_response: str = ""
    model_response_types: list[str] = field(default_factory=list)
    response_rationale: str = ""
    generation_metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "variant_id": self.variant_id,
            "generated_response": self.generated_response,
            "model_response_types": self.model_response_types,
            "response_rationale": self.response_rationale,
            "generation_metadata": self.generation_metadata,
        }


@dataclass
class ValidationReport:
    """Aggregated validation findings for a prompt package."""

    package_id: str
    mechanical_findings: list[ConstraintViolation] = field(default_factory=list)
    semantic_findings: list[BoundaryForgeViolation] = field(default_factory=list)
    contrastive_findings: list[dict[str, Any]] = field(default_factory=list)
    duplicate_findings: list[dict[str, Any]] = field(default_factory=list)
    readiness_status: ReadinessStatus = ReadinessStatus.TECHNICAL_OR_CLASSIFICATION_REVIEW_REQUIRED

    def to_dict(self) -> dict[str, Any]:
        return {
            "package_id": self.package_id,
            "mechanical_findings": [f.to_dict() for f in self.mechanical_findings],
            "semantic_findings": [f.to_dict() for f in self.semantic_findings],
            "contrastive_findings": self.contrastive_findings,
            "duplicate_findings": self.duplicate_findings,
            "readiness_status": self.readiness_status.value,
        }

    @property
    def has_errors(self) -> bool:
        return any(f.severity == Severity.ERROR for f in self.mechanical_findings) or any(
            f.severity == Severity.ERROR for f in self.semantic_findings
        )


@dataclass(frozen=True)
class PromptPackage:
    """A finished, validated contrastive package ready for export."""

    package_id: str
    task_spec: TaskSpec
    validation_report: ValidationReport | None = None
    model_evaluations: list[ModelEvaluation] = field(default_factory=list)
    generated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return {
            "package_id": self.package_id,
            "task_spec": self.task_spec.to_dict(),
            "validation_report": self.validation_report.to_dict() if self.validation_report else None,
            "model_evaluations": [me.to_dict() for me in self.model_evaluations],
            "generated_at": self.generated_at,
        }


def short_id(length: int = 8) -> str:
    """Cryptographically weak but collision-resistant enough for local IDs."""
    return "".join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(length))
