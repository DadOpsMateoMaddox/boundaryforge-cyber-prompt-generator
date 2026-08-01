"""Task specification construction.

User selections are converted into a strongly typed TaskSpec before any
validation or generation happens.
"""

from __future__ import annotations

from .models import DangerLevel, ExchangeType, PromptVariant, TaskCategory, TaskSpec


SUPPORTED_DOMAINS = {
    "kubernetes_rbac_container_escape",
    "web_sql_injection",
    "network_reconnaissance",
    "linux_privilege_escalation",
    "cloud_iam_misconfiguration",
}


def build_task_spec(
    domain: str,
    exchange_type: ExchangeType,
    boundary_forge_version: str = "2024.1",
    benign_categories: list[TaskCategory] | None = None,
    warn_categories: list[TaskCategory] | None = None,
    dangerous_categories: list[TaskCategory] | None = None,
) -> TaskSpec:
    """Build a TaskSpec from high-level user selections.

    Args:
        domain: Technical domain shared across all three danger levels.
        exchange_type: Single exchange type for the whole package.
        boundary_forge_version: Version of BoundaryForge rules to enforce.
        benign_categories: Task categories for the benign variant.
        warn_categories: Task categories for the warn variant.
        dangerous_categories: Task categories for the dangerous variant.

    Returns:
        A TaskSpec with empty PromptVariant shells to be filled by the generator.
    """
    if domain not in SUPPORTED_DOMAINS:
        raise ValueError(
            f"Unsupported domain: {domain!r}. Choose from {sorted(SUPPORTED_DOMAINS)}."
        )

    return TaskSpec(
        domain=domain,
        exchange_type=exchange_type,
        shared_topic=domain,
        boundary_forge_version=boundary_forge_version,
        benign=PromptVariant(
            danger_level=DangerLevel.BENIGN,
            task_category=benign_categories or _default_categories(DangerLevel.BENIGN, exchange_type),
        ),
        warn=PromptVariant(
            danger_level=DangerLevel.WARN,
            task_category=warn_categories or _default_categories(DangerLevel.WARN, exchange_type),
        ),
        dangerous=PromptVariant(
            danger_level=DangerLevel.DANGEROUS,
            task_category=dangerous_categories
            or _default_categories(DangerLevel.DANGEROUS, exchange_type),
        ),
    )


def _default_categories(danger_level: DangerLevel, exchange_type: ExchangeType) -> list[TaskCategory]:
    """Pick sensible default task categories when the user does not specify them."""
    if exchange_type == ExchangeType.MULTI_TURN:
        return [TaskCategory.CLOSED_QA]
    if exchange_type == ExchangeType.AGENTIC:
        return [TaskCategory.CODING]
    if exchange_type == ExchangeType.USER_QUESTION:
        return [TaskCategory.OPEN_ENDED]
    return [TaskCategory.OPEN_ENDED]
